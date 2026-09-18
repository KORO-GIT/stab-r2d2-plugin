#!/usr/bin/env python3
"""R2D2 plugin: reverse-proxy the StabX web UI through the R2D2 host.

The container runs with --network=host.  The R2D2 Raspberry Pi can therefore
reach the StabX Raspberry Pi Zero on its local access-point network, while an
operator opens this proxy on the R2D2 address.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass

from aiohttp import ClientSession, ClientTimeout, TCPConnector, WSMsgType, web


CONFIG_PATH = os.environ.get("R2_CONFIG", "/app/config.json")
STATUS_PATH = "/__r2_stabh_proxy/status"
HDMI_DIAGNOSTICS_PATH = "/__r2_stabh_proxy/hdmi"
PLUGIN_LABEL = "koropwnz.stab-r2d2-plugin"
PLUGIN_VERSION = "0.2.6"
R2_SOCKET_PATH = "/tmp/R2D2.socket"
R2_GROUND = 1000
R2_MAX_FRAME = 128 * 1024
R2_ACK_TIMEOUT_SECONDS = 2.0
R2_ACK_RETRIES = 5
TUNNEL_CHUNK_BYTES = 24 * 1024
TUNNEL_ATOMIC_BYTES = 72 * 1024
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
WEBSOCKET_HEADERS = {
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
}
TEXT_TYPES = (
    "text/",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DISCOVERED_ADDRESSES: set[str] = set()

HDMI_DIAGNOSTIC_COMMAND = r"""
set +e
echo '===== R2D2 HDMI / CSI DIAGNOSTICS ====='
date -Iseconds 2>/dev/null || date
printf 'model: '
tr -d '\000' </proc/device-tree/model 2>/dev/null || echo unavailable
echo
uname -a
printf 'temperature_mC: '
cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo unavailable

echo '===== VIDEO DEVICE NODES ====='
ls -la /dev/video* /dev/media* /dev/v4l-subdev* 2>&1

echo '===== VIDEO SYSFS ====='
found=0
for node in /sys/class/video4linux/*; do
    [ -e "$node" ] || continue
    found=1
    printf '%s name=' "$node"
    cat "$node/name" 2>/dev/null || echo unavailable
    readlink -f "$node/device" 2>/dev/null || true
done
[ "$found" -eq 1 ] || echo 'no /sys/class/video4linux devices'

echo '===== I2C DEVICES ====='
found=0
for name in /sys/bus/i2c/devices/*/name; do
    [ -e "$name" ] || continue
    value=$(cat "$name" 2>/dev/null)
    case "$value" in
        *tc358743*|*unicam*|*adv72*|*bcm2835*)
            found=1
            printf '%s: %s\n' "${name%/name}" "$value"
            ;;
    esac
done
[ "$found" -eq 1 ] || echo 'no matching I2C device names visible'

echo '===== KERNEL MODULES ====='
if command -v lsmod >/dev/null 2>&1; then
    lsmod | grep -Ei 'tc358743|unicam|adv718|bcm2835' || true
else
    echo 'lsmod unavailable'
fi

echo '===== V4L2 DEVICE LIST ====='
if command -v v4l2-ctl >/dev/null 2>&1; then
    v4l2-ctl --list-devices 2>&1
else
    echo 'v4l2-ctl unavailable'
fi

echo '===== V4L2 HDMI STATUS ====='
if command -v v4l2-ctl >/dev/null 2>&1; then
    for device in /dev/video* /dev/v4l-subdev*; do
        [ -e "$device" ] || continue
        echo "----- $device DRIVER -----"
        v4l2-ctl -d "$device" --info 2>&1 || true
        echo "----- $device DV TIMINGS -----"
        v4l2-ctl -d "$device" --query-dv-timings 2>&1 || true
        echo "----- $device EDID -----"
        v4l2-ctl -d "$device" --get-edid 2>&1 || true
        echo "----- $device CONTROLS / FORMAT -----"
        v4l2-ctl -d "$device" --all 2>&1 || true
    done
fi

echo '===== MEDIA GRAPH ====='
if command -v media-ctl >/dev/null 2>&1; then
    found=0
    for device in /dev/media*; do
        [ -e "$device" ] || continue
        found=1
        echo "----- $device -----"
        media-ctl -d "$device" -p 2>&1 || true
    done
    [ "$found" -eq 1 ] || echo 'no /dev/media devices'
else
    echo 'media-ctl unavailable'
fi

echo '===== KERNEL VIDEO LOG ====='
if command -v dmesg >/dev/null 2>&1; then
    dmesg 2>&1 | grep -Ei 'tc358743|unicam|csi|hdmi|video|i2c|under.?voltage|watchdog' | tail -n 240
else
    echo 'dmesg unavailable'
fi
"""


def log(level: str, message: str) -> None:
    # R2D2 log transport is safest with short ASCII lines.
    clean = message.encode("ascii", "replace").decode("ascii")
    print(f"{level}: {clean}"[:200], flush=True)


def load_config(path: str = CONFIG_PATH) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
            return value if isinstance(value, dict) else {}
    except FileNotFoundError:
        log("WARNING", f"config not found at {path}; using defaults")
    except Exception as exc:  # malformed config must not create a crash-loop
        log("ERROR", f"cannot read config: {type(exc).__name__}: {exc}")
    return {}


def _port(value: object, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if 1 <= parsed <= 65535 else default
    except (TypeError, ValueError):
        return default


def _positive_float(value: object, default: float) -> float:
    try:
        parsed = float(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"1", "true", "yes", "on"}:
            return True
        if value.strip().lower() in {"0", "false", "no", "off"}:
            return False
    return default


def _private_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in network for network in PRIVATE_NETWORKS
    )


def _neighbor_candidates() -> tuple[str, ...]:
    """Return likely local peers from DHCP leases and the kernel ARP cache."""
    candidates: list[str] = []
    lease_paths = (
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/run/dnsmasq/dnsmasq.leases",
        "/tmp/dnsmasq.leases",
    )
    for path in lease_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as stream:
                rows = stream.readlines()
        except OSError:
            continue
        preferred: list[str] = []
        other: list[str] = []
        for row in rows:
            fields = row.split()
            if len(fields) < 3 or not _private_ipv4(fields[2]):
                continue
            hostname = fields[3].lower() if len(fields) > 3 else ""
            (preferred if any(token in hostname for token in ("pizero", "stab", "rasp")) else other).append(
                fields[2]
            )
        candidates.extend(preferred)
        candidates.extend(other)

    try:
        with open("/proc/net/arp", "r", encoding="ascii", errors="replace") as stream:
            for row in stream.readlines()[1:]:
                fields = row.split()
                if fields and _private_ipv4(fields[0]):
                    candidates.append(fields[0])
    except OSError:
        pass

    candidates.extend(sorted(DISCOVERED_ADDRESSES))
    return tuple(dict.fromkeys(candidates))


def _local_ipv4_networks() -> tuple[tuple[ipaddress.IPv4Network, str], ...]:
    """Enumerate small RFC1918 networks without depending on the `ip` command."""
    if os.name != "posix":
        return ()
    try:
        import fcntl
    except ImportError:
        return ()

    output: list[tuple[ipaddress.IPv4Network, str]] = []
    for _, name in socket.if_nameindex():
        if name == "lo":
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            request = struct.pack("256s", name.encode("utf-8")[:15])
            address = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), 0x8915, request)[20:24])
            netmask = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), 0x891B, request)[20:24])
            network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        except OSError:
            continue
        finally:
            probe.close()
        if not _private_ipv4(address):
            continue
        # A broad /16 or /20 is too large for an active scan.  Scan the /24
        # around the R2D2 interface instead; this is where an AP client is
        # normally leased an address.
        if network.prefixlen < 24:
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        output.append((network, address))
    return tuple(output[:4])


@dataclass(frozen=True)
class Config:
    target_hosts: tuple[str, ...]
    target_port: int
    listen_host: str
    listen_port: int
    connect_timeout: float
    dns_cache_seconds: float
    health_interval: float
    max_text_rewrite_bytes: int
    rewrite_absolute_urls: bool
    proxy_username: str
    proxy_password: str
    remote_tunnel_enabled: bool
    remote_max_response_bytes: int
    auto_discover: bool
    discovery_interval: float
    terminal_enabled: bool
    terminal_token: str
    terminal_timeout: float
    terminal_max_output_bytes: int

    @classmethod
    def from_dict(
        cls,
        raw: dict,
        *,
        target_port_key: str = "TARGET_PORT",
        default_target_port: int = 8080,
        listen_port_key: str = "LISTEN_PORT",
        default_listen_port: int = 18080,
    ) -> "Config":
        hosts_value = str(raw.get("TARGET_HOSTS", "pizero2,pizero2.local"))
        hosts = tuple(dict.fromkeys(x.strip() for x in hosts_value.split(",") if x.strip()))
        if not hosts:
            hosts = ("pizero2", "pizero2.local")
        return cls(
            target_hosts=hosts,
            target_port=_port(raw.get(target_port_key), default_target_port),
            listen_host=str(raw.get("LISTEN_HOST", "0.0.0.0")).strip() or "0.0.0.0",
            listen_port=_port(raw.get(listen_port_key), default_listen_port),
            connect_timeout=_positive_float(raw.get("CONNECT_TIMEOUT"), 5.0),
            dns_cache_seconds=_positive_float(raw.get("DNS_CACHE_SECONDS"), 10.0),
            health_interval=_positive_float(raw.get("HEALTH_INTERVAL"), 10.0),
            max_text_rewrite_bytes=_positive_int(raw.get("MAX_TEXT_REWRITE_BYTES"), 2_097_152),
            rewrite_absolute_urls=_bool(raw.get("REWRITE_ABSOLUTE_URLS"), True),
            proxy_username=str(raw.get("PROXY_USERNAME", "")),
            proxy_password=str(raw.get("PROXY_PASSWORD", "")),
            remote_tunnel_enabled=_bool(raw.get("REMOTE_TUNNEL_ENABLED"), True),
            remote_max_response_bytes=_positive_int(
                raw.get("REMOTE_MAX_RESPONSE_BYTES"), 4 * 1024 * 1024
            ),
            auto_discover=_bool(raw.get("AUTO_DISCOVER"), True),
            discovery_interval=_positive_float(raw.get("DISCOVERY_INTERVAL"), 60.0),
            terminal_enabled=_bool(raw.get("TERMINAL_ENABLED"), False),
            terminal_token=str(raw.get("TERMINAL_TOKEN", "")),
            terminal_timeout=_positive_float(raw.get("TERMINAL_TIMEOUT"), 20.0),
            terminal_max_output_bytes=_positive_int(
                raw.get("TERMINAL_MAX_OUTPUT_BYTES"), 256 * 1024
            ),
        )


@dataclass(frozen=True)
class Target:
    hostname: str
    address: str
    port: int

    @property
    def url_host(self) -> str:
        return f"[{self.address}]" if ":" in self.address else self.address

    @property
    def authority(self) -> str:
        return f"{self.hostname}:{self.port}"


class StabXProxy:
    def __init__(self, config: Config):
        self.config = config
        self.session: ClientSession | None = None
        self._target: Target | None = None
        self._target_until = 0.0
        self._resolve_lock = asyncio.Lock()
        self._last_online: bool | None = None
        self._monitor_task: asyncio.Task | None = None
        self._next_discovery = 0.0

    async def start(self) -> None:
        timeout = ClientTimeout(
            total=None,
            connect=self.config.connect_timeout,
            sock_connect=self.config.connect_timeout,
            sock_read=None,
        )
        self.session = ClientSession(
            timeout=timeout,
            connector=TCPConnector(limit=32, ttl_dns_cache=0),
            auto_decompress=False,
        )
        self._monitor_task = asyncio.create_task(self._health_monitor())

    async def close(self) -> None:
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def _health_monitor(self) -> None:
        while True:
            try:
                target = await self.resolve_target(force=True)
                online = target is not None
                if online != self._last_online:
                    if target is not None:
                        log("INFO", f"StabX online at {target.address}:{target.port}")
                    else:
                        log("WARNING", "StabX unavailable; proxy remains ready")
                    self._last_online = online
            except Exception as exc:
                if self._last_online is not False:
                    log("WARNING", f"health check failed: {type(exc).__name__}: {exc}")
                    self._last_online = False
            await asyncio.sleep(self.config.health_interval)

    async def resolve_target(self, force: bool = False) -> Target | None:
        now = time.monotonic()
        if not force and self._target is not None and now < self._target_until:
            return self._target

        async with self._resolve_lock:
            now = time.monotonic()
            if not force and self._target is not None and now < self._target_until:
                return self._target

            # Auto-discovered hosts often have no working DNS name.  Keep the
            # last discovered address alive by probing it again after the
            # short cache expires.  Otherwise the proxy drops a healthy target
            # until the longer discovery interval permits another subnet scan.
            previous_target = self._target
            if previous_target is not None and await self._probe_address(
                previous_target.address
            ):
                self._target_until = time.monotonic() + self.config.dns_cache_seconds
                return previous_target

            loop = asyncio.get_running_loop()
            for hostname in self.config.target_hosts:
                try:
                    results = await asyncio.wait_for(
                        loop.getaddrinfo(
                            hostname,
                            self.config.target_port,
                            type=socket.SOCK_STREAM,
                        ),
                        timeout=self.config.connect_timeout,
                    )
                except (OSError, asyncio.TimeoutError):
                    continue

                addresses = list(dict.fromkeys(result[4][0] for result in results))
                for address in addresses:
                    if not await self._probe_address(address):
                        continue
                    target = Target(hostname, address, self.config.target_port)
                    self._target = target
                    self._target_until = time.monotonic() + self.config.dns_cache_seconds
                    return target

            if self.config.auto_discover and time.monotonic() >= self._next_discovery:
                self._next_discovery = time.monotonic() + self.config.discovery_interval
                target = await self._discover_target()
                if target is not None:
                    self._target = target
                    self._target_until = time.monotonic() + self.config.dns_cache_seconds
                    DISCOVERED_ADDRESSES.add(target.address)
                    log("INFO", f"auto-discovered StabX at {target.address}:{target.port}")
                    return target

            self._target = None
            self._target_until = time.monotonic() + min(self.config.dns_cache_seconds, 3.0)
            return None

    async def _probe_address(self, address: str, timeout: float | None = None) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, self.config.target_port),
                timeout=timeout or self.config.connect_timeout,
            )
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            del reader
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _discover_target(self) -> Target | None:
        neighbours = _neighbor_candidates()
        networks = _local_ipv4_networks()
        network_text = ",".join(f"{network}[r2={own}]" for network, own in networks) or "none"
        neighbour_text = ",".join(neighbours) or "none"
        log(
            "INFO",
            f"discovery port {self.config.target_port}: networks={network_text}; "
            f"DHCP/ARP peers={neighbour_text}",
        )

        for address in neighbours:
            if await self._probe_address(address, timeout=0.35):
                return Target(self.config.target_hosts[0], address, self.config.target_port)

        addresses: list[str] = []
        for network, own_address in networks:
            for address in network.hosts():
                value = str(address)
                if value != own_address:
                    addresses.append(value)
        addresses = list(dict.fromkeys(addresses))[:1020]
        if not addresses:
            return None

        semaphore = asyncio.Semaphore(64)

        async def scan(address: str) -> str | None:
            async with semaphore:
                return address if await self._probe_address(address, timeout=0.2) else None

        tasks = [asyncio.create_task(scan(address)) for address in addresses]
        try:
            for task in asyncio.as_completed(tasks):
                address = await task
                if address is not None:
                    return Target(self.config.target_hosts[0], address, self.config.target_port)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        log("WARNING", f"discovery port {self.config.target_port}: no listening StabX service found")
        return None

    def invalidate_target(self) -> None:
        self._target = None
        self._target_until = 0.0

    def _authorized(self, request: web.Request) -> bool:
        user = self.config.proxy_username
        if not user:
            return True
        expected = base64.b64encode(
            f"{user}:{self.config.proxy_password}".encode("utf-8")
        ).decode("ascii")
        received = request.headers.get("Authorization", "")
        return hmac.compare_digest(received, f"Basic {expected}")

    def _auth_response(self) -> web.Response:
        return web.Response(
            status=401,
            text="Proxy authentication required",
            headers={"WWW-Authenticate": 'Basic realm="StabX through R2D2"'},
        )

    def _diagnostics_authorized(self, request: web.Request) -> bool:
        token = self.config.terminal_token
        if not self.config.terminal_enabled or len(token) < 24:
            return False
        supplied = request.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {token}")

    async def hdmi_diagnostics(self, request: web.Request) -> web.Response:
        if not self._diagnostics_authorized(request):
            return web.Response(
                status=401,
                text="Valid TERMINAL_TOKEN bearer authorization is required\n",
                headers={"WWW-Authenticate": "Bearer"},
            )
        maximum = min(max(int(self.config.terminal_max_output_bytes), 4096), 512 * 1024)
        timeout = min(max(float(self.config.terminal_timeout), 5.0), 60.0)
        try:
            process = await asyncio.create_subprocess_exec(
                "/bin/sh",
                "-lc",
                HDMI_DIAGNOSTIC_COMMAND,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                timed_out = False
            except asyncio.TimeoutError:
                timed_out = True
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGKILL)
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                output, _ = await process.communicate()
            truncated = len(output) > maximum
            output = output[:maximum]
            footer = (
                f"\n===== RESULT =====\nexit_code={process.returncode} "
                f"timed_out={str(timed_out).lower()} "
                f"truncated={str(truncated).lower()}\n"
            ).encode("utf-8")
            return web.Response(
                body=output + footer,
                content_type="text/plain",
                charset="utf-8",
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:
            log("ERROR", f"HDMI diagnostics failed: {type(exc).__name__}")
            return web.Response(
                status=500,
                text=f"HDMI diagnostics failed: {type(exc).__name__}\n",
                headers={"Cache-Control": "no-store"},
            )

    def _upstream_headers(self, request: web.Request, target: Target) -> dict[str, str]:
        headers: dict[str, str] = {}
        for name, value in request.headers.items():
            lower = name.lower()
            if lower in HOP_BY_HOP or lower in WEBSOCKET_HEADERS:
                continue
            if lower == "authorization" and self.config.proxy_username:
                continue
            headers[name] = value
        headers["Host"] = target.authority
        headers["X-Forwarded-Host"] = request.host
        headers["X-Forwarded-Proto"] = request.scheme
        peer = request.remote
        if peer:
            prior = headers.get("X-Forwarded-For")
            headers["X-Forwarded-For"] = f"{prior}, {peer}" if prior else peer

        target_origin = f"http://{target.authority}"
        for header_name in ("Origin", "Referer"):
            value = headers.get(header_name)
            if value:
                for authority in self._target_authorities(target):
                    value = value.replace(f"http://{request.host}", target_origin)
                    value = value.replace(f"https://{request.host}", target_origin)
                    value = value.replace(f"http://{authority}", target_origin)
                    value = value.replace(f"https://{authority}", target_origin)
                headers[header_name] = value
        return headers

    def _target_authorities(self, target: Target) -> tuple[str, ...]:
        values = [f"{host}:{self.config.target_port}" for host in self.config.target_hosts]
        values.append(f"{target.url_host}:{target.port}")
        return tuple(dict.fromkeys(values))

    def _rewrite_location(self, request: web.Request, target: Target, value: str) -> str:
        external = f"{request.scheme}://{request.host}"
        for authority in self._target_authorities(target):
            for scheme in ("http", "https"):
                prefix = f"{scheme}://{authority}"
                if value.startswith(prefix):
                    return external + value[len(prefix):]
        return value

    def _rewrite_text(self, request: web.Request, target: Target, body: bytes) -> bytes:
        external_http = f"{request.scheme}://{request.host}".encode("utf-8")
        external_ws_scheme = "wss" if request.scheme == "https" else "ws"
        external_ws = f"{external_ws_scheme}://{request.host}".encode("utf-8")
        for authority in self._target_authorities(target):
            auth = authority.encode("utf-8")
            body = body.replace(b"http://" + auth, external_http)
            body = body.replace(b"https://" + auth, external_http)
            body = body.replace(b"ws://" + auth, external_ws)
            body = body.replace(b"wss://" + auth, external_ws)
            body = body.replace(b"//" + auth, b"//" + request.host.encode("utf-8"))
        return body

    async def status(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return self._auth_response()
        target = await self.resolve_target(force=True)
        return web.json_response(
            {
                "ok": target is not None,
                "listen": f"{self.config.listen_host}:{self.config.listen_port}",
                "target_hosts": list(self.config.target_hosts),
                "target_port": self.config.target_port,
                "resolved_address": target.address if target else None,
            },
            status=200 if target else 503,
        )

    async def handle(self, request: web.Request) -> web.StreamResponse:
        if not self._authorized(request):
            return self._auth_response()
        target = await self.resolve_target()
        if target is None:
            return web.Response(
                status=502,
                content_type="text/html",
                text=(
                    "<!doctype html><meta charset=utf-8><title>StabX unavailable</title>"
                    "<h1>StabX is unavailable</h1>"
                    "<p>R2D2 cannot reach pizero2:8080. Check that StabX is powered "
                    "and connected to uapilot or uapilotstab.</p>"
                ),
            )
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self._websocket(request, target)
        return await self._http(request, target)

    async def _http(self, request: web.Request, target: Target) -> web.StreamResponse:
        assert self.session is not None
        url = f"http://{target.url_host}:{target.port}{request.rel_url}"
        headers = self._upstream_headers(request, target)
        data: object = None
        if request.can_read_body:
            data = request.content.iter_chunked(64 * 1024)
        try:
            upstream = await self.session.request(
                request.method,
                url,
                headers=headers,
                data=data,
                allow_redirects=False,
            )
        except Exception as exc:
            self.invalidate_target()
            log("WARNING", f"upstream request failed: {type(exc).__name__}: {exc}")
            return web.Response(status=502, text="StabX upstream request failed")

        async with upstream:
            content_type = upstream.headers.get("Content-Type", "").lower()
            encoding = upstream.headers.get("Content-Encoding", "").lower()
            length = upstream.content_length
            is_text = any(content_type.startswith(prefix) for prefix in TEXT_TYPES)
            can_rewrite = (
                self.config.rewrite_absolute_urls
                and request.method != "HEAD"
                and is_text
                and not encoding
                and (length is None or length <= self.config.max_text_rewrite_bytes)
            )
            if can_rewrite:
                body = await upstream.read()
                if len(body) <= self.config.max_text_rewrite_bytes:
                    body = self._rewrite_text(request, target, body)
                    response = web.Response(status=upstream.status, reason=upstream.reason, body=body)
                    self._copy_response_headers(
                        response,
                        upstream,
                        request,
                        target,
                        skip={"content-length", "content-encoding"},
                    )
                    return response

            response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
            self._copy_response_headers(response, upstream, request, target)
            await response.prepare(request)
            if request.method != "HEAD":
                async for chunk in upstream.content.iter_chunked(64 * 1024):
                    await response.write(chunk)
            await response.write_eof()
            return response

    def _copy_response_headers(
        self,
        response: web.StreamResponse,
        upstream,
        request: web.Request,
        target: Target,
        skip: set[str] | None = None,
    ) -> None:
        skipped = HOP_BY_HOP | (skip or set())
        for raw_name, raw_value in upstream.raw_headers:
            name = raw_name.decode("latin-1")
            value = raw_value.decode("latin-1")
            lower = name.lower()
            if lower in skipped:
                continue
            if lower == "location":
                value = self._rewrite_location(request, target, value)
            if lower == "set-cookie":
                for authority in self._target_authorities(target):
                    host = authority.rsplit(":", 1)[0].strip("[]")
                    value = value.replace(f"Domain={host}", "Domain=" + request.host.split(":", 1)[0])
                    value = value.replace(f"domain={host}", "domain=" + request.host.split(":", 1)[0])
            if lower == "set-cookie":
                response.headers.add(name, value)
            else:
                response.headers[name] = value

    async def _websocket(self, request: web.Request, target: Target) -> web.StreamResponse:
        assert self.session is not None
        url = f"ws://{target.url_host}:{target.port}{request.rel_url}"
        requested_protocols: list[str] = []
        for value in request.headers.getall("Sec-WebSocket-Protocol", []):
            requested_protocols.extend(x.strip() for x in value.split(",") if x.strip())
        headers = self._upstream_headers(request, target)
        try:
            upstream = await self.session.ws_connect(
                url,
                headers=headers,
                protocols=requested_protocols,
                autoping=True,
                heartbeat=30,
                max_msg_size=16 * 1024 * 1024,
            )
        except Exception as exc:
            self.invalidate_target()
            log("WARNING", f"upstream websocket failed: {type(exc).__name__}: {exc}")
            return web.Response(status=502, text="StabX WebSocket connection failed")

        selected = [upstream.protocol] if upstream.protocol else []
        client = web.WebSocketResponse(
            protocols=selected,
            autoping=True,
            heartbeat=30,
            max_msg_size=16 * 1024 * 1024,
        )
        try:
            await client.prepare(request)

            async def client_to_upstream() -> None:
                async for message in client:
                    await self._send_ws(upstream, message)

            async def upstream_to_client() -> None:
                async for message in upstream:
                    await self._send_ws(client, message)

            tasks = {
                asyncio.create_task(client_to_upstream()),
                asyncio.create_task(upstream_to_client()),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done | pending:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        finally:
            await upstream.close()
            await client.close()
        return client

    @staticmethod
    async def _send_ws(destination, message) -> None:
        if message.type == WSMsgType.TEXT:
            await destination.send_str(message.data)
        elif message.type == WSMsgType.BINARY:
            await destination.send_bytes(message.data)
        elif message.type == WSMsgType.PING:
            await destination.ping(message.data)
        elif message.type == WSMsgType.PONG:
            await destination.pong(message.data)
        elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
            await destination.close()
        elif message.type == WSMsgType.ERROR:
            raise RuntimeError("WebSocket peer reported an error")


class R2RemoteTunnel:
    """Bridge small browser requests through R2D2's plugin.ctl channel.

    Direct host-network ports remain useful on the local Wi-Fi network.  This
    bridge is the separate path used by the Windows helper while the operator
    reaches the aircraft through the R2D2 Internet/cloud connection.
    """

    def __init__(self, configs: tuple[Config, ...]):
        self.configs = {config.target_port: config for config in configs}
        self.proxies = {
            target_port: StabXProxy(config)
            for target_port, config in self.configs.items()
        }
        self.writer: asyncio.StreamWriter | None = None
        self._write_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()
        self._websockets: dict[str, tuple[object, int]] = {}
        self._connected_logged = False
        self._logged_request_ports: set[int] = set()
        self._shell_cwds: dict[str, str] = {}
        self._shell_requests: set[str] = set()
        self._ack_enabled = False
        self._ack_waiters: dict[tuple[str, int], asyncio.Event] = {}
        self._event_sequences: dict[str, int] = {}

    @property
    def shell_config(self) -> Config:
        return next(iter(self.configs.values()))

    @property
    def shell_available(self) -> bool:
        config = self.shell_config
        return config.terminal_enabled and len(config.terminal_token) >= 24

    async def run(self) -> None:
        for proxy in self.proxies.values():
            await proxy.start()
        try:
            while True:
                try:
                    reader, writer = await asyncio.open_unix_connection(R2_SOCKET_PATH)
                    self.writer = writer
                    if not self._connected_logged:
                        log("INFO", "R2D2 Internet tunnel connected")
                        self._connected_logged = True
                    announce = asyncio.create_task(self._announce_loop())
                    try:
                        await self._read_loop(reader)
                    finally:
                        announce.cancel()
                        with contextlib.suppress(asyncio.CancelledError):
                            await announce
                        self.writer = None
                        writer.close()
                        with contextlib.suppress(Exception):
                            await writer.wait_closed()
                except asyncio.CancelledError:
                    raise
                except (OSError, asyncio.IncompleteReadError, ValueError) as exc:
                    if self._connected_logged:
                        log("WARNING", f"R2D2 Internet tunnel disconnected: {type(exc).__name__}")
                        self._connected_logged = False
                    await asyncio.sleep(2)
        finally:
            for task in self._tasks:
                task.cancel()
            for websocket, _ in self._websockets.values():
                with contextlib.suppress(Exception):
                    await websocket.close()
            for proxy in self.proxies.values():
                await proxy.close()

    async def _announce_loop(self) -> None:
        while True:
            await self._send(
                R2_GROUND,
                {
                    "announce": True,
                    "tm": {
                        "service": "stabh-browser-tunnel",
                        "ports": sorted(self.configs),
                        "terminal": self.shell_available,
                    },
                },
            )
            await asyncio.sleep(5)

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        self._ack_enabled = True
        try:
            while True:
                length = struct.unpack("<I", await reader.readexactly(4))[0]
                if length <= 0 or length > R2_MAX_FRAME:
                    raise ValueError(f"invalid R2D2 frame length: {length}")
                raw = await reader.readexactly(length)
                frame = json.loads(raw.split(b"\0", 1)[0].decode("utf-8"))
                if frame.get("PT") != "plugin.ctl":
                    continue
                command = frame.get("cmd")
                if command not in {
                    "stabh.http",
                    "stabh.ws.open",
                    "stabh.ws.send",
                    "stabh.ws.close",
                    "stabh.ack",
                    "r2shell.exec",
                }:
                    continue
                task = asyncio.create_task(self._dispatch(frame))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
        finally:
            self._ack_enabled = False
            for waiter in self._ack_waiters.values():
                waiter.set()
            self._ack_waiters.clear()

    async def _dispatch(self, frame: dict) -> None:
        command = frame.get("cmd")
        if command == "stabh.http":
            await self._handle_http(frame)
        elif command == "stabh.ws.open":
            await self._open_websocket(frame)
        elif command == "stabh.ws.send":
            await self._send_websocket(frame)
        elif command == "stabh.ws.close":
            await self._close_websocket(frame)
        elif command == "stabh.ack":
            self._handle_ack(frame)
        elif command == "r2shell.exec":
            await self._handle_shell(frame)

    def _handle_ack(self, frame: dict) -> None:
        arg = frame.get("arg") if isinstance(frame.get("arg"), dict) else {}
        request_id = str(arg.get("id", ""))[:80]
        try:
            sequence = int(arg.get("seq", 0))
        except (TypeError, ValueError):
            return
        waiter = self._ack_waiters.get((request_id, sequence))
        if waiter is not None:
            waiter.set()

    def _request_parts(self, frame: dict) -> tuple[int, str, dict, int]:
        arg = frame.get("arg") if isinstance(frame.get("arg"), dict) else {}
        request_id = str(arg.get("id", ""))[:80]
        target_port = _port(arg.get("port"), 0)
        # Some older R2D2 Internet relays remove `src` from frames forwarded
        # to a TGZ process.  Replies addressed to the documented ground
        # endpoint 1000 are still delivered to every desktop WebSocket;
        # request IDs let the intended bridge select its own response.
        source = int(frame.get("src") or R2_GROUND)
        return source, request_id, arg, target_port

    async def _send(self, destination: int, fields: dict) -> None:
        writer = self.writer
        if writer is None:
            raise ConnectionError("R2D2 socket is not connected")
        frame = {
            "PT": "plugin.ctl",
            "dst": destination,
            "PKTFLAG-force-delivery": True,
            "plugin": PLUGIN_LABEL,
            **fields,
        }
        body = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        if len(body) > R2_MAX_FRAME:
            raise ValueError("outgoing R2D2 frame is too large")
        async with self._write_lock:
            writer.write(struct.pack("<I", len(body)) + body)
            await writer.drain()

    async def _tunnel_event(self, destination: int, payload: dict) -> None:
        # Current R2D2 Internet relays forward plugin telemetry (`tm`) but may
        # discard unknown top-level fields.  Keep the original top-level field
        # for direct/older bridges and mirror it into `tm` for the real relay.
        # The Internet relay rewrites the request source, so replying to that
        # transient value can route the answer back into an onboard service.
        # Endpoint 1000 is the documented ground-station broadcast endpoint;
        # request IDs ensure that only the requesting desktop bridge consumes
        # the response.
        request_id = str(payload.get("id", ""))[:80]
        sequence = self._event_sequences.get(request_id, 0) + 1
        self._event_sequences[request_id] = sequence
        wire_payload = {**payload, "seq": sequence}
        fields = {
            "tunnel": wire_payload,
            "tm": {
                "service": "stabh-browser-tunnel",
                "tunnel": wire_payload,
            },
        }
        # The Internet relay exposes telemetry as a latest-value snapshot.  A
        # complete response therefore has to be useful on its own: waiting for
        # an acknowledgement would only keep the plugin task open after the
        # desktop has already received the final result.
        if wire_payload.get("kind") in {"http.response", "shell.result"}:
            await self._send(R2_GROUND, fields)
            return
        if not self._ack_enabled or not request_id:
            await self._send(R2_GROUND, fields)
            return

        waiter = asyncio.Event()
        key = (request_id, sequence)
        self._ack_waiters[key] = waiter
        try:
            for _ in range(R2_ACK_RETRIES):
                await self._send(R2_GROUND, fields)
                try:
                    await asyncio.wait_for(
                        waiter.wait(), timeout=R2_ACK_TIMEOUT_SECONDS
                    )
                    return
                except asyncio.TimeoutError:
                    continue
            log(
                "WARNING",
                f"R2D2 tunnel event not acknowledged: id={request_id} seq={sequence}",
            )
        finally:
            self._ack_waiters.pop(key, None)

    async def _handle_http(self, frame: dict) -> None:
        source, request_id, arg, target_port = self._request_parts(frame)
        if not source or not request_id:
            return
        if target_port not in self._logged_request_ports:
            log("INFO", f"Internet browser request received for StabX port {target_port}")
            self._logged_request_ports.add(target_port)
        config = self.configs.get(target_port)
        proxy = self.proxies.get(target_port)
        if config is None or proxy is None:
            await self._tunnel_error(source, request_id, "unsupported target port")
            return
        target = await proxy.resolve_target()
        if target is None or proxy.session is None:
            await self._tunnel_error(source, request_id, f"StabX port {target_port} unavailable")
            return

        method = str(arg.get("method", "GET")).upper()[:12]
        path = str(arg.get("path", "/"))
        if not path.startswith("/"):
            path = "/" + path
        headers = self._clean_request_headers(arg.get("headers"), target)
        try:
            body = base64.b64decode(str(arg.get("body", "")), validate=True)
        except (ValueError, binascii.Error):
            await self._tunnel_error(source, request_id, "invalid request body")
            return
        if len(body) > TUNNEL_CHUNK_BYTES:
            await self._tunnel_error(source, request_id, "request body exceeds 24 KiB")
            return

        url = f"http://{target.url_host}:{target.port}{path}"
        try:
            response = await proxy.session.request(
                method,
                url,
                headers=headers,
                data=body if body else None,
                allow_redirects=False,
            )
            async with response:
                content_type = response.headers.get("Content-Type", "").lower()
                if content_type.startswith("video/") or content_type.startswith("multipart/x-mixed-replace"):
                    await self._tunnel_error(
                        source,
                        request_id,
                        "video streams are blocked on the R2D2 control channel",
                    )
                    return
                maximum = config.remote_max_response_bytes
                if response.content_length is not None and response.content_length > maximum:
                    await self._tunnel_error(source, request_id, "response exceeds remote tunnel limit")
                    return
                data = await response.read()
                if len(data) > maximum:
                    await self._tunnel_error(source, request_id, "response exceeds remote tunnel limit")
                    return
                if any(content_type.startswith(prefix) for prefix in TEXT_TYPES):
                    data = self._rewrite_remote_text(config, target, data)
                response_headers = self._remote_response_headers(config, target, response.headers)
                packed = zlib.compress(data, level=6)
                if len(packed) < len(data):
                    wire_data = packed
                    compression = "zlib"
                else:
                    wire_data = data
                    compression = ""
                if len(wire_data) > TUNNEL_ATOMIC_BYTES:
                    await self._tunnel_error(
                        source,
                        request_id,
                        "response is too large for the reliable R2D2 control channel",
                    )
                    return
                await self._tunnel_event(
                    source,
                    {
                        "kind": "http.response",
                        "id": request_id,
                        "status": response.status,
                        "reason": response.reason or "",
                        "headers": response_headers,
                        "data": base64.b64encode(wire_data).decode("ascii"),
                        "compression": compression,
                    },
                )
        except Exception as exc:
            proxy.invalidate_target()
            with contextlib.suppress(Exception):
                await self._tunnel_error(source, request_id, f"upstream {type(exc).__name__}")

    def _clean_request_headers(self, value: object, target: Target) -> dict[str, str]:
        headers: dict[str, str] = {}
        if isinstance(value, dict):
            for name, raw in value.items():
                lower = str(name).lower()
                if lower in HOP_BY_HOP or lower in WEBSOCKET_HEADERS or lower == "host":
                    continue
                headers[str(name)] = str(raw)
        headers["Host"] = target.authority
        return headers

    def _rewrite_remote_text(self, config: Config, target: Target, body: bytes) -> bytes:
        external_http = f"http://127.0.0.1:{config.listen_port}".encode("ascii")
        external_ws = f"ws://127.0.0.1:{config.listen_port}".encode("ascii")
        for authority in StabXProxy._target_authorities(self.proxies[target.port], target):
            encoded = authority.encode("utf-8")
            body = body.replace(b"http://" + encoded, external_http)
            body = body.replace(b"https://" + encoded, external_http)
            body = body.replace(b"ws://" + encoded, external_ws)
            body = body.replace(b"wss://" + encoded, external_ws)
        return body

    def _remote_response_headers(self, config: Config, target: Target, headers) -> list[list[str]]:
        output: list[list[str]] = []
        for name, value in headers.items():
            lower = name.lower()
            if lower in HOP_BY_HOP or lower in {"content-length", "content-encoding"}:
                continue
            if lower == "location":
                for authority in self.proxies[target.port]._target_authorities(target):
                    for scheme in ("http", "https"):
                        prefix = f"{scheme}://{authority}"
                        if value.startswith(prefix):
                            value = f"http://127.0.0.1:{config.listen_port}" + value[len(prefix) :]
            output.append([name, value])
        return output

    async def _open_websocket(self, frame: dict) -> None:
        source, request_id, arg, target_port = self._request_parts(frame)
        proxy = self.proxies.get(target_port)
        if not source or not request_id or proxy is None:
            return
        target = await proxy.resolve_target()
        if target is None or proxy.session is None:
            await self._tunnel_error(source, request_id, f"StabX port {target_port} unavailable")
            return
        path = str(arg.get("path", "/"))
        if not path.startswith("/"):
            path = "/" + path
        headers = self._clean_request_headers(arg.get("headers"), target)
        protocols = arg.get("protocols") if isinstance(arg.get("protocols"), list) else []
        url = f"ws://{target.url_host}:{target.port}{path}"
        try:
            websocket = await proxy.session.ws_connect(
                url,
                headers=headers,
                protocols=[str(item) for item in protocols],
                heartbeat=30,
                max_msg_size=TUNNEL_CHUNK_BYTES,
            )
            self._websockets[request_id] = (websocket, source)
            await self._tunnel_event(
                source,
                {"kind": "ws.opened", "id": request_id, "protocol": websocket.protocol or ""},
            )
            async for message in websocket:
                if message.type == WSMsgType.TEXT:
                    payload = {"type": "text", "data": message.data}
                elif message.type == WSMsgType.BINARY:
                    if len(message.data) > TUNNEL_CHUNK_BYTES:
                        raise ValueError("WebSocket message exceeds 24 KiB")
                    payload = {
                        "type": "binary",
                        "data": base64.b64encode(message.data).decode("ascii"),
                    }
                elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                    break
                elif message.type == WSMsgType.ERROR:
                    raise RuntimeError("upstream WebSocket error")
                else:
                    continue
                await self._tunnel_event(
                    source,
                    {"kind": "ws.message", "id": request_id, **payload},
                )
        except Exception as exc:
            with contextlib.suppress(Exception):
                await self._tunnel_error(source, request_id, f"websocket {type(exc).__name__}")
        finally:
            item = self._websockets.pop(request_id, None)
            if item is not None:
                with contextlib.suppress(Exception):
                    await item[0].close()
            with contextlib.suppress(Exception):
                await self._tunnel_event(source, {"kind": "ws.closed", "id": request_id})

    async def _send_websocket(self, frame: dict) -> None:
        source, request_id, arg, _ = self._request_parts(frame)
        item = self._websockets.get(request_id)
        if item is None:
            if source:
                await self._tunnel_error(source, request_id, "WebSocket is not open")
            return
        websocket, _ = item
        if arg.get("type") == "binary":
            data = base64.b64decode(str(arg.get("data", "")), validate=True)
            if len(data) > TUNNEL_CHUNK_BYTES:
                raise ValueError("WebSocket message exceeds 24 KiB")
            await websocket.send_bytes(data)
        else:
            await websocket.send_str(str(arg.get("data", "")))

    async def _close_websocket(self, frame: dict) -> None:
        _, request_id, _, _ = self._request_parts(frame)
        item = self._websockets.get(request_id)
        if item is not None:
            await item[0].close()

    async def _tunnel_error(self, destination: int, request_id: str, message: str) -> None:
        await self._tunnel_event(
            destination,
            {"kind": "error", "id": request_id, "message": message[:160]},
        )

    async def _handle_shell(self, frame: dict) -> None:
        source, request_id, arg, _ = self._request_parts(frame)
        if not source or not request_id:
            return
        config = self.shell_config
        if not self.shell_available:
            await self._tunnel_error(
                source,
                request_id,
                "R2D2 terminal is disabled or TERMINAL_TOKEN is shorter than 24 characters",
            )
            return
        session_id = str(arg.get("session", "default"))[:80]
        command = str(arg.get("command", ""))
        signed = f"{request_id}\0{session_id}\0{command}".encode("utf-8")
        expected_auth = hmac.new(
            config.terminal_token.encode("utf-8"), signed, hashlib.sha256
        ).hexdigest()
        supplied_auth = str(arg.get("auth", ""))
        if not hmac.compare_digest(supplied_auth, expected_auth):
            await self._tunnel_error(source, request_id, "terminal authentication failed")
            return
        if request_id in self._shell_requests:
            await self._tunnel_error(source, request_id, "duplicate terminal request")
            return
        self._shell_requests.add(request_id)
        if len(self._shell_requests) > 2048:
            self._shell_requests = set(list(self._shell_requests)[-1024:])
        if not command.strip():
            await self._tunnel_error(source, request_id, "terminal command is empty")
            return
        if len(command.encode("utf-8")) > 8192 or "\0" in command:
            await self._tunnel_error(source, request_id, "terminal command is too long")
            return

        cwd = self._shell_cwds.get(session_id, "/")
        changed, change_output = self._change_directory(command, cwd)
        if changed is not None:
            self._shell_cwds[session_id] = changed
            await self._tunnel_event(
                source,
                {
                    "kind": "shell.result",
                    "id": request_id,
                    "data": base64.b64encode(change_output).decode("ascii"),
                    "exit_code": 0 if not change_output else 1,
                    "cwd": changed if not change_output else cwd,
                    "timed_out": False,
                    "truncated": False,
                    "compression": "",
                },
            )
            return

        timeout = min(max(float(config.terminal_timeout), 1.0), 60.0)
        maximum = min(max(int(config.terminal_max_output_bytes), 4096), 512 * 1024)
        log("INFO", "authenticated R2D2 terminal command received")
        try:
            process = await asyncio.create_subprocess_exec(
                "/bin/sh",
                "-lc",
                command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except Exception as exc:
            await self._tunnel_error(
                source, request_id, f"cannot start shell: {type(exc).__name__}"
            )
            return
        assert process.stdout is not None
        output = bytearray()
        truncated = False

        async def forward_output() -> int:
            nonlocal truncated
            while True:
                chunk = await process.stdout.read(8 * 1024)
                if not chunk:
                    break
                remaining = maximum - len(output)
                if remaining <= 0:
                    truncated = True
                    continue
                payload = chunk[:remaining]
                output.extend(payload)
                if len(payload) < len(chunk):
                    truncated = True
            return await process.wait()

        timed_out = False
        try:
            exit_code = await asyncio.wait_for(forward_output(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            truncated = True
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            exit_code = await process.wait()

        raw_output = bytes(output)
        packed_output = zlib.compress(raw_output, level=6)
        if len(packed_output) < len(raw_output):
            wire_output = packed_output
            compression = "zlib"
        else:
            wire_output = raw_output
            compression = ""
        if len(wire_output) > TUNNEL_ATOMIC_BYTES:
            wire_output = raw_output[:TUNNEL_ATOMIC_BYTES]
            compression = ""
            truncated = True
        await self._tunnel_event(
            source,
            {
                "kind": "shell.result",
                "id": request_id,
                "data": base64.b64encode(wire_output).decode("ascii"),
                "compression": compression,
                "exit_code": int(exit_code),
                "cwd": cwd,
                "timed_out": timed_out,
                "truncated": truncated,
            },
        )

    @staticmethod
    def _change_directory(command: str, cwd: str) -> tuple[str | None, bytes]:
        try:
            parts = shlex.split(command, posix=True)
        except ValueError:
            return None, b""
        if not parts or parts[0] != "cd" or len(parts) > 2:
            return None, b""
        target = os.path.expanduser(parts[1] if len(parts) == 2 else "~")
        if not os.path.isabs(target):
            target = os.path.join(cwd, target)
        target = os.path.realpath(target)
        if not os.path.isdir(target):
            return cwd, f"cd: no such directory: {target}\n".encode("utf-8")
        return target, b""


def create_app(config: Config) -> web.Application:
    proxy = StabXProxy(config)
    app = web.Application(client_max_size=1024 * 1024 * 1024)
    app.router.add_route("*", STATUS_PATH, proxy.status)
    app.router.add_get(HDMI_DIAGNOSTICS_PATH, proxy.hdmi_diagnostics)
    app.router.add_route("*", "/{path:.*}", proxy.handle)

    async def startup(_: web.Application) -> None:
        await proxy.start()

    async def cleanup(_: web.Application) -> None:
        await proxy.close()

    app.on_startup.append(startup)
    app.on_cleanup.append(cleanup)
    return app


async def run(configs: tuple[Config, ...]) -> None:
    log("INFO", f"StabX R2D2 plugin version {PLUGIN_VERSION}")
    shell_config = configs[0]
    if shell_config.terminal_enabled and len(shell_config.terminal_token) < 24:
        log("ERROR", "terminal requested but TERMINAL_TOKEN must contain at least 24 characters")
    elif shell_config.terminal_enabled:
        log("WARNING", "authenticated R2D2 command terminal is enabled")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(sig, stop.set)

    runners: list[web.AppRunner] = []
    tunnel_task: asyncio.Task | None = None
    try:
        for config in configs:
            app = create_app(config)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            runners.append(runner)
            site: web.TCPSite | None = None
            while site is None:
                candidate = web.TCPSite(runner, config.listen_host, config.listen_port)
                try:
                    await candidate.start()
                    site = candidate
                except OSError as exc:
                    log(
                        "ERROR",
                        f"cannot bind {config.listen_host}:{config.listen_port}: {exc}; retrying",
                    )
                    await asyncio.sleep(10)

            log(
                "INFO",
                f"StabX proxy listening on {config.listen_host}:{config.listen_port} "
                f"for {','.join(config.target_hosts)}:{config.target_port}",
            )
            if not config.proxy_username:
                log("WARNING", f"proxy authentication is disabled on {config.listen_port}")
        if any(config.remote_tunnel_enabled for config in configs):
            tunnel_task = asyncio.create_task(R2RemoteTunnel(configs).run())
        await stop.wait()
    finally:
        if tunnel_task is not None:
            tunnel_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await tunnel_task
        for runner in reversed(runners):
            await runner.cleanup()


def main() -> int:
    raw = load_config()
    configs = (
        Config.from_dict(raw),
        Config.from_dict(
            raw,
            target_port_key="SECONDARY_TARGET_PORT",
            default_target_port=5050,
            listen_port_key="SECONDARY_LISTEN_PORT",
            default_listen_port=15050,
        ),
    )
    try:
        asyncio.run(run(configs))
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log("ERROR", f"fatal error: {type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
