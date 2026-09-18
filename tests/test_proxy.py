from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

from aiohttp import ClientSession, WSMsgType, web


PLUGIN_DIRECTORY = Path(__file__).resolve().parents[1] / "plugin"
sys.path.insert(0, str(PLUGIN_DIRECTORY))

import plugin  # noqa: E402


class MemoryWriter:
    def __init__(self) -> None:
        self.data = bytearray()

    def write(self, value: bytes) -> None:
        self.data.extend(value)

    async def drain(self) -> None:
        return None

    def frames(self) -> list[dict]:
        result: list[dict] = []
        data = bytes(self.data)
        while data:
            length = struct.unpack("<I", data[:4])[0]
            result.append(json.loads(data[4 : 4 + length]))
            data = data[4 + length :]
        return result


class FakeDiagnosticProcess:
    returncode = 0
    pid = 12345

    async def communicate(self) -> tuple[bytes, None]:
        return b"diagnostic-ok\n", None


class ProxyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.upstream_port = 0
        upstream_app = web.Application()
        upstream_app.router.add_get("/", self.home)
        upstream_app.router.add_get("/next", self.next_page)
        upstream_app.router.add_post("/echo", self.echo)
        upstream_app.router.add_get("/redirect", self.redirect)
        upstream_app.router.add_get("/ws", self.websocket)
        self.upstream_runner = web.AppRunner(upstream_app, access_log=None)
        await self.upstream_runner.setup()
        self.upstream_site = web.TCPSite(self.upstream_runner, "127.0.0.1", 0)
        await self.upstream_site.start()
        self.upstream_port = self.upstream_site._server.sockets[0].getsockname()[1]

        self.proxy_runner, self.proxy_port = await self.start_proxy()
        self.client = ClientSession()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.proxy_runner.cleanup()
        await self.upstream_runner.cleanup()

    def config(self, **changes: object) -> plugin.Config:
        values: dict[str, object] = {
            "TARGET_HOSTS": "127.0.0.1",
            "TARGET_PORT": self.upstream_port,
            "LISTEN_PORT": 18080,
            "CONNECT_TIMEOUT": 0.5,
            "DNS_CACHE_SECONDS": 0.5,
            "HEALTH_INTERVAL": 60,
            "REWRITE_ABSOLUTE_URLS": True,
        }
        values.update(changes)
        return plugin.Config.from_dict(values)

    async def start_proxy(self, **changes: object) -> tuple[web.AppRunner, int]:
        app = plugin.create_app(self.config(**changes))
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return runner, port

    async def home(self, _: web.Request) -> web.Response:
        address = f"127.0.0.1:{self.upstream_port}"
        return web.Response(
            text=(
                f'<a href="http://{address}/next">next</a>'
                f'<script>const ws="ws://{address}/ws";</script>'
            ),
            content_type="text/html",
        )

    async def next_page(self, _: web.Request) -> web.Response:
        return web.Response(text="next")

    async def echo(self, request: web.Request) -> web.Response:
        return web.Response(body=await request.read(), content_type="application/octet-stream")

    async def redirect(self, _: web.Request) -> web.Response:
        return web.Response(
            status=302,
            headers={"Location": f"http://127.0.0.1:{self.upstream_port}/next"},
        )

    async def websocket(self, request: web.Request) -> web.WebSocketResponse:
        socket = web.WebSocketResponse()
        await socket.prepare(request)
        async for message in socket:
            if message.type == WSMsgType.TEXT:
                await socket.send_str(message.data)
            elif message.type == WSMsgType.BINARY:
                await socket.send_bytes(message.data)
        return socket

    async def test_status_and_http_url_rewrite(self) -> None:
        base = f"http://127.0.0.1:{self.proxy_port}"
        async with self.client.get(base + plugin.STATUS_PATH) as response:
            payload = await response.json()
            self.assertEqual(response.status, 200)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["resolved_address"], "127.0.0.1")

        async with self.client.get(base + "/") as response:
            body = await response.text()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Type"].split(";", 1)[0], "text/html")
            self.assertIn(base + "/next", body)
            self.assertIn(f"ws://127.0.0.1:{self.proxy_port}/ws", body)
            self.assertNotIn(f"127.0.0.1:{self.upstream_port}", body)

    async def test_expired_discovered_target_is_reprobed(self) -> None:
        config = self.config(
            TARGET_HOSTS="pizero2.invalid",
            AUTO_DISCOVER=True,
            DISCOVERY_INTERVAL=60,
        )
        proxy = plugin.StabXProxy(config)
        discovered = plugin.Target("pizero2", "10.0.0.139", config.target_port)
        proxy._target = discovered
        proxy._target_until = 0.0
        proxy._next_discovery = float("inf")

        probe = mock.AsyncMock(return_value=True)
        discover = mock.AsyncMock(return_value=None)
        with mock.patch.object(proxy, "_probe_address", probe), mock.patch.object(
            proxy, "_discover_target", discover
        ):
            resolved = await proxy.resolve_target()

        self.assertIs(resolved, discovered)
        probe.assert_awaited_once_with(discovered.address)
        discover.assert_not_awaited()
        self.assertGreater(proxy._target_until, 0.0)

    async def test_hdmi_diagnostics_requires_terminal_token(self) -> None:
        token = "diagnostic-token-1234567890"
        runner, port = await self.start_proxy(
            TERMINAL_ENABLED=True,
            TERMINAL_TOKEN=token,
        )
        base = f"http://127.0.0.1:{port}"
        try:
            async with self.client.get(base + plugin.HDMI_DIAGNOSTICS_PATH) as response:
                self.assertEqual(response.status, 401)

            create_process = mock.AsyncMock(return_value=FakeDiagnosticProcess())
            with mock.patch.object(plugin.asyncio, "create_subprocess_exec", create_process):
                async with self.client.get(
                    base + plugin.HDMI_DIAGNOSTICS_PATH,
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    body = await response.text()
                    self.assertEqual(response.status, 200)
                    self.assertIn("diagnostic-ok", body)
                    self.assertIn("exit_code=0", body)
                command = create_process.await_args.args[2]
                self.assertIn("--query-dv-timings", command)
                self.assertIn("--get-edid", command)
        finally:
            await runner.cleanup()

    async def test_post_redirect_and_websocket(self) -> None:
        base = f"http://127.0.0.1:{self.proxy_port}"
        content = b"stabx-settings"
        async with self.client.post(base + "/echo", data=content) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.read(), content)

        async with self.client.get(base + "/redirect", allow_redirects=False) as response:
            self.assertEqual(response.status, 302)
            self.assertEqual(response.headers["Location"], base + "/next")

        socket = await self.client.ws_connect(base.replace("http://", "ws://") + "/ws")
        await socket.send_str("camera-control")
        message = await socket.receive(timeout=2)
        self.assertEqual(message.type, WSMsgType.TEXT)
        self.assertEqual(message.data, "camera-control")
        await socket.close()

    async def test_optional_basic_auth(self) -> None:
        runner, port = await self.start_proxy(
            PROXY_USERNAME="operator",
            PROXY_PASSWORD="stabh-secure",
        )
        try:
            base = f"http://127.0.0.1:{port}"
            async with self.client.get(base + "/") as response:
                self.assertEqual(response.status, 401)

            token = base64.b64encode(b"operator:stabh-secure").decode("ascii")
            async with self.client.get(
                base + "/",
                headers={"Authorization": f"Basic {token}"},
            ) as response:
                self.assertEqual(response.status, 200)
        finally:
            await runner.cleanup()

    async def test_secondary_proxy_port_defaults(self) -> None:
        secondary = plugin.Config.from_dict(
            {"TARGET_HOSTS": "pizero2,pizero2.local"},
            target_port_key="SECONDARY_TARGET_PORT",
            default_target_port=5050,
            listen_port_key="SECONDARY_LISTEN_PORT",
            default_listen_port=15050,
        )
        self.assertEqual(secondary.target_port, 5050)
        self.assertEqual(secondary.listen_port, 15050)
        self.assertTrue(secondary.auto_discover)

    def test_private_ipv4_filter(self) -> None:
        self.assertTrue(plugin._private_ipv4("192.168.4.2"))
        self.assertTrue(plugin._private_ipv4("10.42.0.7"))
        self.assertFalse(plugin._private_ipv4("127.0.0.1"))
        self.assertFalse(plugin._private_ipv4("8.8.8.8"))

    async def test_r2d2_remote_http_tunnel(self) -> None:
        config = self.config()
        tunnel = plugin.R2RemoteTunnel((config,))
        writer = MemoryWriter()
        tunnel.writer = writer
        proxy = tunnel.proxies[self.upstream_port]
        await proxy.start()
        try:
            await tunnel._handle_http(
                {
                    "PT": "plugin.ctl",
                    "src": 4567,
                    "cmd": "stabh.http",
                    "arg": {
                        "id": "remote-test",
                        "port": self.upstream_port,
                        "method": "GET",
                        "path": "/",
                        "headers": {},
                        "body": "",
                    },
                }
            )
        finally:
            await proxy.close()

        frames = writer.frames()
        events = [frame["tunnel"] for frame in frames]
        self.assertEqual(frames[0]["tm"]["tunnel"], events[0])
        self.assertEqual(events[0]["kind"], "http.head")
        self.assertEqual(events[0]["status"], 200)
        self.assertTrue(events[-1]["eof"])
        body = b"".join(
            base64.b64decode(event["data"])
            for event in events
            if event["kind"] == "http.body" and event["data"]
        ).decode("utf-8")
        self.assertIn("http://127.0.0.1:18080/next", body)

    async def test_terminal_is_disabled_by_default(self) -> None:
        config = self.config()
        self.assertFalse(config.terminal_enabled)
        self.assertEqual(config.terminal_token, "")
        tunnel = plugin.R2RemoteTunnel((config,))
        writer = MemoryWriter()
        tunnel.writer = writer
        await tunnel._handle_shell(
            {
                "PT": "plugin.ctl",
                "src": 4567,
                "cmd": "r2shell.exec",
                "arg": {
                    "id": "terminal-disabled",
                    "session": "test",
                    "command": "id",
                    "auth": "invalid",
                },
            }
        )
        event = writer.frames()[0]["tunnel"]
        self.assertEqual(event["kind"], "error")
        self.assertIn("disabled", event["message"])

    async def test_terminal_hmac_and_cd(self) -> None:
        token = "unit-test-terminal-token-1234567890"
        config = self.config(TERMINAL_ENABLED=True, TERMINAL_TOKEN=token)
        tunnel = plugin.R2RemoteTunnel((config,))
        writer = MemoryWriter()
        tunnel.writer = writer
        request_id = "terminal-cd"
        session_id = "test-session"
        command = "cd /"
        signature = hmac.new(
            token.encode("utf-8"),
            f"{request_id}\0{session_id}\0{command}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        await tunnel._handle_shell(
            {
                "PT": "plugin.ctl",
                "src": 4567,
                "cmd": "r2shell.exec",
                "arg": {
                    "id": request_id,
                    "session": session_id,
                    "command": command,
                    "auth": signature,
                },
            }
        )
        events = [frame["tunnel"] for frame in writer.frames()]
        self.assertEqual(events[-1]["kind"], "shell.done")
        self.assertEqual(events[-1]["exit_code"], 0)
        self.assertEqual(events[-1]["cwd"], os.path.realpath("/"))
        self.assertNotIn(token, json.dumps(writer.frames()))


if __name__ == "__main__":
    unittest.main()
