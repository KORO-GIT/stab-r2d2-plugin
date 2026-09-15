#!/usr/bin/env python3
"""Local browser bridge for StabX over an active R2D2 Internet session."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import json
import uuid
import webbrowser

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web


PLUGIN_LABEL = "koropwnz.stab-r2d2-plugin"
MAX_BODY = 24 * 1024
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


class R2D2Transport:
    def __init__(self, url: str):
        self.url = url
        self.session: ClientSession | None = None
        self.websocket = None
        self.plugin_source: int | None = None
        self.vpn: str | None = None
        self.routing_locked = False
        self.ready = asyncio.Event()
        self.session_ready = asyncio.Event()
        self.pending: dict[str, asyncio.Queue] = {}
        self.task: asyncio.Task | None = None
        self.send_lock = asyncio.Lock()

    async def start(self) -> None:
        self.session = ClientSession(timeout=ClientTimeout(total=None))
        self.task = asyncio.create_task(self._connection_loop())

    async def close(self) -> None:
        if self.task is not None:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
        if self.session is not None:
            await self.session.close()

    def register(self, request_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.pending[request_id] = queue
        return queue

    def unregister(self, request_id: str) -> None:
        self.pending.pop(request_id, None)

    async def wait_ready(self, timeout: float = 30.0) -> bool:
        if self.ready.is_set() and self.session_ready.is_set() and self.plugin_source is not None:
            return True
        try:
            await asyncio.wait_for(
                asyncio.gather(self.ready.wait(), self.session_ready.wait()),
                timeout,
            )
            return self.plugin_source is not None and self.vpn is not None
        except asyncio.TimeoutError:
            return False

    async def command(self, command: str, argument: dict) -> None:
        if not await self.wait_ready():
            raise ConnectionError("R2D2 plugin is not connected")
        websocket = self.websocket
        destination = self.plugin_source
        vpn = self.vpn
        if websocket is None or destination is None or not vpn or websocket.closed:
            raise ConnectionError("R2D2 ground station is not connected")
        frame = {
            "PT": "plugin.ctl",
            "VPN": vpn,
            "PKTFLAG-force-delivery": True,
            "cmd": command,
            "arg": argument,
        }
        destinations = [destination]
        if not self.routing_locked and command in {"stabh.http", "stabh.ws.open"}:
            # Old R2D2 Internet builds may rewrite the source announced by a
            # TGZ process to one of the adjacent local service addresses.
            destinations = list(dict.fromkeys([destination, 65606, 65607, 65608, 65609]))
        async with self.send_lock:
            for candidate in destinations:
                await websocket.send_json({**frame, "dst": candidate})

    async def _connection_loop(self) -> None:
        assert self.session is not None
        while True:
            self.ready.clear()
            self.session_ready.clear()
            self.plugin_source = None
            self.vpn = None
            self.routing_locked = False
            try:
                async with self.session.ws_connect(
                    self.url,
                    heartbeat=20,
                    max_msg_size=2 * 1024 * 1024,
                ) as websocket:
                    self.websocket = websocket
                    print(f"INFO: connected to R2D2 ground station at {self.url}", flush=True)
                    await websocket.send_json({"PT": "api.getSessionForMap"})
                    async for message in websocket:
                        if message.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                            continue
                        try:
                            raw = message.data.decode("utf-8") if isinstance(message.data, bytes) else message.data
                            frame = json.loads(raw)
                        except (UnicodeError, ValueError):
                            continue
                        if frame.get("PT") == "api.getSessionForMap.resp":
                            if frame.get("success"):
                                self.session_ready.set()
                                print("INFO: R2D2 browser session authorized", flush=True)
                            continue
                        if frame.get("PT") != "plugin.ctl" or frame.get("plugin") != PLUGIN_LABEL:
                            continue
                        if frame.get("announce") and frame.get("src") is not None:
                            source = int(frame["src"])
                            vpn = str(frame.get("VPN", ""))
                            if source != self.plugin_source or vpn != self.vpn:
                                self.plugin_source = source
                                self.vpn = vpn or None
                                self.ready.set()
                                print(
                                    f"INFO: StabX plugin found on {self.vpn or 'unknown board'} "
                                    f"source {source}",
                                    flush=True,
                                )
                        event = frame.get("tunnel")
                        if isinstance(event, dict):
                            if frame.get("src") is not None and not self.routing_locked:
                                self.plugin_source = int(frame["src"])
                                self.routing_locked = True
                                print(
                                    f"INFO: R2D2 command route confirmed at source {self.plugin_source}",
                                    flush=True,
                                )
                            queue = self.pending.get(str(event.get("id", "")))
                            if queue is not None:
                                await queue.put(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(f"WARNING: R2D2 connection unavailable: {type(exc).__name__}", flush=True)
            finally:
                self.websocket = None
                self.ready.clear()
                self.session_ready.clear()
                self.plugin_source = None
                self.vpn = None
                self.routing_locked = False
                for queue in list(self.pending.values()):
                    await queue.put({"kind": "error", "message": "R2D2 connection lost"})
            await asyncio.sleep(2)


class LocalProxy:
    def __init__(self, transport: R2D2Transport, target_port: int):
        self.transport = transport
        self.target_port = target_port

    async def handle(self, request: web.Request) -> web.StreamResponse:
        if request.path == "/__r2_stabh_bridge/status":
            return web.json_response(
                {
                    "ok": self.transport.ready.is_set() and self.transport.session_ready.is_set(),
                    "r2d2": self.transport.url,
                    "plugin_source": self.transport.plugin_source,
                    "vpn": self.transport.vpn,
                    "target_port": self.target_port,
                },
                status=200 if self.transport.ready.is_set() else 503,
            )
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self._websocket(request)
        return await self._http(request)

    async def _http(self, request: web.Request) -> web.StreamResponse:
        try:
            body = await request.read()
        except Exception:
            return web.Response(status=400, text="Cannot read browser request")
        if len(body) > MAX_BODY:
            return web.Response(status=413, text="Remote StabX request body exceeds 24 KiB")

        request_id = uuid.uuid4().hex
        queue = self.transport.register(request_id)
        try:
            await self.transport.command(
                "stabh.http",
                {
                    "id": request_id,
                    "port": self.target_port,
                    "method": request.method,
                    "path": str(request.rel_url),
                    "headers": self._request_headers(request),
                    "body": base64.b64encode(body).decode("ascii"),
                },
            )
            first = await asyncio.wait_for(queue.get(), 45)
            if first.get("kind") == "error":
                return web.Response(status=502, text=str(first.get("message", "StabX tunnel error")))
            if first.get("kind") != "http.head":
                return web.Response(status=502, text="Invalid response from StabX tunnel")

            response = web.StreamResponse(
                status=int(first.get("status", 502)),
                reason=str(first.get("reason", "")),
            )
            for item in first.get("headers", []):
                if not isinstance(item, list) or len(item) != 2:
                    continue
                name, value = str(item[0]), str(item[1])
                if name.lower() not in HOP_BY_HOP:
                    response.headers.add(name, value)
            await response.prepare(request)
            while True:
                event = await asyncio.wait_for(queue.get(), 45)
                if event.get("kind") == "error":
                    break
                if event.get("kind") != "http.body":
                    continue
                encoded = str(event.get("data", ""))
                if encoded:
                    await response.write(base64.b64decode(encoded))
                if event.get("eof"):
                    break
            await response.write_eof()
            return response
        except (asyncio.TimeoutError, ConnectionError) as exc:
            return web.Response(status=504, text=str(exc) or "StabX tunnel timeout")
        finally:
            self.transport.unregister(request_id)

    async def _websocket(self, request: web.Request) -> web.StreamResponse:
        request_id = uuid.uuid4().hex
        queue = self.transport.register(request_id)
        requested_protocols = [
            item.strip()
            for item in request.headers.get("Sec-WebSocket-Protocol", "").split(",")
            if item.strip()
        ]
        try:
            await self.transport.command(
                "stabh.ws.open",
                {
                    "id": request_id,
                    "port": self.target_port,
                    "path": str(request.rel_url),
                    "headers": self._request_headers(request),
                    "protocols": requested_protocols,
                },
            )
            first = await asyncio.wait_for(queue.get(), 45)
            if first.get("kind") == "error":
                return web.Response(status=502, text=str(first.get("message", "WebSocket tunnel error")))
            if first.get("kind") != "ws.opened":
                return web.Response(status=502, text="Invalid WebSocket tunnel response")

            selected = str(first.get("protocol", ""))
            local = web.WebSocketResponse(
                protocols=[selected] if selected else requested_protocols,
                heartbeat=30,
                max_msg_size=MAX_BODY,
            )
            await local.prepare(request)

            async def browser_to_r2d2() -> None:
                async for message in local:
                    if message.type == WSMsgType.TEXT:
                        payload = {"type": "text", "data": message.data}
                    elif message.type == WSMsgType.BINARY:
                        if len(message.data) > MAX_BODY:
                            await local.close(code=1009, message=b"message too large")
                            return
                        payload = {
                            "type": "binary",
                            "data": base64.b64encode(message.data).decode("ascii"),
                        }
                    else:
                        continue
                    await self.transport.command(
                        "stabh.ws.send",
                        {"id": request_id, "port": self.target_port, **payload},
                    )

            async def r2d2_to_browser() -> None:
                while True:
                    event = await queue.get()
                    kind = event.get("kind")
                    if kind in {"error", "ws.closed"}:
                        return
                    if kind != "ws.message":
                        continue
                    if event.get("type") == "binary":
                        await local.send_bytes(base64.b64decode(str(event.get("data", ""))))
                    else:
                        await local.send_str(str(event.get("data", "")))

            tasks = {
                asyncio.create_task(browser_to_r2d2()),
                asyncio.create_task(r2d2_to_browser()),
            }
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done | pending:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            with contextlib.suppress(Exception):
                await self.transport.command(
                    "stabh.ws.close",
                    {"id": request_id, "port": self.target_port},
                )
            await local.close()
            return local
        except (asyncio.TimeoutError, ConnectionError) as exc:
            return web.Response(status=504, text=str(exc) or "StabX WebSocket tunnel timeout")
        finally:
            self.transport.unregister(request_id)

    @staticmethod
    def _request_headers(request: web.Request) -> dict[str, str]:
        output: dict[str, str] = {}
        for name, value in request.headers.items():
            if name.lower() not in HOP_BY_HOP and name.lower() != "host":
                output[name] = value
        return output


async def run(arguments: argparse.Namespace) -> None:
    transport = R2D2Transport(arguments.r2d2)
    await transport.start()
    runners: list[web.AppRunner] = []
    try:
        for local_port, target_port in ((18080, 8080), (15050, 5050)):
            proxy = LocalProxy(transport, target_port)
            app = web.Application(client_max_size=MAX_BODY)
            app.router.add_route("*", "/{path:.*}", proxy.handle)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", local_port).start()
            runners.append(runner)
            print(
                f"INFO: browser http://127.0.0.1:{local_port}/ -> StabX pizero2:{target_port}",
                flush=True,
            )

        if not arguments.no_browser:
            async def open_when_ready() -> None:
                await transport.ready.wait()
                webbrowser.open("http://127.0.0.1:18080/")
                webbrowser.open("http://127.0.0.1:15050/")

            asyncio.create_task(open_when_ready())
        print("INFO: keep this window open; press Ctrl+C to stop", flush=True)
        await asyncio.Event().wait()
    finally:
        for runner in reversed(runners):
            await runner.cleanup()
        await transport.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="StabX browser tunnel over R2D2")
    parser.add_argument("--r2d2", default="ws://127.0.0.1:54546/")
    parser.add_argument("--no-browser", action="store_true")
    arguments = parser.parse_args()
    try:
        asyncio.run(run(arguments))
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"ERROR: cannot start local bridge: {exc}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
