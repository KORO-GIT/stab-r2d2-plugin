from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import unittest
from pathlib import Path

from aiohttp import ClientSession, web


BRIDGE_PATH = Path(__file__).resolve().parents[1] / "desktop" / "stabh-internet-bridge.py"
SPEC = importlib.util.spec_from_file_location("stabh_internet_bridge", BRIDGE_PATH)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class FakeTransport:
    def __init__(self) -> None:
        self.ready = asyncio.Event()
        self.ready.set()
        self.session_ready = asyncio.Event()
        self.session_ready.set()
        self.url = "ws://127.0.0.1:54546/"
        self.plugin_source = 65609
        self.vpn = "test-board"
        self.pending: dict[str, asyncio.Queue] = {}
        self.last_command: tuple[str, dict] | None = None

    def register(self, request_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.pending[request_id] = queue
        return queue

    def unregister(self, request_id: str) -> None:
        self.pending.pop(request_id, None)

    async def command(self, command: str, argument: dict) -> None:
        self.last_command = (command, argument)
        queue = self.pending[argument["id"]]
        await queue.put(
            {
                "kind": "shell.output",
                "id": argument["id"],
                "data": base64.b64encode(b"terminal-ok\n").decode("ascii"),
            }
        )
        await queue.put(
            {
                "kind": "shell.done",
                "id": argument["id"],
                "exit_code": 0,
                "cwd": "/",
                "timed_out": False,
                "truncated": False,
            }
        )


class TerminalBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.transport = FakeTransport()
        terminal = bridge.TerminalProxy(self.transport)
        app = web.Application()
        app.router.add_get("/", terminal.index)
        app.router.add_get("/api/status", terminal.status)
        app.router.add_post("/api/exec", terminal.execute)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.client = ClientSession()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.runner.cleanup()

    async def test_terminal_page_and_status(self) -> None:
        async with self.client.get(self.base + "/") as response:
            body = await response.text()
            self.assertEqual(response.status, 200)
            self.assertIn("Терминал Raspberry Pi R2D2", body)
            self.assertIn("HDMI / CSI", body)
        async with self.client.get(self.base + "/api/status") as response:
            value = await response.json()
            self.assertTrue(value["ok"])
            self.assertEqual(value["vpn"], "test-board")

    async def test_terminal_command_is_hmac_signed(self) -> None:
        token = "browser-terminal-token-1234567890"
        async with self.client.post(
            self.base + "/api/exec",
            json={"token": token, "command": "id", "session": "web-test", "cwd": "/"},
        ) as response:
            value = await response.json()
            self.assertEqual(response.status, 200, json.dumps(value))
            self.assertEqual(value["output"], "terminal-ok\n")
        command, argument = self.transport.last_command
        self.assertEqual(command, "r2shell.exec")
        self.assertNotIn("token", argument)
        self.assertEqual(len(argument["auth"]), 64)


if __name__ == "__main__":
    unittest.main()
