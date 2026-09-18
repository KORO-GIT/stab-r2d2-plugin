#!/usr/bin/env python3
"""Local browser bridge for StabX over an active R2D2 Internet session."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
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

TERMINAL_HTML = r"""<!doctype html>
<html lang="ru">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>R2D2 Terminal</title>
<style>
  :root{color-scheme:dark;--bg:#0b0f14;--panel:#121923;--line:#253143;--green:#5ee98a;--text:#dbe6f3;--muted:#8695a8;--red:#ff6b7d}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}
  main{max-width:1100px;margin:auto;padding:24px}h1{font-size:22px;margin:0 0 6px}.hint{color:var(--muted);margin:0 0 18px}
  .bar,.presets{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}input,textarea,button{border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text)}
  input{padding:10px 12px;min-width:260px;flex:1}textarea{width:100%;min-height:92px;padding:12px;font:14px/1.45 Consolas,monospace;resize:vertical}
  button{padding:10px 14px;cursor:pointer}button.primary{background:#167a43;border-color:#239759}button:disabled{opacity:.55;cursor:wait}
  #status{margin-left:auto;color:var(--muted);align-self:center}#output{white-space:pre-wrap;word-break:break-word;background:#05080c;border:1px solid var(--line);border-radius:8px;min-height:420px;padding:14px;margin-top:12px;font:14px/1.4 Consolas,monospace;color:#cfe8d6}
  .error{color:var(--red)}.ok{color:var(--green)}
</style>
<main>
  <h1>Терминал Raspberry Pi R2D2</h1>
  <p class="hint">Команды идут только через активное соединение R2D2. Токен хранится лишь в этой вкладке и не записывается на ПК.</p>
  <div class="bar"><input id="token" type="password" autocomplete="off" placeholder="TERMINAL_TOKEN из настроек плагина"><span id="status">проверка соединения…</span></div>
  <div class="presets">
    <button data-preset="hdmi">HDMI / CSI</button>
    <button data-preset="system">Система</button>
    <button data-preset="network">Сеть</button>
    <button data-preset="services">Видеосервисы</button>
  </div>
  <textarea id="command" spellcheck="false">pwd
id
uname -a</textarea>
  <div class="bar"><button id="run" class="primary">Выполнить</button><button id="clear">Очистить вывод</button></div>
  <div id="output">R2D2 terminal ready.
</div>
</main>
<script>
const presets = {
  hdmi: `echo '===== ID / KERNEL ====='
id
uname -a
echo '===== VIDEO NODES ====='
ls -la /dev/video* /dev/media* /dev/v4l-subdev* 2>&1
echo '===== V4L2 DEVICES ====='
if command -v v4l2-ctl >/dev/null 2>&1; then v4l2-ctl --list-devices 2>&1; else echo 'v4l2-ctl is not installed'; fi
echo '===== HDMI DV TIMINGS ====='
for d in /dev/video* /dev/v4l-subdev*; do
  [ -e "$d" ] || continue
  echo "----- $d -----"
  v4l2-ctl -d "$d" --query-dv-timings 2>&1 || true
done
echo '===== MEDIA GRAPH ====='
if command -v media-ctl >/dev/null 2>&1; then media-ctl -p 2>&1; else echo 'media-ctl is not installed'; fi
echo '===== KERNEL VIDEO LOG ====='
(dmesg 2>/dev/null || journalctl -k --no-pager -n 300 2>/dev/null) | grep -Ei 'tc358743|unicam|csi|hdmi|video|i2c' | tail -n 180`,
  system: `echo '===== SYSTEM ====='
id
uname -a
cat /etc/os-release 2>/dev/null
echo '===== UPTIME / STORAGE / MEMORY ====='
uptime
df -h
free -h 2>/dev/null || true
echo '===== TEMPERATURE ====='
vcgencmd measure_temp 2>/dev/null || cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null`,
  network: `echo '===== ADDRESSES ====='
ip -br address 2>&1
echo '===== ROUTES ====='
ip route 2>&1
echo '===== NEIGHBOURS ====='
ip neigh 2>&1
echo '===== LISTENING PORTS ====='
ss -lntup 2>&1`,
  services: `echo '===== VIDEO PROCESSES ====='
ps auxww | grep -Ei 'r2d2|camera|video|ffmpeg|gst|libcamera|rpicam' | grep -v grep
echo '===== RUNNING SERVICES ====='
systemctl --type=service --state=running --no-pager 2>&1 | grep -Ei 'r2|camera|video|ffmpeg|gst' || true
echo '===== FAILED SERVICES ====='
systemctl --failed --no-pager 2>&1 || true`
};
const token = document.querySelector('#token'), command = document.querySelector('#command');
const output = document.querySelector('#output'), run = document.querySelector('#run'), status = document.querySelector('#status');
const session = sessionStorage.r2shellSession || (sessionStorage.r2shellSession = crypto.randomUUID());
let cwd = sessionStorage.r2shellCwd || '/';
document.querySelectorAll('[data-preset]').forEach(b => b.onclick = () => command.value = presets[b.dataset.preset]);
document.querySelector('#clear').onclick = () => output.textContent = '';
async function refreshStatus(){
  try{const r=await fetch('/api/status');const j=await r.json();status.textContent=j.ok?`R2D2 подключён · ${j.vpn||''}`:'R2D2 не подключён';status.className=j.ok?'ok':'error'}
  catch(e){status.textContent='локальный мост недоступен';status.className='error'}
}
run.onclick = async () => {
  if(!token.value){output.textContent += '\nОШИБКА: введите TERMINAL_TOKEN.\n';token.focus();return}
  if(!command.value.trim())return;
  run.disabled=true; output.textContent += `\n${cwd} $ ${command.value}\n`;
  try{
    const r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:token.value,command:command.value,session,cwd})});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||`HTTP ${r.status}`);
    if(j.output)output.textContent+=j.output;
    if(j.cwd){cwd=j.cwd;sessionStorage.r2shellCwd=cwd}
    output.textContent+=`\n[код ${j.exit_code}${j.timed_out?', таймаут':''}${j.truncated?', вывод обрезан':''}]\n`;
  }catch(e){output.textContent+=`\nОШИБКА: ${e.message}\n`}finally{run.disabled=false;output.scrollTop=output.scrollHeight}
};
command.addEventListener('keydown',e=>{if(e.ctrlKey&&e.key==='Enter')run.click()});
refreshStatus(); setInterval(refreshStatus,5000);
</script>
</html>"""


def tunnel_event_from_frame(frame: dict) -> dict | None:
    event = frame.get("tunnel")
    if isinstance(event, dict):
        return event
    telemetry = frame.get("tm")
    if isinstance(telemetry, dict):
        event = telemetry.get("tunnel")
        if isinstance(event, dict):
            return event
    return None


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
        if not self.routing_locked and command in {"stabh.http", "stabh.ws.open", "r2shell.exec"}:
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
                        event = tunnel_event_from_frame(frame)
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
                            request_id = str(event.get("id", ""))[:80]
                            try:
                                sequence = int(event.get("seq", 0))
                            except (TypeError, ValueError):
                                sequence = 0
                            if request_id and sequence > 0:
                                await self.command(
                                    "stabh.ack",
                                    {"id": request_id, "seq": sequence},
                                )
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


class TerminalProxy:
    def __init__(self, transport: R2D2Transport):
        self.transport = transport

    async def index(self, _: web.Request) -> web.Response:
        return web.Response(text=TERMINAL_HTML, content_type="text/html")

    async def status(self, _: web.Request) -> web.Response:
        ready = self.transport.ready.is_set() and self.transport.session_ready.is_set()
        return web.json_response(
            {
                "ok": ready,
                "r2d2": self.transport.url,
                "plugin_source": self.transport.plugin_source,
                "vpn": self.transport.vpn,
            },
            status=200 if ready else 503,
        )

    async def execute(self, request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON request"}, status=400)
        token = str(payload.get("token", ""))
        command = str(payload.get("command", ""))
        session_id = str(payload.get("session", "default"))[:80]
        if not token:
            return web.json_response({"error": "TERMINAL_TOKEN is required"}, status=401)
        if not command.strip():
            return web.json_response({"error": "command is empty"}, status=400)
        if len(command.encode("utf-8")) > 8192:
            return web.json_response({"error": "command exceeds 8 KiB"}, status=413)

        request_id = uuid.uuid4().hex
        signature = hmac.new(
            token.encode("utf-8"),
            f"{request_id}\0{session_id}\0{command}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        queue = self.transport.register(request_id)
        chunks: list[bytes] = []
        result = {
            "exit_code": -1,
            "cwd": str(payload.get("cwd", "/")),
            "timed_out": False,
            "truncated": False,
        }
        try:
            await self.transport.command(
                "r2shell.exec",
                {
                    "id": request_id,
                    "auth": signature,
                    "command": command,
                    "session": session_id,
                },
            )
            while True:
                event = await asyncio.wait_for(queue.get(), 75)
                kind = event.get("kind")
                if kind == "error":
                    return web.json_response(
                        {"error": str(event.get("message", "terminal error"))},
                        status=502,
                    )
                if kind == "shell.output":
                    try:
                        chunks.append(base64.b64decode(str(event.get("data", "")), validate=True))
                    except ValueError:
                        return web.json_response({"error": "invalid terminal output"}, status=502)
                if kind == "shell.done":
                    result.update(
                        exit_code=int(event.get("exit_code", -1)),
                        cwd=str(event.get("cwd", result["cwd"])),
                        timed_out=bool(event.get("timed_out")),
                        truncated=bool(event.get("truncated")),
                    )
                    break
            result["output"] = b"".join(chunks).decode("utf-8", errors="replace")
            return web.json_response(result)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            return web.json_response(
                {"error": str(exc) or "R2D2 terminal timeout"},
                status=504,
            )
        finally:
            self.transport.unregister(request_id)


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

        terminal = TerminalProxy(transport)
        terminal_app = web.Application(client_max_size=16 * 1024)
        terminal_app.router.add_get("/", terminal.index)
        terminal_app.router.add_get("/api/status", terminal.status)
        terminal_app.router.add_post("/api/exec", terminal.execute)
        terminal_runner = web.AppRunner(terminal_app, access_log=None)
        await terminal_runner.setup()
        await web.TCPSite(terminal_runner, "127.0.0.1", 18081).start()
        runners.append(terminal_runner)
        print("INFO: R2D2 terminal http://127.0.0.1:18081/", flush=True)

        if not arguments.no_browser:
            async def open_when_ready() -> None:
                await transport.ready.wait()
                webbrowser.open("http://127.0.0.1:18080/")
                webbrowser.open("http://127.0.0.1:15050/")
                if arguments.open_terminal:
                    webbrowser.open("http://127.0.0.1:18081/")

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
    parser.add_argument("--open-terminal", action="store_true")
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
