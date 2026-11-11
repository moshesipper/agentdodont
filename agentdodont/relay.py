"""Laptop relay: keeps the Anthropic API key off the phone.

    python -m agentdodont relay            # listens on 127.0.0.1:8787, tunnels to the phone over USB

The phone app holds only a random relay token, which this process writes into the app's private
storage over adb (it is not compiled into the APK). The app reaches this process through `adb reverse`
(phone 127.0.0.1:8787 -> laptop 127.0.0.1:8787), so nothing listens on the network. The relay
checks the token, swaps in the real key, and forwards to the Messages API. Because a token on a
phone can leak, it is deliberately narrow:

  * only POST /v1/messages, non-streaming
  * only models in ALLOWED_MODELS, max_tokens capped
  * a per-minute request limit and a daily spend cap (estimated from returned usage)
  * logs metadata only (model, tokens, cost, status) - never request or response content

Errors the relay itself raises use the API's error shape with a message starting "relay:", so the
phone can tell "the relay refused" from "Claude returned an error".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
from collections import deque
from datetime import date, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from .suite import PRICES

UPSTREAM = "https://api.anthropic.com"
ALLOWED_MODELS = frozenset(PRICES)
MAX_TOKENS_CAP = 16_000
FORWARD_HEADERS = ("anthropic-version", "anthropic-beta", "content-type")
RETURN_HEADERS = ("content-type", "request-id", "retry-after")

# (status, headers, body) <- send(url, headers, body)
Sender = Callable[[str, dict[str, str], bytes], tuple[int, dict[str, str], bytes]]


def _httpx_send(url: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, str], bytes]:
    import httpx

    r = httpx.post(url, headers=headers, content=body, timeout=httpx.Timeout(600, connect=10))
    return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content


def cost_usd(model: str, usage: dict) -> float:
    p = PRICES.get(model)
    if not p:
        return 0.0
    return (usage.get("input_tokens", 0) * p[0] + usage.get("output_tokens", 0) * p[1]
            + (usage.get("cache_read_input_tokens") or 0) * p[2]
            + (usage.get("cache_creation_input_tokens") or 0) * p[3]) / 1e6


class Relay:
    def __init__(self, api_key: str, token: str, *, daily_budget_usd: float = 2.0,
                 max_requests_per_minute: int = 30, state_dir: Path = Path("logs"),
                 upstream: str = UPSTREAM, send: Sender = _httpx_send,
                 devices=None, pairing=None):
        if not api_key or not token:
            raise ValueError("relay needs both an API key and a token")
        self.api_key, self.token = api_key, token
        self.daily_budget_usd = daily_budget_usd
        self.max_rpm = max_requests_per_minute
        self.upstream, self.send = upstream.rstrip("/"), send
        state_dir.mkdir(parents=True, exist_ok=True)
        self.spend_path = state_dir / "relay_spend.json"
        self.log_path = state_dir / "relay.jsonl"
        self._lock = threading.Lock()
        self._recent: deque[float] = deque()
        self.devices = devices  # pairing.DeviceRegistry: phones paired over Wi-Fi
        self.pairing = pairing  # pairing.PairingSession while a pairing code is on screen

    # --- spend tracking (survives restarts) -------------------------------------------------
    def spent_today(self) -> float:
        try:
            d = json.loads(self.spend_path.read_text())
            return float(d.get(date.today().isoformat(), 0.0))
        except (OSError, ValueError):
            return 0.0

    def _add_spend(self, usd: float) -> float:
        try:
            d = json.loads(self.spend_path.read_text())
        except (OSError, ValueError):
            d = {}
        today = date.today().isoformat()
        d[today] = round(float(d.get(today, 0.0)) + usd, 6)
        self.spend_path.write_text(json.dumps(d))
        return d[today]

    def _log(self, **fields) -> None:
        fields = {"ts": datetime.now().isoformat(timespec="seconds"), **fields}
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(fields) + "\n")

    # --- request handling (pure: no sockets, so it is unit-testable) -----------------------
    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes,
               now: float | None = None) -> tuple[int, dict[str, str], bytes]:
        headers = {k.lower(): v for k, v in headers.items()}
        now = time.time() if now is None else now

        # Liveness check for the phone's "Claude connected" indicator. No token needed and nothing
        # revealed beyond "a relay is here"; it never reaches the API.
        if method == "GET" and path.split("?")[0] == "/health":
            return 200, {"content-type": "application/json"}, b'{"ok":true}'

        def refuse(status: int, kind: str, msg: str):
            self._log(status=status, refused=msg)
            return status, {"content-type": "application/json"}, json.dumps(
                {"type": "error", "error": {"type": kind, "message": f"relay: {msg}"}}).encode()

        if method == "POST" and path.split("?")[0] in ("/pair/hello", "/pair/complete"):
            return self._pair(path.split("?")[0], body, refuse)

        # The Java SDK (3.x) sends its credential as "Authorization: Bearer ..."; others use x-api-key.
        auth = headers.get("authorization", "")
        presented = auth[7:] if auth[:7].lower() == "bearer " else headers.get("x-api-key", "")
        usb = hmac.compare_digest(presented.encode(), self.token.encode())
        if not usb and not (self.devices and self.devices.check(presented)):
            return refuse(401, "authentication_error", "wrong or missing relay token")
        if method != "POST" or path.split("?")[0] != "/v1/messages":
            return refuse(404, "not_found_error", f"only POST /v1/messages is relayed, not {method} {path}")
        try:
            req = json.loads(body)
        except ValueError:
            return refuse(400, "invalid_request_error", "body is not JSON")
        model = req.get("model")
        if model not in ALLOWED_MODELS:
            return refuse(400, "invalid_request_error", f"model {model!r} is not allowed")
        if not isinstance(req.get("max_tokens"), int) or req["max_tokens"] > MAX_TOKENS_CAP:
            return refuse(400, "invalid_request_error", f"max_tokens must be at most {MAX_TOKENS_CAP}")
        if req.get("stream"):
            return refuse(400, "invalid_request_error", "streaming is not relayed")

        with self._lock:
            while self._recent and self._recent[0] < now - 60:
                self._recent.popleft()
            if len(self._recent) >= self.max_rpm:
                # 403, not 429: the SDK retries 429s, which would only hammer the limit.
                return refuse(403, "permission_error", f"more than {self.max_rpm} requests in a minute")
            spent = self.spent_today()
            if spent >= self.daily_budget_usd:
                return refuse(403, "permission_error",
                              f"daily budget of ${self.daily_budget_usd:.2f} reached (spent ${spent:.2f})")
            self._recent.append(now)

        fwd = {k: headers[k] for k in FORWARD_HEADERS if k in headers}
        fwd["x-api-key"] = self.api_key
        try:
            status, up_headers, up_body = self.send(f"{self.upstream}/v1/messages", fwd, body)
        except Exception as e:  # noqa: BLE001 - network failure upstream
            return refuse(502, "api_error", f"could not reach the Anthropic API ({type(e).__name__})")

        entry = {"status": status, "model": model, "request_id": up_headers.get("request-id")}
        if status == 200:
            try:
                usage = json.loads(up_body).get("usage", {})
            except ValueError:
                usage = {}
            usd = cost_usd(model, usage)
            with self._lock:
                total = self._add_spend(usd)
            entry |= {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens"),
                      "cache_read": usage.get("cache_read_input_tokens"), "cost_usd": round(usd, 5),
                      "spent_today_usd": round(total, 4)}
        self._log(**entry)
        return status, {k: up_headers[k] for k in RETURN_HEADERS if k in up_headers}, up_body

    def _pair(self, path: str, body: bytes, refuse):
        from .pairing import proof

        if self.pairing is None or self.devices is None:
            return refuse(404, "not_found_error", "pairing isn't open (run the relay with --pair)")
        try:
            req = json.loads(body)
        except ValueError:
            return refuse(400, "invalid_request_error", "body is not JSON")
        why = self.pairing.usable()
        if why:
            return refuse(410, "permission_error", why)
        if path == "/pair/hello":
            nonce = str(req.get("nonce", ""))
            if len(nonce) < 16:
                return refuse(400, "invalid_request_error", "nonce too short")
            return 200, {"content-type": "application/json"}, json.dumps(
                {"proof": proof(self.pairing.code, nonce, self.pairing.fingerprint)}).encode()
        why = self.pairing.check(str(req.get("code", "")))
        if why:
            return refuse(403, "permission_error", why)
        device_id, token = self.devices.add(str(req.get("name", "phone")))
        self._log(status=200, paired=device_id)  # never the token
        print(f"  paired: {device_id} ({req.get('name', 'phone')})")
        return 200, {"content-type": "application/json"}, json.dumps({"device_id": device_id, "token": token}).encode()



def make_tls_server(relay: Relay, host: str, port: int, cert: Path, key: Path) -> ThreadingHTTPServer:
    """The Wi-Fi relay: same handler, wrapped in TLS with the relay's own certificate."""
    import ssl

    server = make_server(relay, host=host, port=port)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def make_server(relay: Relay, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self):
            n = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(n) if n else b""
            status, headers, out = relay.handle(self.command, self.path, dict(self.headers.items()), body)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_POST = do_GET = do_PUT = do_DELETE = _serve

        def log_message(self, *a):  # relay.jsonl is the log; keep the console quiet
            pass

    return ThreadingHTTPServer((host, port), Handler)


# --- local.properties: where the key lives and where the token is shared with the build ------
def read_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "!")) and "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def set_property(path: Path, key: str, value: str) -> None:
    """Set one key in a .properties file, keeping the other lines. The file holds secrets, so on
    first write it's readable by you only (on Windows, your user folder already is)."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    lines = [ln for ln in lines if ln.split("=", 1)[0].strip() != key]
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    path.write_text("\n".join(lines + [f"{key}={value}"]) + "\n", encoding="utf-8")
    if new and os.name != "nt":
        os.chmod(path, 0o600)


def ensure_token(path: Path, rotate: bool = False) -> tuple[str, bool]:
    """Return (token, created). Creates aos.relayToken on first use, or replaces it when rotating."""
    existing = read_properties(path).get("aos.relayToken")
    if existing and not rotate:
        return existing, False
    token = secrets.token_urlsafe(32)
    set_property(path, "aos.relayToken", token)
    return token, True


PACKAGE = "dev.agentdodont.app"
TOKEN_FILE = "files/relay_token"  # relative to the app's private data dir (/data/user/0/<package>)

Runner = Callable[..., subprocess.CompletedProcess]


def provision_token(adb: str, serial: str | None, token: str, run: Runner = subprocess.run) -> bool:
    """Write the token into the app's private storage, then verify it by hash.

    `run-as` executes as the app's own user, so the file lands in a directory only the app can
    read. The token travels over stdin, never on a command line. Requires a debuggable build.
    """
    base = [adb] + (["-s", serial] if serial else [])
    tmp = TOKEN_FILE + ".tmp"
    try:
        # exec-in tears the remote command down when stdin closes, so only the write happens there;
        # locking down and renaming into place is a separate command.
        # mkdir: a freshly installed app has no files/ folder until its first launch.
        run(base + ["exec-in", f"run-as {PACKAGE} sh -c 'umask 077; mkdir -p files && cat > {tmp}'"],
            input=token.encode(), capture_output=True, timeout=15)
        run(base + ["exec-out", f"run-as {PACKAGE} sh -c 'chmod 600 {tmp} && mv {tmp} {TOKEN_FILE}'"],
            capture_output=True, timeout=15)
        # exec-in does not report the remote exit status, so check what actually landed.
        r = run(base + ["exec-out", f"run-as {PACKAGE} sha256sum {TOKEN_FILE}"], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.stdout.decode(errors="replace").split(" ")[0].strip() == hashlib.sha256(token.encode()).hexdigest()


def keep_phone_linked(adb: str, serial: str | None, port: int, token: str, stop: threading.Event) -> None:
    """Every 15 s: re-apply `adb reverse` (lost whenever the cable is replugged), and hand the
    token to the app whenever the phone (re)appears."""
    cmd = [adb] + (["-s", serial] if serial else []) + ["reverse", f"tcp:{port}", f"tcp:{port}"]
    last_ok = None
    while not stop.is_set():
        try:
            ok = subprocess.run(cmd, capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        if ok != last_ok:
            print("  tunnel: phone 127.0.0.1:%d -> laptop  %s" % (port, "up" if ok else "DOWN (phone not connected?)"))
            if ok:
                good = provision_token(adb, serial, token)
                print("  token:  " + ("in the app's private storage" if good else
                                      "not handed over USB (that needs a debug build; the release app "
                                      "pairs over Wi-Fi instead: relay --pair)"))
                ok = ok if good else None  # retry provisioning next round
            last_ok = ok
        stop.wait(15)
