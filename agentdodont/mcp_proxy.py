"""MCP proxy: the rules engine between any MCP client (an agent) and an MCP server (its tools).

    client (Claude Code, Claude Desktop, any MCP agent)
        │ stdio, JSON-RPC
    agentdodont mcp-proxy  ── rules.py decides every tools/call: do it, ask you, or refuse
        │ stdio, JSON-RPC
    the real MCP server (filesystem, fetch, email, ...)

Configure the client to start the proxy instead of the server:

    python -m agentdodont mcp-proxy --rules rules.json -- npx -y @modelcontextprotocol/server-fetch

Everything passes through unchanged except tools/call, which goes through the rules:
  - do it: forwarded; if the tool's output is untrusted, the session is tainted from then on;
  - ask: the question goes to you through the client (MCP elicitation), naming the rule; if the
    client can't ask, the call is refused and the reason says so;
  - refuse: never reaches the server; the agent gets an error result explaining why.

Two ways of asking, matching the client's protocol version:
  - up to 2025-11-25 (the client sends `initialize`): an elicitation/create request to the client;
  - from 2026-07-28 (capabilities in each request's _meta, no `initialize`): multi round-trip
    requests. The call's result is "input_required" with the question and a signed requestState;
    the client asks you and retries the call with your answer. The state is signed with a key
    only this proxy process knows and names the tool, a digest of its exact arguments and an
    expiry, and each one works once, so neither the agent nor a forged retry can approve a call.

The proxy talks JSON-RPC directly (no SDK). Nothing but protocol messages is written to stdout;
the audit log is a JSONL file.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import presets, rules
from .shared import SharedTaint, append_line

_META_CAPS = "io.modelcontextprotocol/clientCapabilities"
_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT = "io.modelcontextprotocol/clientInfo"
_ASK_KEY = "agentdodont_approval"  # our key in inputRequests / inputResponses
_STATE_PREFIX = "agentdodont1."  # our requestState; anything else belongs to the server
_STATE_TTL = 15 * 60  # seconds you have to answer a question


class Proxy:
    def __init__(self, server_cmd: list[str], config: rules.Config, log_path: Path, name: str,
                 client_in=None, client_out=None, shared: SharedTaint | None = None, preset: str | None = None):
        self.config = config
        self.name = name
        self.preset = preset
        self.session = rules.Session()
        self.shared = shared or SharedTaint(None, "not shared")
        self.tools: dict[str, rules.Tool] = {}
        self.client_in = client_in or sys.stdin
        self.client_out = client_out or sys.stdout
        # Binary pipes: text mode on Windows would turn "\n" into "\r\n" on the wire.
        self.server = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
        self.out_lock = threading.Lock()
        self.srv_lock = threading.Lock()
        self.log_lock = threading.Lock()
        self.log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.client_can_ask = False
        self.pending_list: set = set()  # ids of tools/list requests
        self.pending_calls: dict = {}  # forwarded tools/call id -> tool
        self.pending_asks: dict = {}  # our elicitation id -> (original request, tool, decision)
        self.approved_calls: set = set()  # forwarded ids you approved (2026-07-28 protocol)
        self.call_args: dict = {}  # forwarded tools/call id -> (name, arguments)
        self.ids = itertools.count(1)
        self.started = False  # session_start logged
        self.secret = os.urandom(32)  # signs our requestState; never leaves this process
        self.used_states: set = set()  # nonces already redeemed

    # --- plumbing -------------------------------------------------------------------------
    def to_client(self, msg: dict) -> None:
        with self.out_lock:
            self.client_out.write(json.dumps(msg, ensure_ascii=False) + "\n")
            self.client_out.flush()

    def to_server(self, msg: dict) -> None:
        with self.srv_lock:
            self.server.stdin.write((json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))
            self.server.stdin.flush()

    def log(self, **fields) -> None:
        fields = {"t": round(time.time(), 3), "server": self.name, **fields}
        with self.log_lock:
            append_line(self.log_path, json.dumps(fields, ensure_ascii=False))

    def tool(self, name: str) -> rules.Tool:
        t = self.tools.get(name)
        if t is None:  # called before (or without) tools/list: the cautious defaults
            t = rules.Tool.from_mcp({"name": name}, self.name, self.config.tools.get(name))
        return t

    # --- client -> server -----------------------------------------------------------------
    def on_client(self, msg: dict) -> None:
        method = msg.get("method")
        if method is None and "id" in msg and msg["id"] in self.pending_asks:
            self.on_answer(msg)
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if method == "initialize":
            caps = params.get("capabilities") or {}
            self.client_can_ask = "elicitation" in caps
            self.start_session(params.get("protocolVersion"), params.get("clientInfo"), self.client_can_ask)
        elif not self.started and _META_VERSION in meta:  # 2026-07-28 and later: no initialize
            self.start_session(meta.get(_META_VERSION), meta.get(_META_CLIENT), self.can_ask(params))
        if method == "tools/list" and "id" in msg:
            self.pending_list.add(msg["id"])
        elif method == "tools/call" and "id" in msg:
            self.on_call(msg)
            return
        self.to_server(msg)

    def start_session(self, version, client_info, can_ask: bool) -> None:
        self.started = True
        client = client_info.get("name") if isinstance(client_info, dict) else None
        self.log(kind="session_start", client=client, protocol=version, client_can_ask=can_ask,
                 shared_with=self.shared.label, preset=self.preset)

    @staticmethod
    def uses_mrtr(params: dict) -> bool:
        """True if this request comes from a 2026-07-28+ client (capabilities in _meta)."""
        meta = params.get("_meta")
        return isinstance(meta, dict) and isinstance(meta.get(_META_CAPS), dict)

    def can_ask(self, params: dict) -> bool:
        if not self.uses_mrtr(params):
            return self.client_can_ask
        el = params["_meta"][_META_CAPS].get("elicitation")
        return isinstance(el, dict) and (not el or "form" in el)  # {} means form mode

    # --- signed requestState (2026-07-28 protocol) -----------------------------------------
    @staticmethod
    def call_digest(name: str, args) -> str:
        return hashlib.sha256(json.dumps([name, args], sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def seal(self, payload: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()
        return f"{_STATE_PREFIX}{body}.{sig}"

    def unseal(self, state: str, name: str, args) -> tuple[dict | None, str]:
        """(payload, "") if `state` is ours, intact, unexpired, unused and for this exact call;
        otherwise (None, why). Redeeming it uses it up."""
        try:
            body, sig = state[len(_STATE_PREFIX):].rsplit(".", 1)
            if not hmac.compare_digest(sig, hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()):
                return None, "the approval's signature doesn't match (or the proxy restarted)"
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except (ValueError, TypeError):
            return None, "the approval is malformed"
        if payload.get("digest") != self.call_digest(name, args):
            return None, "the approval was for a different call"
        if payload.get("exp", 0) < time.time():
            return None, "the approval expired"
        if payload.get("nonce") in self.used_states:
            return None, "the approval was already used"
        self.used_states.add(payload.get("nonce"))
        return payload, ""

    def new_state(self, kind: str, name: str, args, inner: str | None, inner_responses=None) -> str:
        return self.seal({"kind": kind, "digest": self.call_digest(name, args), "exp": time.time() + _STATE_TTL,
                          "nonce": os.urandom(12).hex(), "inner": inner, "inner_responses": inner_responses})

    def sync(self) -> None:
        """Take in what other proxies in this session have read."""
        for src in self.shared.sources():
            if self.session.add_source(src):
                self.log(kind="shared_taint", source=src)

    def on_call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        name, args = params.get("name", ""), params.get("arguments") or {}
        tool = self.tool(name)
        mrtr = self.uses_mrtr(params)
        approved = False
        state = params.get("requestState")
        if mrtr and isinstance(state, str) and state.startswith(_STATE_PREFIX):
            # A retry carrying our state: your answer to our question, or a call you already
            # approved that the server then asked its own question about. Restore the server's
            # part of the request before deciding, so what's forwarded is what it expects.
            payload, why = self.unseal(state, name, args)
            params = dict(params)
            responses = dict(params.get("inputResponses") or {})
            answer = responses.pop(_ASK_KEY, None)
            params.pop("requestState", None)
            params.pop("inputResponses", None)
            if payload is not None:
                if payload.get("inner") is not None:
                    params["requestState"] = payload["inner"]
                responses = {**(payload.get("inner_responses") or {}), **responses}
            if responses:
                params["inputResponses"] = responses
            msg = {**msg, "params": params}
            if payload is None:
                self.log(kind="approval_rejected", tool=name, reason=why)
            elif payload.get("kind") == "approved":
                approved = True
            else:
                res = answer if isinstance(answer, dict) else {}
                allowed = res.get("action") == "accept" and (res.get("content") or {}).get("allow", True) is not False
                self.log(kind="answer", tool=name, allowed=allowed, action=res.get("action"), error=None)
                if not allowed:
                    self.refuse(msg, self.not_allowed_text(name, res.get("action")))
                    return
                approved = True
        self.sync()
        d = rules.decide(tool, args, self.session, self.config)
        self.log(kind="decision", tool=name, args=args, verdict=d.verdict, rule=d.rule,
                 tainted=self.session.tainted, sources=list(self.session.sources), **({"approved": True} if approved else {}))
        if d.verdict == rules.AUTO or (d.verdict == rules.ASK and approved):
            # Approval satisfies "ask" but never "deny": the rules were checked again just now.
            if approved:
                self.approved_calls.add(msg["id"])
            self.forward_call(msg, tool)
        elif d.verdict == rules.DENY:
            self.refuse(msg, f"Blocked by Agent Do/Don't ({d.rule}). Don't try to achieve this another way; tell the user.")
        elif not self.can_ask(params):
            self.refuse(msg, f"Agent Do/Don't needs the user's OK for this ({d.rule}), but this client can't ask "
                             "questions (no MCP elicitation support), so it was not done. Tell the user.")
        elif mrtr:
            self.log(kind="ask", tool=name)
            self.to_client({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "resultType": "input_required",
                "inputRequests": {_ASK_KEY: {"method": "elicitation/create", "params": self.question(name, args, d, mrtr=True)}},
                "requestState": self.new_state("ask", name, args, params.get("requestState"),
                                               params.get("inputResponses")),
            }})
        else:
            ask_id = f"agentdodont-{next(self.ids)}"
            self.pending_asks[ask_id] = (msg, tool, d)
            self.to_client({"jsonrpc": "2.0", "id": ask_id, "method": "elicitation/create",
                            "params": self.question(name, args, d)})

    @staticmethod
    def not_allowed_text(what: str, action) -> str:
        if action == "decline":
            return f"The user declined: {what}. Do not retry it another way."
        return (f"Not done: {what} needs the user's OK, and the question was dismissed or couldn't be shown. "
                "Do not retry it another way; tell the user.")

    def question(self, name: str, args, d, mrtr: bool = False) -> dict:
        summary = json.dumps(args, ensure_ascii=False)
        summary = summary if len(summary) <= 400 else summary[:399] + "…"
        q = {"message": f"Agent Do/Don't: allow {self.name}/{name} {summary}?\nWhy I'm asking: {d.rule}.",
             "requestedSchema": {"type": "object", "properties": {
                 "allow": {"type": "boolean", "title": "Allow this call", "default": True}}}}
        return {"mode": "form", **q} if mrtr else q  # "mode" arrived with 2025-11-25

    def on_answer(self, msg: dict) -> None:
        original, tool, d = self.pending_asks.pop(msg["id"])
        res = msg.get("result") or {}
        allowed = res.get("action") == "accept" and (res.get("content") or {}).get("allow", True) is not False
        self.log(kind="answer", tool=tool.name, allowed=allowed, action=res.get("action"), error=msg.get("error"))
        if not allowed:
            self.refuse(original, self.not_allowed_text(f"{tool.name} ({d.rule})", res.get("action")))
            return
        # Approval satisfies "ask" but never "deny": decide again with the state as it is now.
        self.sync()
        again = rules.decide(tool, (original.get("params") or {}).get("arguments") or {}, self.session, self.config)
        if again.verdict == rules.DENY:
            self.refuse(original, f"Blocked by Agent Do/Don't ({again.rule}).")
            return
        self.forward_call(original, tool)

    def forward_call(self, msg: dict, tool: rules.Tool) -> None:
        rules.record(tool, self.session)
        self.pending_calls[msg["id"]] = tool
        p = msg.get("params") or {}
        self.call_args[msg["id"]] = (p.get("name", ""), p.get("arguments") or {})
        self.to_server(msg)

    def refuse(self, msg: dict, text: str) -> None:
        self.log(kind="refused", tool=(msg.get("params") or {}).get("name"), reason=text)
        self.to_client({"jsonrpc": "2.0", "id": msg["id"],
                        "result": {"content": [{"type": "text", "text": text}], "isError": True}})

    # --- server -> client -----------------------------------------------------------------
    def on_server(self, msg: dict) -> None:
        mid = msg.get("id")
        if "method" not in msg and mid in self.pending_list:
            self.pending_list.discard(mid)
            for t in (msg.get("result") or {}).get("tools", []):
                if "name" in t:
                    self.tools[t["name"]] = rules.Tool.from_mcp(t, self.name, self.config.tools.get(t["name"]))
            self.log(kind="tools", tools={n: vars(t) for n, t in self.tools.items()})
        elif "method" not in msg and mid in self.pending_calls:
            tool = self.pending_calls.pop(mid)
            approved = mid in self.approved_calls
            self.approved_calls.discard(mid)
            result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
            if result.get("resultType") == "input_required":
                # The server needs input before it finishes: not a result yet, so no taint. If
                # you approved this call, wrap the server's state in ours so its retry isn't
                # asked about again.
                self.log(kind="server_input_required", tool=tool.name)
                if approved:
                    name, args = self.call_args.pop(mid, (tool.name, {}))
                    result = {**result, "requestState": self.new_state("approved", name, args, result.get("requestState"))}
                    msg = {**msg, "result": result}
                self.call_args.pop(mid, None)
                self.to_client(msg)
                return
            self.call_args.pop(mid, None)
            ok = "result" in msg and not (msg.get("result") or {}).get("isError", False)
            was = self.session.tainted
            if self.session.note_result(tool, ok):
                self.shared.add(tool.untrusted_output, self.name)
            self.log(kind="result", tool=tool.name, ok=ok, tainted=self.session.tainted,
                     newly_tainted=self.session.tainted and not was)
        self.to_client(msg)

    # --- run ------------------------------------------------------------------------------
    def pump_server(self) -> None:
        for raw in self.server.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                print("agentdodont mcp-proxy: non-JSON line from the server ignored", file=sys.stderr)
                continue
            for m in (msg if isinstance(msg, list) else [msg]):
                self.on_server(m)

    def run(self) -> int:
        threading.Thread(target=self.pump_server, daemon=True).start()
        for line in self.client_in:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, list):  # JSON-RPC batch (older protocol versions)
                for m in msg:
                    self.on_client(m)
            else:
                self.on_client(msg)
        try:
            self.server.stdin.close()
        except OSError:
            pass
        return self.server.wait(timeout=10)


def main(args) -> int:
    if not args.server:
        print("usage: agentdodont mcp-proxy [--rules rules.json] -- <server command ...>", file=sys.stderr)
        return 2
    cmd = args.server[1:] if args.server[0] == "--" else args.server
    if not cmd:
        print("usage: agentdodont mcp-proxy [--rules rules.json] -- <server command ...>", file=sys.stderr)
        return 2
    # Windows: "npx" is npx.cmd, which CreateProcess won't find by its bare name.
    resolved = None
    if os.name == "nt" and not Path(cmd[0]).suffix:  # prefer npx.cmd over the extensionless sh script
        for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";"):
            resolved = resolved or (shutil.which(cmd[0] + ext) if ext else None)
    resolved = resolved or shutil.which(cmd[0])
    if resolved:
        cmd = [resolved, *cmd[1:]]
    config = rules.Config.load(args.rules)
    preset = getattr(args, "preset", None)
    preset = presets.detect(cmd) if preset in (None, "auto") else (None if preset == "none" else preset)
    if preset:
        try:
            config.tools = presets.merge_tools(presets.load(preset), config.tools)
        except ValueError as e:
            print(f"agentdodont mcp-proxy: {e}", file=sys.stderr)
            return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # the protocol channel: "\n" only
        sys.stdin.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    name = args.name or Path(cmd[0]).name
    log = Path(args.log)
    shared = SharedTaint.open(log.parent / "sessions", args.session or os.environ.get("AGENTDODONT_SESSION"))
    return Proxy(cmd, config, log, name, shared=shared, preset=preset).run()
