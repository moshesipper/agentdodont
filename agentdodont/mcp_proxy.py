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

The proxy talks JSON-RPC directly (no SDK), so it doesn't depend on a protocol version. Nothing
but protocol messages is written to stdout; the audit log is a JSONL file.
"""
from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import rules


class Proxy:
    def __init__(self, server_cmd: list[str], config: rules.Config, log_path: Path, name: str,
                 client_in=None, client_out=None):
        self.config = config
        self.name = name
        self.session = rules.Session()
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
        self.ids = itertools.count(1)

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
        with self.log_lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(fields, ensure_ascii=False) + "\n")

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
        if method == "initialize":
            caps = (msg.get("params") or {}).get("capabilities") or {}
            self.client_can_ask = "elicitation" in caps
            self.log(kind="session_start", client_can_ask=self.client_can_ask)
        elif method == "tools/list" and "id" in msg:
            self.pending_list.add(msg["id"])
        elif method == "tools/call" and "id" in msg:
            self.on_call(msg)
            return
        self.to_server(msg)

    def on_call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        name, args = params.get("name", ""), params.get("arguments") or {}
        tool = self.tool(name)
        d = rules.decide(tool, args, self.session, self.config)
        self.log(kind="decision", tool=name, args=args, verdict=d.verdict, rule=d.rule,
                 tainted=self.session.tainted, sources=list(self.session.sources))
        if d.verdict == rules.AUTO:
            self.forward_call(msg, tool)
        elif d.verdict == rules.DENY:
            self.refuse(msg, f"Blocked by Agent Do/Don't ({d.rule}). Don't try to achieve this another way; tell the user.")
        elif not self.client_can_ask:
            self.refuse(msg, f"Agent Do/Don't needs the user's OK for this ({d.rule}), but this client can't ask "
                             "questions (no MCP elicitation support), so it was not done. Tell the user.")
        else:
            ask_id = f"agentdodont-{next(self.ids)}"
            self.pending_asks[ask_id] = (msg, tool, d)
            summary = json.dumps(args, ensure_ascii=False)
            summary = summary if len(summary) <= 400 else summary[:399] + "…"
            self.to_client({"jsonrpc": "2.0", "id": ask_id, "method": "elicitation/create", "params": {
                "message": f"Agent Do/Don't: allow {self.name}/{name} {summary}?\nWhy I'm asking: {d.rule}.",
                "requestedSchema": {"type": "object", "properties": {
                    "allow": {"type": "boolean", "title": "Allow this call", "default": True}}},
            }})

    def on_answer(self, msg: dict) -> None:
        original, tool, d = self.pending_asks.pop(msg["id"])
        res = msg.get("result") or {}
        allowed = res.get("action") == "accept" and (res.get("content") or {}).get("allow", True) is not False
        self.log(kind="answer", tool=tool.name, allowed=allowed, action=res.get("action"), error=msg.get("error"))
        if not allowed:
            self.refuse(original, f"The user declined: {tool.name} ({d.rule}). Do not retry it another way.")
            return
        # Approval satisfies "ask" but never "deny": decide again with the state as it is now.
        again = rules.decide(tool, (original.get("params") or {}).get("arguments") or {}, self.session, self.config)
        if again.verdict == rules.DENY:
            self.refuse(original, f"Blocked by Agent Do/Don't ({again.rule}).")
            return
        self.forward_call(original, tool)

    def forward_call(self, msg: dict, tool: rules.Tool) -> None:
        rules.record(tool, self.session)
        self.pending_calls[msg["id"]] = tool
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
            ok = "result" in msg and not (msg.get("result") or {}).get("isError", False)
            was = self.session.tainted
            self.session.note_result(tool, ok)
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
    try:
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # the protocol channel: "\n" only
        sys.stdin.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    name = args.name or Path(cmd[0]).name
    return Proxy(cmd, config, Path(args.log), name).run()
