"""The rules engine for any agent's tool calls (used by the MCP proxy).

The same design as the phone's engine (android/.../capabilities/Policy.kt), for tools it doesn't
know in advance: "the model proposes; the rules decide". It assumes the model can be hijacked by
anything it reads, so it tracks what the session has read (taint, with named sources) and where
each call would send data, and it never relies on the model's account of what it's doing.

Verdicts: "auto" (do it), "ask" (the user decides), "deny" (refused). Every applicable rule is
evaluated and the strictest wins; an approval can satisfy "ask" but never overrides "deny".
"""
from __future__ import annotations

import fnmatch
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field

AUTO, ASK, DENY = "auto", "ask", "deny"
_RANK = {AUTO: 0, ASK: 1, DENY: 2}
LABEL = {AUTO: "Do it", ASK: "Ask me", DENY: "Never"}

NONE, REVERSIBLE, IRREVERSIBLE = "none", "reversible", "irreversible"

# Addresses in arguments. Deliberately narrow for free text (code and prose are full of dotted
# words); argument names that hold an address are checked more broadly.
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://([a-z0-9.-]+\.[a-z]{2,24}|\[[0-9a-f:]+\]|\d{1,3}(?:\.\d{1,3}){3})")
_EMAIL = re.compile(r"[^\s@<>()\"',;:]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_HOST = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,24}$")
_PHONE = re.compile(r"^\+?[\d\s\-().]{6,22}$")
HOST_ARGS = {"url", "uri", "host", "hostname", "domain", "endpoint", "server", "address", "link", "href", "site"}
RECIPIENT_ARGS = {"to", "cc", "bcc", "recipient", "recipients", "email", "phone", "number", "channel", "user", "username"}


@dataclass(frozen=True)
class Destination:
    value: str
    recipient: bool  # a person / account (vs a site)


def normalize_recipient(s: str) -> str:
    s = s.strip()
    return s.lower() if "@" in s else "".join(c for c in s if c.isdigit())[-9:]


def destinations(args: dict, extra: dict[str, str] | None = None) -> list[Destination]:
    """Every place a call with these arguments could send data. [extra]: arg name -> "site" | "recipient"."""
    out: list[Destination] = []

    def walk(key: str, v) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                walk(str(k), x)
        elif isinstance(v, list):
            for x in v:
                walk(key, x)
        elif isinstance(v, str):
            k = key.lower()
            kind = (extra or {}).get(key)
            for m in _URL.finditer(v):
                out.append(Destination(m.group(1).lower().strip("[]"), recipient=False))
            for m in _EMAIL.finditer(v):
                out.append(Destination(m.group(0).lower(), recipient=True))
            s = v.strip()
            if (kind == "site" or k in HOST_ARGS) and _HOST.match(s):
                out.append(Destination(s.lower(), recipient=False))
            if kind == "recipient" or k in RECIPIENT_ARGS:
                if _PHONE.match(s) and 7 <= sum(c.isdigit() for c in s) <= 15:
                    out.append(Destination(normalize_recipient(s), recipient=True))
                elif kind == "recipient" and not _EMAIL.search(s) and s:
                    out.append(Destination(s.lower(), recipient=True))  # e.g. a chat channel or handle

    for k, v in (args or {}).items():
        walk(str(k), v)
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


@dataclass
class Tool:
    """What the rules know about a tool: from the user's config, else the server's annotations."""
    name: str
    risk: str = IRREVERSIBLE
    untrusted_output: str | None = "its output"  # what reading it brings in; None = trusted
    sends_data_out: bool = True
    destination_args: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_mcp(t: dict, server: str, override: dict | None = None) -> "Tool":
        """MCP annotations are hints from the server; the spec's defaults are the cautious ones
        (not read-only => destructive; open-world). The user's config wins over both."""
        a = t.get("annotations") or {}
        read_only = bool(a.get("readOnlyHint", False))
        destructive = bool(a.get("destructiveHint", True))
        open_world = bool(a.get("openWorldHint", True))
        risk = NONE if read_only else (IRREVERSIBLE if destructive else REVERSIBLE)
        tool = Tool(t["name"], risk=risk,
                    untrusted_output=f"output of {server}/{t['name']}" if open_world else None,
                    sends_data_out=open_world)
        o = override or {}
        if "risk" in o:
            tool.risk = o["risk"]
        if "untrusted_output" in o:
            tool.untrusted_output = (f"output of {server}/{t['name']}" if o["untrusted_output"] is True
                                     else o["untrusted_output"] or None)
        if "sends_data_out" in o:
            tool.sends_data_out = bool(o["sends_data_out"])
        tool.destination_args = dict(o.get("destination_args") or {})
        return tool


@dataclass
class Config:
    levels: dict[str, str] = field(default_factory=dict)  # tool name (glob) -> auto | ask | deny
    allowed_sites: set[str] = field(default_factory=set)  # "example.com" also allows its subdomains
    blocked_sites: set[str] = field(default_factory=set)
    known_recipients: set[str] = field(default_factory=set)
    tools: dict[str, dict] = field(default_factory=dict)  # per-tool overrides (risk, untrusted_output, ...)
    max_calls_per_minute: int = 30
    tainted_egress: str = DENY  # deny (default) | ask: what a tainted session gets for a new destination

    @staticmethod
    def load(path: str | None) -> "Config":
        if not path:
            return Config()
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return Config(
            levels=dict(d.get("levels", {})),
            allowed_sites={s.lower() for s in d.get("allowed_sites", [])},
            blocked_sites={s.lower() for s in d.get("blocked_sites", [])},
            known_recipients={normalize_recipient(s) if ("@" in s or any(c.isdigit() for c in s)) else s.lower()
                              for s in d.get("known_recipients", [])},
            tools=dict(d.get("tools", {})),
            max_calls_per_minute=int(d.get("max_calls_per_minute", 30)),
            tainted_egress=d.get("tainted_egress", DENY),
        )

    def site_allowed(self, host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in self.allowed_sites)

    def site_blocked(self, host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in self.blocked_sites)

    def level_for(self, tool: str) -> str | None:
        for pattern, level in self.levels.items():
            if fnmatch.fnmatchcase(tool, pattern):
                return level
        return None


@dataclass
class Decision:
    verdict: str
    rule: str


@dataclass
class Session:
    """Per-connection state the model can't touch: once untrusted content enters, it stays."""
    tainted: bool = False
    sources: list[str] = field(default_factory=list)
    recent: deque = field(default_factory=deque)  # (tool, time) of executed calls

    def add_source(self, source: str) -> bool:
        """Untrusted content entered the session; True if this source is new."""
        self.tainted = True
        if source in self.sources:
            return False
        self.sources.append(source)
        return True

    def note_result(self, tool: Tool, ok: bool) -> bool:
        """A call finished; True if its output brought in a new untrusted source."""
        return bool(ok and tool.untrusted_output) and self.add_source(tool.untrusted_output)


def default_level(risk: str) -> str:
    return {NONE: AUTO, REVERSIBLE: AUTO, IRREVERSIBLE: ASK}[risk]


def decide(tool: Tool, args: dict, session: Session, config: Config, now: float | None = None) -> Decision:
    now = time.time() if now is None else now
    found: list[Decision] = []
    pretty = tool.name.replace("_", " ")

    # 1. Level: the user's setting, else the default for the risk.
    user = config.level_for(tool.name)
    if user:
        found.append(Decision(user, f"your setting for {tool.name} is \"{LABEL[user]}\""))
    else:
        d = default_level(tool.risk)
        what = {NONE: "only reads", REVERSIBLE: "is reversible", IRREVERSIBLE: "may be irreversible"}[tool.risk]
        found.append(Decision(d, f"{pretty} {what} (default: \"{LABEL[d]}\")"))

    # 2. Floor: anything that may be irreversible asks, whatever the setting.
    if tool.risk == IRREVERSIBLE:
        found.append(Decision(ASK, "actions that may be irreversible always ask"))

    # 3. Taint, and where data would go.
    read = "this session has read untrusted content (" + (", ".join(session.sources) or "unknown") + ")"
    if session.tainted and tool.risk != NONE:
        found.append(Decision(ASK, read))
    if tool.sends_data_out:
        for dest in destinations(args, tool.destination_args):
            allowed = (dest.value in config.known_recipients) if dest.recipient else config.site_allowed(dest.value)
            where = ("isn't one of your known recipients" if dest.recipient
                     else "isn't on your list of allowed sites")
            if not dest.recipient and config.site_blocked(dest.value):
                found.append(Decision(DENY, f"{dest.value} is on your blocked list"))
            elif session.tainted and allowed:
                found.append(Decision(ASK, f"{read}, and this would send data to {dest.value}"))
            elif session.tainted:
                found.append(Decision(config.tainted_egress if config.tainted_egress in (ASK, DENY) else DENY,
                                      f"{read}, and {dest.value} {where}"))
            elif not allowed:
                found.append(Decision(ASK, f"the agent wants to send data to {dest.value}, which {where}"))

    # 4. Rate limit: a runaway loop.
    while session.recent and session.recent[0][1] < now - 60:
        session.recent.popleft()
    n = sum(1 for t, _ in session.recent if t == tool.name)
    if n >= config.max_calls_per_minute:
        found.append(Decision(DENY, f"{tool.name} ran {n} times in the last minute (limit {config.max_calls_per_minute})"))

    verdict = max((d.verdict for d in found), key=_RANK.__getitem__)
    return Decision(verdict, "; ".join(d.rule for d in found if d.verdict == verdict))


def record(tool: Tool, session: Session, now: float | None = None) -> None:
    session.recent.append((tool.name, time.time() if now is None else now))
