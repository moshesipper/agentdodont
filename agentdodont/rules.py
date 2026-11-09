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
import os
import posixpath
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


def is_phone(s: str) -> bool:
    return bool(_PHONE.match(s)) and 7 <= sum(c.isdigit() for c in s) <= 15


def normalize_recipient(s: str) -> str:
    """Emails and handles compare case-insensitively; phone numbers by their last nine digits."""
    s = s.strip()
    if "@" not in s and is_phone(s):
        return "".join(c for c in s if c.isdigit())[-9:]
    return s.lower()


def destinations(args: dict, extra: dict[str, str] | None = None) -> list[Destination]:
    """Every place a call with these arguments could send data. [extra]: arg name -> "site" | "recipient" |
    "none" (not a destination, e.g. the account the call acts as, or a search query)."""
    out: list[Destination] = []

    def walk(key: str, v) -> None:
        if (extra or {}).get(key) == "none":
            return
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
                if is_phone(s):
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


# Files the agent must never read or change through a tool: Agent Do/Don't's own (rules, audit
# log, session taint files, its code) and the client's settings that decide whether the proxy
# runs at all. A folder with one of these names anywhere in a path, or a file with one of these
# names, is protected wherever it is; the exact paths of this proxy's files come from the proxy.
PROTECTED_DIRS = {".agentdodont", ".claude"}
PROTECTED_FILES = {".mcp.json", ".claude.json", "claude_desktop_config.json"}
# Argument names that hold a path: always checked. Other strings are checked only if they look
# like a path (so a sentence that mentions ~/.agentdodont isn't refused).
PATH_ARGS = {"path", "paths", "source", "destination", "file", "files", "filename", "file_path", "filepath",
             "dir", "directory", "folder", "root", "target", "src", "dest", "from_path", "to_path"}
_PATHLIKE = re.compile(r"^(?:~|/|\\|\.{1,2}[/\\]|[A-Za-z]:[/\\]|file://)")


def norm_path(s: str) -> str:
    """A path in one comparable form: ~ expanded, forward slashes, . and .. resolved, case-folded
    (stricter than POSIX needs, never looser). C:\\x, C:/x, /c/x and file:///C:/x are the same."""
    s = s.strip()
    if s.lower().startswith("file://"):
        s = s[7:]
    if s.startswith("~"):
        s = os.path.expanduser(s)
    s = re.sub(r"^/{2,}", "/", s.replace("\\", "/"))  # file:////x, //x: normpath would keep the "//"
    if re.match(r"^/[A-Za-z]:/", s):
        s = s[1:]
    if os.name == "nt" and re.match(r"^/[A-Za-z](/|$)", s):  # Git Bash and MSYS: /c/Users -> c:/Users
        s = s[1] + ":/" + s[3:]
    s = posixpath.normpath(s) if s else s
    if _is_abs(s.casefold()):
        # One file, one name: symbolic links, and on Windows 8.3 short names (C:\PROGRA~1),
        # resolve to the real path (as far as it exists).
        try:
            s = os.path.realpath(s).replace("\\", "/")
        except (OSError, ValueError):
            pass
    return s.casefold()


def _is_abs(p: str) -> bool:
    return p.startswith("/") or bool(re.match(r"^[a-z]:/", p))


def protected_target(args: dict, protected: list[str], writes: bool) -> str | None:
    """The first argument that names a protected file or folder (or, for a tool that changes
    things, a folder that contains one, which a move or delete would take with it); else None.
    [protected]: absolute paths, already normalized."""
    def hit(raw: str) -> bool:
        p = norm_path(raw)
        if not p or p == ".":
            return False
        segs = p.split("/")
        if any(s in PROTECTED_DIRS for s in segs) or segs[-1] in PROTECTED_FILES:
            return True
        for q in protected:
            if _is_abs(p):
                if p == q or p.startswith(q + "/") or (writes and q.startswith(p.rstrip("/") + "/")):
                    return True
            else:  # relative to a root we don't know: match it against the end of q
                if q.endswith("/" + p):
                    return True  # p is q ("mcp-rules.json" in the folder that holds it)
                for i in range(2, len(segs)):
                    if q.endswith("/" + "/".join(segs[:i])):
                        return True  # p is inside q, named by at least two folders of q's path
                if writes and ("/" + p + "/") in (q + "/"):
                    return True  # p is a folder that contains q
        return False

    found: list[str] = []

    def walk(key: str, v) -> None:
        if found:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                walk(str(k), x)
        elif isinstance(v, list):
            for x in v:
                walk(key, x)
        elif isinstance(v, str) and "\n" not in v and len(v) <= 4096:
            s = v.strip()
            if "://" in s and not s.lower().startswith("file://"):
                return  # a web address, not a file (sending data there is the destination rules' job)
            looks = key.lower() in PATH_ARGS or _PATHLIKE.match(s) or (s and not any(c.isspace() for c in s))
            if looks and hit(s):
                found.append(s)

    for k, v in (args or {}).items():
        walk(str(k), v)
    return found[0] if found else None


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
    protected_paths: list[str] = field(default_factory=list)  # normalized; added to, never replacing, the built-in ones

    def protect(self, *paths) -> None:
        for p in paths:
            n = norm_path(str(p))
            if n and n != "." and n not in self.protected_paths:
                self.protected_paths.append(n)

    @staticmethod
    def load(path: str | None) -> "Config":
        if not path:
            return Config()
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        c = Config(
            levels=dict(d.get("levels", {})),
            allowed_sites={s.lower() for s in d.get("allowed_sites", [])},
            blocked_sites={s.lower() for s in d.get("blocked_sites", [])},
            known_recipients={normalize_recipient(s) for s in d.get("known_recipients", [])},
            tools=dict(d.get("tools", {})),
            max_calls_per_minute=int(d.get("max_calls_per_minute", 30)),
            tainted_egress=d.get("tainted_egress", DENY),
        )
        c.protect(*d.get("protected_paths", []))
        return c

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

    # 0. Agent Do/Don't's own files and the client's settings: never, whatever the settings say.
    target = protected_target(args, config.protected_paths, writes=tool.risk != NONE)
    if target:
        shown = target if len(target) <= 120 else target[:119] + "…"
        found.append(Decision(DENY, f"{shown} belongs to Agent Do/Don't or to your agent's own settings, "
                                    "which the agent may not read or change"))

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
                                      f"{read}, and {dest.value} {where} (to be asked instead, add it to "
                                      f"{'known_recipients' if dest.recipient else 'allowed_sites'} in your rules file)"))
            elif not allowed:
                found.append(Decision(ASK, f"the agent wants to send data to {dest.value}, which {where}"))

    if session.tainted and tool.risk != NONE and not any(read in d.rule for d in found):
        found.append(Decision(ASK, read))  # (said once: a destination rule above may already say it)

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
