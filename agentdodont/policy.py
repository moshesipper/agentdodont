"""Policy engine: sits between the model and every device action.

"The model proposes; the policy engine decides." Decisions are made from ground truth — the
element actually under the tap in the latest UI dump, the foreground package, the literal text to
be typed — never from the model's own description of what it is doing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .ui import Node, Screen

AUTO, ASK, DENY = "auto", "ask", "deny"
MAX_CONTROL_LABEL = 40  # longer label fragments are treated as content, not as the control's name
_FRAGMENT_SPLIT = re.compile(r"\s*\|\s*|,\s+|\n")
_RANK = {AUTO: 0, ASK: 1, DENY: 2}


@dataclass
class Action:
    name: str  # tap | long_press | type_text | scroll | back | home | open_app | wait
    args: dict
    target: Node | None = None  # resolved element (tap / type / scroll)
    point: tuple[int, int] | None = None
    package: str | None = None  # for open_app


@dataclass
class Decision:
    verdict: str  # auto | ask | deny
    category: str
    rule: str  # which rule fired, human-readable (shown to user + logged)


DEFAULT_CONFIG: dict = {
    # Autonomy level per category: auto (do and report) | ask (ask first) | deny.
    "levels": {
        "navigate": AUTO,  # back, home, scroll, wait
        "open_app": AUTO,
        "tap": AUTO,
        "type": AUTO,
        "tap_unverified": ASK,  # tap target has no label we can check
        "irreversible": ASK,  # send / pay / delete / install ...
        "sensitive_app": ASK,  # any action inside payment / banking apps
        "credentials": ASK,  # typing into password fields
        "sensitive_data": ASK,  # typing something that looks like a card number
        "submit_message": ASK,  # pressing Enter in a messaging / mail app
        "core_surface": DENY,  # factory reset, emergency, USB debugging, ...
    },
    "irreversible_words": [
        "send", "pay", "buy", "purchase", "order", "checkout", "check out", "delete", "remove",
        "uninstall", "install", "erase", "transfer", "subscribe", "unsubscribe", "post", "publish",
        "share", "call", "dial", "accept", "agree", "submit", "sign out", "log out", "logout",
        "format", "discard", "clear data", "clear storage", "clear cache", "block", "report",
        "forward", "confirm", "donate", "book", "reserve", "move to trash", "empty trash",
    ],
    "core_surface_words": [
        "factory data reset", "factory reset", "reset phone", "erase all", "emergency call",
        "emergency sos", "emergency", "usb debugging", "developer options", "find my mobile",
        "lock phone", "power off", "restart",
    ],
    "sensitive_packages": [
        "com.samsung.android.spay", "com.google.android.apps.walletnfcrel", "com.paypal",
        "*bank*", "*wallet*", "*pay*", "com.android.vending",
    ],
    "messaging_packages": [
        "com.samsung.android.messaging", "com.google.android.apps.messaging", "com.whatsapp",
        "org.telegram.messenger", "com.google.android.gm", "com.samsung.android.email.provider",
        "com.facebook.orca", "org.thoughtcrime.securesms",
    ],
}


def _words_regex(words: list[str]) -> re.Pattern:
    alts = sorted((re.escape(w).replace(r"\ ", r"[\s_\-]+") for w in words), key=len, reverse=True)
    return re.compile(r"(?<![a-z])(" + "|".join(alts) + r")(?![a-z])", re.IGNORECASE)


def _pkg_match(pkg: str, patterns: list[str]) -> bool:
    for p in patterns:
        if "*" in p:
            if re.fullmatch(p.replace(".", r"\.").replace("*", ".*"), pkg):
                return True
        elif pkg == p or pkg.startswith(p + "."):
            return True
    return False


def control_name(t: Node) -> str:
    """The text keyword rules may look at: resource id, hint, and the *first* fragment of the label
    (a button's text, a settings row's title, an inbox row's sender). The rest of a label is
    content (subjects, message previews, article text), often attacker-controlled, and must never
    steer the policy. A first fragment longer than MAX_CONTROL_LABEL is treated as content too."""
    head = _FRAGMENT_SPLIT.split(t.label.strip(), maxsplit=1)[0].strip() if t.label else ""
    parts = [t.short_id.replace("_", " "), t.hint]
    if len(head) <= MAX_CONTROL_LABEL:
        parts.append(head)
    return " ".join(p for p in parts if p)


_CARD = re.compile(r"(?:\d[ -]?){13,19}")


@dataclass
class Policy:
    config: dict = field(default_factory=lambda: json.loads(json.dumps(DEFAULT_CONFIG)))
    ask_all: bool = False

    def __post_init__(self) -> None:
        self._irrev = _words_regex(self.config["irreversible_words"])
        self._core = _words_regex(self.config["core_surface_words"])

    @classmethod
    def load(cls, path: str | None, ask_all: bool = False) -> "Policy":
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        if path:
            user = json.loads(Path(path).read_text(encoding="utf-8"))
            cfg["levels"].update(user.pop("levels", {}))
            cfg.update(user)
        return cls(config=cfg, ask_all=ask_all)

    # ------------------------------------------------------------------------
    def check(self, action: Action, screen: Screen) -> Decision:
        """Evaluate every applicable rule and return the strictest outcome."""
        found: list[tuple[str, str]] = []  # (category, rule)
        a = action
        pkg = screen.package

        target_text = ""
        if a.target is not None:
            t = a.target
            target_text = control_name(t)

        # Base category by action type
        if a.name in ("back", "home", "scroll", "wait"):
            found.append(("navigate", f"{a.name} is navigation"))
        elif a.name == "open_app":
            found.append(("open_app", f"open {a.package}"))
        elif a.name in ("tap", "long_press"):
            found.append(("tap", "tap"))
            if a.target is None or not (a.target.label or a.target.short_id):
                found.append(("tap_unverified", "tap target has no label or id the policy can check"))
        elif a.name == "type_text":
            found.append(("type", "type text"))

        # Target-content rules (what the tap would really hit)
        if target_text and a.name in ("tap", "long_press", "type_text"):
            if m := self._core.search(target_text):
                found.append(("core_surface", f'target "{target_text[:60]}" matches protected surface "{m.group(0)}"'))
            if a.name != "type_text" and (m := self._irrev.search(target_text)):
                found.append(("irreversible", f'target "{target_text[:60]}" matches "{m.group(0)}"'))

        # App context
        app = a.package if a.name == "open_app" else pkg
        if app and _pkg_match(app, self.config["sensitive_packages"]) and a.name not in ("back", "home", "wait"):
            found.append(("sensitive_app", f"{app} is a sensitive (payment/store) app"))

        # Typing rules
        if a.name == "type_text":
            text = a.args.get("text", "")
            if a.target is not None and a.target.password:
                found.append(("credentials", "target is a password field"))
            if _CARD.search(text):
                found.append(("sensitive_data", "text looks like a card/account number"))
            if a.args.get("submit") and _pkg_match(pkg, self.config["messaging_packages"]):
                found.append(("submit_message", f"pressing Enter in {pkg} may send a message"))

        levels = self.config["levels"]
        best = Decision(AUTO, "none", "no rule")
        for cat, rule in found:
            v = levels.get(cat, ASK)
            if _RANK[v] > _RANK[best.verdict] or best.category == "none":
                best = Decision(v, cat, rule)
        if self.ask_all and best.verdict == AUTO and a.name != "wait":
            best = Decision(ASK, best.category, best.rule + " (ask-all mode)")
        return best
