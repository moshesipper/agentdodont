"""Parse `uiautomator dump` XML into a compact, numbered element list for the model."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
MAX_LABEL = 80


def _b(v: str | None) -> bool:
    return v == "true"


@dataclass
class Node:
    text: str
    desc: str
    hint: str
    res_id: str
    cls: str
    package: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    long_clickable: bool
    scrollable: bool
    checkable: bool
    checked: bool
    enabled: bool
    focused: bool
    selected: bool
    password: bool
    parent: "Node | None" = None
    children: list["Node"] = field(default_factory=list)
    derived: str = ""  # label gathered from descendants for unlabeled containers
    idx: int | None = None  # id shown to the model (None = not listed)

    @property
    def editable(self) -> bool:
        return "EditText" in self.cls or "AutoCompleteTextView" in self.cls

    @property
    def interactive(self) -> bool:
        return self.clickable or self.long_clickable or self.scrollable or self.checkable or self.editable

    @property
    def own_label(self) -> str:
        return self.text or self.desc

    @property
    def label(self) -> str:
        return self.own_label or self.derived

    @property
    def area(self) -> int:
        x1, y1, x2, y2 = self.bounds
        return max(0, x2 - x1) * max(0, y2 - y1)

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    @property
    def short_id(self) -> str:
        return self.res_id.split("/", 1)[-1] if self.res_id else ""

    def contains(self, x: int, y: int) -> bool:
        x1, y1, x2, y2 = self.bounds
        return x1 <= x < x2 and y1 <= y < y2

    def describe(self) -> str:
        """Human-readable target description (used in confirmations and the log)."""
        parts = [self.cls.rsplit(".", 1)[-1] or "View"]
        if self.label:
            parts.append(f'"{_clip(self.label)}"')
        if self.short_id:
            parts.append(f"id={self.short_id}")
        return " ".join(parts)


def _clip(s: str, n: int = MAX_LABEL) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


@dataclass
class Screen:
    nodes: list[Node]  # every node (for hit-testing)
    elements: list[Node]  # listed nodes, elements[i].idx == i
    package: str
    width: int
    height: int

    def element(self, idx: int) -> Node | None:
        return self.elements[idx] if 0 <= idx < len(self.elements) else None

    def hit_test(self, x: int, y: int) -> Node | None:
        """The node a tap at (x, y) would most likely land on: smallest containing node,
        preferring interactive ones."""
        hits = [n for n in self.nodes if n.area > 0 and n.contains(x, y)]
        if not hits:
            return None
        interactive = [n for n in hits if n.interactive]
        return min(interactive or hits, key=lambda n: n.area)

    def render(self) -> str:
        lines = [f"Foreground app: {self.package or 'unknown'}   Screen: {self.width}x{self.height} px"]
        if not self.elements:
            lines.append("(no UI elements reported — try screenshot)")
        for n in self.elements:
            cx, cy = n.center
            line = f"[{n.idx}] {n.cls.rsplit('.', 1)[-1]}"
            if n.label:
                line += f' "{_clip(n.label)}"'
            elif n.hint:
                line += f' hint="{_clip(n.hint)}"'
            if n.short_id:
                line += f" id={n.short_id}"
            line += f" ({cx},{cy})"
            flags = []
            if n.editable:
                flags.append("editable")
            elif n.clickable:
                flags.append("clickable")
            if n.scrollable:
                flags.append("scrollable")
            if n.checkable:
                flags.append("checked" if n.checked else "unchecked")
            if n.selected:
                flags.append("selected")
            if n.focused:
                flags.append("focused")
            if n.password:
                flags.append("password")
            if not n.enabled:
                flags.append("disabled")
            if flags:
                line += " " + " ".join(flags)
            lines.append(line)
        return "\n".join(lines)

    def fingerprint(self) -> str:
        return hashlib.sha1(self.render().encode()).hexdigest()[:12]


def parse(xml: str, size: tuple[int, int] | None = None) -> Screen:
    start = xml.find("<hierarchy")
    end = xml.rfind("</hierarchy>")
    if start < 0 or end < 0:
        raise ValueError("no <hierarchy> in UI dump")
    root = ET.fromstring(xml[start : end + len("</hierarchy>")])

    nodes: list[Node] = []

    def build(el: ET.Element, parent: Node | None) -> None:
        for child in el:
            if child.tag != "node":
                continue
            a = child.attrib
            m = _BOUNDS.match(a.get("bounds", ""))
            bounds = tuple(int(v) for v in m.groups()) if m else (0, 0, 0, 0)
            n = Node(
                text=(a.get("text") or "").strip(),
                desc=(a.get("content-desc") or "").strip(),
                hint=(a.get("hint") or "").strip(),
                res_id=a.get("resource-id", ""),
                cls=a.get("class", ""),
                package=a.get("package", ""),
                bounds=bounds,  # type: ignore[arg-type]
                clickable=_b(a.get("clickable")),
                long_clickable=_b(a.get("long-clickable")),
                scrollable=_b(a.get("scrollable")),
                checkable=_b(a.get("checkable")),
                checked=_b(a.get("checked")),
                enabled=a.get("enabled", "true") == "true",
                focused=_b(a.get("focused")),
                selected=_b(a.get("selected")),
                password=_b(a.get("password")),
                parent=parent,
            )
            if a.get("visible-to-user") == "false":
                n.bounds = (0, 0, 0, 0)
            nodes.append(n)
            if parent:
                parent.children.append(n)
            build(child, n)

    build(root, None)

    def descendant_labels(n: Node, acc: list[str]) -> None:
        for c in n.children:
            if len(acc) >= 3:
                return
            if c.own_label:
                acc.append(c.own_label)
            else:
                descendant_labels(c, acc)

    for n in nodes:
        if n.interactive and not n.scrollable and not n.own_label:
            acc: list[str] = []
            descendant_labels(n, acc)
            n.derived = " | ".join(acc)

    def covered_by_ancestor(n: Node) -> bool:
        p = n.parent
        while p:
            if p.interactive and not p.own_label and p.derived and n.own_label in p.derived:
                return True
            p = p.parent
        return False

    elements: list[Node] = []
    for n in nodes:
        if n.area == 0:
            continue
        if n.interactive or (n.own_label and not covered_by_ancestor(n)):
            n.idx = len(elements)
            elements.append(n)

    package = next((n.package for n in nodes if n.package), "")
    if size is None:
        size = (max((n.bounds[2] for n in nodes), default=0), max((n.bounds[3] for n in nodes), default=0))
    return Screen(nodes=nodes, elements=elements, package=package, width=size[0], height=size[1])
