"""Append-only audit log: one JSONL file per session, plus optional screen/screenshot captures."""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path


class AuditLog:
    def __init__(self, root: str | Path = "logs", save_screens: bool = False):
        self.dir = Path(root) / datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "actions.jsonl"
        self.save_screens = save_screens
        self._f = self.path.open("a", encoding="utf-8")

    def event(self, kind: str, **data) -> None:
        rec = {"t": round(time.time(), 3), "kind": kind, **data}
        self._f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._f.flush()

    def save_screen(self, step: int, xml: str, rendered: str) -> None:
        if self.save_screens:
            (self.dir / f"step{step:03d}.xml").write_text(xml, encoding="utf-8")
            (self.dir / f"step{step:03d}.txt").write_text(rendered, encoding="utf-8")

    def save_png(self, step: int, png: bytes) -> Path:
        p = self.dir / f"step{step:03d}.png"
        p.write_bytes(png)
        return p

    def close(self) -> None:
        self._f.close()


def show(session_dir: str | Path) -> str:
    """Render a session log as a 'why did you do that?' trace."""
    path = Path(session_dir)
    if path.is_dir():
        path = path / "actions.jsonl"
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        k = r["kind"]
        if k == "session_start":
            out.append(f"TASK: {r['task']}   (model {r['model']}, device {r.get('device')})")
        elif k == "proposal":
            out.append(f"\n#{r['step']} {r['action']} {json.dumps(r['args'], ensure_ascii=False)}")
            if r.get("target"):
                out.append(f"    target: {r['target']}")
            out.append(f"    why (model): {r.get('reason') or '-'}")
        elif k == "decision":
            out.append(f"    policy: {r['verdict'].upper()} [{r['category']}] {r['rule']}")
        elif k == "confirmation":
            out.append(f"    user: {'approved' if r['approved'] else 'declined'}" + (f" — {r['note']}" if r.get("note") else ""))
        elif k == "result":
            out.append(f"    result: {r['outcome']}")
        elif k == "ask_user":
            out.append(f"\n#{r['step']} asked user: {r['question']!r} -> {r['answer']!r}")
        elif k == "done":
            out.append(f"\nDONE ({'success' if r.get('success') else 'not completed'}): {r['summary']}")
        elif k == "stop":
            out.append(f"\nSTOPPED: {r['reason']}")
        elif k == "usage_total":
            out.append(f"\ntokens: input {r['input']} + cache read {r['cache_read']} + cache write "
                       f"{r['cache_write']}, output {r['output']}")
    return "\n".join(out)
