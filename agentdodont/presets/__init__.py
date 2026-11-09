"""Ready-made descriptions of popular MCP servers' tools.

A preset corrects what a server's annotations get wrong or leave out (for example, that a tool's
output can carry an injection). It only describes tools: what's allowed stays in your rules file,
which wins over a preset field by field. Each preset names the server version it was checked
against; tools it doesn't list fall back to the server's annotations, read the cautious way.
"""
from __future__ import annotations

import json
from importlib import resources


def names() -> list[str]:
    return sorted(p.name[:-5] for p in resources.files(__name__).iterdir() if p.name.endswith(".json"))


def load(name: str) -> dict:
    if name not in names():
        raise ValueError(f"no preset named {name!r} (available: {', '.join(names()) or 'none'})")
    return json.loads(resources.files(__name__).joinpath(f"{name}.json").read_text(encoding="utf-8"))


def detect(server_cmd: list[str]) -> str | None:
    """The preset for this server command, if one matches a known package or program name."""
    joined = " ".join(server_cmd).replace("\\", "/").lower()
    for name in names():
        if any(m.lower() in joined for m in load(name).get("match", [])):
            return name
    return None


def merge_tools(preset: dict, user: dict) -> dict:
    """Per tool, the user's fields win over the preset's."""
    out = {k: dict(v) for k, v in (preset.get("tools") or {}).items()}
    for k, v in (user or {}).items():
        out[k] = {**out.get(k, {}), **v}
    return out
