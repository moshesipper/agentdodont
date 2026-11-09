"""Taint shared by every proxy that serves the same agent session.

An MCP client starts one proxy per server, so without this, content read through one server
(say, a fetched web page) wouldn't count when the agent calls another (say, email). Proxies
started by the same client process share one session file:

    ~/.agentdodont/sessions/client-<pid>-<start>.jsonl

The client is found by walking up from the proxy past launchers (cmd, sh, uvx, python shims...)
to the first other process: Claude Code, Claude Desktop, or your own agent. Its start time is
part of the name, so a later process that reuses the PID never inherits an old session. You can
also name a session yourself (--session), or turn sharing off (--session none).

The file only ever grows: one line per untrusted source. Taint never goes away during a
session, so there is nothing to merge or lock; a proxy reads the file before every decision and
appends when one of its tools brings in untrusted content. Each proxy also keeps what it knows
in memory, so deleting the file can't make a proxy forget its own taint.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Processes between the client and the proxy that aren't the client itself. "agentdodont" is the
# proxy's own launcher: on Windows, pip and uvx install it as agentdodont.exe, which starts Python.
_LAUNCHERS = re.compile(r"^(cmd|conhost|powershell|pwsh|sh|bash|zsh|dash|fish|ksh|env|nohup|sudo|uv|uvx|"
                        r"pipx|py|pyw|python[\d.]*w?|pythonw|agentdodont)$")


def _proc_windows(pid: int):
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return None
    found = None
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(wintypes.HANDLE(snap), ctypes.byref(e))
        while ok:
            if e.th32ProcessID == pid:
                found = (e.th32ParentProcessID, e.szExeFile)
                break
            ok = k32.Process32NextW(wintypes.HANDLE(snap), ctypes.byref(e))
    finally:
        k32.CloseHandle(wintypes.HANDLE(snap))
    if found is None:
        return None
    start = ""
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if h:
        try:
            t = [wintypes.FILETIME() for _ in range(4)]
            if k32.GetProcessTimes(wintypes.HANDLE(h), *(ctypes.byref(x) for x in t)):
                start = str((t[0].dwHighDateTime << 32) | t[0].dwLowDateTime)
        finally:
            k32.CloseHandle(wintypes.HANDLE(h))
    return found[0], found[1], start


def _proc_linux(pid: int):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    name = stat[stat.index("(") + 1:stat.rindex(")")]
    fields = stat[stat.rindex(")") + 2:].split()
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()[:8]
    except OSError:
        boot = ""
    return int(fields[1]), name, f"{boot}{fields[19]}"


def _proc_ps(pid: int):
    try:
        out = subprocess.run(["ps", "-o", "ppid=", "-o", "lstart=", "-o", "comm=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return None
    if len(out) < 7:
        return None
    return int(out[0]), os.path.basename(" ".join(out[6:])), re.sub(r"\W", "", "".join(out[1:6]))


def append_line(path, line: str) -> None:
    """Append one line so that other processes appending to the same file can't overwrite it.

    Several proxies write to the same audit log and session file. Python's append mode isn't
    safe for that on Windows: it seeks to the end, then writes, so two processes can write to the
    same spot and a line is lost. Here every line is a single write that the OS itself puts at
    the end: a file opened with append-only access on Windows, O_APPEND elsewhere."""
    data = (line + "\n").encode("utf-8")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD,
                                  ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        # FILE_APPEND_DATA only (no FILE_WRITE_DATA); share read/write/delete; OPEN_ALWAYS
        h = k32.CreateFileW(str(path), 0x0004, 0x7, None, 4, 0x80, None)
        if h is None or h == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            done = wintypes.DWORD()
            if not k32.WriteFile(h, data, len(data), ctypes.byref(done), None) or done.value != len(data):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            k32.CloseHandle(h)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


def proc_info(pid: int):
    """(parent pid, executable name, start token) of a running process, or None if there isn't one.
    The start token is "" when the process exists but its start time can't be read."""
    try:
        if os.name == "nt":
            return _proc_windows(pid)
        if sys.platform.startswith("linux"):
            return _proc_linux(pid)
        return _proc_ps(pid)
    except Exception:  # never let process inspection break the proxy; sharing just turns off
        return None


def find_client(start_pid: int | None = None) -> tuple[int, str, str] | None:
    """The agent process this proxy serves: (pid, name, start token), or None if it can't be found."""
    pid = os.getppid() if start_pid is None else start_pid
    for _ in range(8):
        if pid <= 1:
            return None
        info = proc_info(pid)
        if info is None:
            return None
        parent, name, start = info
        base = name.lower().rsplit("/", 1)[-1]
        base = base[:-4] if base.endswith(".exe") else base
        if not _LAUNCHERS.match(base):
            return (pid, name, start) if start else None
        pid = parent
    return None


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:80] or "session"


class SharedTaint:
    """The session file. path None = not shared (this proxy keeps its own taint only)."""

    def __init__(self, path: Path | None, label: str = ""):
        self.path = path
        self.label = label  # who the session belongs to, for the audit log
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def open(state_dir: Path, session: str | None) -> "SharedTaint":
        """session: None = find the client automatically; "none" = don't share; else a name."""
        if session == "none":
            return SharedTaint(None, "not shared")
        if session:
            return SharedTaint(state_dir / f"named-{_safe(session)}.jsonl", f"named session {session}")
        client = find_client()
        if client is None:
            return SharedTaint(None, "not shared (the client process couldn't be identified)")
        pid, name, start = client
        SharedTaint.clean(state_dir)
        return SharedTaint(state_dir / f"client-{pid}-{_safe(start)}.jsonl", f"{name} (pid {pid})")

    @staticmethod
    def clean(state_dir: Path) -> None:
        """Remove files of clients that have exited (or whose PID now belongs to another process)."""
        if not state_dir.is_dir():
            return
        for f in state_dir.glob("client-*.jsonl"):
            m = re.match(r"client-(\d+)-(.+)\.jsonl$", f.name)
            if not m:
                continue
            info = proc_info(int(m.group(1)))
            if info is None or (info[2] and _safe(info[2]) != m.group(2)):
                try:
                    f.unlink()
                except OSError:
                    pass

    def sources(self) -> list[str]:
        if not self.path:
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                src = json.loads(line).get("source")
            except (ValueError, AttributeError):
                continue  # a half-written line from another proxy: the next read gets it whole
            if isinstance(src, str) and src not in out:
                out.append(src)
        return out

    def add(self, source: str, server: str) -> None:
        if not self.path:
            return
        line = json.dumps({"t": round(time.time(), 3), "server": server, "source": source}, ensure_ascii=False)
        append_line(self.path, line)
