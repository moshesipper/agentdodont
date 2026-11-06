"""Thin wrapper around the adb binary: observe the screen and inject input."""

from __future__ import annotations

import re
import shutil
import subprocess
import time

# Common app names -> candidate packages (Samsung first, then AOSP/Google).
APP_ALIASES: dict[str, list[str]] = {
    "settings": ["com.android.settings"],
    "chrome": ["com.android.chrome"],
    "browser": ["com.sec.android.app.sbrowser", "com.android.chrome"],
    "internet": ["com.sec.android.app.sbrowser"],
    "messages": ["com.samsung.android.messaging", "com.google.android.apps.messaging"],
    "sms": ["com.samsung.android.messaging", "com.google.android.apps.messaging"],
    "phone": ["com.samsung.android.dialer", "com.google.android.dialer"],
    "dialer": ["com.samsung.android.dialer", "com.google.android.dialer"],
    "contacts": ["com.samsung.android.app.contacts", "com.google.android.contacts"],
    "camera": ["com.sec.android.app.camera"],
    "gallery": ["com.sec.android.gallery3d", "com.google.android.apps.photos"],
    "photos": ["com.google.android.apps.photos", "com.sec.android.gallery3d"],
    "clock": ["com.sec.android.app.clockpackage", "com.google.android.deskclock"],
    "alarm": ["com.sec.android.app.clockpackage", "com.google.android.deskclock"],
    "calendar": ["com.samsung.android.calendar", "com.google.android.calendar"],
    "calculator": ["com.sec.android.app.popupcalculator", "com.google.android.calculator"],
    "notes": ["com.samsung.android.app.notes", "com.google.android.keep"],
    "my files": ["com.sec.android.app.myfiles"],
    "files": ["com.sec.android.app.myfiles", "com.google.android.apps.nbu.files"],
    "play store": ["com.android.vending"],
    "gmail": ["com.google.android.gm"],
    "email": ["com.samsung.android.email.provider", "com.google.android.gm"],
    "maps": ["com.google.android.apps.maps"],
    "youtube": ["com.google.android.youtube"],
    "google": ["com.google.android.googlequicksearchbox"],
}

# Characters the device shell would interpret inside `input text`.
_SHELL_SPECIAL = set("\\'\"`$&|;<>()*~#!?[]{}^")


class AdbError(RuntimeError):
    pass


def escape_input_text(text: str) -> str:
    """Escape text for `adb shell input text`. Only printable ASCII is supported."""
    out = []
    for ch in text:
        if ord(ch) > 126 or (ord(ch) < 32):
            raise AdbError(
                f"`input text` cannot type {ch!r}; only printable ASCII on one line is supported "
                "(install ADBKeyboard for Unicode — a later improvement)."
            )
        if ch == " ":
            out.append("%s")
        elif ch in _SHELL_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def resolve_app(name: str, installed: list[str]) -> tuple[str | None, list[str]]:
    """Map a human app name to an installed package. Returns (package, candidates)."""
    key = name.strip().lower()
    if key in installed:  # already a package name
        return key, []
    for pkg in APP_ALIASES.get(key, []):
        if pkg in installed:
            return pkg, []
    tokens = [t for t in re.split(r"[^a-z0-9]+", key) if t]
    if not tokens:
        return None, []
    hits = [p for p in installed if all(t in p.lower() for t in tokens)]
    if len(hits) == 1:
        return hits[0], []
    return None, sorted(hits)[:15]


class Device:
    def __init__(self, serial: str | None = None, adb_path: str | None = None):
        self.adb = adb_path or shutil.which("adb") or "adb"
        self.serial = serial
        self._size: tuple[int, int] | None = None
        self._packages: list[str] | None = None

    # --- plumbing -----------------------------------------------------------
    def _cmd(self, *args: str) -> list[str]:
        base = [self.adb]
        if self.serial:
            base += ["-s", self.serial]
        return base + list(args)

    def run(self, *args: str, timeout: float = 30, binary: bool = False):
        try:
            proc = subprocess.run(self._cmd(*args), capture_output=True, timeout=timeout)
        except FileNotFoundError as e:
            raise AdbError(f"adb not found at {self.adb!r}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb {' '.join(args)} timed out") from e
        if proc.returncode != 0:
            err = proc.stderr.decode(errors="replace").strip() or proc.stdout.decode(errors="replace").strip()
            raise AdbError(f"adb {' '.join(args)} failed: {err}")
        return proc.stdout if binary else proc.stdout.decode(errors="replace")

    def shell(self, command: str, timeout: float = 30) -> str:
        return self.run("shell", command, timeout=timeout)

    # --- info ---------------------------------------------------------------
    def list_devices(self) -> list[tuple[str, str]]:
        out = self.run("devices")
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                rows.append((parts[0], parts[1]))
        return rows

    def getprop(self, name: str) -> str:
        return self.shell(f"getprop {name}").strip()

    def screen_size(self) -> tuple[int, int]:
        if self._size is None:
            out = self.shell("wm size")
            # "Physical size: 1080x2340" possibly followed by "Override size: ..."
            matches = re.findall(r"(\d+)x(\d+)", out)
            if not matches:
                raise AdbError(f"cannot parse screen size from {out!r}")
            w, h = matches[-1]
            self._size = (int(w), int(h))
        return self._size

    def packages(self, refresh: bool = False) -> list[str]:
        if self._packages is None or refresh:
            out = self.shell("pm list packages")
            self._packages = [l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:")]
        return self._packages

    # --- observe ------------------------------------------------------------
    def dump_ui(self, retries: int = 3) -> str:
        last = ""
        for attempt in range(retries):
            out = self.shell("uiautomator dump /sdcard/aos_dump.xml", timeout=30)
            if "dumped to" in out:
                xml = self.run("exec-out", "cat /sdcard/aos_dump.xml")
                if "<hierarchy" in xml:
                    return xml
            last = out.strip()
            time.sleep(0.7 * (attempt + 1))  # usually "could not get idle state" during animations
        raise AdbError(f"uiautomator dump failed: {last}")

    def screencap(self) -> bytes:
        data = self.run("exec-out", "screencap -p", binary=True, timeout=30)
        if not data.startswith(b"\x89PNG"):
            raise AdbError("screencap did not return a PNG")
        return data

    # --- act ----------------------------------------------------------------
    def tap(self, x: int, y: int) -> None:
        self.shell(f"input tap {int(x)} {int(y)}")

    def long_press(self, x: int, y: int, ms: int = 800) -> None:
        self.shell(f"input swipe {int(x)} {int(y)} {int(x)} {int(y)} {ms}")

    def swipe(self, x1: int, y1: int, x2: int, y2: int, ms: int = 350) -> None:
        self.shell(f"input swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {ms}")

    def keyevent(self, code: int | str) -> None:
        self.shell(f"input keyevent {code}")

    def type_text(self, text: str) -> None:
        if text:
            self.shell(f"input text {escape_input_text(text)}")

    def clear_field(self) -> None:
        # Ctrl+A then Delete (Android 13+ supports keycombination); fall back to many DELs.
        try:
            self.shell("input keycombination 113 29")
            self.keyevent(67)
        except AdbError:
            self.keyevent("KEYCODE_MOVE_END")
            self.shell("input keyevent " + " ".join(["67"] * 60))

    def launch(self, package: str) -> None:
        out = self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
        if "No activities found" in out or "aborted" in out.lower():
            raise AdbError(f"could not launch {package}: {out.strip()}")
