"""Pairing a phone with the relay over Wi-Fi, without adb.

    python -m agentdodont relay --lan --pair     # shows a QR code + text; scan it with the phone

Protocol (TLS, relay certificate pinned by fingerprint):
  1. The relay shows: address, a one-time 8-digit code (5 minutes, 5 attempts), and the SHA-256
     fingerprint of its certificate, as a QR link  agentdodont://pair?a=<host:port>&c=<code>&f=<fingerprint>
  2. The phone connects to the address and accepts only a certificate with that fingerprint.
  3. Before revealing the code, the phone sends a random nonce; the relay must answer with
     HMAC(code, nonce + fingerprint), proving it knows the code (matters when the fingerprint was
     typed rather than scanned: a look-alike relay on the Wi-Fi can't produce it).
  4. The phone sends the code; the relay checks it and issues a device token. Only the token's
     SHA-256 is stored, so the relay's state file can't be used to impersonate the phone.
Devices can be listed and revoked:  relay --devices  /  relay --revoke <id>
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CODE_TTL_S = 300
MAX_ATTEMPTS = 5


def proof(code: str, nonce: str, fingerprint: str) -> str:
    """What the relay sends to show it knows the code (step 3)."""
    return hmac.new(code.encode(), (nonce + fingerprint.lower()).encode(), hashlib.sha256).hexdigest()


def pair_link(host_port: str, code: str, fingerprint: str) -> str:
    return f"agentdodont://pair?a={host_port}&c={code}&f={fingerprint}"


@dataclass
class PairingSession:
    """One pairing window: a code that works once, for a few minutes, with few attempts."""

    fingerprint: str
    code: str = field(default_factory=lambda: f"{secrets.randbelow(10**8):08d}")
    created: float = field(default_factory=time.time)
    attempts: int = 0
    used: bool = False

    def usable(self, now: float | None = None) -> str | None:
        """None if the code may still be tried, else why not."""
        now = time.time() if now is None else now
        if self.used:
            return "this pairing code was already used; start pairing again on the laptop"
        if now - self.created > CODE_TTL_S:
            return "this pairing code expired; start pairing again on the laptop"
        if self.attempts >= MAX_ATTEMPTS:
            return "too many wrong codes; start pairing again on the laptop"
        return None

    def check(self, code: str, now: float | None = None) -> str | None:
        """None if the code is right (and now spent), else why not."""
        why = self.usable(now)
        if why:
            return why
        self.attempts += 1
        if not hmac.compare_digest(code.encode(), self.code.encode()):
            return "wrong pairing code"
        self.used = True
        return None


class DeviceRegistry:
    """Paired phones. Stores token hashes only; every change is written to disk."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime = 0.0
        self.devices: list[dict] = []
        self._reload()

    def _reload(self) -> None:
        """Pick up changes made by another process (relay --revoke while the relay runs)."""
        try:
            m = self.path.stat().st_mtime
        except FileNotFoundError:
            self.devices, self._mtime = [], 0.0
            return
        if m != self._mtime:
            self.devices, self._mtime = json.loads(self.path.read_text()), m

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.devices, indent=1))
        tmp.replace(self.path)
        self._mtime = self.path.stat().st_mtime

    def add(self, name: str) -> tuple[str, str]:
        """Register a device; returns (device_id, token). The token is shown to the phone only once."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._reload()
            device_id = f"d{max([int(d['id'][1:]) for d in self.devices] + [0]) + 1}"
            self.devices.append({"id": device_id, "name": name[:60], "token_sha256": _h(token),
                                 "paired": _now(), "last_seen": None})
            self._save()
        return device_id, token

    def check(self, token: str) -> str | None:
        """The device id this token belongs to, or None."""
        if not token:
            return None
        h = _h(token)
        with self._lock:
            self._reload()
            for d in self.devices:
                if hmac.compare_digest(d["token_sha256"], h):
                    d["last_seen"] = _now()
                    self._save()
                    return d["id"]
        return None

    def revoke(self, device_id: str) -> bool:
        with self._lock:
            self._reload()
            before = len(self.devices)
            self.devices = [d for d in self.devices if d["id"] != device_id]
            if len(self.devices) != before:
                self._save()
                return True
        return False


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


# --- certificate, address, QR ----------------------------------------------------------------

def ensure_cert(state_dir: Path) -> tuple[Path, Path, str]:
    """Self-signed certificate for the LAN relay: (cert, key, sha256 fingerprint). Made once."""
    cert, key = state_dir / "relay_cert.pem", state_dir / "relay_key.pem"
    if not (cert.exists() and key.exists()):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        state_dir.mkdir(parents=True, exist_ok=True)
        k = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Agent Do/Don't relay")])
        now = dt.datetime.now(dt.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
             .not_valid_after(now + dt.timedelta(days=3650)).sign(k, hashes.SHA256()))
        key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return cert, key, cert_fingerprint(cert.read_text())


def cert_fingerprint(pem: str) -> str:
    import ssl

    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def lan_ip() -> str:
    """The laptop's address on the local network (the interface used to reach the internet)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET address: nothing is sent, it just picks the route
        ip = s.getsockname()[0]
    finally:
        s.close()
    if not ipaddress.ip_address(ip).is_private:
        raise RuntimeError(f"{ip} isn't a private (home network) address; refusing to expose the relay")
    return ip


def qr_ascii(text: str) -> str:
    import io

    import qrcode

    q = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    q.add_data(text)
    out = io.StringIO()
    q.print_ascii(out=out, invert=True)
    return out.getvalue()
