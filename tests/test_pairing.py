"""Pairing over Wi-Fi: one-time code, relay proof, device tokens (hash-only), revocation, TLS.
Offline; a fake upstream stands in for the API.  python -m unittest discover -s tests -v"""

import hashlib
import json
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from agentdodont.pairing import (CODE_TTL_S, MAX_ATTEMPTS, DeviceRegistry, PairingSession, cert_fingerprint,
                               ensure_cert, pair_link, proof)
from agentdodont.relay import Relay, make_tls_server

OK_BODY = {"model": "claude-opus-5-5", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}


def fake_upstream(url, headers, body):
    return 200, {"content-type": "application/json"}, json.dumps({"type": "message", "usage": {}}).encode()


class PairingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.devices = DeviceRegistry(self.dir / "devices.json")
        self.relay = Relay("real-key", "usb-token", state_dir=self.dir, send=fake_upstream, devices=self.devices)
        self.relay.pairing = PairingSession("ab" * 32)

    def tearDown(self):
        self._tmp.cleanup()

    def post(self, path, obj, token=None):
        h = {"content-type": "application/json"}
        if token:
            h["authorization"] = f"Bearer {token}"
        s, _, b = self.relay.handle("POST", path, h, json.dumps(obj).encode())
        return s, json.loads(b)

    def test_full_pairing_flow(self):
        code = self.relay.pairing.code
        nonce = "n" * 32
        s, out = self.post("/pair/hello", {"nonce": nonce})
        self.assertEqual(s, 200)
        self.assertEqual(out["proof"], proof(code, nonce, "ab" * 32))  # relay proves it knows the code
        s, out = self.post("/pair/complete", {"code": code, "name": "SM-S901E"})
        self.assertEqual(s, 200)
        token = out["token"]
        self.assertEqual(self.post("/v1/messages", OK_BODY, token)[0], 200)  # the new token works
        self.assertEqual(self.post("/pair/complete", {"code": code})[0], 410)  # code is single-use
        stored = (self.dir / "devices.json").read_text()
        self.assertNotIn(token, stored)
        self.assertIn(hashlib.sha256(token.encode()).hexdigest(), stored)

    def test_wrong_codes_burn_the_session(self):
        for _ in range(MAX_ATTEMPTS):
            self.assertEqual(self.post("/pair/complete", {"code": "00000000"})[0], 403)
        s, out = self.post("/pair/complete", {"code": self.relay.pairing.code})
        self.assertEqual(s, 410)
        self.assertIn("too many", out["error"]["message"])
        self.assertEqual(self.devices.devices, [])

    def test_code_expires(self):
        sess = PairingSession("ff")
        self.assertIsNone(sess.usable(now=sess.created + CODE_TTL_S - 1))
        self.assertIn("expired", sess.usable(now=sess.created + CODE_TTL_S + 1))

    def test_no_pairing_without_an_open_session(self):
        self.relay.pairing = None
        self.assertEqual(self.post("/pair/hello", {"nonce": "n" * 32})[0], 404)

    def test_revoked_device_is_refused_and_usb_token_still_works(self):
        device_id, token = self.devices.add("phone")
        self.assertEqual(self.post("/v1/messages", OK_BODY, token)[0], 200)
        self.assertTrue(self.devices.revoke(device_id))
        self.assertEqual(self.post("/v1/messages", OK_BODY, token)[0], 401)
        self.assertEqual(self.post("/v1/messages", OK_BODY, "usb-token")[0], 200)
        self.assertEqual(self.post("/v1/messages", OK_BODY, "")[0], 401)

    def test_revoke_from_another_process_takes_effect_in_the_running_relay(self):
        device_id, token = self.devices.add("phone")
        self.assertEqual(self.post("/v1/messages", OK_BODY, token)[0], 200)
        import os, time as _t
        _t.sleep(0.02)
        DeviceRegistry(self.dir / "devices.json").revoke(device_id)  # what `relay --revoke` does
        os.utime(self.dir / "devices.json")  # make sure the mtime moves on coarse clocks
        self.assertEqual(self.post("/v1/messages", OK_BODY, token)[0], 401)

    def test_link_format(self):
        self.assertEqual(pair_link("192.168.1.20:8788", "01234567", "ab"), "agentdodont://pair?a=192.168.1.20:8788&c=01234567&f=ab")

    def test_tls_server_presents_the_pinned_certificate(self):
        cert, key, fp = ensure_cert(self.dir / "state")
        self.assertEqual(fp, cert_fingerprint(cert.read_text()))
        self.assertEqual(ensure_cert(self.dir / "state")[2], fp)  # made once, then reused
        server = make_tls_server(self.relay, "127.0.0.1", 0, cert, key)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # the phone pins by fingerprint instead of a CA
            with socket.create_connection(("127.0.0.1", server.server_address[1])) as raw:
                with ctx.wrap_socket(raw) as tls:
                    self.assertEqual(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest(), fp)
                    tls.sendall(b"GET /health HTTP/1.0\r\n\r\n")
                    data = b""
                    while chunk := tls.recv(4096):
                        data += chunk
                    self.assertIn(b'{"ok":true}', data)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
