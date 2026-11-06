"""Relay tests: the gatekeeping that makes a leaked phone token low-value. A fake upstream stands in
for the Anthropic API, so nothing here spends money.  python -m unittest discover -s tests -v"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from agentdodont.relay import Relay, ensure_token, make_server, provision_token, read_properties

TOKEN = "phone-token"
OK_BODY = {"model": "claude-opus-5-5", "max_tokens": 1000, "messages": [{"role": "user", "content": "hi"}]}


class FakeUpstream:
    def __init__(self, status=200, usage=None):
        self.calls = []
        self.status = status
        self.usage = usage or {"input_tokens": 1_000_000, "output_tokens": 0}  # $4 on Opus 5.5

    def __call__(self, url, headers, body):
        self.calls.append((url, headers, body))
        return self.status, {"content-type": "application/json", "request-id": "req_1", "x-secret": "no"}, \
            json.dumps({"type": "message", "usage": self.usage}).encode()


class RelayTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def make(self, status=200, usage=None, **kw):
        up = FakeUpstream(status, usage)
        return Relay("real-key", TOKEN, state_dir=self.dir, send=up, **kw), up

    @staticmethod
    def call(relay, body=OK_BODY, token=TOKEN, method="POST", path="/v1/messages", now=None, extra=None):
        headers = {"X-Api-Key": token, "Content-Type": "application/json", "anthropic-version": "2023-06-01",
                   "User-Agent": "phone", **(extra or {})}
        status, h, out = relay.handle(method, path, headers, json.dumps(body).encode(), now=now)
        return status, h, json.loads(out)

    def test_forwards_with_real_key_and_only_allowed_headers(self):
        relay, up = self.make()
        status, headers, out = self.call(relay, extra={"anthropic-beta": "x"})
        self.assertEqual((status, out["type"]), (200, "message"))
        url, fwd, _ = up.calls[0]
        self.assertEqual(url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(fwd, {"anthropic-version": "2023-06-01", "anthropic-beta": "x",
                               "content-type": "application/json", "x-api-key": "real-key"})
        self.assertNotIn("x-secret", headers)
        self.assertEqual(headers["request-id"], "req_1")

    def test_accepts_bearer_token_like_the_java_sdk_and_never_forwards_it(self):
        relay, up = self.make()
        headers = {"Authorization": f"Bearer {TOKEN}", "content-type": "application/json"}
        status, _, _ = relay.handle("POST", "/v1/messages", headers, json.dumps(OK_BODY).encode())
        self.assertEqual(status, 200)
        self.assertNotIn("authorization", up.calls[0][1])
        self.assertEqual(up.calls[0][1]["x-api-key"], "real-key")
        bad = {"Authorization": "Bearer nope"}
        self.assertEqual(relay.handle("POST", "/v1/messages", bad, json.dumps(OK_BODY).encode())[0], 401)

    def test_health_needs_no_token_and_never_reaches_upstream(self):
        relay, up = self.make()
        status, _, body = relay.handle("GET", "/health", {}, b"")
        self.assertEqual((status, body), (200, b'{"ok":true}'))
        self.assertEqual(up.calls, [])
        self.assertFalse((self.dir / "relay.jsonl").exists())  # not even logged

    def test_refusals_never_reach_upstream(self):
        cases = [
            ({"token": "wrong"}, 401, "token"),
            ({"token": ""}, 401, "token"),
            ({"path": "/v1/models", "method": "GET"}, 404, "only POST"),
            ({"body": {**OK_BODY, "model": "claude-mythos"}}, 400, "not allowed"),
            ({"body": {**OK_BODY, "max_tokens": 64_000}}, 400, "max_tokens"),
            ({"body": {**OK_BODY, "stream": True}}, 400, "streaming"),
        ]
        for kwargs, status, needle in cases:
            with self.subTest(kwargs=kwargs):
                relay, up = self.make()
                s, _, out = self.call(relay, **kwargs)
                msg = out["error"]["message"]
                self.assertEqual(s, status)
                self.assertTrue(msg.startswith("relay: ") and needle in msg, msg)
                self.assertEqual(up.calls, [])

    def test_daily_budget_stops_further_calls(self):
        relay, up = self.make(daily_budget_usd=5.0)  # $4/call: two allowed, third refused
        self.assertEqual(self.call(relay)[0], 200)
        self.assertEqual(self.call(relay)[0], 200)
        s, _, out = self.call(relay)
        self.assertEqual(s, 403)
        self.assertIn("budget", out["error"]["message"])
        self.assertEqual(len(up.calls), 2)
        self.assertAlmostEqual(Relay("k", "t", state_dir=self.dir).spent_today(), 8.0)  # survives restart

    def test_rate_limit_window(self):
        relay, _ = self.make(usage={"input_tokens": 1, "output_tokens": 1}, max_requests_per_minute=2)
        self.assertEqual(self.call(relay, now=1000)[0], 200)
        self.assertEqual(self.call(relay, now=1001)[0], 200)
        self.assertEqual(self.call(relay, now=1002)[0], 403)
        self.assertEqual(self.call(relay, now=1062)[0], 200)

    def test_log_has_metadata_but_no_content_or_secrets(self):
        relay, _ = self.make()
        self.call(relay, body={**OK_BODY, "messages": [{"role": "user", "content": "my secret plans"}]})
        self.call(relay, token="wrong")
        log = (self.dir / "relay.jsonl").read_text()
        for secret in ("secret plans", "real-key", TOKEN):
            self.assertNotIn(secret, log)
        lines = [json.loads(x) for x in log.splitlines()]
        self.assertEqual((lines[0]["status"], lines[0]["cost_usd"]), (200, 4.0))
        self.assertEqual(lines[1]["status"], 401)

    def test_upstream_errors_pass_through_and_cost_nothing(self):
        relay, _ = self.make(status=529)
        self.assertEqual(self.call(relay)[0], 529)
        self.assertEqual(relay.spent_today(), 0)

    def test_ensure_token_appends_once_and_keeps_existing_props(self):
        p = self.dir / "local.properties"
        p.write_text("sdk.dir=C\\:\\\\Android\nanthropic.apiKey=sk-x", encoding="utf-8")
        t1, created = ensure_token(p)
        t2, created2 = ensure_token(p)
        self.assertTrue(created)
        self.assertFalse(created2)
        self.assertEqual(t1, t2)
        self.assertGreaterEqual(len(t1), 40)
        props = read_properties(p)
        self.assertEqual((props["anthropic.apiKey"], props["aos.relayToken"]), ("sk-x", t1))

    def test_rotate_replaces_token_and_keeps_key(self):
        p = self.dir / "local.properties"
        p.write_text("anthropic.apiKey=sk-x\n", encoding="utf-8")
        t1, _ = ensure_token(p)
        t2, created = ensure_token(p, rotate=True)
        self.assertTrue(created)
        self.assertNotEqual(t1, t2)
        self.assertEqual(p.read_text().count("aos.relayToken"), 1)
        self.assertEqual(read_properties(p), {"anthropic.apiKey": "sk-x", "aos.relayToken": t2})

    def test_provision_sends_token_on_stdin_and_verifies_by_hash(self):
        import hashlib
        import subprocess

        stored = {}

        def fake_run(cmd, input=None, **kw):
            if "exec-in" in cmd:
                stored["token"] = input.decode()
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            digest = hashlib.sha256(stored.get("token", "").encode()).hexdigest()
            return subprocess.CompletedProcess(cmd, 0, f"{digest}  files/relay_token\n".encode(), b"")

        calls = []
        ok = provision_token("adb", "SER", "tok-123", run=lambda c, **k: (calls.append(c), fake_run(c, **k))[1])
        self.assertTrue(ok)
        self.assertEqual(stored["token"], "tok-123")
        self.assertTrue(all("tok-123" not in " ".join(c) for c in calls))  # never on a command line
        self.assertEqual(calls[0][:3], ["adb", "-s", "SER"])
        self.assertIn("run-as dev.aos.launcher", calls[0][-1])

        # A failed write (e.g. app not installed) is detected by the hash check.
        bad = lambda c, **k: subprocess.CompletedProcess(c, 0, b"run-as: unknown package\n", b"")
        self.assertFalse(provision_token("adb", None, "tok-123", run=bad))

    def test_real_http_server_round_trip(self):
        relay, _ = self.make()
        server = make_server(relay, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/v1/messages"
            req = urllib.request.Request(url, data=json.dumps(OK_BODY).encode(), method="POST",
                                         headers={"x-api-key": TOKEN, "content-type": "application/json"})
            with urllib.request.urlopen(req) as r:
                self.assertEqual(r.status, 200)
                self.assertEqual(json.loads(r.read())["type"], "message")
            bad = urllib.request.Request(url, data=b"{}", method="POST", headers={"x-api-key": "nope"})
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(bad)
            self.assertEqual(e.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
