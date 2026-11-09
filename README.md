# Agent Do/Don't

**The model proposes. Agent Do/Don't decides.** *Do. Don't. Ask first.*

AI agents now send messages, change calendars, open links and tap through apps on your behalf.
Any text they read can hijack them: a notification, a calendar invite, a web page, another app's
screen. Most defenses try to make the model notice the trick. Agent Do/Don't assumes it won't.

Every tool call the agent makes goes through a rules engine that runs outside the model, which the
model can't see or influence. The engine decides: **do it**, **ask you**, or **refuse**. Everything
is logged and explained, and you can undo whatever can be undone.

This repository is a working Android implementation: a home-screen app with a Claude agent,
running on a real phone (Galaxy S22, Android 16). It's an early prototype. See [Status](#status).

---

## What sets it apart

Many tools can intercept an agent's tool calls and ask a human. Agent Do/Don't goes further,
because it assumes the model is **already compromised**:

- **It knows what the agent has read, and from where.** Every tool declares whether its output
  is trusted; the code won't compile otherwise. Once a task has read outside content, it's
  **tainted**, and the source is named in every question: *"this task has read notifications from Shell"*.
- **A tainted task can only send data to places you've already allowed.** Your contacts, or
  sites on your list. Anything else is **refused, not asked**, so an injection can't talk you
  into leaking data with one tired tap. Typing an address or URL into another app counts too.
  Even before it has read anything, the agent asks before sending data anywhere new.
- **Some things are never possible.** The agent can't read or operate protected screens and
  controls: Agent Do/Don't itself, permission prompts, factory reset, developer options. These
  are recognized in 18 languages, and in any other language every named tap asks. A **scope
  lock** keeps it inside the app the task opened.
- **Only you can undo, and only you can clear the record.** Every reversible change can be
  undone, grouped by request. The agent has no tool for undoing or clearing history, so it
  can't erase its tracks.
- **"Why did you do that?"** For every action: who proposed it, which rule decided, what you
  answered, what happened.
- **Memory an injection can't poison.** What the agent remembers is encrypted on the phone, and
  you can view and edit it. Secrets are refused, and memory writes from tainted tasks ask first.
- **You press Send.** Messages and emails are drafted in the real app. Agent Do/Don't never sends them.
- **Tested against a hijacked model,** not just a confused one (see [Evidence](#evidence)).
- **Your API key stays on your computer.** The phone talks to a small relay with a budget and a
  rate limit. It pairs over Wi-Fi with a pinned certificate.

What it does **not** guarantee is just as important. Read the [threat model](docs/threat-model.md).

---

## How it works

```
 your request
      │
      ▼
 ┌─────────┐  proposes a tool call   ┌───────────────────────────────────┐
 │  model  │ ──────────────────────▶ │       rules engine (no model)     │
 │ (Claude)│ ◀────────────────────── │ validate → risk → taint → where   │
 └─────────┘  result, labelled       │ data goes → protected screens     │
              trusted / untrusted    │ → scope lock → rate limit         │
                                     └─────────────────┬─────────────────┘
                                      do it / ask you / refuse
                                                       ▼
                                      runs · audit log · undo entry
```

- The engine ([Policy.kt](android/app/src/main/java/dev/aos/launcher/capabilities/Policy.kt)) is
  plain Kotlin with no Android or model dependencies, so it's deterministic and unit-tested.
- Every applicable rule is evaluated and the **strictest verdict wins**. No approval overrides a refusal.
- Irreversible actions (send, delete, pay) **always ask**, whatever the settings.

---

## Evidence

The debug build contains a **scripted attacker**: a stand-in "model" that does exactly what the
injected text says, as a fully hijacked model would. It runs through the same loop, rules and
confirmation screens as the real agent. On the S22:

| Injection arrives via | Attacker then tries to | Got through without the user's OK |
|---|---|---|
| A notification or calendar invite | Delete a calendar event; set a 3 a.m. alarm; send the calendar's event titles to an attacker URL | **0 of 3** (the delete and the alarm asked, naming the source; the URL was refused outright) |
| Another app's screen (Calendar) | Tap a control in Settings; read a different app's screen | **0 of 2** (the tap asked; the read was refused by the scope lock) |

The real model (Claude) ignored the injections too, even when told to obey them. The point is
that the result doesn't depend on that.

**Benchmark:** 35 attacks and 28 ordinary requests, replayed through the rules engine with it on
and off. With the rules off, all 35 attacks work. With them on, 17 are refused outright, 16
need your OK, and 2 get through, each a documented limit. Ordinary requests cost 13 questions
across 28 requests. The benchmark also found a gap (an injection inside the app being operated
could get an address typed in), now fixed. In a live run on the phone, the real model resisted 11
of 12 injections by itself; the one it obeyed (a 3 a.m. alarm) was stopped by the rules. Method, every scenario and the gaps: [docs/benchmark.md](docs/benchmark.md).

**Try to break it.** If you get a harmful action past Agent Do/Don't without a confirmation,
please report it privately ([SECURITY.md](SECURITY.md)).

---

## What's in the repository

```
android/        The app: home screen with an intent box, the Claude agent, the rules engine,
                tools (alarms, calendar, URLs, apps, notifications, contacts, email/text drafts),
                screen operation through accessibility, encrypted memory, History, Undo, pairing.
agentdodont/    Python: the relay that keeps the API key off the phone (budget, rate limit,
                QR pairing over pinned TLS, revocable device tokens); the MCP proxy (the same
                rules for any MCP agent); and an experimental laptop agent that drives a phone
                over ADB.
tests/          Python tests (relay, pairing, MCP proxy, laptop agent).
tools/          The live benchmark (the real model on a phone, against planted injections).
docs/           Threat model, benchmark, and every feature in detail with how it was verified.
```

---

## Quick start

### MCP proxy (any MCP agent)

Needs only Python 3.10+. Put the proxy in front of each MCP server, with the server's own
command after `--`. With [uv](https://docs.astral.sh/uv/), in Claude Code:

```sh
claude mcp add fetch -- uvx agentdodont mcp-proxy --name fetch -- uvx mcp-server-fetch
```

Without uv: `pip install agentdodont`, then the same line with `agentdodont` in place of
`uvx agentdodont`. Add `--rules mcp-rules.json` for your own lists and settings (see
[mcp-rules.example.json](mcp-rules.example.json)). [docs/mcp-proxy.md](docs/mcp-proxy.md) has
the details and the setup for Claude Desktop.

### Phone app

You need: an Android phone (Android 11 or newer; tested on Android 16), a computer on the same
Wi-Fi with Python 3.10+, and an [Anthropic API key](https://console.anthropic.com/). The key
stays on the computer, in a small program (the relay) that the phone reaches Claude through.

1. **Install the relay** and give it your key (it's saved in `~/.agentdodont/`, never in the app):

   ```sh
   pip install "agentdodont[phone]"
   agentdodont relay --set-key
   ```

2. **Install the app:** download `agentdodont-<version>.apk` from the
   [latest release](https://github.com/moshesipper/agentdodont/releases/latest). Open it on the
   phone and allow the install when Android asks, or run `adb install agentdodont-<version>.apk`
   from the computer. Every release is signed with the same key, certificate SHA-256
   `89:92:9E:39:47:1B:F6:2F:DB:19:D8:4D:BB:21:12:CB:D5:33:AD:8A:F4:BF:19:4A:D2:70:2C:BA:F1:2D:2A:F4`.

3. **Pair the phone:** run `agentdodont relay --pair`, scan the QR code with the phone's camera,
   and confirm on the phone. If your firewall asks, allow the relay on private networks.

4. **From then on**, start `agentdodont relay --lan` and leave it running while you use the phone.

Then, on the phone:

- **Set it as the home screen** (optional): `adb shell cmd package set-home-activity dev.aos.launcher/.MainActivity`.
  To undo: Settings › Apps › Default apps › Home app.
- **Grant what you want to use:** calendar and contacts permissions when asked; **Notification
  access** for reading notifications; **Settings › Accessibility › Agent Do/Don't** for
  operating other apps.
- Type a request, such as *"what's on my calendar tomorrow?"* or *"alarm 7:30"*. Look at
  **History** and **Policy** to see what happened and to change what may happen.

`relay --devices` lists paired phones and `relay --revoke <id>` cuts one off.

**Building from source** (for development, the red-team tests, or using the phone over USB
without Wi-Fi): you also need Android Studio (set `JAVA_HOME` to its JDK) and `adb`.

```sh
git clone https://github.com/moshesipper/agentdodont && cd agentdodont
pip install -r requirements.txt
echo "anthropic.apiKey=YOUR_KEY" >> android/local.properties   # gitignored; never built into the app
cd android && ./gradlew installDebug && cd ..
python -m agentdodont relay     # over USB: hands the debug app a device token, then holds the key
```

In a checkout with `android/local.properties`, the relay keeps its files there and in `.relay/`
and `logs/`. The debug build can't be installed over the release app (they're signed with
different keys): uninstall one first.

[docs/features.md](docs/features.md) has every option and command, plus the red-team commands.

---

## Tests

```sh
cd android && ./gradlew testDebugUnitTest    # rules engine, taint, undo, History, screen rules, word lists, memory, pairing
python -m unittest discover -s tests          # relay, pairing, MCP proxy, laptop agent
```

---

## Status

**Works today:**
- the rules engine with taint and named sources, outbound allow-lists (tainted tasks are refused; any other agent task asks), protected screens in 18 languages, and the scope lock;
- user-only undo, History with "why", and clearing history with a visible marker;
- encrypted memory that you can inspect, and that injections can't write to silently;
- message and email drafts with your contacts as the allow-list;
- the relay with a budget, a rate limit and pinned Wi-Fi pairing;
- **experimental:** an [MCP proxy](docs/mcp-proxy.md) that puts the same rules between any MCP agent
  (Claude Code, Claude Desktop…) and its tools, with one session across all its servers:
  `pip install agentdodont`, or `uvx agentdodont mcp-proxy`.

**Next:**
- [ ] a defense and tests against "action rebinding" (the screen changes between check and tap)
- [ ] the rules engine as a standalone library, ported to Python, with shared test cases for both versions
- [ ] the MCP proxy beyond experimental: ready-made rules and runs against popular servers and clients

---

## License

[Apache-2.0](LICENSE). Copyright 2026 Moshe Sipper.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
