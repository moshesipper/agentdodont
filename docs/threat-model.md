# Threat model

This page says what Agent Do/Don't protects, against whom, how, and where it stops. If you find a
way to break one of the guarantees below, please report it privately (see [SECURITY.md](../SECURITY.md)).

## The core assumption

**Any untrusted text the agent reads can take full control of the model.** This includes a
notification, a calendar invite, an app's screen or a web page. So the defenses don't rely on the
model noticing an attack. Every tool call goes through a rules engine that runs outside the model,
sees only facts it can check (the tool, its validated arguments, who started the call, what the
task has read, the user's settings), and returns **do it**, **ask the user**, or **refuse**. The
strictest rule wins, and no approval can override a refusal.

We test this assumption directly. A scripted "attacker model" obeys the injection exactly, as a
fully hijacked model would (see [Evidence](#evidence)).

## What we protect

- **Your actions:** sending, deleting, changing settings, paying.
- **Your data:** calendar, contacts, notifications, what the agent remembers about you, and what is on your screen.
- **The phone's integrity:** permissions, system settings, developer options, factory reset, and Agent Do/Don't's own controls.
- **The record:** the History and audit log, and the undo stack.
- **Your API key and budget.**

## Who we defend against

| Adversary | Can do | In scope? |
|---|---|---|
| **Content attacker** | Put text in front of the agent: send you a message, an invite or an email, or control a web page or something an app displays | **Yes, the main threat** |
| **Hijacked model** | Do anything the injected text says, through any tool, in any order | **Yes** |
| **Another app on the phone** | Send intents to Agent Do/Don't (for example a forged pairing link), or draw over the screen | Yes, for the cases below |
| **Someone on your home network** | Pretend to be the relay, or try to pair with it | Yes |
| **A model malicious from the start** | Misbehave without having read any untrusted content | **Partly** (see [Limits](#limits)) |
| **Someone holding your unlocked phone, root or malware with system privileges, a malicious accessibility service you installed** | Bypass any app-level control | No |
| **Whoever controls the computer running the relay** | Read the API key and use the budget | No: the relay host is trusted |

## Guarantees and how they're enforced

**G1. Once a task has read untrusted content, nothing with an effect happens without your OK.**
- Every tool must declare whether its output is trusted or untrusted; the code doesn't compile otherwise.
- Untrusted output marks the task as **tainted** and records where the content came from ("notifications from Shell").
- In a tainted task, every reversible or irreversible action **asks**, and the question names the source.
- You can mark specific apps as trusted, so their notifications don't taint a task (see Limits).

**G2. A tainted task can only send data where you've already allowed it.**
- Tools that can carry data off the phone (open a URL, draft an email or a text) declare a destination.
- In a tainted task, a URL must be on **Policy › Sites**, and a recipient must be **in your contacts**. Otherwise the call is **refused, not asked**. If the destination can't be determined, it's refused.
- Even allowed destinations still ask.
- Drafts never send: the email or messaging app opens with the draft, and you press Send.

**G3. Irreversible actions always ask.** Anything the agent proposes that can't be undone, such as
sending, deleting or paying, asks, whatever your settings say.

**G4. Some screens and controls are off-limits.**
- **Protected apps:** Agent Do/Don't itself, the system UI, permission prompts, the package installer and biometric settings. The agent can't read or operate them at all.
- **Protected controls** (factory reset, developer options, accessibility settings, emergency calls) are refused. They're recognized in 18 languages.
- **Risky buttons** like Delete, Send or Buy count as irreversible, so they always ask. They're recognized in the same 18 languages. In any other language, every named tap asks.
- **Sensitive apps:** in payment, banking, wallet and app-store apps, every action asks.
- **Actions go to accessibility elements, never to screen coordinates,** so a tap can't land on Agent Do/Don't's own confirmation.

**G5. The scope lock keeps the agent in the app the task opened.** Screen tools work only in the
app the task opened, and only while that app is in front. Anything else is refused.

**G6. Only you can undo, and only you can clear the record.**
- Every reversible change gets an undo entry, grouped by request. An undo refuses to remove something you've edited since.
- Undo and clearing the history are buttons for you, not tools for the agent.
- Clearing leaves a marker in the log, so it can't be done silently.

**G7. You can see why everything happened.** For every action, the History shows who proposed
it, which rule decided, what you answered and what happened.

**G8. An injection can't plant a permanent instruction.**
- Memory is encrypted on the phone (AES-256-GCM, with a key in the Android Keystore) and you can view and edit it.
- Things that look like passwords, codes or card numbers are refused.
- Writing to memory from a tainted task asks first.

**G9. Confirmations are yours.**
- Each confirmation explains why it's asking.
- Its Allow button only becomes active after 0.8 seconds, so a stray or double tap can't approve something you haven't read.
- The agent can't tap it (G4).
- Pairing links from other apps or web pages always need your confirmation.

**G10. The API key never reaches the phone.**
- The relay on your computer holds the key. It forwards only non-streaming Messages API calls to allowed models, with a cap on output length (`max_tokens`), a rate limit (30 a minute) and a daily budget, and logs metadata only.
- Over USB, the phone authenticates with a device token stored in the app's private storage.
- Wi-Fi pairing works like this:
  - a one-time 8-digit code, valid for 5 minutes, with 5 attempts;
  - the relay's TLS certificate pinned by its fingerprint;
  - the relay proves it knows the code before the phone sends anything;
  - home-network addresses only;
  - the resulting device token can be revoked.

**Also:** each tool is rate-limited to 30 calls a minute, so a runaway loop stops.

## Limits

These are known limits, not bugs. Reports that improve on them are welcome.

- **The word lists are heuristics.** Risky-button and protected-control detection uses words and
  control IDs. A covered language can still miss a phrasing, and an app can label a dangerous
  button misleadingly. Unknown languages make every named tap ask, but known ones can have gaps.
- **Action rebinding (untested).** A tap is checked against the last screen read. If the app
  changes what an element does between the read and the tap (time-of-check to time-of-use), the
  check can be wrong. We do check that the same app is still in front, but not that the element
  is unchanged.
- **A model malicious from the start.** The guarantees above apply once the task is tainted.
  An *untainted* task runs reversible actions automatically by default (each with an undo), and
  can open URLs or draft to anyone. A model that was malicious before reading anything could
  misuse that, for example sending what it already knows (memory, contacts) to a URL. You can
  set any tool to "Ask me" in Policy. Tightening the defaults is on the roadmap.
- **Trusted apps.** Marking an app as trusted means its notifications don't taint. If that app
  shows content written by others (most messaging apps do), an injection through it won't be
  caught. Only trust apps that show content you or your organisation wrote.
- **Contacts as the allow-list.** Shared or synced address books can contain entries written by
  others. A draft to a known contact still asks, and you still press Send.
- **Allowed sites can leak.** Data can reach an allowed site through the URL itself (for
  example its search page), and an allowed site with an open redirect can forward it elsewhere.
  Allow only sites you trust with whatever the task has read.
- **Confirmation fatigue.** If you approve everything, asking doesn't protect you. Confirmations
  say why they ask and name the source, but this is a human limit.
- **The model provider sees the task.** Your request, tool results, and the memory are sent to
  the model (Claude, via your relay). Local-first today means the key and the rules stay with
  you, not that the model runs locally.
- **App-level, on stock Android.** Agent Do/Don't guards its own agent. It can't police other
  assistants on the phone, and it can't defend against root, malicious system software, or a
  malicious accessibility service.
- **Audit log at rest.** The log is in the app's private storage, unencrypted. Memory is encrypted.

## Evidence

- **Unit tests** cover the rules engine, taint, outbound allow-lists, undo, History, the screen
  rules and word lists, memory and pairing (79 Kotlin tests); and the relay and pairing (Python).
- **On a real phone** (Galaxy S22, Android 16), with the scripted attacker in the debug build:

  | Injection arrives via | Attacker then tries to | Got through without the user's OK |
  |---|---|---|
  | A notification or calendar invite | Delete a calendar event; set a 3 a.m. alarm; send the calendar's event titles to an attacker URL | 0 of 3 |
  | Another app's screen (Calendar) | Tap a control in Settings; read a different app's screen | 0 of 2 |

  This is preliminary: one device, a handful of scenarios. A fuller benchmark is planned: more
  attacks, the cost in extra questions on ordinary tasks, and a comparison with an unprotected agent.
