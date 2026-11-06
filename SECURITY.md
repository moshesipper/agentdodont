# Security policy

Agent Do/Don't is a security project, so finding ways around it is useful work. Thank you for doing it.

## Reporting a vulnerability

**Please report privately**, through GitHub's
[private vulnerability reporting](https://github.com/moshesipper/agentdodont/security/advisories/new) (the **Security** tab, then
**Report a vulnerability**). Please don't open a public issue for a bypass until it's fixed.

A useful report includes:

- what got through: the tool call, and the verdict you expected (ask or refuse) versus what happened;
- how the untrusted content reached the agent: a notification, a calendar invite, an app's screen, a web page;
- the steps, or a scripted attack, that reproduce it, plus the phone model, Android version and phone language;
- the relevant lines from the History screen or the audit log, if you have them.

This is maintained by one person. I aim to acknowledge a report within 7 days and to agree on a
disclosure date with you. Unless you'd rather stay anonymous, confirmed bypasses are credited in
the release notes.

## What counts

**In scope:** anything that defeats a guarantee in the [threat model](docs/threat-model.md). For example:

- an effectful action from a tainted task that runs **without asking**;
- data reaching a site or recipient outside the allow-lists from a tainted task;
- a tap or read on a protected screen or control, or outside the app the task opened (the scope lock);
- the agent starting an undo, clearing the history, or approving its own confirmation;
- an injected instruction written into memory without the user's OK;
- the phone pairing with a relay the user didn't approve, or the relay accepting a revoked or unpaired device;
- the API key or a device token leaking from the relay or the phone.

**Out of scope** (see the threat model for why):

- attacks that need root, an unlocked phone in the attacker's hands, or a malicious accessibility service the user installed;
- the user approving a clearly described harmful action;
- a model that is malicious from the start, rather than one hijacked by content it reads (a known limit of the current version);
- denial of service against your own relay.

## Testing safely

Test only on devices, accounts and contacts that you own, or that you are allowed to test. The
debug build includes a scripted attacker (`DEBUG_AGENT_TASK`) for exactly this. Don't send real
messages to real people, or real data to sites you don't control.
