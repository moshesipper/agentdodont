# MCP proxy

The same rules engine, for any agent that uses [MCP](https://modelcontextprotocol.io) tools:
Claude Code, Claude Desktop, or your own. The proxy sits between the agent and an MCP server.
Every tool call goes through the rules: **do it**, **ask you**, or **refuse**. The agent and the
server don't need any changes.

```
 agent (MCP client) ──▶ agentdodont mcp-proxy ──▶ the real MCP server (fetch, mail, files…)
                          rules.py decides each tools/call
```

Status: **experimental.** It's tested end to end against a scripted client and server
([tests/test_mcp_proxy.py](../tests/test_mcp_proxy.py)), but not yet run against many real
servers and clients.

## Set up

Start the proxy in place of the server, with the server's own command after `--`. The proxy
needs Python 3.10+ and nothing else. With [uv](https://docs.astral.sh/uv/), `uvx` fetches it on
first use; without uv, run `pip install agentdodont` and replace `uvx agentdodont` below with
`agentdodont`.

Claude Code, in one line:

```
claude mcp add fetch -- uvx agentdodont mcp-proxy --rules /path/to/mcp-rules.json --name fetch -- uvx mcp-server-fetch
```

Or in `.mcp.json` in your project (Claude Code asks you to approve it at the next start):

```json
{
  "mcpServers": {
    "fetch": {
      "command": "uvx",
      "args": ["agentdodont", "mcp-proxy", "--rules", "/path/to/mcp-rules.json", "--name", "fetch",
               "--", "uvx", "mcp-server-fetch"]
    }
  }
}
```

Claude Desktop uses the same entry in `claude_desktop_config.json`.

Put a proxy in front of every server you use: they share one session (below). On Windows,
commands like `npx` are found as `npx.cmd` automatically.

From a checkout of this repository instead: `"command": "python"`, with
`"args": ["-P", "-m", "agentdodont", "mcp-proxy", ...]` and `"env": {"PYTHONPATH": "/path/to/agentdodont"}`.
`-P` (Python 3.11+) stops Python from loading a different `agentdodont` folder from the
directory the client starts it in.

## What it does

- **Taint.** Unless your rules say otherwise, a tool's output counts as untrusted: the MCP spec
  treats tools as "open world" by default. After the first such result, the session is tainted,
  and every question names the source ("output of fetch/fetch").
- **One session across servers.** A client starts one proxy per server, and all the proxies it
  starts share their taint. So a web page read through a fetch server counts when the agent
  then calls an email server. The proxies find the client process themselves (Claude Code,
  Claude Desktop, …) and keep a small file per client in `~/.agentdodont/sessions/`, removed
  after the client exits. `--session NAME` shares taint between every proxy given that
  name instead, and `--session none` turns sharing off. Deleting the file doesn't untaint a
  proxy: each one also remembers what it has seen.
- **Where data goes.** The proxy finds addresses in each call's arguments: URLs, email
  addresses, and any host or phone number in arguments named like `url`, `host`, `to` or
  `phone`. You can name more with `destination_args`.
  - Once the session is tainted, an address that isn't on your lists is **refused, not asked**.
    Set `"tainted_egress": "ask"` if you'd rather be asked.
  - An address that *is* on your lists still asks.
  - Before any untrusted content, a new address asks.
- **Risk.** The defaults come from the server's annotations, read the cautious way, as the spec
  intends. Unannotated tools count as possibly irreversible and always ask. `readOnlyHint` tools
  run. Non-destructive tools run until the session is tainted, then ask. Your `tools` and
  `levels` settings override the annotations. A `levels` setting can't take a possibly
  irreversible tool below "ask"; if you know a tool is safe, change its `risk` instead.
- **Asking.** Questions go to you through the client, using MCP *elicitation*. If the client
  doesn't support elicitation, a call that would ask is refused instead, and the agent is told
  why. It never runs silently.
- **Refusing.** A refused call never reaches the server. The agent gets an error result saying
  why, and an instruction not to try another way.
- **Log.** Every decision, answer and result goes to `~/.agentdodont/mcp-audit.jsonl` (or the
  file given with `--log`). Arguments are logged too, so keep that file private.

## Rules file

See [mcp-rules.example.json](../mcp-rules.example.json). Every field is optional.

| Field | Meaning |
|---|---|
| `allowed_sites` | Sites data may go to (`example.com` also covers its subdomains) |
| `blocked_sites` | Always refused |
| `known_recipients` | Email addresses, phone numbers or handles data may go to |
| `levels` | `auto` / `ask` / `deny` per tool name, with `*` wildcards (`delete_*`) |
| `tools` | Per tool: `risk` (`none` / `reversible` / `irreversible`), `untrusted_output` (`true` / `false` / a description), `sends_data_out`, `destination_args` (`{"arg": "site"}` or `{"arg": "recipient"}`) |
| `tainted_egress` | `deny` (default) or `ask`: what a tainted session gets for a new destination |
| `max_calls_per_minute` | Per tool (default 30) |

## Limits

- **Sharing depends on finding the client.** If the proxy can't identify the client process
  (the audit log's `session_start` line says "not shared"), it falls back to tracking taint for
  its own server only. Give every proxy the same `--session` name to share anyway.
- **Only MCP tools are covered.** An agent's built-in tools (Claude Code's Bash, WebFetch…) don't
  go through the proxy, so content they read doesn't taint the session, and data they send isn't
  checked. Use the client's own permission settings for those.
- **The rate limit is per server**, not shared.
- **A session stays tainted** until the client restarts the server. That's deliberate, but it
  means a long session asks more as it goes on.
- **Addresses are found by pattern.** Data can also leave in ways that don't look like an
  address: a free-text argument a server forwards somewhere, or something encoded. Mark such
  tools with `levels` or `destination_args`.
- **Annotations come from the server.** The proxy reads them cautiously, but a server you don't
  trust can label a dangerous tool as read-only. Set `tools` for servers you don't control.
- **Questions depend on the client.** How an elicitation looks (and whether it shows the whole
  argument list) is up to the client.
