# Agent Do/Don't

A rules engine between an AI agent and its tools, built assuming the model can be hijacked by
anything it reads. The model proposes; the rules decide: **do it**, **ask you**, or **refuse**.

This package contains the **MCP proxy**. It works with any agent that uses
[MCP](https://modelcontextprotocol.io) tools, such as Claude Code, Claude Desktop, or your own.
It sits between the agent and an MCP server, and neither of them needs any changes. It needs
nothing beyond the Python standard library. The project also includes an Android app with the
same rules ([GitHub](https://github.com/moshesipper/agentdodont)).

Status: **experimental.**

## What it does

Suppose an agent reads a web page with hidden instructions telling it to email your notes to
helpdesk@evil.example. If the model falls for it, the proxy sees the session has read untrusted
content, and refuses the email: that address isn't one of yours. The call never reaches the
email server.

- **Taint.** After a tool returns untrusted content, the session counts as untrusted from then
  on. This holds across every server the agent uses, and questions name where the content came
  from.
- **Where data goes.** URLs, email addresses and phone numbers in a call's arguments are checked
  against your lists. Once the session is tainted, an address you haven't listed is refused,
  not asked. Before that, a new address asks.
- **Risk.** It reads the server's tool annotations the cautious way. A tool with no annotations
  counts as possibly irreversible and asks.
- **Your settings.** You can set any tool to "do it", "ask" or "never", and there's a rate limit.
- **Asking.** Questions appear in the client (MCP elicitation). If the client can't ask, the call
  is refused, never run silently.
- **Log.** Every decision goes to `~/.agentdodont/mcp-audit.jsonl`.

## Set up

Start the proxy in place of the server, with the server's own command after `--`. With
[uv](https://docs.astral.sh/uv/) installed, nothing else needs installing. For Claude Code:

```
claude mcp add fetch -- uvx agentdodont mcp-proxy --rules /path/to/mcp-rules.json --name fetch -- uvx mcp-server-fetch
```

Or put this in `.mcp.json` in your project:

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

Claude Desktop uses the same entry in `claude_desktop_config.json`. Without uv, run
`pip install agentdodont` and use `"command": "agentdodont"` with the same arguments minus the
first `"agentdodont"`.

A rules file is optional. Every field in it is optional too:

```json
{
  "allowed_sites": ["wikipedia.org", "github.com"],
  "known_recipients": ["dana@example.com"],
  "levels": {"read_*": "auto", "delete_*": "ask", "get-env": "deny"},
  "tools": {"send_message": {"destination_args": {"channel": "recipient"}}}
}
```

## More

- [The full proxy guide](https://github.com/moshesipper/agentdodont/blob/main/docs/mcp-proxy.md):
  every rule, every field, and the limits.
- [Threat model](https://github.com/moshesipper/agentdodont/blob/main/docs/threat-model.md)
- [Benchmark](https://github.com/moshesipper/agentdodont/blob/main/docs/benchmark.md)

Apache License 2.0.
