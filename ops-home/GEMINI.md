# svcops Gemini Operating Account

Use Gemini CLI with `agent-runtime-ops` for natural-language operations under the `svcops` Unix
account.

Primary references:

```text
/opt/agent-runtime-ops/current/AGENTS.md
/home/svcops/.gemini/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops/SKILL.md
MCP: agent-runtime-ops
```

Primary commands:

```bash
gemini
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl profile list
/usr/local/bin/agent-runtime-ops-mcp
```

Use the `agent-runtime-ops` MCP server and `opsctl` first for operations. Do not use baseline
scripts for normal operations. Baseline scripts are retained legacy artifacts and may be used only
as recorded urgent exceptions.

Gemini/API keys for runtime slots are managed through `opsctl runtime-secret`. Gemini CLI
authentication for this account must use `~/.gemini/.env` or the CLI's normal auth flow, and secret
values must not be pasted into chat, MCP arguments, or logs.
