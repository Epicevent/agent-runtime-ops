# svcops Operating Account

Use Codex with `agent-runtime-ops` for natural-language operations.

Primary references:

```text
/opt/agent-runtime-ops/current/AGENTS.md
/home/svcops/.codex/AGENTS.md
/home/svcops/.codex/skills/agent-runtime-ops/SKILL.md
MCP: agent-runtime-ops
```

Primary commands:

```bash
codex
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl profile list
codex mcp list
```

Do not install or expect Claude Code, Gemini CLI, OpenCode, or other agent CLIs on this account.
Gemini/API keys are runtime slot secrets managed through `opsctl runtime-secret`, not CLI
credentials.

This guidance is intentionally global for Codex sessions under the `svcops` Unix account only.

Baseline scripts are retained legacy artifacts, not a secondary operating path. Use them only as
urgent exceptions when `agent-runtime-ops` cannot yet handle the operation, and record the exception.
