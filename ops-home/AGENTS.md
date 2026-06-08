# svcops Operating Account

Use Codex or Gemini CLI with `agent-runtime-ops` for natural-language operations.

Primary references:

```text
/opt/agent-runtime-ops/current/AGENTS.md
/home/svcops/.codex/AGENTS.md
/home/svcops/.gemini/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops/SKILL.md
MCP: agent-runtime-ops
```

Primary commands:

```bash
codex
gemini
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl profile list
codex mcp list
```

Do not install or expect Claude Code, OpenCode, or other agent CLIs on this account. Gemini/API
keys for runtime slots are managed through `opsctl runtime-secret`; Gemini CLI authentication is a
separate operating-account credential.

This guidance is intentionally global for Codex and Gemini CLI sessions under the `svcops` Unix
account only.

Baseline scripts are retained legacy artifacts, not a secondary operating path. Use them only as
urgent exceptions when `agent-runtime-ops` cannot yet handle the operation, and record the exception.
