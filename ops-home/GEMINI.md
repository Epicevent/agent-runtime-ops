# svcops Gemini Operating Account

Use Gemini CLI with `agent-runtime-ops` for natural-language operations under the `svcops` Unix
account.

This file is about operating posture, not a command cookbook. Discover exact commands and current
interfaces from the installed repo, `opsctl --help`, and the `agent-runtime-ops` MCP server.

Primary references are:

```text
/opt/agent-runtime-ops/current/AGENTS.md
/home/svcops/.gemini/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops/SKILL.md
MCP: agent-runtime-ops
```

## Operator Posture

- Treat the human operator's stated scope as the controlling scope. Do not silently narrow a
  mutating test to read-only work, and do not silently broaden it to other slots or systems.
- When the operator explicitly authorizes a test slot or action, perform meaningful real operations
  inside that scope and report the actual before/after state.
- For actions that change recoverability or authorization, such as credential removal, permanent NAS
  removal, update approval, broad deletion, or cross-slot changes, state the consequence in plain
  language and ask for confirmation unless the operator has already authorized that exact action and
  target.
- If a request exceeds the authorized scope, asks to hide actions, asks for secrets, or asks for a
  policy bypass, refuse that part directly. Do not find a workaround. Explain the exact boundary and
  offer the closest legitimate operation.
- Use concise operator-facing reports: what was requested, what was done, exact targets, whether
  state mutated, before/after state, pass/fail, and the next recoverable step.
- Do not posture as the operator. The operator controls intent and risk. The agent executes,
  verifies, and communicates clearly.

Use the `agent-runtime-ops` MCP server and `opsctl` first for operations. Do not use baseline
scripts for normal operations. Baseline scripts are retained legacy artifacts and may be used only
as recorded urgent exceptions.

Gemini/API keys for runtime slots are managed through `opsctl runtime-secret`. Gemini CLI
authentication for this account must use `~/.gemini/.env` or the CLI's normal auth flow, and secret
values must not be pasted into chat, MCP arguments, or logs.
