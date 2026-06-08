---
name: agent-runtime-ops
description: Operate the agent-runtime-ops repository and the svcops server runtime. Use when Codex is asked to inspect, update, deploy, verify, or troubleshoot opsctl, runtime profiles, dev/customer slots, runtime secrets such as Gemini keys, NAS mount workflows, self-update approvals, or the agent-runtime-ops MCP server.
---

# Agent Runtime Ops

## Overview

Use this skill to keep natural-language operations tied to the real repository and the real
`svcops` server installation. Read the repository root `AGENTS.md` first when it is available.

## Operating Rules

- Start with repo and server orientation before server-impacting work.
- Prefer the `agent-runtime-ops` MCP tools when they are exposed; otherwise run the same `opsctl`
  commands manually through `ssh svcops`.
- Treat Codex and Gemini CLI as the standard operating-agent CLIs on `svcops`.
- Do not install or depend on Claude Code, OpenCode, or other agent CLIs for routine operations.
- Do not claim a server change is complete after local tests only.
- Do not edit rendered Docker compose files directly.
- Do not put customer state, NAS passwords, API keys, gateway tokens, or real slot assignment details
  in the repo.
- Do not pass raw secret values in MCP tool arguments. Use allowed files or terminal stdin.

## Runbooks

For exact commands and stop conditions, read:

```text
references/runbooks.md
```

Load only the relevant section:

- Update or install: "Deploy an Approved Repo Update"
- Operating agent surface: "Standard Operating Agent"
- Slot verification: "Check a Slot"
- Gemini/API key injection: "Runtime Secret Injection"
- Retained legacy exception for heartbeat: "Heartbeat Operations"
- Apply or rollback: "Apply and Rollback"
- NAS work: "NAS Operations"
- MCP verification: "MCP Setup and Smoke Test"
