---
name: agent-runtime-ops
description: Operate the agent-runtime-ops repository and the svcops server runtime. Use when Codex is asked to inspect, update, deploy, verify, or troubleshoot opsctl, runtime profiles, dev/customer slots, runtime secrets such as Gemini keys, NAS mount workflows, self-update approvals, or the agent-runtime-ops MCP server.
---

# Agent Runtime Ops

## Purpose

Use this skill only as a thin bootstrap marker. It should help the agent discover that this is an
`agent-runtime-ops` task, then push the agent to the repo, MCP, and `opsctl` for current truth.

Do not treat this skill as a command catalog or a runtime state source.

## Operating Posture

- Read the repository root `AGENTS.md` first when it is available.
- Prefer the `agent-runtime-ops` MCP tools when they are exposed; otherwise run the same `opsctl`
  commands manually through `ssh svcops`.
- Before changing a slot, separate routing contract, live image truth, canonical recipe, runtime
  profile, and applied manifest. A live HTTP failure is not automatically a profile problem.
- Treat `slot-registry.json` as Apache-facing routing only: slot, public host, gateway port, bridge
  port, enabled. Do not look there for family, image, release, runtime profile, or recipe truth.
- Treat running wrapper image labels, inspected through MCP/`opsctl`, as runtime truth.
- Do not claim a server change is complete after local tests only.
- Do not edit rendered Docker compose files directly.
- Do not guess target identifiers; resolve slots, routing entries, image digests, profiles, accounts,
  and shares from MCP, `opsctl`, or the installed repo before giving commands.
- If asked for the exact location of a token, password, credential, session, or other secret, do not
  mix verified structure with guesses. If the exact file and field are not known, say that briefly.
  A mounted config/auth/profile directory is not proof of the exact token location.
- Runtime provider secrets and handoff credentials are different. Use MCP `handoff_status` or
  `opsctl handoff status SLOT` to discover exact handoff file/field structure without printing
  values. Do not replace that with broad secret-file discovery commands.
- Do not put customer state, NAS passwords, API keys, gateway tokens, or real slot assignment details
  in the repo.
- Do not pass raw secret values in MCP tool arguments. Use allowed files or terminal stdin.
- Preserve the safety boundaries in `references/safety.md`; do not replace them with broad secret
  discovery commands or normal baseline-script operation.
