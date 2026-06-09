---
name: agent-runtime-ops
description: Operate the agent-runtime-ops repository and the svcops server runtime. Use when Codex is asked to inspect, update, deploy, verify, or troubleshoot opsctl, runtime profiles, dev/customer slots, runtime secrets such as Gemini keys, NAS mount workflows, self-update approvals, or the agent-runtime-ops MCP server.
---

# Agent Runtime Ops

## Purpose

Use this skill as procedural memory for `agent-runtime-ops` work on the `svcops` operating account.
It should tell the agent how to orient, which runbook to load, which tool family to prefer, and what
must be verified before reporting success.

Do not treat this skill as runtime state. Current slot, routing, image, secret, NAS, and update
state must still be read from MCP, `opsctl`, the installed repo, or the live server.

## Core Procedure

- Read the repository root `AGENTS.md` first when it is available.
- Prefer the `agent-runtime-ops` MCP tools when they are exposed; otherwise run the same `opsctl`
  commands manually through `ssh svcops`.
- For exact commands and stop conditions, load only the relevant section of
  `references/runbooks.md`.
- Before changing a slot, separate port allocation, Apache public-host truth, live image truth,
  canonical recipe, runtime profile, and applied manifest. A live HTTP failure is not automatically
  a profile problem.
- Treat `slot-registry.json` as port allocation only: slot, gateway port, bridge port, enabled. Do
  not look there for public host, family, image, release, runtime profile, or recipe truth.
- Treat Apache route status as public-host truth.
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

## Runbook Index

Read the named section from `references/runbooks.md` when the task matches:

- First orientation: "Orientation"
- Operating account Codex/Gemini CLI: "Operating Agent Surface"
- Install or update: "Deploy an Approved Repo Update"
- MCP registration or smoke test: "MCP Setup and Smoke Test"
- Slot diagnosis: "Check a Slot"
- Router, public host, or subdomain diagnosis/change: "Route and Public Host Diagnosis"
- Image rollout from wrapper/product digests: "Image Rollout"
- Dev source-mode work: "Dev Recipe"
- Runtime API keys such as Gemini/OpenAI: "Runtime Secret Injection"
- Gateway tokens or workspace passwords: "Handoff Credentials"
- NAS mount, unmount, remove, or credential tracking: "NAS Operations"
- Apply or rollback a single slot: "Apply and Rollback"
- Missing `opsctl` capability with urgent production need: "Legacy Exception"
