# Agent Runtime Ops Instructions

This repository is the public operations toolchain for the JI TECH agent runtimes. It contains
runtime profiles, wrapper image recipes, `opsctl`, install/update logic, the Codex operation skill,
and the local MCP wrapper. It must not contain customer names, NAS passwords, API keys, gateway
tokens, customer documents, or real slot assignment details.

Private server state lives on the server, normally under:

```text
/srv/openclaw-ops
```

The normal operating account is:

```bash
ssh svcops
```

## Standard Operating Agents

The standard natural-language operating harnesses for `svcops` are Codex and Gemini CLI. This repo
installs and maintains the Codex global `AGENTS.md`, Gemini global `GEMINI.md`, operation skill, and
`agent-runtime-ops` MCP registration for that account. This affects sessions under the `svcops`
Unix account, and does not touch other Unix accounts or a developer's local accounts.

Agent-facing markdown should teach operating posture more than rote command memorization. Discover
current command shapes from `opsctl --help`, the installed repo, and the `agent-runtime-ops` MCP
server before acting.

Normal operator entry:

```bash
ssh svcops
codex
gemini
```

Do not install Claude Code, OpenCode, or other agent CLIs as part of `install.sh`, `self-update`,
or routine server operations. If another CLI is needed later, treat it as a separate approved
project with its own install, auth, rollback, and verification plan.

Gemini/API keys in this repo are runtime slot secrets only. They are injected into managed runtime
profiles with `opsctl runtime-secret`; they are not credentials for a Gemini CLI installation.

## Operator Posture

Treat the human operator's stated scope as the controlling scope. Do not silently narrow an
authorized mutating test into read-only checks, and do not silently broaden it to other slots,
accounts, or systems.

When an action changes recoverability, authorization, credentials, update state, or another slot,
say that plainly before doing it unless the operator has already authorized that exact target and
effect. If a request asks the agent to reveal secrets, conceal actions, escape scope, or bypass
policy, refuse that part directly and explain the exact boundary.

Do not treat every sensitive operation as impossible. Some operations, such as retrieving a secret
for an authorized operator or performing a permanent removal, may be valid when the operator uses
their own terminal and authority. In that case, do not run the sensitive command yourself and do not
ask for the secret value. Provide the full command for the operator to type manually, explain what it
will expose or mutate, and ask them to report only non-secret status.

When the operator performs a manual command, record it in the operator-facing report without secret
values: exact command shape, target, reason, who executed it, operator-reported result, and
`secret_value_recorded=no`. Do not invent a new logging mechanism when the existing terminal,
sudo/session logging, command output, or operator report is the intended record.

Report like an operator would expect: request interpreted, targets, actual actions, whether state
mutated, before/after state, pass/fail, and the next recoverable step. Do not posture as the
operator; the operator controls intent and risk, and the agent executes, verifies, and communicates.

## First Move

When work may affect the server, do all of the following before claiming completion:

```bash
git status --short --branch
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl profile list"
```

If the task is slot-specific, also run the non-mutating checks first:

```bash
ssh svcops "/usr/local/bin/opsctl status SLOT"
ssh svcops "/usr/local/bin/opsctl plan SLOT"
ssh svcops "/usr/local/bin/opsctl check SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Do not finish a server-impacting task with local tests only. Local checks prove the repo shape;
server checks prove the installed release and runtime state.

## Update Protocol

Server updates are commit-addressed. Branch names and short SHAs are not installation targets.

The complete flow is:

1. Commit and push the repo change.
2. Identify the full 40-character commit SHA.
3. Ask a root/admin operator to approve exactly that SHA:

```bash
sudo /usr/local/bin/opsctl update approve FULL_40_CHARACTER_COMMIT_SHA
```

4. From `svcops`, install the approved SHA:

```bash
sudo /usr/local/bin/opsctl self-update
```

5. Verify the server:

```bash
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl profile list
/usr/local/bin/opsctl check SLOT
sudo /usr/local/bin/opsctl check --live SLOT
```

`update status` should end with:

```text
approved_matches_installed=yes
```

Never ask vague approval questions such as "may I install this?". Provide the full command with the
exact SHA. If root approval is missing, stop at the approval command and explain that `svcops` cannot
run `update approve`.

## Safety Rules

Treat these as read-only unless the user is explicitly asking for an operation:

```bash
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl profile list
/usr/local/bin/opsctl status SLOT
/usr/local/bin/opsctl plan SLOT
/usr/local/bin/opsctl check SLOT
sudo /usr/local/bin/opsctl check --live SLOT
/usr/local/bin/opsctl nas requests
/usr/local/bin/opsctl nas mounted SLOT
/usr/local/bin/opsctl nas policy-check SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl runtime-secret status SLOT
```

These mutate runtime or server state:

```bash
sudo /usr/local/bin/opsctl self-update
sudo /usr/local/bin/opsctl apply SLOT
sudo /usr/local/bin/opsctl rollback SLOT
sudo /usr/local/bin/opsctl runtime-secret set SLOT --key KEY --value-stdin --check
sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas approve-auto
```

Use `opsctl`; do not directly edit rendered Docker compose files. `opsctl apply` renders from the
runtime profiles in this repo. NAS changes are child CIFS mounts under `/home/ocN/nas_docs`; do not
turn NAS shares into compose volumes.

## Retained Legacy Artifact

This repo is the operating source for runtime profiles, desired state, render/apply/check,
runtime manifests, NAS convergence, and rollout/release mechanics. The operating agent should use
this repo, `opsctl`, and the `agent-runtime-ops` MCP first.

The baseline scripts are retained legacy artifacts, not a secondary operating path. They remain on
the server because deleting them abruptly is operationally risky. Do not use them for normal
operations.

Use a baseline script only as an urgent exception when both are true:

```text
agent-runtime-ops does not yet expose the needed operation
production operation cannot safely wait for that gap to be implemented here
```

When a baseline script is used, record it in the operator report:

```text
legacy_exception_used=yes
reason=<why opsctl/MCP could not handle it>
command=<exact baseline command>
verification=<post-check result>
migration_gap=<what should be moved into agent-runtime-ops>
```

```bash
/opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh
```

Current known gap: OpenClaw heartbeat is not yet exposed through `opsctl`, so the retained baseline
wrapper may be used as an exception:

```bash
ssh svcops "sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-status dev-oc"
ssh svcops "sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-disable dev-oc"
```

Disabled heartbeat should show:

```text
heartbeat_config_every=0m
heartbeat_config_enabled=no
```

## Secrets

Never print, paste, commit, or log secret values. Do not pass secret values as MCP JSON arguments.
Use terminal stdin or an allowed server-side secret file.

Gemini/API key stdin pattern:

```bash
read -rsp "GEMINI_API_KEY for SLOT: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set SLOT --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
```

Status check:

```bash
sudo /usr/local/bin/opsctl runtime-secret status SLOT
```

## MCP

This repo installs a local stdio MCP server wrapper at:

```bash
/usr/local/bin/agent-runtime-ops-mcp
```

`install.sh` also tries to register it for the `svcops` Codex account:

```bash
codex mcp add agent-runtime-ops -- /usr/local/bin/agent-runtime-ops-mcp
```

The MCP server wraps `opsctl`; it does not reimplement operations policy. It may run runbook-backed
mutations, but it must reject raw secret values and use `opsctl` with argv lists, not shell strings.

No Claude/OpenCode MCP registration is managed by this repo.

## Remote Commands

Prefer simple remote commands:

```bash
ssh svcops "/usr/local/bin/opsctl update status"
```

Avoid local shell interpolation inside remote commands. In PowerShell, `$(...)` inside a double-quoted
SSH command is expanded locally before SSH runs. Split complex remote checks into separate simple
commands or use carefully quoted remote scripts.

## Reporting

Report the installed SHA, approved SHA, commands run, and verification result. Redact private paths
or values when they could reveal customer state. If a task is blocked by root approval, give the exact
approval command and stop before pretending the server was updated.
