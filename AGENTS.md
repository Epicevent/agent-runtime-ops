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
