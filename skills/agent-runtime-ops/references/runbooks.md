# Agent Runtime Ops Runbooks

## Orientation

Use these commands before server-impacting work:

```bash
git status --short --branch
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl profile list"
```

Expected update status when current:

```text
approved_matches_installed=yes
```

If PowerShell is the local shell, avoid `$(...)` inside double-quoted SSH commands because it expands
locally before SSH runs.

## Standard Operating Agents

Codex and Gemini CLI are the standard natural-language operating CLIs for `svcops`.

Normal entry:

```bash
ssh svcops
codex
gemini
```

This repo currently installs:

```text
/home/svcops/AGENTS.md
/home/svcops/.codex/AGENTS.md
/home/svcops/.gemini/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops
/usr/local/bin/agent-runtime-ops-mcp
Codex MCP registration: agent-runtime-ops
Gemini MCP settings: ~/.gemini/settings.json
```

The `/home/svcops/.codex/AGENTS.md` link is intentionally global for every Codex session that runs
as the `svcops` Unix account. It must not affect other server accounts or a developer's local Codex
account.

The `/home/svcops/.gemini/GEMINI.md` link is intentionally global for every Gemini CLI session that
runs as the `svcops` Unix account. It must not affect other server accounts or a developer's local
Gemini account.

This repo does not install or manage Claude Code, OpenCode, or other agent CLIs. Do not add them
during routine `self-update` work. If another CLI becomes necessary, handle it as a separate
approved project with an explicit install and rollback plan.

Codex ChatGPT login for the `svcops` operating account:

```bash
ssh svcops
codex login --device-auth
codex login status
```

Gemini CLI API key for the `svcops` operating account:

```bash
ssh svcops
install -d -m 0700 ~/.gemini
read -rsp "GEMINI_API_KEY for svcops Gemini CLI: " GEMINI_API_KEY
printf '\n'
umask 077
printf 'GEMINI_API_KEY=%s\n' "$GEMINI_API_KEY" > ~/.gemini/.env
unset GEMINI_API_KEY
gemini --version
GEMINI_CLI_TRUST_WORKSPACE=true gemini "Reply exactly: OK"
```

The managed `/usr/local/bin/gemini` wrapper loads `/home/svcops/.gemini/.env` before starting the
Gemini CLI. A present file alone is not enough; verify an actual CLI call after setting the key.

Do not put the Codex login token or Gemini API key in chat, command arguments, MCP JSON arguments,
or repo files.

## Deploy an Approved Repo Update

After committing and pushing, get the full SHA:

```bash
git rev-parse HEAD
```

Root/admin approval command:

```bash
sudo /usr/local/bin/opsctl update approve FULL_40_CHARACTER_COMMIT_SHA
```

`svcops` install command:

```bash
ssh svcops "sudo /usr/local/bin/opsctl self-update"
```

Verify:

```bash
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl profile list"
```

If the operator asks for an approval command, provide the full command with the exact SHA. `svcops`
does not run `update approve`.

## Check a Slot

Static checks:

```bash
ssh svcops "/usr/local/bin/opsctl status SLOT"
ssh svcops "/usr/local/bin/opsctl plan SLOT"
ssh svcops "/usr/local/bin/opsctl check SLOT"
```

Live check:

```bash
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Use live checks after update, apply, rollback, NAS mount/unmount, or runtime secret changes.

## Runtime Secret Injection

Gemini/API keys here are runtime slot secrets, not Gemini CLI credentials. Gemini CLI
authentication for `svcops` is separate and lives under `/home/svcops/.gemini`.

Never print the secret value. Preferred terminal stdin pattern:

```bash
ssh svcops
read -rsp "GEMINI_API_KEY for dev-oc: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set dev-oc --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
```

For Hermes dev:

```bash
ssh svcops
read -rsp "GEMINI_API_KEY for dev-hermess: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set dev-hermess --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
sudo /usr/local/bin/opsctl runtime-secret status dev-hermess
```

When MCP is available, use `runtime_secret_set_from_file` only with `secret_file` under an allowed
secret root. Do not send the key value as a JSON argument.

## Heartbeat Operations

Use `agent-runtime-ops` first. Baseline scripts are retained legacy artifacts, not a secondary
operating path. They should not be used for normal operations.

OpenClaw heartbeat is a current gap because it is not yet exposed through `opsctl`. Use the retained
baseline wrapper only as an urgent exception, then record the exception and the migration gap in the
operator report.

Check heartbeat:

```bash
ssh svcops "sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-status SLOT"
```

Disable heartbeat:

```bash
ssh svcops "sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-disable SLOT"
```

Disabled status should include:

```text
heartbeat_config_every=0m
heartbeat_config_enabled=no
```

The disable command is idempotent and refreshes/recreates the gateway through the baseline wrapper.
After disabling, verify:

```bash
ssh svcops "sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-status SLOT"
ssh svcops "/usr/local/bin/opsctl check SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Known note: `HEARTBEAT.md` files are optional checklist files. The scheduler is controlled by
`agents.defaults.heartbeat.every` in the OpenClaw config.

Record any use like this:

```text
legacy_exception_used=yes
reason=heartbeat is not yet exposed through opsctl
command=sudo /opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh heartbeat-disable SLOT
verification=heartbeat_config_every=0m heartbeat_config_enabled=no
migration_gap=bring heartbeat status/disable into agent-runtime-ops
```

## Apply and Rollback

Apply a slot only after static checks pass:

```bash
ssh svcops "/usr/local/bin/opsctl check SLOT"
ssh svcops "sudo /usr/local/bin/opsctl apply SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

For first migration from legacy runtime, use the explicit first-apply flag only when the operator
intends it:

```bash
ssh svcops "sudo /usr/local/bin/opsctl apply SLOT --allow-first-apply"
```

Rollback:

```bash
ssh svcops "/usr/local/bin/opsctl status SLOT"
ssh svcops "sudo /usr/local/bin/opsctl rollback SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

## NAS Operations

Read-only status:

```bash
ssh svcops "/usr/local/bin/opsctl nas requests"
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "/usr/local/bin/opsctl nas policy-check SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas credential status SLOT //HOST/SHARE"
```

Mount an already-credentialed and policy-allowed share:

```bash
ssh svcops "/usr/local/bin/opsctl nas policy-check SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Temporary unmount. This keeps official root/customer credentials and the managed fstab entry, so
the share can be mounted again without re-entering the password:

```bash
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Permanent removal. Use this for authorization withdrawal or share removal. It unmounts the share,
removes the managed fstab entry, and deletes only official root/customer credentials. Legacy
`.openclaw-nas` credentials are not counted as official credentials and are not removed:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas credential status SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas remove SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas credential status SLOT //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
```

Customer NAS requests can be processed once:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas approve-auto"
```

Do not add NAS shares as compose volumes. Managed NAS is a child CIFS mount under
`/home/ocN/nas_docs`.

## MCP Setup and Smoke Test

The install script creates:

```bash
/usr/local/bin/agent-runtime-ops-mcp
```

It also attempts:

```bash
codex mcp add agent-runtime-ops -- /usr/local/bin/agent-runtime-ops-mcp
```

Verify registration:

```bash
ssh svcops "codex mcp list"
```

Use a newline-delimited JSON-RPC smoke test rather than running the MCP server interactively:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | /usr/local/bin/agent-runtime-ops-mcp
```

The server must write only valid MCP JSON-RPC messages to stdout.
