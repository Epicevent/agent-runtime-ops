# Agent Runtime Ops Runbooks

This file is procedural memory for agents. It is not runtime state. Before using a command, resolve
current targets from MCP, `opsctl`, the installed repo, or the live server.

## Orientation

Start here before server-impacting work:

```bash
git status --short --branch
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl binding list"
ssh svcops "/usr/local/bin/opsctl binding status"
ssh svcops "/usr/local/bin/opsctl apache status"
ssh svcops "/usr/local/bin/opsctl profile list"
```

Expected update status when current:

```text
approved_matches_installed=yes
```

For runtime-target-specific work, establish layers in this order:

```text
intended runtime binding -> actual Apache route -> live image truth -> canonical runtime recipe -> runtime profile -> applied manifest
```

The binding registry declares the intended relationship between immutable instance id, Linux
account, public host, family, runtime class, and ports. Apache is actual route state. Running wrapper
image labels are actual runtime state.

## Operating Agent Surface

Codex and Gemini CLI are the standard natural-language operating CLIs for the `svcops` Unix account.
The install manages only that account's surface:

```text
/home/svcops/AGENTS.md
/home/svcops/.codex/AGENTS.md
/home/svcops/.gemini/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops
/usr/local/bin/agent-runtime-ops-mcp
Codex MCP registration: agent-runtime-ops
Gemini MCP settings and repo include directory: ~/.gemini/settings.json
```

This must not affect other server accounts or a developer's local Codex/Gemini account.

Codex ChatGPT login for the `svcops` account:

```bash
ssh svcops
codex login --device-auth
codex login status
```

Gemini CLI API key for the `svcops` account:

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

Do not put the Codex login token or Gemini API key in chat, command arguments, MCP JSON arguments,
or repo files.

## Deploy an Approved Repo Update

After committing and pushing, get the full SHA:

```bash
git rev-parse HEAD
```

Give the root/admin approval command exactly:

```bash
sudo /usr/local/bin/opsctl update approve FULL_40_CHARACTER_COMMIT_SHA
```

After approval, install as `svcops`:

```bash
ssh svcops "sudo /usr/local/bin/opsctl self-update"
```

Verify:

```bash
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl binding list"
ssh svcops "/usr/local/bin/opsctl binding status"
ssh svcops "/usr/local/bin/opsctl apache status"
ssh svcops "/usr/local/bin/opsctl profile list"
ssh svcops "codex mcp list"
```

If the work touched a target, also verify:

```bash
ssh svcops "sudo /usr/local/bin/opsctl runtime truth TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

Do not claim server completion after local tests only.

## MCP Setup and Smoke Test

Install creates:

```bash
/usr/local/bin/agent-runtime-ops-mcp
```

It attempts Codex registration:

```bash
codex mcp add agent-runtime-ops -- /usr/local/bin/agent-runtime-ops-mcp
```

Verify registration:

```bash
ssh svcops "codex mcp list"
```

Use newline-delimited JSON-RPC for smoke tests. Do not run the MCP server interactively for a long
session:

```bash
ssh svcops "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"smoke\",\"version\":\"1\"}}}' '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}' | /usr/local/bin/agent-runtime-ops-mcp"
```

The server must write only valid MCP JSON-RPC messages to stdout.

## Check a Runtime Binding

Preferred MCP tool:

```text
target_check {"target":"TARGET"}
```

Manual equivalent:

```bash
ssh svcops "/usr/local/bin/opsctl status TARGET"
ssh svcops "/usr/local/bin/opsctl binding status TARGET"
ssh svcops "/usr/local/bin/opsctl apache status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

For group checks, prefer MCP selector arguments such as `runtime_class` or `family` instead of many
parallel per-target calls.

## Binding and Public Host Diagnosis

MCP tool names do not fully explain the layering. Always keep these facts separate:

```text
binding_status = intended instance/account/host/family/class/port binding
apache_status = actual Apache public host and proxy port state
runtime_truth = running image labels and runtime recipe/profile state
```

For a router/subdomain/public-host question, inspect intended binding and actual route before
drawing conclusions:

```bash
ssh svcops "/usr/local/bin/opsctl binding status TARGET"
ssh svcops "/usr/local/bin/opsctl apache status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth LINUX_ACCOUNT"
```

Interpretation:

```text
binding public_host is the intended external name
Apache public_host is the current configured external name
binding gateway_port must equal Apache gateway_port
DNS/wildcard acceptance is not enough to prove Apache dispatch to the target
image labels do not prove intended public host, Linux account, or host port allocation
```

Changing the visible site name means changing the binding public host and Apache ServerName
together. Use the dedicated command and verify the full path:

```bash
ssh svcops "sudo /usr/local/bin/opsctl binding set-public-host TARGET NEW-NAME.ji-tech.co.kr"
ssh svcops "/usr/local/bin/opsctl binding status TARGET"
ssh svcops "/usr/local/bin/opsctl apache status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live LINUX_ACCOUNT"
```

Do not hand-edit Apache alone for a normal public host change. `apache set-host` is a low-level
repair path. Do not rename Linux accounts unless there is a separate migration plan covering home
directory, secrets, NAS, containers, labels, backups, and state.

## Image Rollout

Use digest-pinned wrapper and product images. Do not use release-state rollout commands; the public
operating path is the image rollout toolset below.

Rollout order is dev first, then customer canary, then explicit customer targets. A customer canary
is a bridge for promotion, not the first place to discover whether the target image recipe works.
The same wrapper digest should carry the runtime recipe for both dev and customer projections.

Treat NAS as part of the target image runtime contract. Do not "fix" NAS by hand on one customer
account and then promote that image. The wrapper image must declare the NAS root, read-only policy,
mount propagation, and host-propagated child CIFS mode; `runtime truth` and `check --live` must then
confirm that the rendered compose and running container preserve that contract.

Plan:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-plan --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
```

Apply to a dev target:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-dev-apply --target dev-oc --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl runtime truth dev-oc"
ssh svcops "sudo /usr/local/bin/opsctl check --live dev-oc"
```

Apply to one customer canary:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-canary --target oc3 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl runtime truth oc3"
ssh svcops "sudo /usr/local/bin/opsctl check --live oc3"
```

Promote the exact live canary image to explicit targets:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-promote --from-target oc3 --targets oc1,oc2,oc4"
```

After promotion, verify each target with `runtime truth` and `check --live`.

## Dev Recipe

Dev source mode means the container sees an external source/output path. It does not mean customer
targets should use source mounts.

Inspect:

```bash
ssh svcops "/usr/local/bin/opsctl recipe status dev-oc"
```

Apply from an existing output directory:

```bash
ssh svcops "sudo /usr/local/bin/opsctl recipe apply-dev dev-oc --source-output /ABS/PATH --allow-first-apply"
```

Or sync from a source directory into the managed target stage:

```bash
ssh svcops "sudo /usr/local/bin/opsctl recipe apply-dev dev-oc --sync-from /ABS/PATH --allow-first-apply"
```

Then verify:

```bash
ssh svcops "sudo /usr/local/bin/opsctl runtime truth dev-oc"
ssh svcops "sudo /usr/local/bin/opsctl check --live dev-oc"
```

## Runtime Secret Injection

Runtime provider secrets are target secrets, not Gemini CLI credentials for the `svcops` account.

Never print the secret value. Preferred terminal stdin pattern:

```bash
ssh svcops
read -rsp "GEMINI_API_KEY for dev-oc: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set dev-oc --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
```

MCP may use `runtime_secret_set_from_file` only with an allowed `secret_file` path. Do not pass raw
keys as JSON arguments.

## Handoff Credentials

Gateway tokens and workspace passwords are handoff credentials, not runtime provider secrets.

Discover structure and presence without printing values:

```bash
ssh svcops "sudo /usr/local/bin/opsctl handoff status TARGET"
```

If value retrieval is necessary and authorized, use only the exact manual value command reported by
`handoff status`. Explain that it prints a credential, ask the operator to run it in their own
terminal, and tell them not to paste the secret value back into chat. Record only non-secret status.

The non-secret command generator is:

```bash
ssh svcops "sudo /usr/local/bin/opsctl handoff value-command TARGET"
```

The value command it reports is:

```bash
ssh svcops "sudo /usr/local/bin/opsctl handoff print TARGET"
```

## Apply and Rollback

Normal rollouts use image rollout tools. Use single-target `apply` only to re-apply the target's current
runtime manifest after checks identify that exact target:

```bash
ssh svcops "/usr/local/bin/opsctl binding status TARGET"
ssh svcops "/usr/local/bin/opsctl apache status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth TARGET"
ssh svcops "sudo /usr/local/bin/opsctl apply TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

For first migration from an older runtime, use `--allow-first-apply` only when the operator intends
that exact target:

```bash
ssh svcops "sudo /usr/local/bin/opsctl apply TARGET --allow-first-apply"
```

Rollback:

```bash
ssh svcops "/usr/local/bin/opsctl status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl rollback TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

## NAS Operations

Read status:

```bash
ssh svcops "/usr/local/bin/opsctl nas requests"
ssh svcops "/usr/local/bin/opsctl nas mounted TARGET"
ssh svcops "/usr/local/bin/opsctl nas policy-check TARGET //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas credential status TARGET //HOST/SHARE"
```

Mount an already-credentialed and policy-allowed share:

```bash
ssh svcops "/usr/local/bin/opsctl nas policy-check TARGET //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas mount TARGET //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

Temporary unmount keeps official credentials and managed fstab entries:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas unmount TARGET //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas credential status TARGET //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted TARGET"
```

Permanent remove unmounts the share and removes official credentials plus the managed fstab entry:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas credential status TARGET //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas remove TARGET //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas credential status TARGET //HOST/SHARE"
ssh svcops "/usr/local/bin/opsctl nas mounted TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

Customer NAS requests can be processed once:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas approve-auto"
```

Do not add NAS shares as compose volumes. Managed NAS is a child CIFS mount under
`/home/ocN/nas_docs`.

## OpenClaw Heartbeat

Check heartbeat:

```bash
ssh svcops "sudo /usr/local/bin/opsctl heartbeat status TARGET"
```

Disable heartbeat:

```bash
ssh svcops "sudo /usr/local/bin/opsctl heartbeat disable TARGET"
```

Verify:

```bash
ssh svcops "sudo /usr/local/bin/opsctl heartbeat status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
```

Disabled heartbeat should include:

```text
target=TARGET
heartbeat_config_every=0m
heartbeat_config_enabled=no
heartbeat_disable_status=ok
```
