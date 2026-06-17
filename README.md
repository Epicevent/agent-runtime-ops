# Agent Runtime Ops

Public operations tooling for JI TECH AI runtime accounts.

This repository owns the operator-facing tools, runtime profiles, canonical runtime recipes, wrapper
image contract, MCP server, and runbooks. It does not store customer documents, passwords, API keys,
gateway tokens, or mutable production state. Private state lives on the server under
`/srv/openclaw-ops`.

## Install

First install or bootstrap from a full commit SHA:

```bash
OPS_REF="FULL_40_CHARACTER_COMMIT_SHA"
sudo -v
curl -fsSL "https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/$OPS_REF/go" \
  | sudo bash -s -- "$OPS_REF"
```

The normal update flow is:

```text
commit/push -> root approve full SHA -> svcops self-update -> status/check/live verification
```

Root approval command:

```bash
sudo /usr/local/bin/opsctl update approve FULL_40_CHARACTER_COMMIT_SHA
```

Install the approved SHA:

```bash
ssh svcops "sudo /usr/local/bin/opsctl self-update"
```

The server keeps only the active release as a code directory. Older installed tool releases are pruned
after a successful install, leaving hash/summary history under `/opt/agent-runtime-ops/release-history`.

Verify after install:

```bash
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl profile list"
ssh svcops "/usr/local/bin/opsctl binding list"
```

## Runtime Truth

Image rollout truth is not `releases.yaml` or a rollout ledger. The public rollout path is:

```text
digest-pinned wrapper image + digest-pinned product image
wrapper image labels
runtime binding
runtime manifest
live container image labels
```

The routing registry stays intentionally small. It owns the Apache-facing contract only:

```text
linux_account, public_host, gateway_port, bridge_port, enabled
```

It must not become the source of image, runtime profile, canonical recipe, or applied-result truth.

## Core Commands

Read-only orientation:

```bash
ssh svcops "/usr/local/bin/opsctl status SLOT"
ssh svcops "/usr/local/bin/opsctl plan SLOT"
ssh svcops "/usr/local/bin/opsctl check SLOT"
ssh svcops "sudo /usr/local/bin/opsctl check --live SLOT"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth SLOT"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth --all"
ssh svcops "/usr/local/bin/opsctl binding status TARGET"
ssh svcops "/usr/local/bin/opsctl apache status TARGET"
```

Single-slot re-apply and rollback:

```bash
ssh svcops "sudo /usr/local/bin/opsctl apply SLOT"
ssh svcops "sudo /usr/local/bin/opsctl apply SLOT --allow-first-apply"
ssh svcops "sudo /usr/local/bin/opsctl rollback SLOT"
```

Normal product rollout uses only image rollout commands:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout status --family hermes"
ssh svcops "sudo /usr/local/bin/opsctl rollout image-plan --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl rollout image-dev-apply --slot dev-oc --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl rollout image-canary --slot oc3 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl rollout image-promote --from-slot oc3 --slots oc1,oc2,oc4"
```

The old release command group and release-state rollout flow are absent from the public CLI.

## Secrets

Never pass raw secrets through MCP JSON arguments or chat. Use terminal stdin or a restricted secret
file path.

Runtime provider secret example:

```bash
ssh svcops
read -rsp "GEMINI_API_KEY for dev-oc: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set dev-oc --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
```

Handoff credentials are different from runtime provider secrets:

```bash
ssh svcops "sudo /usr/local/bin/opsctl handoff status SLOT"
```

If value retrieval is explicitly authorized, use only the exact manual command printed by
`handoff status`. Do not paste the secret value back into chat.

## NAS

NAS requests and managed mounts:

```bash
ssh svcops "sudo /usr/local/bin/opsctl nas requests"
ssh svcops "/usr/local/bin/opsctl nas mounted SLOT"
ssh svcops "sudo /usr/local/bin/opsctl nas approve-auto"
ssh svcops "sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE"
ssh svcops "sudo /usr/local/bin/opsctl nas remove SLOT //HOST/SHARE"
```

Manual credential injection uses stdin:

```bash
printf '%s' "$NAS_PASSWORD" | ssh svcops "sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE --username NAS_USER --password-stdin"
```

## Codex and MCP

Install activates:

```text
/usr/local/bin/opsctl
/usr/local/bin/agent-runtime-ops-mcp
/home/svcops/AGENTS.md
/home/svcops/GEMINI.md
/home/svcops/.codex/skills/agent-runtime-ops
```

The MCP server wraps `opsctl` with structured tools for agents. It does not approve updates and does
not accept raw secret values.

Smoke checks:

```bash
ssh svcops "codex mcp list"
ssh svcops "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"smoke\",\"version\":\"0\"}}}\n' | /usr/local/bin/agent-runtime-ops-mcp"
```
