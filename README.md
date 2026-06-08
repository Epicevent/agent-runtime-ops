# Agent Runtime Ops

Public runtime operations tooling for JI TECH agent services.

This repository does not store live server state. Live state stays on the
server under `/srv/openclaw-ops`.

## Repository Boundaries

```text
Epicevent/openclaw-jitech
  OpenClaw product source and product image.

Epicevent/hermes-jitech
  Hermes product source and product image.

Epicevent/agent-runtime-ops
  Runtime profiles, wrapper image recipes, apply/check/rollback tooling,
  NAS policy logic, admin console, and schema definitions.

/srv/openclaw-ops
  Private server state: slots, lanes, releases, NAS policy, action logs,
  drift reports, and applied manifests.
```

This repository must not contain customer names, NAS passwords, API keys,
gateway tokens, customer documents, or real slot assignment state.

## Core Rule

Slots are described by two deployment identities:

```text
image release + runtime profile
```

The image release describes what is inside the container. The runtime profile
describes how the image is executed on the server.

Runtime profiles live in `profiles/runtime/`. Compose files are rendered from
profile templates only. Operational commands must not invent compose fragments
or include compose files merely because they happen to exist.

## Runtime Profiles

```text
profiles/runtime/
  openclaw-customer/
  hermes-customer/
  openclaw-dev/
  hermes-dev/
```

Profile names do not include `v1`. The profile name is the semantic role; the
profile digest and ops repository commit are the version identity.

## CLI Shape

The CLI entrypoint is `opsctl`.

```text
opsctl status SLOT
opsctl plan SLOT
opsctl apply SLOT
opsctl rollback SLOT
opsctl check SLOT
opsctl rollout LANE
opsctl release add NAME IMAGE
opsctl release promote NAME LANE
opsctl nas requests
opsctl nas approve-auto
opsctl nas policy-check SLOT SHARE
opsctl admin serve
```

`status`, `plan`, `check`, and `nas policy-check` are non-mutating. Mutating
commands are intentionally guarded in the initial skeleton until the full apply
engine is implemented and reviewed.

## Install Shape

An administrator installs the tool package with sudo. The installer may ask for
the administrator password. After installation, the existing `svcops` operating
account runs `opsctl`.

```bash
curl -fsSL https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/main/install.sh | sudo bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -u svcops opsctl profile list
```

Live state remains outside this repository under `/srv/openclaw-ops`.

## Development Check

```bash
python -m compileall opsctl
python -m agent_runtime_ops.cli --help
python -m agent_runtime_ops.cli profile list
```
