# Agent Runtime Ops Instructions

This repository is the public operations toolchain for the JI TECH agent runtimes. It contains
runtime profiles, wrapper image recipes, `opsctl`, install/update logic, the Codex operation skill,
and the local MCP wrapper. It must not contain customer names, NAS passwords, API keys, gateway
tokens, customer documents, or real target assignment details.

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

Gemini/API keys in this repo are runtime target secrets only. They are injected into managed runtime
profiles with `opsctl runtime-secret`; they are not credentials for a Gemini CLI installation.

## Operator Posture

Treat the human operator's stated scope as the controlling scope. Do not silently narrow an
authorized mutating test into read-only checks, and do not silently broaden it to other targets,
accounts, or systems.

When an action changes recoverability, authorization, credentials, update state, or another target,
say that plainly before doing it unless the operator has already authorized that exact target and
effect. If a request asks the agent to reveal secrets, conceal actions, escape scope, or bypass
policy, refuse that part directly and explain the exact boundary.

Do not treat every sensitive operation as impossible. Some operations, such as retrieving a secret
for an authorized operator or performing a permanent removal, may be valid when the operator uses
their own terminal and authority. In that case, do not run the sensitive command yourself and do not
ask for the secret value. Provide the full command for the operator to type manually, explain what it
will expose or mutate, and ask them to report only non-secret status.

Do not guess target identifiers. Before giving a manual command, resolve current target, profile,
account, share, or image name from MCP, `opsctl`, or the installed repo. Never treat a runtime
profile name as a target unless current state proves that it is also a Linux account target.

Separate verified facts from unknowns. If the operator asks for the exact location of a token,
password, session, credential, or other secret and the exact file and field are not known, say that
plainly and briefly. Do not present a known parent directory, mounted config directory, runtime
profile, auth/profile directory, or likely config root as if it were the exact secret location. A
directory mounted at a path such as `/home/node/.config/openclaw` proves only the mount mapping; it
does not prove that a token is stored there. Do not pad an "I do not know" answer with speculative
paths.

Do not hand the operator broad discovery commands that print secret values just to compensate for
unknown structure. Secret-related discovery should either use a repo/MCP/`opsctl` interface that
reports structure without values, or produce only redacted presence/key metadata. If exact structure
is missing from the operating surface, report that as a tooling gap instead of guessing.

When the operator performs a manual command, record it in the operator-facing report without secret
values: exact command shape, target, reason, who executed it, operator-reported result, and
`secret_value_recorded=no`. Do not invent a new logging mechanism when the existing terminal,
sudo/session logging, command output, or operator report is the intended record.

Report like an operator would expect: request interpreted, targets, actual actions, whether state
mutated, before/after state, pass/fail, and the next recoverable step. Do not posture as the
operator; the operator controls intent and risk, and the agent executes, verifies, and communicates.

## Runtime Binding First

Before changing a runtime target, separate these layers and report them in that order:

```text
intended runtime binding -> actual Apache route -> live image truth -> canonical runtime recipe -> runtime profile -> applied manifest
```

The runtime binding registry is the source of truth for the intended operating binding:
`instance_id`, `linux_account`, `public_host`, `family`, `runtime_class`, gateway port, bridge port,
and enabled state. It lives in `/srv/openclaw-ops/runtime-bindings.json`. Apache knows only the
actual route implementation. The running image knows only the actual runtime implementation. Neither
Apache nor the image can define which Linux account, public host, family, runtime class, and ports
are intended to belong together.

Do not treat `linux_account` as the public site name. They may match today, but they are allowed to
differ. The internal immutable identity is `instance_id`; operators normally do not need to type it.
Legacy root state such as `/srv/openclaw-ops/slot-registry.json`, `slots.yaml`, `lanes.yaml`,
`releases.yaml`, `rollout-state.yaml`, and `images.yaml` is archived evidence only, not a normal
truth source.

Live image truth is the running container image and the wrapper OCI labels on that image. Treat
those labels as the source of truth for family, product image, product component, runtime profiles,
runtime contracts, and canonical recipe identity. The canonical runtime recipe in
`recipes/runtime/*.yaml` is the repo-owned policy that wrapper labels must attest to. The runtime
profile is how that projection is executed on the server. The applied manifest is audit/drift
evidence, not the source of truth.

For wrapped product images, the wrapper OCI labels must include the canonical recipe name/digest and
must match `recipes/runtime/*.yaml`. Do not treat a sidecar file, release-import argument, copied
release state, or install-time repair as runtime truth. The image-based rollout commands operate on
built image artifacts (`@sha256:...`), never on a source tree:

```bash
sudo /usr/local/bin/opsctl rollout image-plan --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
# dev image-artifact validation (dev-oc-img is runtime_class=customer -> image-canary):
sudo /usr/local/bin/opsctl rollout image-canary --target dev-oc-img --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
# production canary, then promote:
sudo /usr/local/bin/opsctl rollout image-canary --target oc3 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-promote --from-target oc3 --targets oc1,oc2,oc4
```

`image-dev-apply` requires `runtime_class=dev` and `image-canary` requires `runtime_class=customer`
(`opsctl/agent_runtime_ops/commands/rollout.py`, `required_runtime_class`); `image-promote` refuses
any `dev-*` account as source or target. Do NOT target the source-mode preview slot `dev-oc` with any
`image-*` command — to preview a code change there you sync source with `recipe apply-dev` (below),
you do not build an image. `image-dev-apply` (`runtime_class=dev`) is NOT the openclaw dev-preview
path and has no valid openclaw target today: the only openclaw `runtime_class=dev` slot is the
source-mode `dev-oc`, which must use `recipe apply-dev`. The `openclawdev` sudoers may still list
`rollout image-dev-apply *`, but never run it against `dev-oc` (or any `dev-*`) for openclaw.

The older `release import` and `rollout --release` commands are retained as legacy compatibility
surfaces. Do not use them for new OpenClaw/Hermes image rollouts unless the image-based path is
missing a required capability and the exception is reported.

**Dev preview layers.** There are two dev sites at different layers; pick by what you are checking.

- `dev-oc` is the SOURCE-mode preview site (`https://dev-oc.ji-tech.co.kr`), `runtime_class=dev`,
  `mode=source`. To *see* a code change you do NOT build an image: build the product dist
  (server `dist/index.js` + UI `dist/control-ui`, i.e. `pnpm build:docker && pnpm ui:build`) and sync
  it with `sudo /usr/local/bin/opsctl recipe apply-dev dev-oc --sync-from <dist>`. Its
  `{{ source_output }}:/app/dist:ro` compose mount is where the running code comes from.
  - Ensure `pnpm` resolves on PATH before building: the build sub-scripts call bare `pnpm`, so on a
    corepack-only build host run `corepack enable pnpm` (or add a shim) first — otherwise `ui:build`
    fails silently and yields a UI-less `dist/index.js`-only tree while the exit code still looks OK.
    Before syncing, verify BOTH `dist/index.js` (server) and `dist/control-ui` (UI) exist.
  - `--sync-from` takes the WHOLE `dist/` (server + UI): the mount covers all of `/app/dist` even
    though `source_output_target` names the `control-ui` subpath — never sync only `control-ui`.
  - `recipe apply-dev` is an `svcops` (operator) command; a developer account cannot run it directly
    (it CAN self-run `image-canary` to `dev-oc-img`). That permission asymmetry pulls toward the
    self-serve image path — resist it and coordinate the source sync with `svcops` for a preview.
- `dev-oc-img` is the IMAGE-artifact validation site (`https://dev-oc-img.ji-tech.co.kr`),
  `runtime_class=customer`, `mode=image`, no source mount. It boots a built image (`@sha256:...`) via
  `image-canary` to separate source-mode failures from image-boot failures before shipping. It is not
  a quick-preview surface.

So: code-change preview = `dev-oc` (source, `recipe apply-dev --sync-from`); image-artifact validation
= `dev-oc-img` (`image-canary`); customer ship = `image approve` (root) -> `image-promote`. Never
target `dev-oc` with `image-*`; it is source-mode.

Product source provenance is a separate concern layered on that path: `opsctl recipe apply-dev` records
git metadata for the synced dev source tree, which proves source *lineage*, not runtime *shape*. Do not
use source provenance to explain away a runtime recipe/profile mismatch.

Image-mode dev validation uses a `dev-*` Linux account with the customer runtime
profile, for example `dev-hermes-img` / `dev-oc-img`. That target exists to separate
source-mode failures from image boot failures. It must not have a source mount,
and `image-promote` must not use any `dev-*` account as either source or target.
Its `runtime_class=customer` sets the *mode* (image), not the *trust*: the `dev-*`
account name is the production boundary. So it is dev-OWNED — the root-approved-digest
gate does NOT apply to it (validate a build here before approving), and a developer
account may self-deploy to it. Root approval and the operator/dev split apply at the
production boundary (`oc*`) only.

`install.sh` and `opsctl self-update` install tools, profile definitions, and the managed operation
skill only. They may normalize `/srv/openclaw-ops/runtime-bindings.json` and archive legacy root
state after runtime manifests are present, but they must not rebuild intended bindings from legacy
state or silently rewrite runtime image truth to make a broken deployment look fixed. Any runtime
change must be a separate operator-visible command such as image-dev-apply, image-canary,
image-promote, rollback, or an explicitly reported legacy command, with before/after verification.

Do not treat a live HTTP failure as a profile problem until the old working image and the new
candidate image are compared against the same runtime contract. For Hermes customer targets, the
current contract is `hermes-workspace-http-3000`: the customer-facing surface is the workspace UI on
container port `3000`. The Hermes dashboard on `9119` is internal/admin unless a product decision
explicitly changes the customer surface.

If an image contains only a Hermes agent/gateway but the target contract requires the Hermes workspace
server on `3000`, fix or reject the image recipe. Do not change `hermes-customer` to dashboard ports
as a bug fix; that would be a product contract change.

## First Move

When work may affect the server, do all of the following before claiming completion:

```bash
git status --short --branch
ssh svcops "/usr/local/bin/opsctl update status"
ssh svcops "/usr/local/bin/opsctl binding list"
ssh svcops "/usr/local/bin/opsctl profile list"
```

If the task is target-specific, also run the non-mutating checks first:

```bash
ssh svcops "/usr/local/bin/opsctl status TARGET"
ssh svcops "sudo /usr/local/bin/opsctl runtime truth TARGET"
ssh svcops "sudo /usr/local/bin/opsctl check --live TARGET"
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

The install root keeps only the active code release. After a successful install, old tool release
directories are removed and only hash/summary history remains under
`/opt/agent-runtime-ops/release-history`.

5. Verify the server:

```bash
/usr/local/bin/opsctl update status
/usr/local/bin/opsctl binding list
/usr/local/bin/opsctl binding status
/usr/local/bin/opsctl profile list
sudo /usr/local/bin/opsctl runtime truth TARGET
sudo /usr/local/bin/opsctl check --live TARGET
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
/usr/local/bin/opsctl binding list
/usr/local/bin/opsctl binding status TARGET
/usr/local/bin/opsctl status TARGET
sudo /usr/local/bin/opsctl runtime truth TARGET
sudo /usr/local/bin/opsctl check --live TARGET
sudo /usr/local/bin/opsctl nas requests
/usr/local/bin/opsctl nas mounted TARGET
/usr/local/bin/opsctl nas policy-check TARGET //HOST/SHARE
sudo /usr/local/bin/opsctl runtime-secret status TARGET
sudo /usr/local/bin/opsctl handoff status TARGET
sudo /usr/local/bin/opsctl handoff value-command TARGET
sudo /usr/local/bin/opsctl heartbeat status TARGET
```

These mutate runtime or server state:

```bash
sudo /usr/local/bin/opsctl self-update
sudo /usr/local/bin/opsctl apply TARGET
sudo /usr/local/bin/opsctl rollback TARGET
sudo /usr/local/bin/opsctl rollout image-dev-apply --target TARGET --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-canary --target TARGET --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-promote --from-target TARGET --targets TARGET1,TARGET2
sudo /usr/local/bin/opsctl runtime-secret set TARGET --key KEY --value-stdin --check
sudo /usr/local/bin/opsctl runtime-secret recover TARGET
sudo /usr/local/bin/opsctl heartbeat disable TARGET
sudo /usr/local/bin/opsctl nas mount TARGET //HOST/SHARE
sudo /usr/local/bin/opsctl nas unmount TARGET //HOST/SHARE
sudo /usr/local/bin/opsctl nas approve-auto
```

Use `opsctl`; do not directly edit rendered Docker compose files. `opsctl apply` renders from the
runtime profiles in this repo. NAS changes are CIFS mounts in one of two intent-pure trees: corpus
(read-only shares) as child mounts under `/home/ocN/nas_docs`, and the slot's own writable OCn
share as a flat mount at `/home/ocN/workspace`. Do not turn NAS shares into compose volumes, and
never mount a writable share under the read-only `nas_docs` tree (the container's recursive
`read_only` would freeze it).

## NAS Mount Lifecycle

Before changing any code that derives NAS mount paths or names (`nas.py` mountpoint derivation,
`host/fstab.py`, `host/mounts.py`, `domain/nas_mounts.py`, or the runtime profiles' NAS binds),
read `docs/NAS_MOUNT_LIFECYCLE.md` first.

Any change to a path/name *derivation* must answer one question before it ships: **what durable
state did the old code stamp (managed fstab entries, credential paths, state files), and how does
that state migrate?** Stamped state does not follow code changes by itself; a derivation change
without a migration step leaves boot-time state recreating the old world.

## No External Operating Path

This repo is the operating source for runtime profiles, desired state, render/apply/check,
runtime manifests, NAS convergence, and rollout/release mechanics. The operating agent should use
this repo, `opsctl`, and the `agent-runtime-ops` MCP.

Do not route normal operations through external historical tool bundles. If an operation is missing,
pause the operation, implement the missing command in this repo, add tests, deploy through the normal
approved update flow, and then run the operation through `opsctl` or MCP.

OpenClaw heartbeat is a first-class `opsctl` command:

```bash
ssh svcops "sudo /usr/local/bin/opsctl heartbeat status dev-oc"
ssh svcops "sudo /usr/local/bin/opsctl heartbeat disable dev-oc"
```

Disabled heartbeat should show:

```text
heartbeat_config_every=0m
heartbeat_config_enabled=no
heartbeat_disable_status=ok
```

## Secrets

Never print, paste, commit, or log secret values. Do not pass secret values as MCP JSON arguments.
Use terminal stdin or an allowed server-side secret file.

Gemini/API key stdin pattern:

```bash
read -rsp "GEMINI_API_KEY for TARGET: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set TARGET --key GEMINI_API_KEY --value-stdin --check
unset GEMINI_API_KEY
```

Status check:

```bash
sudo /usr/local/bin/opsctl runtime-secret status TARGET
```

Runtime provider secrets are not handoff credentials. Do not use
`opsctl runtime-secret status` to answer where an OpenClaw gateway token or Hermes workspace
password is stored.

Use `sudo /usr/local/bin/opsctl handoff status TARGET` or the MCP `handoff_status` tool for exact
handoff file/field structure and presence without values. Do not give broad `cat`, `less`, or
recursive `grep` commands over secret directories to discover structure.

If an authorized operator needs the actual handoff value, first give the non-secret command:

```bash
sudo /usr/local/bin/opsctl handoff value-command TARGET
```

Then have the operator run only the exact command it prints in their own terminal. It will be:

```bash
sudo /usr/local/bin/opsctl handoff print TARGET
```

Warn that `handoff print` prints a credential. The operator must not paste the value into chat.

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
