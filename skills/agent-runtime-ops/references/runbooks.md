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
cd /opt/agent-runtime-ops/current
gemini "Reply exactly: OK"
```

The managed `/usr/local/bin/gemini` wrapper sets the trusted workspace default and allows the
`agent-runtime-ops` MCP server automatically when the executing Unix account is `svcops`. Do not ask
operators to type trust/MCP flags for normal `svcops` Gemini sessions.

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

## Typed Root Action and Receipt Recovery

Use this flow only for an operation that the installed executable root-action registry marks enabled.
The historical inventory is evidence, not an executable menu. `kwrag.network_ensure` is hard denied by
the product boundary and must never be translated into another operation, shell command, or handler.

Construct one `agent-runtime-root-action-manifest/v1` object with:

- a fresh unique job, request, and lineage identity;
- the current request/task identity as `request.reply_target`;
- a fresh UTC-second `submitted_at`;
- the exact enabled operation id/version and typed parameters;
- the expected pre-state plus evidence-backed purpose, premises and falsifiers, targets, changes,
  recovery, and risk delta.

Submit it with the MCP tool:

```text
root_action_submit {"manifest": EXACT_TYPED_MANIFEST_OBJECT}
```

Submission creates only a pending sealed job. It does not authenticate, approve, dispatch, or execute.
Preserve all four fields of the returned handle without editing them:

```text
job_id + job_digest + request_id + reply_target
```

If submit returns `acceptance_state=unknown`, the handle is deterministically derived from the sealed
manifest so the agent can recover safely. Call `root_action_retrieve` with that handle before doing
anything else. Never resubmit, change the digest, or invent a replacement job merely because the
submission response was lost.

The exact browser review is:

```text
https://ops.ji-tech.co.kr/root-actions?job=JOB_ID
```

The user reviews the rendered digest, impact, pre-state, recovery, and risk delta and approves only in
that OPS page with a UV-required registered passkey. The read-only OPS session token is not approval.
There is intentionally no MCP approval or credential-enrollment tool.

After submission, the agent owns waiting and receipt recovery:

```text
root_action_wait {"handle": COMPLETE_UNCHANGED_HANDLE}
```

The tool waits for a bounded interval. If it returns `retryable=true` with
`terminal_receipt_polling_timed_out`, call `root_action_wait` again with the same unchanged handle. An
identity-bound `unknown` notice is returned immediately with `retryable=false`: stop polling and keep
the handle and notice as recovery evidence. Do not ask the user to poll, run a root shell, wait in a
terminal, or paste output. `root_action_retrieve` is a read-only single snapshot for diagnosis; it does
not replace continued receipt recovery.

Stop only on an identity-bound terminal receipt, an explicit user cancellation before approval, or a
real invariant/availability failure requiring a decision. A failed, rejected, expired, canceled, or
prestart-failed terminal receipt is a recovered outcome, not permission to resubmit. An unknown notice
must retain the same recovery handle and must never be converted into a second execution attempt.

Before reporting success, verify that the returned handle, projection digest, terminal state, and
receipt all belong to the original job digest and reply target. Report sanitized terminal facts; raw
root output remains root-only.

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

This is runtime product/wrapper image deployment. It is not `opsctl self-update` and not the
"Deploy an Approved Repo Update" flow.

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

Hermes runtime deployment order:

```text
dev-hermess source-mode check
-> fast hermes-runtime product image
-> fast agent-runtime-hermes wrapper image
-> dev-hermes-img image-mode validation
-> oc20 customer canary
-> image-promote from oc20 to explicit customer targets
```

Hermes target rules:

```text
dev-hermess     source mode; never a promote source
dev-hermes-img  image mode using runtime_class=customer; no source mount; never a promote source or target
oc20            customer canary; valid promotion source after checks pass
```

`dev-hermes-img` has a `dev-*` Linux account for operator visibility but uses the customer runtime
profile. Apply images to it with `image-canary`, not `image-dev-apply`.

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

Hermes image-mode dev validation:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-canary --target dev-hermes-img --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl check --live dev-hermes-img"
ssh svcops "sudo /usr/local/bin/opsctl projection verify-target dev-hermes-img --wrapper-image WRAP@sha256:... --product-image PROD@sha256:... --live"
ssh svcops "sudo /usr/local/bin/opsctl checklist pack dev-hermes-img --pack hermes-runtime --gemini-chat-smoke"
```

Hermes customer canary:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-canary --target oc20 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl check --live oc20"
ssh svcops "sudo /usr/local/bin/opsctl projection verify-target oc20 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:... --live"
ssh svcops "sudo /usr/local/bin/opsctl checklist pack oc20 --pack hermes-runtime --gemini-chat-smoke"
```

Promote the exact live canary image to explicit targets:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-promote --from-target oc3 --targets oc1,oc2,oc4"
```

For Hermes, promote from `oc20`, not from `dev-hermes-img`:

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-promote --from-target oc20 --targets oc15,oc16,oc17,oc18,oc19"
```

After promotion, verify each target with `runtime truth` and `check --live`.

## OpenClaw Image Rollout: Trust Gate, Config Preflight, Selftest

OpenClaw rollout uses the same digest-pinned image flow as Hermes, plus three OpenClaw-specific
gates. Slot roles:

```text
dev-oc        source mode; the built dist/ (server dist/index.js + UI) is source-mounted at /app/dist; dev-owned; never a promote source/target
dev-oc-img    image mode (runtime_class=customer) but dev-OWNED; pure-image dev canary; NOT approval-gated; never a promote source/target
oc14          production customer canary; valid promote source after checks pass
oc1..oc13     production customer targets; reached only by image-promote
```

Two axes, not one: `runtime_class` is the **mode** (source/image); the **environment**
(dev/production) is the `dev-*` account-name boundary (same one `image-promote` uses). The
root-approval gate and self-deploy rules key on **environment**, not on `runtime_class`. So
`dev-oc-img` is image-mode (fidelity) yet dev-owned (no production gate).

### 1. Image trust gate (root-approved digest) — PRODUCTION customer slots only

Trust is a root approval of the exact digest, not where it was built. Once a family/role is
approved, opsctl refuses any other digest for **production** customer slots (`oc*`). Dev-owned
slots (`dev-*`, including `dev-oc-img`) are NOT gated: a developer validates a fresh build on
`dev-oc-img` BEFORE approval (build -> validate -> approve -> promote).

Trust does NOT rest on build reproducibility (two builds of one commit produce different digests
— unpinned apt/pip + layer timestamps). It rests on approving the **exact artifact** you
validated and carrying that one digest unchanged (approve pins it, promote applies it verbatim).
`image approve` therefore reads the image's own `org.opencontainers.image.revision` label and,
when `--source-commit` is given, **refuses if it does not match** — binding the approved digest
to the commit it was built from. The verified revision is recorded and shown in `image status`.

```bash
# root login (NOT svcops sudo), like `update approve`:
#   product's revision = the openclaw-jitech source commit; wrapper's = the ops-repo commit.
sudo /usr/local/bin/opsctl image approve openclaw product PROD@sha256:... --source-commit <40-sha>
sudo /usr/local/bin/opsctl image approve openclaw wrapper WRAP@sha256:...
# read-only status (svcops, or MCP image_status):
ssh svcops "/usr/local/bin/opsctl image status"   # shows image_revision per approval
```

`image approve` is root-only and is NOT an MCP tool. `image status` is read-only.
`image approve` now needs docker (to read the image's revision label) — fine on a root login.

**Developer self-deploy:** a developer account (e.g. `openclawdev`) may deploy to its own
`dev-*` slots (`rollout image-dev-apply dev-oc`, `rollout image-canary dev-oc-img`) via a scoped
sudoers grant — no root approval or svcops handoff. opsctl refuses any non-`dev-*` target for a
developer account (production stays operator/root-only). Approve at the production boundary only.

### 2. Config preflight and migration

Before recreating a container, the apply gate validates the slot's on-disk config against the
TARGET image by running the product's own `config validate`, read-only. If the config would not
boot the target image it REFUSES before touching the running container (zero downtime):
`config preflight failed: ...; migrate first: sudo opsctl config migrate <slot>`.

Never hand-edit `openclaw.json`. Migrate with the product's own `doctor --fix` (atomic, writes a
timestamped `.bak`). The operator does NOT need to understand the config: migration is **reviewable**,
not a black box. `config migrate` prints a `diff …` of exactly what changed (secret values redacted),
so the operator sees the change instead of trusting doctor. Prefer `--dry-run` first — it previews the
change on a throwaway copy and shows the diff, writing nothing:

```bash
ssh svcops "sudo /usr/local/bin/opsctl config validate SLOT [--product-image PROD@sha256:...]"   # read-only
ssh svcops "sudo /usr/local/bin/opsctl config migrate  SLOT --dry-run"   # preview: show diff, write nothing
ssh svcops "sudo /usr/local/bin/opsctl config migrate  SLOT [--product-image PROD@sha256:...]"   # apply: doctor --fix, print diff, re-validate
```

Review the `diff` lines: a valid-but-wrong migration (e.g. a key removed with no replacement set)
shows here, and validation passing is NOT proof of correctness — check the diff, and if unexpected,
restore the `.bak`. A migrated config must stay valid for the slot's CURRENT image too (so a restart
can't crash it); when migrating customers still on an old image, confirm with `config validate`
against the running image. MCP tools: `config_validate`, `config_migrate` (accepts `dry_run: true`).

### 3. Canary and the openclaw-runtime selftest checklist

```bash
ssh svcops "sudo /usr/local/bin/opsctl rollout image-canary --target dev-oc-img --wrapper-image WRAP@sha256:... --product-image PROD@sha256:..."
ssh svcops "sudo /usr/local/bin/opsctl checklist pack dev-oc-img --pack openclaw-runtime"   # require checklist_status=pass
# then repeat for oc14, then: image-promote --from-target oc14 --targets oc1,...,oc13
```

The `openclaw-runtime` pack gates on the product-attested selftest via the single aggregate
`selftest_contract_ok`: the product declares its OWN `required_checks` (gateway readiness, a real
model completion, NAS access) in the selftest output, plus opsctl's own infra/edge checks (config
drift `config_disk_valid_for_running_image_ok`, public route, container identity). A NEW product
selftest check flows into both the apply gate and this pack automatically — do not restate product
check names in opsctl.

### Runtime model config (Hermes and OpenClaw)

`opsctl runtime set-model`, `runtime config-status`, and `runtime model-attest` support BOTH
families (each is root-only / svcops NOPASSWD). They dispatch on the slot's family:
- **Hermes**: read/write `.hermes/config.yaml` `agents.defaults.model.default` directly.
- **OpenClaw**: `config-status` reads `.openclaw/openclaw.json` `agents.defaults.model`
  (`provider/model` ref). `set-model` runs the product's OWN `models set` **inside the live gateway
  container** (`docker exec`) — preserving the canonical `agents.defaults.models` entry,
  provider-plugin repair, and load-time validation that a raw JSON write would skip — then prints a
  before/after config diff (`config_diff …`). It requires a **running** gateway container.

OpenClaw's provider is embedded in the model ref, so `--provider google --model gemini-3.5-flash`
composes to `google/gemini-3.5-flash`. The slot's already-injected provider key is reused (a
same-provider bump needs no new key). Verify with a REAL turn, not just config validity:

```bash
ssh svcops "sudo /usr/local/bin/opsctl runtime config-status oc1"                              # current provider/model
ssh svcops "sudo /usr/local/bin/opsctl runtime model-attest oc1"                               # isolated provider receipt
ssh svcops "sudo /usr/local/bin/opsctl runtime set-model oc1 --provider google --model gemini-3.5-flash"
ssh svcops "sudo /usr/local/bin/opsctl checklist pack oc1 --pack openclaw-runtime --gemini-chat-smoke"   # real completion
# hermes uses the same command shape (checklist pack ... --pack hermes-runtime --gemini-chat-smoke)
```

`runtime model-attest` deliberately separates response arrival, provider-receipt presence, the OPS
configured model, the model actually sent in the provider request, and the model version recorded in
the provider response. It must fail closed when a product reports only its selected/configured model.
A numeric provider revision (for example configured `gemini-3.6-flash` and actual
`gemini-3.6-flash-001`) is reported explicitly rather than collapsed into one value. The command
runs one isolated completion and does not use or alter a customer's conversation session.

Most config (including `agents.defaults.model.primary`) hot-reloads live;
`gateway.controlUi.allowedOrigins` requires a gateway restart to apply. Rollback = set-model back to
the previous ref (recorded as `previous_model_ref` and in the action log).

## Dev Recipe

Dev source mode means the container sees an external source/output path. It does not mean customer
targets should use source mounts.

`dev-oc` mounts `--source-output` over the whole `/app/dist` (not just `dist/control-ui`), so both
the server (`dist/index.js`) and the UI run from source — a full-stack live loop. The path you pass
to `--source-output` must therefore be a **complete** build output with the same layout the image
ships (`index.js` plus `control-ui/`), i.e. the result of the product's full build
(`pnpm build:docker && pnpm ui:build`). Passing a partial tree (e.g. only `control-ui`) overlays an
incomplete `/app/dist` and the container's server will fail to start; the apply health check then
auto-rolls-back. The compose contract accepts a source mount at `/app/dist` or at the recipe's
`source_output_target` (`/app/dist/control-ui`); the label itself is unchanged (baked into wrapper
images), so no wrapper rebuild is needed.

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

Runtime secrets are target secrets, not Gemini CLI credentials for the `svcops` account. They include
provider keys such as `GEMINI_API_KEY` and runtime-internal auth keys such as Hermes
`API_SERVER_KEY`.

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

For Hermes Workspace `HTTP 401` on backend verification, first check whether `API_SERVER_KEY` is
present. Rotate it without printing the value:

```bash
ssh svcops "sudo /usr/local/bin/opsctl runtime-secret status TARGET"
ssh svcops "openssl rand -hex 32 | sudo /usr/local/bin/opsctl runtime-secret set TARGET --key API_SERVER_KEY --value-stdin --check"
```

## Handoff Credentials

Gateway tokens and workspace passwords are handoff credentials, not runtime secrets.

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
