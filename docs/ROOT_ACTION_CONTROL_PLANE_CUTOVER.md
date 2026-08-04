# Standalone root-action broker cutover

This source slice separates the root-action broker process from the mutable
`opsctl`, `current`, `install.sh`, update, and self-update lifecycle. The
standalone installer is one bounded root action; it is not a permanent general
administration CLI.

## What is preserved

The dedicated unit runs the existing
`agent_runtime_ops.root_actions.service` module. That keeps the versioned Unix
socket protocol, typed manifest and receipt schemas, WebAuthn verification,
one-shot claim semantics, worker, private store, and public projection. The
executable registry is unchanged: this slice adds no operation, generic argv,
or browserless machine authority.

The broker already owns the root-only `auth_bootstrap_create` endpoint. This
slice neither adds a bootstrap CLI nor exposes the secret to the web service.
The safe human delivery mechanism for the one-time secret remains a later
user-ratified gate.

## Minimal standalone lifecycle

The installer consumes one reviewed wheel, its SHA-256 digest, and the exact
40-hex source commit. It builds dependencies from the adjacent
`systemd/wheelhouse/` with the repository's hash-locked requirements and
`--no-index`, then materializes the result at the immutable path:

```text
/opt/agent-runtime-root-action-broker/releases/<40-hex-source-commit>
```

Run the source-native action from a checkout matching the wheel source:

```text
sudo systemd/install-agent-runtime-root-action-broker-standalone.sh \
  /absolute/path/agent_runtime_ops.whl \
  <64-hex-wheel-sha256> \
  <40-hex-source-commit>
```

The installer rejects mutable dependency inputs, computes the complete release
tree digest, renders the three unit placeholders, disables the legacy broker,
and enables the standalone unit. A failed cutover restores the prior unit and
legacy active/enabled intent. Once input copies are bound, both failed and
successful terminal outcomes write a sanitized, root-owned, `svcops`-readable
durable receipt under
`/var/lib/agent-runtime-ops/install-receipts/`.
The privileged build never depends on root network or cache state, and each
pre-cutover build phase records a typed failure reason in that receipt.

The rendered unit directly executes the commit-pinned release Python with
`-I -B -m agent_runtime_ops.root_actions.service`. It contains no `opsctl`,
mutable `current` link, self-update hook, generic command dispatcher, or custom
release launcher. Root-owned path permissions and the later install receipt are
the artifact boundary; the web deployment preflight independently reattests the
running commit, tree digest, PID, unit, and socket before changing web bytes.

## Remaining source seams

The MCP `root_action_submit`, `root_action_retrieve`, and `root_action_wait`
adapter still needs a separate bounded change from an `opsctl` subprocess to
the existing direct AF_UNIX client. The OPS web repository owns its direct
broker response validation and passkey UI. Neither seam requires a generic
replacement CLI.

Source landing, execution of the root installer, bootstrap delivery, credential
enrollment, web deployment, and browser-to-terminal-receipt E2E remain separate
gates. The installer performs only release materialization and broker cutover.
