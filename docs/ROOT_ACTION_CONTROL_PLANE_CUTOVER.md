# Standalone root-action broker cutover

This source slice separates the root-action broker process from the mutable
`opsctl`, `current`, `install.sh`, update, and self-update lifecycle. It does not
install or switch a host.

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

The root install card must first materialize and attest one reviewed source
release at the immutable path:

```text
/opt/agent-runtime-root-action-broker/releases/<40-hex-source-commit>
```

That release uses the existing `.venv` layout. The install card must bind the
source commit and complete release-tree digest, reject a dirty or mutable
source, and render the three unit placeholders. Those privileged materialize,
unit-publication, cutover, and rollback steps are deliberately not implemented
as another permanent CLI or recovery state machine in this repository.

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

Source landing, root installation, service cutover, bootstrap delivery,
credential enrollment, web deployment, and browser-to-terminal-receipt E2E are
separate gates. This slice grants none of those external actions.
