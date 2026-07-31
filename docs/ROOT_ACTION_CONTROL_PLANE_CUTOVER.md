# Standalone root-action control-plane cutover

This contract removes the root-action broker lifecycle from the `opsctl`,
`current`, `install.sh`, update, and self-update control surfaces. It does not
retire the live CLI or switch a host by itself. Source landing, root install,
web deployment, passkey enrollment, and end-to-end execution remain separate
gates.

## Preserved contract

The standalone release preserves the existing broker Unix-socket protocol,
typed manifest and exact job digest, WebAuthn user-verification flow, one-shot
claim/restart behavior, public projection and terminal receipt schemas, and the
root-owned private/public state roots. Historical inventory remains evidence
only and is not executable registry input. At this source baseline the only
enabled handler is `artifact.probe_kwrag_product`; `kwrag.network_ensure`
remains `disabled_by_product_boundary` with no handler.

The release contains only the production `root_actions` package and its single
`domain.artifact_probe` dependency. It must not contain `agent_runtime_ops.cli`,
MCP code, commands, update/self-update code, or an `opsctl` console script.
Third-party WebAuthn/runtime dependencies are allowed only inside the immutable
release tree and are covered by the same canonical tree digest.

## Immutable release boundary

The root installer must build one root:root commit bundle at:

```text
/opt/agent-runtime-root-action-broker/bundles/<40-hex-source-commit>
```

The broker release tree is the exact nested path
`release/<40-hex-source-commit>` inside that bundle; external launcher,
descriptor, dependency lock, rendered unit, and bundle manifest are under
`control/`. There is no second accepted layout.

The release uses a slim `.runtime`, not a Python virtual environment. Its copied
Python and dependency files must not contain `pyvenv.cfg`, `.pth`, `.egg-link`,
`sitecustomize.py`, or `usercustomize.py`. Every tree entry is root:root,
directories are `0755`, regular
files are `0644` or `0755`, regular-file link count is one, and no symlink,
FIFO, socket, device, or unexpected first-party package entry is admitted.

A root-owned copy of `root_actions/release.py` is installed outside that tree.
Its `describe` command emits a canonical descriptor containing the exact source
commit, release basename, complete-tree digest, entry/byte counts, copied Python
path, package path, and service module. The descriptor, launcher, and their
SHA-256 digests are fixed into the standalone systemd unit. On every start the
launcher validates its own bytes, descriptor bytes, complete release tree, and
minimal first-party closure before executing the exact release Python with
`-I -B -S`. Only then does it insert the validated standalone site-packages path
and import the broker service. Python site startup, user packages, environment
path injection, and mutable ops releases are therefore not import sources. Any
drift stops before broker imports or root-action state mutation.

The same stdlib-only launcher provides a bounded `materialize` command for the
future privileged install card. It reads the first-party closure, dependency
lock, launcher, and unit template from one exact 40-hex Git commit, never from
dirty worktree bytes. Git replacement refs and inherited Git object/config
environment are disabled for every object read. Dependencies are installed with `--require-hashes`,
`--only-binary`, `--no-deps`, and `--no-index` from an exact root-controlled
offline wheelhouse. It creates a commit-named bundle containing the immutable
release, external launcher, canonical descriptor, dependency lock, rendered
unit, and canonical bundle manifest. Every output is owner/mode/type/link and
complete-tree bound before publication. The rendered unit contains no
placeholder and points only into that commit-named bundle. A complete existing
bundle is revalidated and returns the same secret-free manifest without running
pip again; drift fails closed.

`materialize` does not call systemd, replace the live unit, stop the old broker,
start the standalone broker, or delete an incomplete staging directory. Those
effects belong to the later exact install/cutover card, which must preflight and
either atomically publish the validated bundle or preserve a failed staging
identity for explicit inspection. This source slice therefore provides the
artifact producer and verifier, not root installation authority.

The dedicated unit is
`systemd/agent-runtime-root-action-broker-standalone.service`. It retains the
existing state root, socket, reader group, WebAuthn environment file, and
hardening. Its `ExecStart` contains neither `opsctl` nor the mutable operations
`current` link.

## Initial enrollment remains a later gate

This slice does **not** expose a bootstrap command or publish a bootstrap
secret. The existing broker creates the one-time token before its Unix-socket
response is delivered. A response lost after the store commit cannot currently
be recovered idempotently from a trusted root client, and retry can consume the
store's one bounded replacement without recovering the plaintext token. A
launcher-side file journal cannot repair that protocol boundary.

Initial enrollment therefore remains a separate source and user-decision gate.
It needs broker/store request identity and response-loss idempotency, plus a
user-ratified secret transport whose bytes never enter the shared agent-visible
terminal, logs, database fields, or public projection. A browser-created
non-secret setup request digest followed by one exact uid-0 approval is a
candidate, not an implemented contract. The svcops web process is not granted
access to a root-held token. After a ratified enrollment bridge is complete,
normal approvals need no root shell. Chat remains non-authoritative.

The inherited authorization package is also not declared terminal by this
slice. Its current phone slot is platform-only, while the ratified phone path
must later admit verified direct-phone platform and PC-assisted hybrid contexts
without treating attachment or transport metadata as device identity. Current
`recovery_ready` means only that a recovery credential is enrolled; no
recovery ceremony exists yet. Exact three-slot configuration and approval
admission are separate bounded authorization-source gates, not capabilities
supplied here.

## Source slices and stop line

This first slice provides the exact-Git offline materializer, standalone release
verifier/launcher, and dedicated unit template. The next bounded source
slice converts MCP `root_action_submit`, `root_action_retrieve`, and
`root_action_wait` from an `opsctl` subprocess to the existing direct AF_UNIX
client. The OPS web adapter remains presentation-only and must validate direct
method-specific responses while keeping the public projection as durable
history.

No browserless machine mutation authority is created here. In particular the
current NAS `--constructive-only` product policy is not an authority boundary:
it can admit detach/replacement. Any future unattended lane remains disabled
until its lower-layer create-only authority is separately decided and sealed.

The first privileged handoff must be one exact install/deploy/enrollment/E2E
card bound to source commit, launcher digest, descriptor digest, release tree
digest, unit bytes, installed prestate, rollback identity, web source commit,
and the human WebAuthn action. It must stop before any unrelated root, NAS,
provider, canary, rollback drill, or DEV mutation.
