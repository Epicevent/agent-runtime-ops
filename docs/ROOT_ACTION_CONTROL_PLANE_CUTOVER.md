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

The root installer must build a root:root tree at:

```text
/opt/agent-runtime-root-action-broker/releases/<40-hex-source-commit>
```

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

The dedicated unit is
`systemd/agent-runtime-root-action-broker-standalone.service`. It retains the
existing state root, socket, reader group, WebAuthn environment file, and
hardening. Its `ExecStart` contains neither `opsctl` nor the mutable operations
`current` link.

## Root-only initial passkey bootstrap

Initial registration remains the already defined kernel-peer boundary:
`auth_bootstrap_create` accepts only a Unix-socket peer with uid 0 and grants
exactly three bounded registrations. The standalone launcher exposes
`bootstrap-create` only after the same release validation. It writes the token
once to:

```text
/run/agent-runtime-ops/root-action-bootstrap.secret.json
```

The file is created no-replace as root:root `0600`, file- and parent-fsynced.
Stdout contains only a sanitized receipt (bootstrap id, expiry, remaining count,
and secret path); it never contains the token. The token is not written to logs,
agent output, the public projection, or another database column (the existing
private store retains only its digest).

Publication uses one fixed root-only staging file: write and file fsync, exact
read-back, no-replace hard-link publication, parent fsync, staging retirement,
and a second parent fsync. A partial safe staging residue is retired before one
bounded replacement token is requested. A complete staging or two-link
publication is finalized without another broker request, and a complete final
after lost stdout returns only the same sanitized receipt. Invalid or
ownership/type/link-drifted final state remains fail-closed.

A persistent root-owned `0600` lock next to the secret serializes recovery,
broker issuance, and durable publication. Concurrent root invocations therefore
cannot publish a token invalidated by the broker's one bounded replacement.
An exact unexpired final is reused without contacting the broker. An exact
expired final is retired and parent-fsynced while that lock is held, after which
the broker may issue its one bounded replacement. Malformed, noncanonical, or
implausibly future-dated state is preserved and rejected rather than deleted.

This slice does **not** claim that enrollment is reachable yet. The shared Codex
terminal is agent-visible, so `/dev/tty` output would not prove secret isolation;
the svcops web process must not gain read access to the root-only secret either.
Bootstrap transport is an explicit later user-ratification gate. A safer
candidate is for the browser to create a non-secret setup request identity and
digest which one exact root command authorizes, with the broker binding a single
registration window to that request and WebAuthn UV. That changes the bootstrap
trigger and is intentionally not implemented here. After a ratified enrollment
bridge is complete, normal approvals need no root shell. Chat remains
non-authoritative.

The inherited authorization package is also not declared terminal by this
slice. Its current phone slot is platform-only, while the ratified phone path
must later admit verified direct-phone platform and PC-assisted hybrid contexts
without treating attachment or transport metadata as device identity. Current
`recovery_ready` means only that a recovery credential is enrolled; no recovery
ceremony exists yet. Exact three-slot configuration and approval admission are
separate bounded authorization-source gates, not capabilities supplied here.

## Source slices and stop line

This first slice provides the standalone release verifier/launcher, dedicated
unit template, and root-only bootstrap reachability. The next bounded source
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
