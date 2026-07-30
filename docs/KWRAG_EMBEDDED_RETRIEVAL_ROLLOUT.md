# Embedded KWRAG rollout contract

Status: local source contract. This document does not select a product family, target,
backend, invocation policy, or customer rollout.

KWRAG v1 executes inside the existing Hermes/OpenClaw product process. The existing
wrapper + product image tuple remains authoritative. A third running image, sidecar,
host port, product network, central corpus service, token projection, arbitrary path,
or generic shell is not part of this contract.

## Image capability labels

Both the product image and its wrapper image MUST carry the same values under
`com.epicevent.agent-runtime.retrieval.`:

| suffix | value |
| --- | --- |
| `schema` | `jitech-embedded-retrieval/v1` |
| `component-digest` | digest of the exact vendored wheel/component bytes |
| `contract-digest` | digest of the product-owned in-process consumer contract |
| `component-manifest-digest` | digest of the exact component build manifest |
| `source-archive-digest` | digest of the exact KWRAG source archive |
| `source-revision` | 40-character lower-case source revision |
| `transport` | `in_process` |
| `default-enabled` | `false` |
| `host-port-count` | `0` |
| `nas-read-only` | `true` |
| `resource.json` | canonical JSON resource declaration below |
| `verify-command.json` | JSON argv for the product-owned content-free verifier |

The resource object has the exact keys
`cpuReservationMillicores`, `gpuAccess`, `memoryReservationBytes`,
`pidsReservation`, and `profileDigest`. `profileDigest` is the canonical SHA-256 of
the other four fields. `gpuAccess` is `none` or `shared_stateless`.

These values are a reviewable resource envelope, not Docker resource enforcement and
not proof that a target host has enough headroom. The product verifier must return
`within_declared_reservation` or `unavailable`; a bounded canary must separately
measure live host/container headroom before promotion.

For enabled promotion, `opsctl rollout image-promote` runs the fixed product verifier
and then performs a direct, shell-free observation before every target mutation. It
compares source-container CPU, memory, and PID usage to the declared envelope and
requires current host CPU, memory, and PID headroom for one more reservation. The
content-free observation and its digest are printed with the promotion receipt. This
is an instantaneous admission gate, not a capacity guarantee. `shared_stateless` GPU
profiles fail closed until a direct GPU headroom observer is defined. Default-off
canary and promotion do not invoke this enabled-only gate. A persistent root-owned
host mutation lock serializes the observation with all normal runtime apply and
rollback operations, including operations on different slots. PID availability is
the minimum remaining capacity across `pid_max`, `threads-max`, and every finite
ancestor cgroup `pids.max`/`pids.current` pair. The cgroup lineage comes from the
fixed-inspect host PID of the verified source container, and starts at its parent so
the source container's own per-container ceiling is not mistaken for shared capacity.

The verifier argv is image-attested, contains no shell, and accepts no query, path,
backend, network, grant, projection, or credential argument from the operator.

## Target binding

`opsctl` computes `agent-runtime-retrieval-binding/v1` from the immutable instance ID,
family, runtime profile digest, container NAS root, enabled flag, component/contract/
resource digests, `transport=in_process`, `hostPortCount=0`, and `mountReadOnly=true`.
Its canonical SHA-256 is `retrieval_binding_digest`.

The runtime manifest and container receive:

- `retrieval_component_digest`
- `retrieval_enabled` (default `false`)
- `retrieval_binding_digest`
- the complete content-free retrieval capability and binding objects in the private
  runtime manifest recipe

The same intent is projected to the container as `JITECH_RETRIEVAL_*` environment
values and `agent-runtime.retrieval-*` labels. NAS contents and paths outside the
canonical container NAS root are never projected.

## Approval, verification, rollback

Production enablement requires both the existing exact product/wrapper image approvals
and a separate `jitech-retrieval-component-approval/v1` record bound to family,
product image digest, component/contract/manifest/source-archive/resource digests, and source revision.
Dev-owned image canaries remain pre-approval validation surfaces.

The verifier returns exact `jitech-embedded-retrieval-status/v1` JSON. Allowed facts are
component/binding/resource digests, consumer health, host-port count, read-only mount,
resource/GPU status, operation/result/consumption receipt digests, linkage status, and
revocation status. Raw query, result, prompt, NAS content/name, credential, and provider
material are forbidden by exact-key validation.

An enabled status requires healthy consumer state and complete operation -> result ->
consumption linkage, `resourceStatus=within_declared_reservation`, and a GPU observation
matching the declared profile. A disabled status requires no receipt digests,
`resourceStatus=unavailable`, `gpuAccessStatus=none`, and
`revocationStatus=complete`. Apply/canary fails and restores the previous tuple if this
postcondition fails. Rollback rechecks the restored tuple and reports the content-free
disable/revocation observation when the restored tuple carries the capability.

Apply and rollback are serialized per slot by a persistent root-controlled lock. A
crash-recovery marker is durably bound to one immutable backup before `.env`, compose,
or manifest mutation. It is removed only after the candidate reaches its successful
terminal manifest, or after the restored runtime passes its live checks and, when
present, the exact retrieval verifier.
If a failed first apply has no prior runtime tuple, rollback removes the candidate
compose/env/manifests, verifies that the compose project has zero containers, networks,
and volumes, and only then completes the recovery marker. A crash or residual Docker
object preserves the same marker so the exact backup can resume.

Tool self-update also preserves recovery points created by releases that stored
`.agent-runtime-backups` below the slot-owned runtime directory. Before activating
the new release, the installer reads those files with fd-relative no-follow checks,
binds their complete artifact/diagnostic identity, and atomically copies them into
the root-controlled recovery tree. Originals are retained. Unsafe ownership, modes,
links, unexpected entries, size excess, or concurrent replacement abort activation;
an operator rollback repeats the same import if installation did not reach it. The
earliest legacy schema captured only compose and the agent-runtime manifest. Its writer
predates the root-owned runtime state-manifest feature, so the exact three-key variant is
normalized to `had_state_manifest=false` at the canonical root-controlled path and removes
any later stale state manifest during rollback. It predates `.env` backup without proving
that `.env` itself was absent, so only `.env` remains unmeasured and is left untouched.
The later pre-relocation schema's state-manifest marker and private `.env` snapshot, owner,
group, mode, and explicit-absence marker are all migrated with their original rollback
semantics. Collision allocation always derives a canonical `timestamp[.N]` name from the
timestamp base, including when the legacy source name already has a suffix. The installer
also recognizes only the exact nested-suffix residue produced by the superseded publisher,
atomically renames it to the next canonical name, validates the complete root-controlled
backup, and preserves the original legacy source. Validation failure restores the residue
to its prior name. Any other non-canonical entry in the managed backup root aborts the
upgrade instead of being silently skipped. Backup allocation and latest-backup selection
apply the same exact-name rule; an incomplete canonical entry or abandoned staging name is
reported rather than hidden behind a newer valid backup. If validation fails and even the
rename back to the historical residue name fails, activation stops with both paths in the
error and leaves the moved root-controlled entry visible for operator recovery. It is not
silently deleted or treated as quarantined, and no automatic-recovery guarantee is claimed
for that double-failure case.
For the first upgrade only, a backup whose manifest and compose bytes prove that it
predates all retrieval fields may complete rollback when live truth also proves both the
capability and runtime projection labels are wholly absent; partial, extra, current
capability-absent, or otherwise inconsistent projections remain hard failures. Successful
use persists a root-controlled receipt bound to the backup metadata digest. The same
pending backup may resume after a crash, but a later transaction cannot consume the
migration exception again. Normal apply converts a pre-projection runtime manifest in
memory to its exact target-specific disabled binding before rendering; partial migration
fields are rejected instead of guessed.

Public KWRAG v1 schemas are not changed by this OPS-private rollout contract.

## Hermes compatibility fixture

`tests/fixtures/kwrag_embedded_retrieval/hermes-compatibility-v1.json` binds the
OPS-private parser to the exact clean Hermes product source and embedded component
artifacts that adopted this contract. It preserves the capability-contract source
revision separately from the final product source revision that adds the explicit
AIAgent consumption path and verifies the built image contract. The product revision
is the merged Hermes source that produced the published base image, rather than its
pre-merge review head. It includes the exact capability labels, component manifest,
fixed verifier argv, and canonical enabled/disabled status contract fixtures. The fixture
records the local networkless invocation proof separately and explicitly records that no
live enabled invocation, canary target, or runtime mutation was observed. Passing it proves
product/OPS contract compatibility only; it is not live consumer evidence, a target
selection, or canary qualification.
