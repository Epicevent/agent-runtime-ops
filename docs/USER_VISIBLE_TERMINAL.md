# Agent OPS user-visible terminal

The terminal is a current v2 kernel receipt showing every declared groupware grant readable by the exact service principal, with the authenticated OPS page rendering that same receipt digest.

## Layers and blockers

- Source: this branch binds the applied runtime-profile digest and preserves requested versus effective groupware paths in the observer receipt.
- Build/install/runtime: not performed here; the live broker and the Persistent 15-minute producer aligned to the identity buckets must be rebuilt and installed before fresh v2 receipts exist.
- Actual turn: product UI terminals belong to Hermes/OpenClaw and are not claimed by this observer lane.
- First blocker: the current root host must provide a new v2 receipt for each declared slot; old v1 receipts are historical only.

## Cross-lane contract

The page consumes typed receipt states and never turns host ledger evidence into green. Products provide candidate/prestate fixtures to the rollback lane; this lane provides v2 receipt schema and profile/desired/container binding facts.

## Positive/negative and next action

Positive requires requested=mounted=read-success and exact profile/container/desired bindings. Negative cases include source/mount/access/policy failures, stale or pending observations, and requested/effective cardinality mismatch. Next action is focused source/test review, then build/install and fresh server observations; no repair is automated by the observer.

The producer accepts no caller path, argv, or slot override. It enumerates only enabled declared groupware slots, creates one deterministic manifest per slot per 15-minute UTC bucket, and submits only the existing read-only observer. Duplicate bucket submissions are broker-deduplicated; malformed inventory, cap overflow, or broker failure stops before claiming success. The timer never mounts, detaches, changes permissions, or applies a repair.

## Supersession

Observer v1 remains readable history but cannot establish the v2 terminal once profile binding is required.

## Rollback transaction lane

The canary rollback contract seals the target, family, candidate product/wrapper pair, live prestate pair,
and backup identity in one single-use transaction. Candidate and rollback receipts share that transaction
identity; arbitrary historical digests, cross-slot reuse, conflicting reuse, and consumed transactions are
rejected. This source change is not an install, canary, or runtime completion claim.
