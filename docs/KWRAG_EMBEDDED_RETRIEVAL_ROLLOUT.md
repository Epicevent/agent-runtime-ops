# KWRAG product/operations boundary

Status: superseding boundary for the retired OPS-owned retrieval rollout contract.

KWRAG is product code. `agent-runtime-ops` does not define, approve, bind, enable,
verify, or project KWRAG retrieval semantics. In particular, image rollout has no
retrieval flag, runtime capsule, product verifier command, retrieval environment
projection, or retrieval-specific OCI/runtime label contract.

The product boundary is:

- KWRAG opens the product's mounted corpus read-only, observes its current physical
  source and index identity, executes retrieval, and writes its product receipts.
- The Hermes/OpenClaw caller supplies only its caller-owned request shape, validates
  the product result, bounds current-turn context, and uses its existing provider
  handoff.
- Any caller/product contract mismatch is adapted at that caller boundary. OPS does
  not create a second semantic contract to make the two products agree.

`agent-runtime-ops` remains responsible only for product-independent operations:

- apply exact wrapper/product image digests;
- render the selected runtime profile;
- preserve the slot's read-only NAS bind and generic host/runtime safety checks;
- keep rollback and crash recovery recoverable;
- run canary and promotion mechanics without interpreting product retrieval state.

Historical retrieval modules and rollback evidence may remain readable solely to
recover an older installed transaction. They are not CLI/MCP rollout inputs and must
not be used to construct a new product deployment.
