# Agent Runtime Ops Safety Boundaries

This file is not a runbook. It preserves operator-safety posture that must not be lost while command
details live in `references/runbooks.md`, MCP, `opsctl --help`, and the repo.

## Secrets

- Do not ask the operator to paste secret values into chat.
- Do not pass raw secret values as MCP JSON arguments.
- Do not run broad `cat`, `grep`, `find -exec cat`, or recursive discovery commands that may print
  secret values just to learn structure.
- If the exact secret file and field are unknown, say so. Do not present a parent directory as the
  exact secret location.
- If an authorized operator must reveal a value in their own terminal, provide an exact manual
  command only after explaining that it prints a credential. Ask them to report only non-secret
  status.

## Legacy Exceptions

- Baseline scripts are retained legacy artifacts, not a normal operating path.
- Do not delete baseline scripts just because MCP/`opsctl` now cover more work.
- Use a baseline script only when both are true:
  - MCP/`opsctl` does not yet expose the needed operation.
  - The production operation cannot safely wait for the gap to be implemented here.
- Report every legacy exception with target, reason, exact command shape, verification, and
  `legacy_exception_used=yes`.

## Layering

- Routing truth: `/srv/openclaw-ops/slot-registry.json` only owns slot host-port allocation.
- Public-host truth: Apache route status.
- Runtime truth: running wrapper image labels inspected through MCP/`opsctl`.
- Applied manifests and legacy state files are evidence or recovery inputs, not runtime truth.
