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

## Missing Commands

- Do not route operations through external historical tool bundles.
- If MCP/`opsctl` does not expose the needed operation, treat that as a tooling gap in this repo.
- Implement the missing command here, add tests, deploy through the approved update flow, and then
  run the operation through MCP/`opsctl`.
- If the operator chooses to stop before implementation, report the missing command plainly. Do not
  invent broad shell commands that bypass this repo.

## Layering

- Intended binding truth: `/srv/openclaw-ops/runtime-bindings.json` owns instance id, Linux account,
  public host, family, runtime class, ports, and enabled state.
- Actual route state: Apache route status.
- Actual runtime state: running wrapper image labels inspected through MCP/`opsctl`.
- Applied manifests and legacy state files are evidence or recovery inputs, not runtime truth.
