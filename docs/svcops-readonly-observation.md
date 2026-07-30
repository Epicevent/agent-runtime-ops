# svcops read-only observation contract

This contract separates an explicitly approved root mutation from later
operational observation. A successful root action does not make a root shell the
permanent transport for status or receipt recovery.

## Exact installed surfaces

The bounded target snapshot is:

```text
sudo -n /usr/local/bin/opsctl observation status TARGET
```

`TARGET` is not a path or alias. It must be one enabled runtime binding's exact
canonical Linux account. The command accepts no path, shell, Docker exec, PID,
environment, receipt-file, or arbitrary-command argument. It emits one canonical
JSON object with schema `agent-runtime-svcops-readonly-observation/v1`, capped at
256 KiB.

The snapshot contains only allowlisted update identity, family-scoped image
approval identity, the target's runtime manifest tuple, allowlisted live runtime
truth, the pending rollback identity (when present), and boolean check results.
It does not publish raw command output, check details, credentials, environment,
or process data. The runtime probe accepts only fixed Docker `ps` and `inspect`
argv, caps stdout and stderr independently, has a fixed timeout, and kills its
isolated process group on timeout or overflow. It performs no network call,
Docker exec, write, or signal to a pre-existing or product process. `writes=0`
is part of every output.

The top-level states are deliberately independent:

- `runtime_state=healthy|degraded|unavailable`
- `transaction_state=committed|pending|unavailable`
- `terminal_state=unknown` for this target-only command

Healthy runtime state is not canary completion. A pending rollback marker makes
the result `incomplete`. An absent marker means there is no pending rollback
transaction, but terminal action identity remains unknown. Therefore this
target-only surface uses `result=observed|incomplete|degraded` and always sets
`canary_completion_claimed=false`; it never emits `result=complete`.

Routing and runtime-manifest identity are read before and after live truth. A
legitimate rollout that changes either source during the observation is reported
as `changed_during_observation`, never combined into a synthetic current tuple.

Broker-managed terminal status remains the existing exact-handle surface:

```text
/usr/local/bin/opsctl root-action retrieve \
  --job-id JOB_ID \
  --job-digest sha256:... \
  --request-id REQUEST_ID \
  --reply-target REPLY_TARGET
```

That command returns the validated bounded public projection and sanitized
receipt or notice. It does not accept a receipt path and does not expose the raw
root receipt. `root-action wait` is the bounded polling form of the same handle.

Legacy one-shot shell receipts are not admitted by either surface. The exact
443c5fda incident audit remains a one-time bridge; this contract does not turn an
arbitrary protected path into a reader.

## Installer contract

The installer normalizes generated `.venv` and Gemini CLI dependency trees
independently of the invoking root action's umask. Every path required to execute
the installed CLI is group-readable or traversable by `svcops`, group
non-writable, and world-inaccessible. It then runs exact candidate and active CLI
attestations as `svcops` before pruning the previous release.

The only new sudoers grant is the exact read-only command family
`/usr/local/bin/opsctl observation status *`. The command itself validates that
the sole argument is an enabled binding's canonical Linux account. This grant
does not confer arbitrary path, shell, raw receipt, Docker exec, or mutation
authority.
