# NAS view status terminal contract

`opsctl nas view status` emits `agent-runtime-nas-view-status/v1` key-value output.
The command is read-only (`mutates=false`). A consumer must not infer a usable degraded
snapshot from return code alone.

Required terminal fields:

- `view_status_schema=agent-runtime-nas-view-status/v1`
- `view_count=N`, followed by exactly `N` parseable view records
- `view_status=ok|degraded`
- `view_exit_code=0|1`, equal to the process return code
- `view_status_issues_json`, a duplicate-free JSON string array
- `view_observation_gaps_json`, a duplicate-free JSON string array
- `view_snapshot_complete=yes`, emitted last

`ok` requires return code 0 and no issue codes. `degraded` requires return code 1 and
at least one issue code. Observation gaps describe checks that could not be completed;
they do not silently turn a known degraded state into success. Return codes other than
0 or 1, missing terminal fields, count mismatch, status/return-code disagreement, or a
truncated terminal marker make the snapshot unusable.

Current issue-code allowlist:

- `view_unhealthy`
- `boot_fstab_missing`
- `boot_restore_missing`
- `failed_cifs_mount_units`
- `managed_fstab_unmounted`

Current observation-gap allowlist:

- `boot_restore_requires_root`
- `failed_cifs_mount_units_unavailable`
- `grant_evidence_incomplete`

## Granted-path live evidence

The v1 schema is extended append-only. Every view row emits:

- `view_N_desired_digest=sha256:<64 lowercase hex>` when the applied view has
  a desired-state binding; an empty value is retained for legacy/unbound
  records and must never be treated as a current kernel observation.

- `view_N_grant_evidence_applicable=yes|no`
- `view_N_grant_evidence_count=K`
- `view_N_grant_evidence_json=[...]`
- `view_N_grant_evidence_complete=yes|no`

Non-granted corpora emit `no`, `0`, `[]`, and `yes`. For a granted-path corpus,
`paths_json` remains persisted intent only. Each evidence item binds the declared
relative path to its exact `/home/{slot}/nas_docs/{corpus}/{alias}` child mount,
`ro,nosuid,nodev`, source/entry device-inode-type identity, uid/gid/mode, the
canonical slot account uid/gid, and fixed-argv isolated `os.access(X_OK/R_OK)`
results. The access helper emits only an exact `allow` or `deny` sentinel;
runuser/PAM/helper failures are observation gaps, never access-denied verdicts.
The probe enumerates no content and invokes no shell.

The actual mount table below the slot entry is inventoried independently of
`paths_json`. The exact target set must be the entry root plus the declared
child targets; an unrecorded residual child mount makes the evidence incomplete
and the view unhealthy. Each child probe runs in an isolated process group and
is terminated as a group at its wall-clock deadline, covering filesystem/NSS
stalls as well as the fixed-argv account check. Path identities and the exact
mount row are reopened and re-read after observation so a concurrent path or
mount replacement cannot combine old metadata with a new mount verdict.

The path count is capped at 64, account probes are individually bounded, and
the row has a 15-second overall budget. A non-root run, timeout, missing account,
unreadable metadata, invalid path, unexpected actual child mount, or partial result emits
`grant_evidence_complete=no`, adds `grant_evidence_incomplete`, and makes the
view unhealthy. Known mount or access failures are explicit per-item issues and
are never inferred from the recorded request.
