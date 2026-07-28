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
