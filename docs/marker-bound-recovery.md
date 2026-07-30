# Exact marker-bound rollback recovery

The legacy `opsctl rollback TARGET` command remains compatible with historical
operator use and may select the pending or latest managed backup. It is not the
recovery primitive for an immutable interrupted action.

An interrupted action must pass the complete durable identity:

```text
sudo /usr/local/bin/opsctl rollback TARGET \
  --expected-transaction-id TRANSACTION_ID \
  --expected-marker-sha256 sha256:... \
  --expected-backup-name BACKUP_NAME \
  --expected-backup-metadata-sha256 sha256:...
```

`TARGET` must be an enabled runtime binding's exact canonical Linux account. All
four expectations are required together and use strict canonical grammars.
The command acquires the existing host mutation lock and target transaction lock
before reading the marker. Under those locks it opens the root-controlled marker
without following links, binds its stable bytes to `marker_sha256`, validates
the transaction id and backup name, and re-hashes the backup metadata and every
declared artifact. Absence, replacement, link/owner/mode drift, digest drift, or
any expected-field mismatch is rejected before runtime restore with `writes=0`.
There is no latest-backup or legacy-import fallback in this mode.

The implementation marks mutation started at the exact boundary immediately
before the first state-directory or runtime-file write. Backup validation and
other execution failures before that boundary remain rejected with `writes=0`;
failures after the boundary report `writes=1`.

Marker absence during admission is reported as `transaction_state=absent` and
`terminal_state=incomplete`; it is never inferred to mean that this request
committed a recovery. `transaction_state=committed` is emitted only when this
exact invocation observes the marker finish after the restore and all live
checks pass. If the private action-log append then fails, the command reports a
failed, incomplete terminal outcome with `writes=1` and committed transaction
state. It never rewrites that post-mutation failure as an admission rejection or
as `writes=0`.

After admission, the existing restore, prior-runtime live checks, and optional
retrieval verifier run. The exact marker is removed only after those checks pass
and its full identity is revalidated. A failed live check or verifier leaves the
same marker available for an exact retry. No direct marker-finish command is
exposed.

The only stdout for exact mode is canonical JSON with schema
`agent-runtime-marker-bound-recovery/v1`. It contains the target and four
identity fields, whether runtime mutation began, transaction/terminal state,
outcome, and a bounded reason code. Raw environment, command output, check
detail, query, result, and secret content are discarded. Root-private legacy
action logging remains an internal audit input; it is not the public receipt.

This source contract does not authorize installation or a recovery action. A
reviewed merged OPS SHA must be separately approved and installed before a
single immutable recovery action can bind live evidence to these arguments.
