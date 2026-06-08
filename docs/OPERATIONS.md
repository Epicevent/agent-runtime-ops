# Operations

The operating loop is:

```text
status -> plan -> apply -> check
```

`status`, `plan`, and `check` do not write files.

`opsctl check SLOT` checks the desired contract only. It confirms that the
private state, release, and runtime profile can render a valid desired runtime.

`sudo /usr/local/bin/opsctl check --live SLOT` also inspects Docker and NAS mount state. It is still
non-mutating, but it needs root/admin privileges or an equivalent restricted
root helper because it reads Docker metadata and mount namespaces. It must fail
if the running container does not see the host CIFS child mounts, or if the NAS
bind root is not read-only inside the container.

`sudo /usr/local/bin/opsctl apply SLOT` renders the runtime profile compose,
writes the agent-runtime manifest, recreates the slot container, and runs a live
check. It does not edit NAS child mounts.

The first migration from a legacy slot requires:

```bash
sudo /usr/local/bin/opsctl apply SLOT --allow-first-apply
```

`sudo /usr/local/bin/opsctl rollback SLOT` restores the previous
agent-runtime compose and manifest backup. If a slot has never had an
agent-runtime compose, rollback cannot recreate the legacy runtime.

`rollout` remains disabled until single-slot apply/rollback has passed server
migration tests.
