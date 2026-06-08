# Operations

The operating loop is:

```text
status -> plan -> apply -> check
```

`status`, `plan`, and `check` do not write files.

`opsctl check SLOT` checks the desired contract only. It confirms that the
private state, release, and runtime profile can render a valid desired runtime.

`opsctl check --live SLOT` also inspects Docker and NAS mount state. It is still
non-mutating. It must fail if the running container does not see the host CIFS
child mounts, or if the NAS bind root is not read-only inside the container.

`apply`, `rollback`, and `rollout` are the only commands allowed to change
runtime files. In the initial skeleton, mutating commands are intentionally
disabled until the renderer, rollback, audit log, and server migration tests are
implemented.
