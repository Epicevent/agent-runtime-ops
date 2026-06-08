# Operations

The operating loop is:

```text
status -> plan -> apply -> check
```

`status`, `plan`, and `check` do not write files.

`apply`, `rollback`, and `rollout` are the only commands allowed to change
runtime files. In the initial skeleton, mutating commands are intentionally
disabled until the renderer, rollback, audit log, and server migration tests are
implemented.

