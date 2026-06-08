# NAS Policy

NAS policy is private server state and belongs in:

```text
/srv/openclaw-ops/nas-policy.yaml
```

This public repository defines policy parsing and checking behavior only. It
must not contain real NAS grant values or passwords.

NAS completion requires:

```text
host CIFS mount
container CIFS mount
runtime user can read
read-only mount
```

Check commands must not repair failed visibility.

NAS changes must not rewrite compose files.

```text
fixed runtime profile:
  /home/ocN/nas_docs -> container nas_docs root

dynamic NAS state:
  /home/ocN/nas_docs/host-<hosthash>/<share>
```

`opsctl nas policy-check SLOT //HOST/SHARE` reads `nas-policy.yaml` and returns
success only when the account grant allows that source.

`opsctl nas mounted SLOT` lists observed host child CIFS mounts.

`opsctl nas mount SLOT //HOST/SHARE` and `opsctl nas unmount SLOT //HOST/SHARE`
are root/admin commands. They do not edit compose, env, or image state.
