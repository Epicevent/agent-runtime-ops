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

