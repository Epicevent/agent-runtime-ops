# Runtime Profiles

Runtime profiles define how a product image is executed on the server.

Profiles live under:

```text
profiles/runtime/
```

Profile names do not include numeric versions. The profile digest and ops
repository commit are the version identity.

Every customer profile must mount NAS read-only with `rslave` propagation so
host CIFS child mounts appear inside the running container.

