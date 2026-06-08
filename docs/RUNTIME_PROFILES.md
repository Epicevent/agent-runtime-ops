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

The profile contract is not enough by itself. Runtime checks must verify the
live container too:

```text
host nas_docs child CIFS mount
container nas_docs bind root
container child CIFS mount
read-only state inside the container
```

If a NAS share is mounted on the host but appears as an empty ordinary directory
inside the container, the slot is not in the desired runtime state.
