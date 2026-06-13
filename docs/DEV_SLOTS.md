# Dev Slots

Customer slots use image mode only.

Dev slots may use source mode:

```text
dev-oc       -> openclaw-dev
dev-hermess  -> hermes-dev
```

Source mode is for browser-visible development checks before publishing an
image release. Customer slots must not receive source mounts.

Hermes also has an image-mode dev validation slot:

```text
dev-hermes-img -> hermes-runtime-customer profile, no source mount
```

This target uses a `dev-*` Linux account for operator visibility, but its
runtime binding is `runtime_class=customer` so it runs the same image-mode
profile as customer canaries. It is for artifact validation only and must not
be used as an `image-promote` source or target.

When cloning from `dev-hermess`, copy workspace auth secrets such as
`HERMES_PASSWORD` alongside provider keys. Public image-mode workspaces must
not boot with `HOST=0.0.0.0` and no workspace auth.
