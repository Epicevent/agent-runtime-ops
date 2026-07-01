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

## Two axes: mode vs environment

`runtime_class` selects the runtime *mode* (source vs image). It is NOT the trust
boundary. The trust boundary is the account **environment**, identified by the `dev-*`
name prefix (the same boundary `image-promote` uses via `_is_dev_named_target`):

- **mode** (source/image): drives the profile and source-mount policy.
- **environment** (dev/production): drives root-approval and who may deploy.

So `dev-*-img` is `mode=image` (customer-profile fidelity) **and** `environment=dev`
(dev-owned). Consequences:

- The root-approved-digest gate applies to **production** customer slots only (`oc*`),
  not to `dev-*-img`. A developer validates a fresh build on `dev-*-img` *before* root
  approval — restoring build -> validate -> approve -> promote.
- A developer account may self-deploy to its own `dev-*` slots (`image-dev-apply`,
  `image-canary`) via a scoped sudoers grant; opsctl refuses any non-`dev-*` target for
  such accounts. Production deploys stay operator/root-only.

When cloning from `dev-hermess`, copy workspace auth secrets such as
`HERMES_PASSWORD` alongside provider keys. Public image-mode workspaces must
not boot with `HOST=0.0.0.0` and no workspace auth.
