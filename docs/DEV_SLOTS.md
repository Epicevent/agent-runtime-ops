# Dev Slots

Customer slots (`oc*`) use image mode only. Dev slots come in two layers — a source-mode preview
site and an image-mode validation site. Pick by what you are checking: to *see* a code change use
the source site; to validate a built image artifact use the image site.

## Source-mode preview (see a code change; no image build)

```text
dev-oc       -> openclaw-dev   https://dev-oc.ji-tech.co.kr
dev-hermess  -> hermes-dev     (hermes dev URL: verify before documenting)
```

`runtime_class=dev`, `mode=source`. The running code comes from a source mount, not from the image:
compose mounts `{{ source_output }}:/app/dist:ro`. To preview a change you do NOT build an image —
build the product dist (server `dist/index.js` + UI `dist/control-ui`, i.e.
`pnpm build:docker && pnpm ui:build`) and sync it:

```bash
sudo /usr/local/bin/opsctl recipe apply-dev dev-oc --sync-from /ABS/PATH/TO/dist
```

> ⚠️ Ensure `pnpm` resolves on PATH first: the build sub-scripts call bare `pnpm`, so on a
> corepack-only build host run `corepack enable pnpm` (or add a shim) — otherwise `ui:build` fails
> silently and you get a UI-less `dist/index.js`-only tree while the exit code still looks OK. Before
> syncing, verify BOTH `dist/index.js` and `dist/control-ui` exist. `--sync-from` takes the WHOLE
> `dist/` (server + UI); the mount covers all of `/app/dist` even though `source_output_target` names
> the `control-ui` subpath, so never sync only `control-ui`.

`recipe apply-dev` is an `svcops` (operator) command; developer accounts cannot run it directly (a
developer account CAN self-run `image-canary` to `dev-oc-img`), so coordinate the source sync with
`svcops` rather than defaulting to the self-serve image path. Source mode is for browser-visible
development checks before publishing an image release. Customer slots must not receive source mounts.

## Image-mode validation (validate a built image artifact)

```text
dev-oc-img      -> openclaw-customer profile, no source mount   https://dev-oc-img.ji-tech.co.kr
dev-hermes-img  -> hermes-runtime-customer profile, no source mount
```

These use a `dev-*` Linux account for operator visibility, but their runtime binding is
`runtime_class=customer`, so they run the same image-mode profile as customer canaries and boot a
built image (`@sha256:...`). Because `image-canary` requires `runtime_class=customer` and
`image-dev-apply` requires `runtime_class=dev` (`opsctl/agent_runtime_ops/commands/rollout.py`,
`required_runtime_class`), you deploy an image here with `image-canary`, not `image-dev-apply`:

```bash
sudo /usr/local/bin/opsctl rollout image-canary --target dev-oc-img --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
```

An attachment-capable image also needs its exact content-addressed runtime capsule. Keep the
private archive owned and readable only by the invoking developer, at the fixed digest-derived
path, then let the typed canary command validate and publish it:

```bash
chmod 600 /tmp/kwrag-runtime-capsule-sha256-CAPSULE_HEX.tar
sudo /usr/local/bin/opsctl rollout image-canary \
  --target dev-oc-img \
  --wrapper-image WRAP@sha256:... \
  --product-image PROD@sha256:... \
  --retrieval-runtime-capsule-sha256 sha256:CAPSULE_HEX \
  --stage-retrieval-runtime-capsule \
  --retrieval-enabled
```

The same capsule staging contract applies to `dev-hermes-img`; its capsule must declare
`family=hermes`, bind the Hermes product runtime projection, and use the Hermes NAS root.

Staging is accepted only for a `dev-*` target. The command rejects links, non-private archives,
unexpected members, digest drift, and existing content-addressed collisions before applying the
image. It publishes the verified release first and the capsule commit marker last; customer
targets still consume an already-published capsule and cannot use this developer staging flag.

They exist to separate source-mode failures from image-boot failures — artifact validation only, not
a quick-preview surface. They must not be used as an `image-promote` source or target.

`image-dev-apply` (`runtime_class=dev`) is therefore not the openclaw path: the only openclaw
`runtime_class=dev` slot is the source-mode `dev-oc`, which uses `recipe apply-dev`, never `image-*`.
So even though a sudoers grant may still list `rollout image-dev-apply *`, do not run it against
`dev-oc` (or any `dev-*`) for openclaw.

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
