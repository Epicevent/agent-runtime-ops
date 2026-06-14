# Runtime Secrets

Runtime secrets are provider/API keys or runtime-internal auth keys that must
stay outside the public repo and outside `/srv/openclaw-ops` desired state.

Gemini/API keys here are runtime slot secrets. They are not used to install or
authenticate a Gemini CLI on the `svcops` account. Hermes `API_SERVER_KEY` is
also a runtime slot secret; it must match the workspace-side `HERMES_API_TOKEN`
that the compose layer derives from it.

The supported path is repo-owned and explicit:

```text
root or svcops with restricted sudo
  -> opsctl runtime-secret set
  -> profile-declared secret file
  -> full runtime recreate and live checks by default
```

Secret values are never printed and are not written to `actions.log`.

## Gemini Key For Dev Slots

Dev runtime slots are `dev-oc` and `dev-hermess`. The developer account
`openclawdev` owns source checkouts, but browser-visible runtime checks happen
through the dev slots.

Inject a Gemini key into OpenClaw dev:

```bash
read -rsp "GEMINI_API_KEY for dev-oc: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set \
  dev-oc \
  --key GEMINI_API_KEY \
  --value-stdin \
  --check
unset GEMINI_API_KEY
```

Inject a Gemini key into Hermes dev:

```bash
read -rsp "GEMINI_API_KEY for dev-hermess: " GEMINI_API_KEY
printf '\n'
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set \
  dev-hermess \
  --key GEMINI_API_KEY \
  --value-stdin \
  --check
unset GEMINI_API_KEY
```

If the slot has not yet been migrated to an agent-runtime compose, store the key
without restarting:

```bash
printf '%s' "$GEMINI_API_KEY" | sudo /usr/local/bin/opsctl runtime-secret set \
  dev-oc \
  --key GEMINI_API_KEY \
  --value-stdin \
  --no-restart
```

## Env File Input

For multiple provider keys, create a root-only env file:

```bash
sudo install -o root -g root -m 0600 /dev/null /root/agent-runtime-secrets.dev-oc.env
sudoedit /root/agent-runtime-secrets.dev-oc.env
sudo /usr/local/bin/opsctl runtime-secret set dev-oc \
  --env-file /root/agent-runtime-secrets.dev-oc.env \
  --check
```

Only supported runtime secret key names are accepted.

## Hermes Backend Auth

Hermes Workspace talks to the embedded Hermes Agent gateway with bearer auth.
If the browser shows `HTTP 401` while the container health and root HTTP smoke
pass, check `API_SERVER_KEY` presence first:

```bash
sudo /usr/local/bin/opsctl runtime-secret status oc16
```

Generate or rotate the internal gateway key without printing it:

```bash
openssl rand -hex 32 | sudo /usr/local/bin/opsctl runtime-secret set \
  oc16 \
  --key API_SERVER_KEY \
  --value-stdin \
  --check
```

`--check` verifies that both `API_SERVER_KEY` and the derived
`HERMES_API_TOKEN` are present in the recreated container and match without
printing either value.

During a checked rotation, progress is emitted as explicit phases:
`compose_config`, `compose_up`, `live_check`, `secret_check`, and
`hermes_smoke`. `live_check_tick failed=...` shows the current failing live
checks while waiting for startup.

## Runtime Config Sanitize

Provider keys must come from runtime secrets, not stale Hermes config override
paths. Preview the paths that would be removed:

```bash
sudo /usr/local/bin/opsctl runtime config-sanitize oc16 --dry-run
```

Apply the cleanup only after reviewing the dry run:

```bash
sudo /usr/local/bin/opsctl runtime config-sanitize oc16 --apply
```

The command prints only paths and `value_present=yes|no`; it never prints
secret values.

## Status

Status prints only key presence, never values:

```bash
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
sudo /usr/local/bin/opsctl runtime-secret status dev-hermess
```
