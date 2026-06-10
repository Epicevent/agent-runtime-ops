# Runtime Secrets

Runtime secrets are provider/API keys that must stay outside the public repo and
outside `/srv/openclaw-ops` desired state.

Gemini/API keys here are runtime slot secrets. They are not used to install or
authenticate a Gemini CLI on the `svcops` account.

The supported path is repo-owned and explicit:

```text
root or svcops with restricted sudo
  -> opsctl runtime-secret set
  -> profile-declared secret file
  -> optional gateway restart
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

Only provider/API secret key names are accepted.

## Status

Status prints only key presence, never values:

```bash
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
sudo /usr/local/bin/opsctl runtime-secret status dev-hermess
```
