# 운영

기본 운영 루프는 다음 순서다.

```text
status -> plan -> apply -> check
```

`status`, `plan`, `check`는 파일을 쓰지 않는다.

`opsctl check SLOT` validates the slot's runtime manifest, runtime profile, and rendered compose.

`sudo /usr/local/bin/opsctl check --live SLOT`은 Docker metadata와 mount namespace를
읽어서 실제 container, image digest, runtime user, NAS root bind, child CIFS mount를
검사한다. 이 명령도 파일을 쓰지 않는다.

`sudo /usr/local/bin/opsctl apply SLOT`은 runtime profile에서 compose를 렌더링하고
manifest를 쓴 뒤 slot container를 재생성한다. NAS child mount는 수정하지 않는다.

legacy slot에 처음 적용할 때만 명시 플래그가 필요하다.

```bash
sudo /usr/local/bin/opsctl apply SLOT --allow-first-apply
```

`sudo /usr/local/bin/opsctl rollback SLOT`은 직전 agent-runtime compose와 manifest
backup을 복구한다. agent-runtime backup이 없는 legacy 상태로 되돌리는 명령은 아니다.

NAS mount/unmount 실전 절차는 `docs/NAS_RUNBOOK.md`를 기준으로 한다. 이 런북은
Linux host의 CIFS mount와 container 안에서 보이는 child CIFS mount를 분리해서 확인한다.

## Runtime secret 운영

Gemini 같은 provider/API key는 `/srv/openclaw-ops` desired state에 저장하지 않는다.
각 runtime profile의 `env.contract.yaml`에 선언된 secret file에만 쓴다.

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

값 자체를 출력하지 않고 존재 여부만 확인한다.

```bash
sudo /usr/local/bin/opsctl runtime-secret status dev-oc
```

## NAS 운영

NAS share 추가/제거는 compose를 바꾸지 않는다. 동적 변화는 host child CIFS mount에서만
처리한다.

운영자가 credential까지 알고 있으면 바로 mount한다.

```bash
printf '%s' "$NAS_PASSWORD" | sudo /usr/local/bin/opsctl nas mount \
  oc3 //192.168.0.222/hanpass \
  --username NAS_USER \
  --password-stdin
```

고객이 직접 요청하는 흐름은 다음이다.

```bash
opsctl nas request //192.168.0.222/hanpass
printf '%s' "$NAS_PASSWORD" | opsctl nas credential set \
  //192.168.0.222/hanpass \
  --username NAS_USER \
  --password-stdin
```

root 권한의 승인 루프가 pending request를 처리한다.

```bash
sudo /usr/local/bin/opsctl nas approve-auto
sudo /usr/local/bin/opsctl nas approve-auto --watch --interval 15
```

상태 확인과 해제는 항상 `//HOST/SHARE` 기준으로 한다.

```bash
sudo /usr/local/bin/opsctl nas requests
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl nas unmount oc3 //192.168.0.222/hanpass
```

Product rollouts use the digest-pinned image rollout commands below.

## Canonical runtime recipe

Runtime recipe identity starts in this repo, under `recipes/runtime/*.yaml`.
Wrapper image labels must attest to that repo-owned recipe. Runtime manifests and live image labels
are the operational truth. Release-state rollout commands are not operating commands.

## Routing registry and live image truth

`/srv/openclaw-ops/slot-registry.json` is intentionally small. It owns only the Apache-facing
routing contract:

```text
slot, public_host, gateway_port, bridge_port, enabled
```

It must not contain family, runtime profile, release, image, or canonical recipe fields. Those are
read from the running wrapper image labels:

```bash
sudo /usr/local/bin/opsctl runtime truth SLOT
sudo /usr/local/bin/opsctl runtime truth --all
```

OpenClaw and Hermes image rollouts should use digest-pinned image commands:

```bash
sudo /usr/local/bin/opsctl rollout image-plan --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-dev-apply --slot dev-oc --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-canary --slot oc3 --wrapper-image WRAP@sha256:... --product-image PROD@sha256:...
sudo /usr/local/bin/opsctl rollout image-promote --from-slot oc3 --slots oc1,oc2,oc4
```

Useful read-only checks:

```bash
opsctl recipe list-canonical
opsctl recipe validate-canonical hermes-workspace
opsctl recipe validate-canonical hermes-combined
opsctl recipe validate-canonical openclaw-control
```

Wrapper publish workflows use:

```bash
opsctl recipe validate-canonical RECIPE --emit-build-args
```

`opsctl runtime truth SLOT`, `opsctl check SLOT`, `opsctl check --live SLOT`, and
`opsctl rollout image-plan` should report the same `canonical_recipe_name` and
`canonical_recipe_digest` for dev and customer projections when they are part of the same runtime
recipe.

`opsctl recipe apply-dev` records source provenance separately under `dev-recipes.yaml`. Treat that
as product source evidence, not as the runtime recipe source of truth.
