# Runtime Profiles

Runtime profile은 제품 이미지를 서버에서 어떻게 실행할지 정하는 실행계약이다.

제품 이미지는 애플리케이션 코드, UI, 문서 처리 도구, 기본 실행환경을 담는다. Runtime
profile은 그 이미지를 어떤 command, user, env, volume, port, mount propagation으로
실행할지 고정한다.

```text
product image:
  application code
  UI and branding
  document tools
  bundled runtime

runtime profile:
  command and entrypoint
  HOME and state paths
  config and secret mount locations
  container user model
  host port mapping
  NAS root bind and mount propagation
  live check contract
```

이 둘은 같은 층위가 아니다. 제품 이미지를 바꾸지 않아도 runtime profile이 틀리면
게이트웨이는 뜬 것처럼 보이면서 Apache upstream에는 정상 응답하지 않을 수 있다. 반대로
runtime profile이 맞으면 NAS share 추가나 제거는 compose를 다시 만들지 않고 child CIFS
mount만 바꿔 처리할 수 있다.

## Profile 이름과 버전

Profile은 다음 위치에 둔다.

```text
profiles/runtime/
  openclaw-customer/
  hermes-customer/
  openclaw-dev/
  hermes-dev/
```

Profile 이름에는 `v1`, `v2` 같은 숫자 버전을 붙이지 않는다.

```text
profile name:
  의미

profile digest:
  실제 버전

ops repo commit:
  변경 이력
```

같은 이름의 profile이라도 내용이 바뀌면 digest가 바뀐다. Slot manifest에는 profile 이름과
profile digest를 같이 기록한다.

## 공통 NAS 계약

Customer profile은 NAS root 하나만 container에 bind한다. Share별 compose volume을 만들지
않는다.

```text
host:
  /home/ocN/nas_docs

container:
  OpenClaw: /home/node/nas_docs
  Hermes:   /workspace/nas_docs
```

Root bind는 read-only이고 `rslave` propagation이어야 한다.

```yaml
volumes:
  - type: bind
    source: /home/ocN/nas_docs
    target: <container_nas_root>
    read_only: true
    bind:
      propagation: rslave
```

동적인 NAS 변화는 host child CIFS mount에서만 일어난다.

```text
/home/ocN/nas_docs/host-<hosthash>/<share>
```

따라서 NAS share 추가와 제거는 compose 수정이 아니다.

```text
NAS 추가:
  opsctl nas mount SLOT //HOST/SHARE

NAS 제거:
  opsctl nas unmount SLOT //HOST/SHARE
```

이 명령은 fstab managed entry와 child CIFS mount만 다룬다. Compose, image, runtime env를
바꾸면 안 된다.

## 2026-06-08 확인 결과

Agent-runtime profile을 고객 slot에 적용했을 때 처음에는 모든 Apache port가 맞아 보였다.

```text
Apache active conf:
  oc1  -> 127.0.0.1:28789
  oc2  -> 127.0.0.1:28889
  oc15 -> 127.0.0.1:30189

agent-runtime rendered compose:
  oc1  -> 127.0.0.1:28789:18789
  oc2  -> 127.0.0.1:28889:18789
  oc15 -> 127.0.0.1:30189:3000
```

하지만 고객 URL은 proxy error를 냈다. 원인은 Apache port mismatch가 아니었다.

```text
원인:
  runtime profile이 기존 제품별 실행계약을 충분히 재현하지 못함

결론:
  port만 맞는 compose는 운영 가능한 compose가 아니다
```

이 결과 때문에 runtime profile은 단순 compose 템플릿이 아니라 제품별 실행계약으로 관리한다.

## OpenClaw 실행계약

OpenClaw customer profile은 검증된 gateway 실행방식을 유지해야 한다.

```yaml
command:
  [
    "node",
    "dist/index.js",
    "gateway",
    "--bind",
    "${OPENCLAW_GATEWAY_BIND:-lan}",
    "--port",
    "18789",
  ]
```

`openclaw gateway run`처럼 좋아 보이는 CLI alias로 바꾸면 안 된다. 같은 image라도 command,
HOME, config path, secret mount 위치가 바뀌면 gateway가 정상 upstream으로 동작하지 않을 수
있다.

OpenClaw profile의 핵심 env는 다음을 따른다.

```text
HOME=/home/node
OPENCLAW_HOME=/home/node
OPENCLAW_STATE_DIR=/home/node/.openclaw
OPENCLAW_CONFIG_DIR=/home/node/.openclaw
OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json
OPENCLAW_WORKSPACE_DIR=/home/node/.openclaw/workspace
OPENCLAW_NAS_CONTAINER_PATH=/home/node/nas_docs
```

Host mount는 다음 위치를 따른다.

```text
/home/ocN/.openclaw
  -> /home/node/.openclaw

/home/ocN/.openclaw/workspace
  -> /home/node/.openclaw/workspace

/home/ocN/.openclaw-auth-profile-secrets
  -> /home/node/.config/openclaw

/home/ocN/nas_docs
  -> /home/node/nas_docs
```

OpenClaw는 compose에서 runtime user를 명시한다.

```yaml
user: "<ocN_rt uid>:<ocN_rt gid>"
group_add:
  - "<ocN_data gid>"
```

이 방식이 가능한 이유는 OpenClaw gateway 실행 전에 image init이 root 권한으로 UID/GID를
재조정해야 하는 구조가 아니기 때문이다.

OpenClaw customer profile에는 보조 `openclaw-cli` 서비스를 두지 않는다. Gateway recreate
중에 `network_mode: service:openclaw-gateway` 형태의 보조 서비스가 죽은 gateway namespace를
잡으면 compose apply가 실패할 수 있다. 고객 slot 실행계약은 gateway 서비스 하나로 유지한다.
Profile에서 제거된 예전 서비스가 남아 있으면 실행 상태가 profile과 달라지므로 apply는
`--remove-orphans`로 orphan container를 정리한다.

## Hermes 실행계약

Hermes image는 s6 overlay 기반이다. Container 시작 시 image 내부 init script가 user, group,
supervise directory, profile reconciliation을 처리한다.

실패했을 때 확인된 로그는 다음과 같았다.

```text
[stage2] Changing hermes UID to 977
usermod: Permission denied.
s6-applyuidgid: fatal: unable to set supplementary group list: Operation not permitted
cont-init: info: /etc/cont-init.d/01-hermes-setup exited 1
```

원인은 compose가 `user: "<ocN_rt uid>:<ocN_rt gid>"`로 container를 시작한 것이다. Hermes
image가 root로 실행해야 하는 init 단계를 지나지 못했다.

따라서 Hermes profile은 compose-level `user:`를 강제하지 않는다.

```yaml
runtime_user_mode: image-managed
```

NAS group은 image init과 충돌하지 않도록 env와 `group_add`로 전달한다.

```text
OPENCLAW_NAS_DATA_GID=<ocN_data gid>
group_add:
  - <ocN_data gid>
```

Hermes profile은 기존 Hermes 운영 env를 유지한다.

```text
HERMES_HOME=/opt/data
HERMES_DATA_DIR=/opt/data
HERMES_WORKSPACE_DIR=/workspace
HERMES_DASHBOARD=1
HERMES_DASHBOARD_HOST=127.0.0.1
HERMES_DASHBOARD_PORT=9119
HERMES_DASHBOARD_INSECURE=1
API_SERVER_ENABLED=true
API_SERVER_HOST=127.0.0.1
HOME=/opt/data/home
HOST=0.0.0.0
PORT=3000
```

Hermes mount 위치는 다음을 따른다.

```text
/home/ocN/.hermes
  -> /opt/data

/home/ocN/.hermes/workspace
  -> /workspace

/home/ocN/nas_docs
  -> /workspace/nas_docs
```

Hermes는 compose가 아니라 image init이 runtime user 정리를 책임진다. 이 차이를 OpenClaw와
같이 단순화하면 slot이 `unhealthy`가 되고 PID가 0으로 떨어진다.

## Health와 backend smoke

`docker inspect` health가 `starting`이라고 해서 runtime이 성공한 것이 아니다. Apply는
container 상태뿐 아니라 backend HTTP smoke까지 확인해야 한다.

Runtime live check는 다음을 본다.

```text
container exists
container running
container pid > 0
health is healthy, none, or empty
expected image digest
runtime user model
backend HTTP smoke
NAS root bind
NAS root propagation
child CIFS visibility
read-only state
```

Backend smoke는 Apache를 거치지 않고 host loopback upstream을 직접 확인한다.

```text
OpenClaw:
  http://127.0.0.1:<gateway_port>/healthz

Hermes:
  http://127.0.0.1:<gateway_port>/
```

이 smoke가 실패하면 Apache port가 맞아도 slot은 운영 가능 상태가 아니다.

## 금지되는 단순화

다음 변경은 금지한다.

```text
OpenClaw command를 검증되지 않은 CLI alias로 교체
Hermes에 compose-level user 강제
Apache port 숫자만 보고 runtime 정상으로 판단
health=starting을 apply 성공으로 판단
NAS share 변경을 compose volume 변경으로 처리
제품별 HOME/config/secret mount 위치를 공통화
고객 slot에 dev/source mode 적용
```

Runtime profile의 목적은 공통 compose를 만드는 것이 아니다. 제품별로 검증된 실행계약을
공개 artifact로 고정하고, private state가 image digest와 lane을 그 계약에 수렴시키게 하는
것이다.
