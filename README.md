# Agent Runtime Ops

JI TECH AI 에이전트 서비스의 런타임 운영 도구 저장소다.

이 저장소는 실제 서버 운영 상태를 저장하지 않는다. 실제 상태는 서버의
`/srv/openclaw-ops`에 둔다.

## 설치

실행 주체: **관리자/root 권한을 가진 계정**

서버에서 아래 한 줄을 실행한다. `sudo` 비밀번호를 요구할 수 있다.

```bash
curl -L https://raw.github.com/Epicevent/agent-runtime-ops/main/go | sudo bash
```

설치 확인:

```bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -u svcops opsctl profile list
```

같은 명령을 다시 실행하면 `main` 기준 최신 설치본으로 갱신된다.

설치 후 역할은 이렇게 나뉜다.

```text
관리자/root:
  /opt/agent-runtime-ops 설치
  /usr/local/bin/opsctl 배치
  서버 패키지와 권한 정리

svcops:
  설치된 opsctl 실행
  /srv/openclaw-ops 운영 상태 조회
  허용된 운영 명령 실행
```

## 저장소 책임

```text
Epicevent/openclaw-jitech
  OpenClaw 제품 소스와 제품 이미지

Epicevent/hermes-jitech
  Hermes 제품 소스와 제품 이미지

Epicevent/agent-runtime-ops
  runtime profile
  wrapper image recipe
  opsctl
  admin console
  apply/check/rollback/rollout 도구
  NAS grant 판정 로직
  schema 정의

/srv/openclaw-ops
  실제 서버 운영 상태
  slots.yaml
  lanes.yaml
  releases.yaml
  nas-policy.yaml
  actions.log
  drift report
```

이 저장소에 넣지 않는 것:

```text
고객명
NAS password
API key
gateway token
고객 문서
실제 slot 배정 상세
```

## 핵심 기준

slot은 두 가지 기준으로 실행한다.

```text
image release + runtime profile
```

`image release`는 컨테이너 안에 무엇이 들어있는지를 정한다.

`runtime profile`은 그 이미지를 서버에서 어떻게 실행할지를 정한다.

운영 명령은 compose 조각을 즉석에서 만들지 않는다. compose는
`profiles/runtime/*/compose.yml.tpl`에서만 렌더링한다.

## Runtime Profiles

```text
profiles/runtime/
  openclaw-customer/
  hermes-customer/
  openclaw-dev/
  hermes-dev/
```

profile 이름에는 `v1` 같은 숫자를 붙이지 않는다.

```text
profile name:
  의미

profile digest:
  실제 버전

ops repo commit:
  변경 이력
```

## opsctl 명령 형태

```text
opsctl status SLOT
opsctl plan SLOT
opsctl apply SLOT
opsctl rollback SLOT
opsctl check SLOT

opsctl rollout LANE

opsctl release add NAME IMAGE
opsctl release promote NAME LANE

opsctl nas requests
opsctl nas approve-auto
opsctl nas policy-check SLOT SHARE

opsctl admin serve
```

현재 초기 골격에서는 `status`, `plan`, `check`, `nas policy-check`가
비쓰기 명령이다. `apply`, `rollback`, `rollout`은 적용 엔진과 감사 로그가
완성된 뒤 열어야 한다.

## 개발 확인

```bash
python -m compileall opsctl
python -m agent_runtime_ops.cli --help
python -m agent_runtime_ops.cli profile list
```
