# Agent Runtime Ops

JI TECH AI 에이전트 서비스의 런타임 운영 도구 저장소다.

이 저장소는 실제 고객 상태를 저장하지 않는다. 실제 운영 상태는 서버의
`/srv/openclaw-ops`에 둔다.

## 첫 설치

실행 주체: **sudo 가능한 관리자 계정**

```bash
OPS_REF="FULL_40_CHARACTER_COMMIT_SHA"
sudo -v
curl -fsSL "https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/$OPS_REF/go" \
  | sudo bash -s -- "$OPS_REF"
```

이 명령은 서버에 `opsctl`이 아직 없을 때 쓰는 bootstrap이다. `OPS_REF`에는
검토한 commit 전체 SHA를 넣는다. branch 이름은 허용하지 않는다.

## 업데이트 승인

실행 주체: **root 관리자**

업데이트할 commit을 먼저 승인한다. 이 명령은 서버 private 상태인
`/srv/openclaw-ops/ops-update.yaml`만 갱신한다.

```bash
sudo /usr/local/bin/opsctl update approve FULL_40_CHARACTER_COMMIT_SHA
```

승인 상태 확인:

```bash
opsctl update status
```

## 이후 갱신

실행 주체: **svcops 또는 sudo 가능한 관리자 계정**

승인이 끝난 뒤 실제 갱신은 아래 명령만 사용한다.

```bash
sudo /usr/local/bin/opsctl self-update
```

이 명령은 `main` 같은 움직이는 branch를 설치하지 않는다. 오직
`/srv/openclaw-ops/ops-update.yaml`에 승인된 full commit만 설치한다.
설치 스크립트는 `svcops`에 이 명령만 비밀번호 없이 열어 둔다. `update approve`
권한은 열지 않는다.

설치 확인:

```bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -iu svcops -- opsctl profile list
```

`svcops`로 이미 로그인한 상태에서는 `sudo -u svcops`를 붙이지 않는다.

```bash
opsctl profile list
opsctl check oc1
```

`opsctl check SLOT`은 `/srv/openclaw-ops`의 desired state와 runtime profile
계약만 확인한다. 실제 Docker 컨테이너와 NAS mount 상태까지 보려면 live
검사를 실행한다.

```bash
sudo /usr/local/bin/opsctl check --live oc1
```

live 검사는 파일을 쓰지 않는다. host에는 NAS가 mount되어 있는데 컨테이너
안에서 child CIFS mount로 보이지 않거나, 컨테이너의 NAS root가 read-only가
아니면 실패한다.

## 설치 계정과 운영계정

설치한 계정이 운영계정이 되는 구조가 아니다.

```text
설치 실행 계정:
  sudo 가능한 관리자 계정

운영계정:
  기본값 svcops
```

관리자는 패키지를 설치하고 권한을 배치한다. 설치 후 일상 운영 명령은
`svcops`가 실행한다.

## 왜 svcops를 쓰나

`svcops`라는 이름 자체가 중요한 것이 아니라, **root도 고객 계정도 아닌 제한
운영계정**이 필요하다.

현재 서버에는 이미 `svcops`가 있으므로 기본 운영계정으로 사용한다.

이 계정으로 얻는 것:

```text
/srv/openclaw-ops를 운영자가 읽을 수 있음
root shell 없이 상태 조회와 점검을 수행함
고객 계정과 운영 권한을 분리함
```

이 계정으로 하지 않는 것:

```text
제품 소스 수정
이미지 직접 빌드
고객 secret 원문 열람
Docker compose 파일 직접 수정
root shell 임의 작업
```

운영계정을 바꾸려면 설치 전에 의도적으로 정해야 한다. 기본 운영 기준은
`svcops`다.

## 설치 결과

```text
/opt/agent-runtime-ops
  공개 운영 도구 설치 root

/opt/agent-runtime-ops/releases/<commit>
  commit별 설치본

/opt/agent-runtime-ops/current
  현재 활성 설치본 symlink

/usr/local/bin/opsctl
  current 설치본의 opsctl로 연결되는 명령

/srv/openclaw-ops
  서버 private 운영 상태
```

권한 기준:

```text
/opt/agent-runtime-ops   root:svcops
/usr/local/bin/opsctl    current 설치본을 실행하는 wrapper
/srv/openclaw-ops        root:svcops
```

## 현재 서버에서 추가로 필요한 private state

`opsctl profile list`는 설치 직후 확인할 수 있다.

slot 상태까지 보려면 `/srv/openclaw-ops`에 아래 파일이 있어야 한다.

```text
slots.yaml
lanes.yaml
releases.yaml
nas-policy.yaml
```

현재 기존 서버에는 `slots.yaml`, `images.yaml`, `nas-policy.yaml`은 있고,
`lanes.yaml`, `releases.yaml`은 아직 없을 수 있다. 이 경우 설치는 성공해도
`opsctl status oc1`은 준비되지 않은 상태가 맞다.

## 저장소 책임

```text
Epicevent/openclaw-jitech
  OpenClaw 제품 소스
  OpenClaw 제품 이미지

Epicevent/hermes-jitech
  Hermes 제품 소스
  Hermes 제품 이미지

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
sudo /usr/local/bin/opsctl apply SLOT
sudo /usr/local/bin/opsctl rollback SLOT
opsctl check SLOT

opsctl rollout LANE

opsctl release add NAME IMAGE
opsctl release promote NAME LANE

opsctl nas requests
opsctl nas approve-auto
opsctl nas mounted SLOT
opsctl nas policy-check SLOT SHARE
sudo /usr/local/bin/opsctl nas mount SLOT SHARE
sudo /usr/local/bin/opsctl nas unmount SLOT SHARE

opsctl admin serve
```

현재 초기 골격에서는 `status`, `plan`, `check`, `nas policy-check`가 비쓰기
명령이다. `nas mounted`도 비쓰기 명령이다.

`nas mount`와 `nas unmount`는 쓰기 명령이지만 compose를 수정하지 않는다.
동적 NAS 변화는 `/home/ocN/nas_docs/*` child mount에서만 처리한다.

`apply`와 `rollback`은 단일 slot 기준으로 동작한다. 기존 legacy 상태에서 첫 적용을
할 때는 명시적으로 `--allow-first-apply`를 붙인다. `rollout`은 단일 slot migration
검증 뒤에 연다.
