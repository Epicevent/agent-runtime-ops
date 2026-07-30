# 설치

`agent-runtime-ops`는 공개 운영 도구 패키지다. 실제 서버 운영 상태는 이
저장소가 아니라 `/srv/openclaw-ops`에 둔다.

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
설치 스크립트는 `svcops`에 정해진 운영 명령만 비밀번호 없이 열어 둔다.
`update approve` 권한은 열지 않는다.

## 설치 확인

```bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -iu svcops -- opsctl profile list
```

`svcops`로 이미 로그인한 상태에서는 `sudo -u svcops`를 붙이지 않는다.

```bash
opsctl profile list
opsctl check oc1
```

## 설치 계정과 운영계정

새 계정에서 설치해도 그 계정이 운영계정이 되지는 않는다.

```text
설치 실행 계정:
  sudo 가능한 관리자 계정

운영계정:
  기본값 svcops
```

관리자는 설치한다. `svcops`는 설치된 `opsctl`을 실행한다.

## svcops를 쓰는 이유

현재 서버는 `/srv/openclaw-ops`를 `root:svcops` 기준으로 운영한다.

따라서 `svcops`는 root shell 없이 운영 상태를 읽고 점검할 수 있다. 고객
계정과 운영 권한도 분리된다.

`svcops`가 하는 일:

```text
opsctl profile list
opsctl slot list
opsctl status SLOT
opsctl plan SLOT
opsctl check SLOT
sudo /usr/local/bin/opsctl check --live SLOT
sudo /usr/local/bin/opsctl apply SLOT
sudo /usr/local/bin/opsctl rollback SLOT
sudo /usr/local/bin/opsctl runtime-secret set SLOT --key GEMINI_API_KEY --value-stdin
sudo /usr/local/bin/opsctl runtime-secret status SLOT
opsctl nas request //HOST/SHARE
opsctl nas credential set //HOST/SHARE --username NAS_USER --password-stdin
sudo /usr/local/bin/opsctl nas credential status SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas approve-auto
sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas remove SLOT //HOST/SHARE
```

`svcops`가 하지 않는 일:

```text
제품 소스 수정
이미지 직접 빌드
고객 secret 원문 열람
Docker compose 직접 수정
```

`apply`는 runtime profile에서 생성한 compose만 쓴다. 운영자가 compose 파일을 직접
수정하는 작업은 운영 기준이 아니다.

## 설치 후 위치

```text
/opt/agent-runtime-ops
  공개 운영 도구 설치 root

/opt/agent-runtime-ops/releases/<commit>
  commit별 설치본

/opt/agent-runtime-ops/current
  현재 활성 설치본 symlink

/usr/local/bin/opsctl
  current 설치본으로 연결되는 opsctl 명령

/srv/openclaw-ops
  실제 서버 운영 상태
```

## 권한 기준

```text
/opt/agent-runtime-ops   root:svcops
/usr/local/bin/opsctl    current 설치본을 실행하는 wrapper
/srv/openclaw-ops        root:svcops
```

`self-update`는 호출자의 `umask`와 무관하게 생성된 Python `.venv`와 Gemini
`node_modules`를 `root:svcops`로 고정한다. 디렉터리와 실행 파일은 `0750`, 그 외
일반 파일은 `0640`이며 world 권한은 없다. 설치기는 activation 전에 새 release의
CLI를 실제 `svcops` 계정으로 실행하고, activation 뒤에는
`/usr/local/bin/opsctl update status`를 같은 계정으로 다시 검증한다. 이 검증이
끝나기 전에는 이전 release code를 prune하지 않는다.

## 다음 확인

`opsctl status oc1`까지 확인하려면 `/srv/openclaw-ops`에 아래 파일들이
있어야 한다.

```text
runtime-bindings.json
slot-registry.json
runtime/<slot>/manifest.yaml
nas-policy.yaml
```

## Privileged activation continuity

The installer captures the exact previously active release and whether the
root-action broker was active before changing `current`. It immediately runs the
candidate CLI as `svcops`. If that attestation fails, it restores the previous
`current` link and generated wrappers, re-runs the previous CLI attestation, and
restarts and re-attests the broker at the exact previous release when the broker
was already active. A previously inactive broker remains inactive. On a failed
first install, candidate links are removed rather than left as the active
identity. The previous release is not pruned until the candidate CLI and broker
contract have both been verified.

Old slot/lane/release files may still exist as migration or compatibility inputs, but new image
rollout verification should use runtime bindings, runtime manifests, and live image truth.
