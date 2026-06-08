# 설치

`agent-runtime-ops`는 공개 운영 도구 패키지다. 실제 서버 운영 상태는 이
저장소가 아니라 `/srv/openclaw-ops`에 둔다.

## 한 줄 설치

실행 주체: **sudo 가능한 관리자 계정**

```bash
sudo -v && curl -fsSL https://raw.githubusercontent.com/Epicevent/agent-runtime-ops/main/go | sudo bash
```

같은 명령을 다시 실행하면 `main` 기준 최신 설치본으로 갱신된다.

## 설치 확인

```bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -u svcops opsctl profile list
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
opsctl status SLOT
opsctl plan SLOT
opsctl check SLOT
```

`svcops`가 하지 않는 일:

```text
제품 소스 수정
이미지 직접 빌드
고객 secret 원문 열람
Docker compose 직접 수정
```

## 설치 후 위치

```text
/opt/agent-runtime-ops
  설치된 공개 운영 도구

/usr/local/bin/opsctl
  svcops가 실행할 opsctl 명령

/srv/openclaw-ops
  실제 서버 운영 상태
```

## 권한 기준

```text
/opt/agent-runtime-ops   root:svcops
/usr/local/bin/opsctl    /opt/agent-runtime-ops/.venv/bin/opsctl 링크
/srv/openclaw-ops        root:svcops
```

## 다음 확인

`opsctl status oc1`까지 확인하려면 `/srv/openclaw-ops`에 아래 파일들이
있어야 한다.

```text
slots.yaml
lanes.yaml
releases.yaml
nas-policy.yaml
```

기존 서버에 `lanes.yaml` 또는 `releases.yaml`이 없으면 설치는 성공해도 slot
상태 조회는 아직 준비되지 않은 상태다.
