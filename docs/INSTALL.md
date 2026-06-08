# 설치

`agent-runtime-ops`는 공개 운영 도구 패키지다. 실제 서버 운영 상태는 이
저장소가 아니라 `/srv/openclaw-ops`에 둔다.

## 설치 실행 주체

실행 주체: **관리자/root 권한을 가진 계정**

설치 명령은 `sudo` 비밀번호를 요구할 수 있다. 설치가 끝난 뒤 실제 운영
명령은 기존 운영계정 `svcops`가 실행한다.

## 설치 명령

서버에서 아래 한 줄을 실행한다.

```bash
curl -L https://raw.github.com/Epicevent/agent-runtime-ops/main/go | sudo bash
```

같은 명령을 다시 실행하면 `main` 기준 최신 설치본으로 갱신된다.

## 설치 확인

```bash
sudo bash /opt/agent-runtime-ops/install.sh --check
sudo -u svcops opsctl profile list
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

현재 서버에 `lanes.yaml` 또는 `releases.yaml`이 없으면 설치는 성공해도
slot 상태 조회는 아직 준비되지 않은 상태다.
