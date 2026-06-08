# NAS Policy

NAS 정책은 서버 private 상태다.

```text
/srv/openclaw-ops/nas-policy.yaml
```

이 공개 저장소는 정책 파일의 실제 값이 아니라, 정책을 읽고 판정하는 도구와
규칙만 가진다. 실제 NAS grant 값, NAS password, credential 내용은 저장하지 않는다.

NAS 접근 완료 조건은 다음이다.

```text
host CIFS child mount 존재
container 안에서도 같은 child CIFS mount가 보임
runtime user가 읽을 수 있음
host child mount가 read-only
container NAS root가 read-only
container NAS root propagation이 rslave 계열
```

NAS 명령은 compose를 수정하지 않는다.

```text
fixed runtime profile:
  /home/ocN/nas_docs -> container nas_docs root

dynamic NAS state:
  /home/ocN/nas_docs/host-<hosthash>/<share>
```

비쓰기 명령:

```bash
opsctl nas policy-check SLOT //HOST/SHARE
opsctl nas mounted SLOT
```

쓰기 명령:

```bash
sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE
sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE
```

`nas mount`와 `nas unmount`는 host child CIFS mount만 바꾼다. compose, env,
image, runtime profile은 바꾸지 않는다.
