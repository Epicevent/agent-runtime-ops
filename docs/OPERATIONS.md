# 운영

운영 루프는 다음 순서다.

```text
status -> plan -> apply -> check
```

`status`, `plan`, `check`는 파일을 쓰지 않는다.

`opsctl check SLOT`은 desired contract만 확인한다. private state, release,
runtime profile이 유효한 runtime을 렌더링할 수 있는지 본다.

`sudo /usr/local/bin/opsctl check --live SLOT`은 Docker와 NAS mount 상태까지
확인한다. 이 명령도 파일을 쓰지 않는다. 다만 Docker metadata와 mount namespace를
읽으므로 제한된 root helper가 필요하다.

`sudo /usr/local/bin/opsctl apply SLOT`은 runtime profile compose를 렌더링하고,
agent-runtime manifest를 쓰고, slot container를 재생성한 뒤 live check를 실행한다.
NAS child mount는 수정하지 않는다.

legacy slot에서 처음 넘어올 때는 명시 플래그가 필요하다.

```bash
sudo /usr/local/bin/opsctl apply SLOT --allow-first-apply
```

`sudo /usr/local/bin/opsctl rollback SLOT`은 직전 agent-runtime compose와 manifest
backup을 복원한다. agent-runtime compose가 없던 slot은 legacy runtime을 복원할 수
없다.

`rollout`은 단일 slot apply/rollback migration 검증이 끝날 때까지 닫아 둔다.
