# NAS Policy

NAS 정책은 서버 private 상태에 둔다.

```text
/srv/openclaw-ops/nas-policy.yaml
```

이 공개 레포에는 실제 NAS grant 값, NAS password, credential 내용이 들어가지
않는다. 공개 레포는 정책 파일을 어떻게 해석하고 mount 상태를 어떻게 수렴할지만
정의한다.

## Runtime 경계

NAS share 변화는 compose를 바꾸지 않는다.

```text
runtime profile:
  /home/ocN/nas_docs -> container nas_docs root

dynamic NAS state:
  /home/ocN/nas_docs/host-<hosthash>/<share>
```

각 child CIFS mount는 host에서 생성되고, container에는 `rslave` propagation으로
보인다. container 쪽 NAS root와 child mount는 read-only여야 한다.

## 운영자 즉시 mount

운영자가 NAS credential까지 알고 있는 실험/긴급 상황에서는 root 명령으로 바로
credential, managed fstab entry, child mount를 만든다.

```bash
printf '%s' "$NAS_PASSWORD" | sudo /usr/local/bin/opsctl nas mount \
  oc3 //192.168.0.222/hanpass \
  --username NAS_USER \
  --password-stdin
```

비밀번호는 명령 인자로 받지 않는다.

## 고객 요청 자동승인

고객 계정은 request와 credential을 자기 홈에 남긴다.

```bash
opsctl nas request //192.168.0.222/hanpass
printf '%s' "$NAS_PASSWORD" | opsctl nas credential set \
  //192.168.0.222/hanpass \
  --username NAS_USER \
  --password-stdin
```

root 권한의 자동승인 루프는 pending request를 보고 grant와 credential을 확인한 뒤
fstab 등록과 mount를 수행한다.

```bash
sudo /usr/local/bin/opsctl nas approve-auto
sudo /usr/local/bin/opsctl nas approve-auto --watch --interval 15
```

credential이 아직 없으면 request는 pending으로 남는다. grant가 맞지 않거나 파일
소유권/권한이 안전하지 않으면 rejected로 이동한다.

## 조회와 해제

```bash
opsctl nas requests
opsctl nas policy-check oc3 //192.168.0.222/hanpass
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl nas unmount oc3 //192.168.0.222/hanpass --delete-empty-dir
```

`nas unmount`도 `//HOST/SHARE`를 입력으로 받는다. mountpoint 이름만으로 해제하지
않는다.
