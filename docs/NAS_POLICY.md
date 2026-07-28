# NAS Policy

NAS 정책은 서버 private 상태에 둔다.

```text
/srv/openclaw-ops/nas-policy.yaml
```

이 공개 레포에는 실제 NAS grant 값, NAS password, credential 내용이 들어가지
않는다. 공개 레포는 정책 파일을 어떻게 해석하고 mount 상태를 어떻게 수렴할지만
정의한다.

## 이미 존재하는 중앙 corpus mount 재사용

호스트에 collector용 CIFS mount가 이미 있고 슬롯에는 그 중 승인된 경로만 보여야
한다면, private `nas-policy.yaml`에 exact share와 exact mountpoint를 결속한다.

```yaml
corpus_master_mounts:
  //NAS_HOST/SHARE: /mnt/nas/COLLECTOR_MOUNT
```

- 키는 wildcard가 아닌 exact `//HOST/SHARE`다.
- 값은 root가 관리하는 absolute POSIX path이며 CLI/웹 입력으로 받지 않는다.
- `opsctl nas view assign`은 path의 symlink-free identity와 live `findmnt`의
  target/source/fstype를 재검증한다. 매핑이 없는 share는 기존 per-slot CIFS 계약을
  유지한다. 매핑이 선언됐지만 path/mount가 invalid하거나, 저장된 shared view와 현재
  매핑이 drift하면 per-slot 방식으로 fallback하지 않고 실패한다.
- 중앙 mount는 읽기/쓰기일 수 있지만 슬롯에 직접 노출하지 않는다. 선택된 child와
  slot entry는 항상 `ro,nosuid,nodev` bind로 다시 고정한다.
- 이 모드에서는 slot별 NAS credential, slot별 CIFS session, slot별 managed fstab
  entry를 만들지 않는다. detach도 중앙 mount를 unmount하지 않는다.
- 재부팅 복구는 exact 중앙 CIFS fstab entry와 `nas view restore`를 모두 확인한다.
- 기존에 실패한 slot별 managed fstab entry가 있으면 exact slot/share/derived target,
  read-only, unmounted 상태가 모두 맞을 때만 assign이 제거한다. 다른 revision/slot의
  entry나 살아 있는 mount는 건드리지 않는다.

이 선언은 NAS 서버 권한을 강화하지 않는다. 중앙 credential이 쓰기 권한이면 그
credential의 피해 반경은 그대로다. 제품 경계가 보장하는 것은 slot에 보이는 선택된
subtree가 host mount options상 read-only/nosuid/nodev라는 점이다.

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
sudo /usr/local/bin/opsctl nas requests
opsctl nas policy-check oc3 //192.168.0.222/hanpass
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl nas credential status oc3 //192.168.0.222/hanpass
sudo /usr/local/bin/opsctl nas unmount oc3 //192.168.0.222/hanpass --delete-empty-dir
sudo /usr/local/bin/opsctl nas remove oc3 //192.168.0.222/hanpass
```

`nas unmount`도 `//HOST/SHARE`를 입력으로 받는다. mountpoint 이름만으로 해제하지
않는다.
