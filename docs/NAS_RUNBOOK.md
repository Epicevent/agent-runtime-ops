# NAS Mount Runbook

이 문서는 고객 slot의 NAS share를 붙이고 떼는 운영 절차다.

가장 중요한 기준은 두 층위를 분리해서 보는 것이다.

```text
1. Linux host 층위
   corpus: /home/ocN/nas_docs 아래에 실제 CIFS child mount가 있는가
   OCn:    /home/ocN/nas_rw/host-<hosthash>/<share> 에 CIFS mount가 있고,
           /home/ocN/workspace 가 그중 하나에 bind로 연결돼 있는가

2. Container 층위
   OpenClaw/Hermes container 안에서 그 mount가 보이는가
```

Host에 mount가 있어도 container에서 안 보이면 runtime profile의 NAS root bind 또는
propagation 문제다. Container NAS root가 보여도 child CIFS가 0이면 실제 share는 붙어 있지
않은 상태다.

## 원칙

NAS share 추가와 제거는 compose 변경이 아니다.

```text
compose가 고정하는 것 (의도별 두 트리):
  OpenClaw: /home/ocN/nas_docs  -> /home/node/nas_docs   (corpus, read_only)
            /home/ocN/workspace -> /home/node/workspace  (OCn, rw)
  Hermes:   /home/ocN/nas_docs  -> /workspace/nas_docs   (corpus, read_only)
            /home/ocN/workspace -> /workspace/ocn        (OCn, rw)

NAS 명령이 바꾸는 것:
  corpus(읽기 공유):  /home/ocN/nas_docs/host-<hosthash>/<share>
  OCn(쓰기 자기폴더): /home/ocN/nas_rw/host-<hosthash>/<share>
                      + /home/ocN/workspace (bind, 도구가 자동 관리)
```

쓰기 공유는 나스 주소별로 자기 자리를 갖는다. 그래서 이사 중에 구나스 OC5와 신나스
OC5를 동시에 마운트할 수 있다. container가 보는 자리는 언제나 /home/ocN/workspace
하나이고, 도구가 거기에 bind를 건다: 쓰기 mount가 하나면 자동으로 그걸 걸고, 둘
이상이면 자동으로 걸지 않으므로 고른다:

```bash
sudo /usr/local/bin/opsctl nas workspace-assign oc5 '//10.10.10.2/OC5'
```

이 명령은 bind를 바꾼 뒤 apply(container 재생성)까지 이어서 한다 — 떠 있는
container는 옛 bind를 계속 보기 때문이다. bind만 바꾸려면 `--no-apply`.

따라서 NAS를 붙이거나 뗄 때 다음을 하지 않는다.

```text
docker compose 파일 수정
env 파일 수정
container image 변경
Apache conf 수정
gateway-refresh로 문제를 덮기
mountpoint 이름만 보고 해제
```

입력 기준은 항상 SMB source다.

```text
//HOST/SHARE
```

예:

```text
//192.168.0.222/OC1
//192.168.0.222/hanpass
//192.168.0.222/한패스
```

## 상태 확인

### 1. Host CIFS mount 확인

```bash
opsctl nas mounted oc3
```

출력에서 봐야 할 값:

```text
mounted_child_cifs_count=1
mount_1_source=//192.168.0.222/hanpass
mount_1_fstype=cifs
mount_1_readonly=yes
```

`mounted_child_cifs_count=0`이면 Linux host 기준으로 실제 NAS share가 붙어 있지 않다.
count는 nas_docs 아래 corpus mount와 `/home/ocN/workspace`의 OCn mount를 합해서 센다.

### 2. Container visibility 확인

```bash
sudo /usr/local/bin/opsctl check --live oc3
```

출력에서 봐야 할 값:

```text
PASS live_container_nas_root_findmnt_ok
PASS live_container_nas_root_propagation required=rslave actual=slave
PASS live_container_child_cifs_count count=1
PASS live_container_sees_host_cifs_sources host=1 container=1
```

`live_container_nas_root_findmnt_ok`만 PASS이고 `live_container_child_cifs_count count=0`이면
container는 NAS root 통로만 보고 있고 실제 share는 없다.

### 3. Public service 확인

NAS 작업 후 gateway 자체가 살아 있는지도 본다.

```bash
sudo /usr/local/bin/opsctl check --live oc3
```

OpenClaw면 다음이 PASS여야 한다.

```text
PASS live_backend_http_smoke_ok url=http://127.0.0.1:<port>/healthz status=200
```

Hermes면 다음이 PASS여야 한다.

```text
PASS live_backend_http_smoke_ok url=http://127.0.0.1:<port>/ status=200
```

### 4. Writable workspace 실제 쓰기 확인

마운트 옵션과 그룹 비트만으로 쓰기 성공을 단정하지 않는다. 도구가 runtime 서비스
계정(`ocN_rt`)으로 임시 파일을 생성하고 fsync한 뒤 즉시 삭제해야 완료다. 파일명은
무작위이며 `O_EXCL|O_NOFOLLOW`로 만들고, 실패해도 root 부모가 잔여 파일을 정리한다.

```bash
sudo /usr/local/bin/opsctl nas workspace-write-probe oc17
sudo /usr/local/bin/opsctl nas workspace-write-probe --all
```

출력의 `mutates=temporary_file_create_fsync_remove`는 영구 데이터를 만들 의도가 없지만
실제 쓰기 권한을 증명하기 위해 짧게 파일을 생성한다는 뜻이다. 이 검사는 비밀값이나
기존 파일 내용을 읽지 않는다.

`workspace-assign`은 아직 마운트되지 않은 로컬 workspace에 항목이 있으면
`workspace_local_data_present`로 거부한다. bind가 로컬 작업물을 가리는 사고를 막기 위한
preflight이므로, 내용을 이관하거나 명시적으로 정리한 뒤 다시 실행한다.

## 운영자가 credential을 알고 있는 경우

실험용 NAS를 바로 붙여야 하거나 운영자가 NAS username/password를 알고 있는 경우다.

이 경로는 root 전용 credential을 만들고, managed fstab entry를 등록하고, 즉시 child CIFS
mount까지 수행한다.

```bash
read -rsp "NAS password: " NAS_PASSWORD
printf '\n'

printf '%s' "$NAS_PASSWORD" | sudo /usr/local/bin/opsctl nas mount \
  oc3 '//192.168.0.222/한패스' \
  --username '한패스' \
  --password-stdin

unset NAS_PASSWORD
```

성공 출력의 핵심:

```text
slot=oc3
share=//192.168.0.222/한패스
mountpoint=/home/oc3/nas_docs/host-<hosthash>/한패스
mounted_fstype=cifs
mounted_readonly=yes
mount_status=ok
```

OCn share(쓰기 자기폴더)를 붙이면 mountpoint와 모드가 다르고, workspace bind
결과가 한 줄 더 나온다:

```text
mountpoint=/home/oc3/nas_rw/host-<hosthash>/OC3
mounted_readonly=no
workspace_bind=ok auto_assign bound source=//10.10.10.2/OC3 ...
```

확인:

```bash
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl check --live oc3
```

## 고객이 직접 요청하는 경우

고객 계정은 자기 NAS source와 credential만 등록한다. fstab 등록과 mount 실행은 root 권한의
자동승인 루프가 처리한다.

고객 계정에서:

```bash
opsctl nas request '//192.168.0.222/OC1'

read -rsp "NAS password: " NAS_PASSWORD
printf '\n'

printf '%s' "$NAS_PASSWORD" | opsctl nas credential set \
  '//192.168.0.222/OC1' \
  --username 'OC1' \
  --password-stdin

unset NAS_PASSWORD
```

운영자 또는 데몬:

```bash
sudo /usr/local/bin/opsctl nas approve-auto
```

상시 감시는 다음처럼 실행한다.

```bash
sudo /usr/local/bin/opsctl nas approve-auto --watch --interval 15
```

대기 요청 확인:

```bash
sudo /usr/local/bin/opsctl nas requests
```

정책만 미리 확인:

```bash
opsctl nas policy-check oc3 '//192.168.0.222/한패스'
```

## NAS unmount

해제도 항상 `//HOST/SHARE` 기준으로 한다. Mountpoint 이름만 넣지 않는다.

```bash
sudo /usr/local/bin/opsctl nas unmount oc3 '//192.168.0.222/한패스' --delete-empty-dir
```

성공 출력:

```text
existing_mount_source=//192.168.0.222/한패스
existing_mount_fstype=cifs
existing_mount_readonly=yes
unmount_status=ok
empty_dir_removed=yes
```

이미 내려가 있으면 성공 상태로 처리된다.

```text
unmount_status=already_unmounted
```

확인:

```bash
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl check --live oc3
```

기대 상태:

```text
mounted_child_cifs_count=0
PASS live_container_child_cifs_count count=0
PASS live_no_host_child_cifs_mounted
```

## NAS remove

`nas unmount` is temporary. It keeps official root/customer credentials and the managed fstab
entry, so the same share can be mounted again without re-entering the password.

Use `nas remove` for permanent removal or authorization withdrawal:

```bash
sudo /usr/local/bin/opsctl nas credential status oc3 '//192.168.0.222/한패스'
sudo /usr/local/bin/opsctl nas remove oc3 '//192.168.0.222/한패스' --delete-empty-dir
sudo /usr/local/bin/opsctl nas credential status oc3 '//192.168.0.222/한패스'
```

`nas remove` deletes only official root/customer credentials:

```text
/root/agent-runtime-ops/nas-credentials/SLOT/...
/home/SLOT/.agent-runtime-nas/credentials/...
```

Legacy `.openclaw-nas` credentials are not official credential state and are not removed.

## Busy mount 처리

기본 unmount는 normal `umount`만 쓴다. Busy 상태를 숨기지 않기 위해 lazy unmount는 기본으로
쓰지 않는다.

Busy로 실패하면 먼저 해당 NAS를 사용 중인 작업을 멈춘다. 그래도 운영자가 명시적으로
lazy unmount를 선택해야 하는 경우에만 다음을 쓴다.

```bash
sudo /usr/local/bin/opsctl nas unmount oc3 '//192.168.0.222/한패스' --lazy --delete-empty-dir
```

`--lazy`는 일반 운영 절차가 아니다.

## 현재 상태를 요약하는 법

한 slot을 볼 때:

```bash
opsctl nas mounted oc3
sudo /usr/local/bin/opsctl check --live oc3
```

전체 slot을 볼 때:

```bash
for i in $(seq 1 20); do
  u="oc$i"
  echo "===== $u host mount ====="
  opsctl nas mounted "$u" | grep -E 'mounted_child_cifs_count|mount_[0-9]+_source|mount_[0-9]+_readonly'
  echo "===== $u container ====="
  sudo /usr/local/bin/opsctl check --live "$u" \
    | grep -E 'live_container_child_cifs_count|live_container_sees_host_cifs_sources|live_no_host_child_cifs_mounted|check_status='
done
```

보고할 때는 다음 형식을 쓴다.

```text
Host CIFS mount 있음:
  oc1 -> //192.168.0.222/OC1
  oc3 -> //192.168.0.222/hanpass

Container에서도 보임:
  oc1 host=1 container=1
  oc3 host=1 container=1

Host CIFS mount 없음:
  oc15, oc17, oc18

Container child CIFS 없음:
  oc15, oc17, oc18
```

## 문제 판정표

```text
host count=0, container count=0:
  NAS share가 붙어 있지 않음

host count=1, container count=1:
  정상. Host mount와 container visibility 모두 있음

host count=1, container count=0:
  runtime profile, bind propagation, container namespace 문제

host count=0, container count=1:
  비정상. stale namespace 또는 관측 오류 가능성. 즉시 조사

readonly=no (corpus share):
  비정상. NAS mount 옵션 또는 root bind 설정 문제

readonly=yes (OCn share):
  비정상. OCn은 에이전트 자기 workspace라 rw여야 한다.
  container 안에서만 ro라면 nas_docs 아래 옛 자리에 마운트된 잔재가
  recursive read_only 도장을 맞은 것이다 — workspace로 이주한다
  (아래 "OCn workspace 이주", 원리는 docs/NAS_MOUNT_LIFECYCLE.md)

source가 요청한 //HOST/SHARE와 다름:
  비정상. 잘못된 share를 건드릴 수 있으므로 unmount 중단
```

## OCn workspace 이주 (자리 규칙이 바뀔 때, slot당 1회)

OCn의 자리 규칙이 바뀌면(2026-07: nas_docs 아래 → flat workspace → nas_rw+bind) 옛
자리의 fstab 줄과 살아 있는 mount가 남는다. `live_fstab_stamp_matches_derivation`이
옛 줄을 전부 빨갛게 띄우므로 그 목록이 곧 할 일 목록이다. slot마다:

```bash
# 1) 옛 자리에 살아 있는 mount를 직접 umount (도구는 새 자리만 계산하므로 경로 직접 지정)
sudo umount /home/oc2/workspace            # flat 시절 자리면 이 줄
sudo umount /home/oc2/nas_docs/host-*/OC2  # 분리 이전 자리면 이 줄

# 2) 새 자리에 mount — fstab 줄은 (slot,source) 키라 자동 교체되고,
#    쓰기 mount가 하나뿐이라 workspace bind도 자동으로 걸린다
sudo /usr/local/bin/opsctl nas mount oc2 '//10.10.10.2/OC2'

# 3) container 재생성 후 확인
sudo /usr/local/bin/opsctl apply oc2
opsctl nas mounted oc2                     # workspace_bound_to=//10.10.10.2/OC2 이어야 한다
sudo /usr/local/bin/opsctl check --live oc2
```

**불변식: OCn을 host에서 재마운트(unmount+mount)하면 반드시 `apply`(container 재생성)까지
한 세트다.** workspace bind는 CIFS mount 자체를 루트로 무는 flat bind라, host에서 그 mount를
갈아끼워도 rslave 전파가 container의 bind 루트를 교체해주지 않는다(전파는 bind *아래에* 새로
서는 mount에만 적용된다 — nas_docs 밑 corpus 자식들과 다른 점). 재생성 없이 두면 container는
옛 mount의 클론이나 빈 디렉토리를 물고 있고, 에이전트 쓰기는 Permission denied로 죽는다
(2026-07-15 oc2에서 실측).

최종 확인은 container 안 쓰기 실증까지다 (기본 유저 = runtime 계정으로):

```bash
docker exec $(docker ps -qf label=agent-runtime.slot=oc2) sh -lc \
  'touch /home/node/workspace/.rw_probe && rm /home/node/workspace/.rw_probe && echo AGENT_WRITE_OK'
```

## 기록 위치

NAS 작업 결과는 action log에 남는다.

```text
/srv/openclaw-ops/reports/actions.log
```

이 파일에는 secret 원문을 남기지 않는다.
