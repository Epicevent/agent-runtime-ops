# NAS Mount Lifecycle

이 문서는 운영 절차가 아니라 **변경자용 기전 원장**이다. 마운트 경로·이름을 파생하는 코드를
바꾸기 전에 읽는다 (`AGENTS.md`의 NAS Mount Lifecycle 계약). 절차는 `NAS_RUNBOOK.md`,
정책 데이터는 `NAS_POLICY.md`.

의도 하나에서 출발한다 — slot 에이전트가 자기 폴더에 쓴 파일은 실제 NAS에 남아야 하고,
공유 지식(corpus)은 읽되 어떤 경우에도 부수지 못해야 한다. 이 의도가 성립하려면 여덟 가지가
필요하고, 각각 답하는 자리가 다르다.

## Q1. 서버가 신원에 열어야 한다 — DSM 계정 (모드의 1차 권위)

호스트·컨테이너가 무슨 짓을 해도 NAS 서버가 안 열면 끝이다. OCn 공유는 자기 계정이 자기
폴더를 rw 소유하고, corpus는 전용 read-only 계정으로만 접근한다(비밀번호가 새어도 그 신원은
쓸 수 없다). 권한 차등은 slot(컴퓨트)이 아니라 계정·공유폴더(스토리지)에 둔다.

## Q2. 열쇠는 거처가 갈린다 — 두 credential 금고

OCn 열쇠는 slot 소유 self-service 경로, corpus 열쇠는 root 전용 금고
(`/root/agent-runtime-ops/nas-credentials/…`)로, 고객 계정이 읽을 수 없어야 한다.
corpus 열쇠가 slot 홈에서 발견되면 root 금고로 이관된다.
근거: `nas.py` `customer_credential_path`/`root_credential_path`,
`domain/nas_credentials.py`.

## Q3. 허락은 root 선언 데이터 — nas-policy.yaml

무엇을(grants)·몇 개까지(max_mounts)·자동승인 여부(auto_approve)는 root가 편집하는
`nas-policy.yaml`의 `accounts[slot]`에 선언되고, 모든 마운트 시도가 `check_nas_policy`를
지난다. 두 한정:

- 모드(rw/ro)는 이 파일이 아니라 이름 클래스가 정하는 **기대치**다 — `share_is_writable`
  (`nas.py`): `OC\d+`만 쓰기 클래스, 나머지는 전부 ro 클래스. 강제는 Q1 계정 + Q4 마운트
  옵션이 한다.
- 정책은 **등록 시점의 관문**이지 상시 감시가 아니다. 정책을 조여도 이미 박제된 등록(Q4)은
  사라지지 않는다. 회수는 `nas remove`다.

## Q4. 부팅이 재현할 박제 — managed /etc/fstab (이 문서의 존재 이유)

살아있는 마운트는 재부팅에 죽는다. 부팅이 다시 실행할 기록이 root 소유 `/etc/fstab`의
managed 엔트리다: 마커 `# agent-runtime-ops nas slot={slot} source={share}` + cifs 줄
(credentials·rw/ro·uid/gid 강제·nofail). 근거: `host/fstab.py`.

**불변식: 키는 (slot, source)이고 mountpoint는 값이다.**

- mountpoint를 *계산하는 코드*(Q5)를 바꿔도 *박제된 값*은 그대로다. 파생을 바꾸는 변경은
  박제 이주를 함께 져야 한다 — 안 지면 부팅마다 옛 세계가 재현된다.
- 이주 수단은 키 설계가 이미 준다: 같은 (slot, source)로 `nas mount`를 다시 치면 엔트리가
  통째로 새 mountpoint로 **교체**된다(추가가 아니라서 좀비가 안 남는다). 옛 자리에 살아있는
  마운트만 직접 umount한다. 절차: `NAS_RUNBOOK.md`의 "OCn workspace 이주".

공유 corpus에 이미 root가 관리하는 중앙 collector mount가 있다면 예외적으로 그 mount를
`nas-policy.yaml`의 `corpus_master_mounts`에 exact share→path로 선언할 수 있다. 이때 슬롯별
managed CIFS entry를 새로 박제하지 않는다. 대신 중앙 mount의 기존 fstab entry가 부팅 권위이고,
slot view 원장은 `master_mode=shared_policy_mount`와 당시 exact path를 함께 보존한다. restore는
현재 private policy와 원장의 path가 같고 live CIFS source가 같은 경우에만 bind를 재생한다.
detach는 중앙 mount/fstab을 절대 제거하지 않는다. 기존 실패가 남긴 슬롯별 entry는 exact
slot/share/derived target이고 미마운트임을 확인한 경우에만 shared mode assign이 이주 제거한다.

## Q5. 자리는 의도의 함수 — mountpoint 파생

Docker의 `read_only` 바인드는 **recursive read-only**다: 컨테이너 create/start/restart
시점에 그 트리 밑에 존재하는 모든 서브마운트에 per-mount ro 도장을 찍는다(그 뒤 rslave
전파로 들어온 마운트만 도장을 피한다). 그러므로 **쓰기 마운트가 ro 트리 밑에 있으면 반드시
언젠가 얼어붙는다** — 2026-07 oc2 동결의 기전이다(생성 시점에 이미 마운트돼 있던 OC2는 ro
도장, 생성 후 마운트된 oc6는 rw — 타이밍이 갈랐다).

따라서 자리 규칙은 취향이 아니라 필연이다: **한 트리에는 한 의도만, 한 소스에는 한
자리씩.**

```text
쓰기 클래스(OCn):  /home/{slot}/nas_rw/host-<hosthash>/<share>   (소스별 자리)
ro 클래스(corpus): /home/{slot}/nas_docs/host-<hosthash>/<share>
container가 보는 자리: /home/{slot}/workspace — nas_rw 중 하나에 bind로 연결
```

자리를 소스별로 나누는 이유: 구나스 OC5와 신나스 OC5처럼 share 이름이 같은 두 소스가
한 자리를 놓고 부딪히면 remove/unmount가 남의 mount를 지울까 봐 거부하게 된다(2026-07
실측). container 경로를 하나로 유지하는 건 bind가 맡는다 — 쓰기 mount가 하나면 도구가
자동으로 걸고, 둘 이상이면 `nas workspace-assign`으로 고른다(slot 배정 웹이 부를 자리).
bind도 fstab에 적혀 재부팅을 살아남고, 갈아탈 때는 apply(재생성)까지가 한 세트다(bind
뿌리는 전파로 안 갈린다 — Q6).

근거: `nas.py` `mountpoint_for_share`/`nas_rw_root`/`workspace_root`,
`domain/workspace_bind.py`. 이 함수들이 등록·마운트·해제 전부의 경로 원천이다. 탈출
가드는 slot 홈을 경계로 한다(`domain/nas_mounts.py`, `commands/nas.py`).

## Q6. 컨테이너가 보려면 — compose 두 트리

runtime profile이 두 바인드를 고정한다: corpus 트리는 `read_only: true` + `rslave`,
OCn workspace 트리는 모드 없이 + `rslave`. corpus 바인드의 `read_only`는 권위(Q1)가 아니라
**방어 심층 두 번째 자물쇠**이고, Q5로 트리가 단일 의도가 됐기 때문에야 안전하다(얼릴 쓰기
자식이 없다). rslave 덕에 호스트에서 나중에 선 마운트도 재생성 없이 흘러든다.
근거: `profiles/runtime/*/compose.yml.tpl`. workspace 디렉토리는 slot 생성 시
(`commands/admin.py`)와 **매 apply마다**(`domain/runtime_apply.py`
`ensure_nas_workspace_dir`) 보장된다 — apply는 자기 컴포즈가 요구하는 바인드
소스를 스스로 보장해야 하며, 분리 이전에 만들어진 slot에 그 디렉토리가 없다는
이유로 compose up이 실패해선 안 된다(Q4와 같은 부류: 새 코드의 요구는 옛 코드가
만든 세계에 저절로 적용되지 않는다).

## Q7. 세우는 손이 마운트도 — 미완 (실행자 갭)

오늘 마운트 실행자는 root 명령 셋(`nas mount` 수동 · `nas approve-auto` 요청 워처 ·
`nas view` corpus 전용)이고, slot을 세우는 `apply`는 마운트를 몰지 않는다
(`domain/runtime_apply.py`). 승인된 설계: apply가 Q3의 선언에서 그 slot의 쓰기 소스를 읽어
root `nas mount`에 위임 — 새 선언·하드코딩 없이 apply를 이미 선언된 것의 집행자로 만든다.
slot 배정(웹) 로직과 만나는 지점이라 섬세 설계 대상.

## Q8. 바닥까지 감시 — 미완 (검사 갭)

감시는 대칭이어야 한다: corpus가 *더 써지면* 잡고(천장), OCn이 *못 써지면*도 잡아야(바닥)
한다. 오늘은 천장만 있다 — 컨테이너 검사는 ro를 항상 용인해 얼어붙은 OCn을 잡지 못하고
(`domain/runtime_checks.py` `_child_cifs_mode_ok` `ro_always_ok=True`), 모드 가드는 required
집합에 없다. 신설 대상: ① workspace-rw 바닥검사 + required 등록(이주 완료 slot과 lockstep),
② Q4 불변식의 기계화 — 박제 mountpoint ↔ 현재 파생값 대조 검사(어긋나면 FAIL). ②가 서면
파생 변경이 이주를 잊어도 도구가 잡는다.

## 관통 원칙

> **결정마다 그것을 소유한 자리가 있고, 다른 자리는 베끼지 말고 받아야 한다.**

- 모드의 소유는 스토리지(Q1) — compose가 NAS 데이터의 authority를 쓰기 시작하면 한 결정에
  서명이 둘이 되고, 어긋남이 장애로 청구된다(oc2 동결).
- 존재의 소유는 박제(Q4) — 파생 코드는 박제를 베낀 게 아니라 박제가 파생의 과거 출력이다.
  파생을 바꾸면 박제를 이주시킨다.
- 허용의 소유는 root 데이터(Q3) — 코드에 예산·허락 특례를 넣지 않는다.
