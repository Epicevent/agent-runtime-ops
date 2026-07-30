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

The installer does not claim that the five managed entry points (`opsctl`, MCP,
Gemini, manifest, and `current`) plus the root-action broker are group-atomic.
Instead it uses one durable, restartable activation transaction. Before the
first visible replacement, the transaction records the exact previous and
candidate identities, the exact prior broker unit bytes, and whether the broker
was active, inactive, absent, or unavailable. Unsafe pre-state (including a
dangling managed symlink, hard link, special node, wrong owner, or unexpected
type) is rejected before the journal or a managed entry is written.

One compatibility admission exists for the exact historical
`443c5fdaac231a1c62d4a927ca93e19d055e400a` release. That installer inherited a
caller `umask 077` into its generated `.venv`, so an otherwise exact root-owned
baseline can have `.venv` mode `0700` and be unexecutable by `svcops`. The
successor does not chmod or otherwise repair that active baseline in place. It
requires the exact legacy source, release manifest, policy approval, wrapper
bytes, ownership, link topology, and restrictive mode; proves the direct
legacy CLI fails with rc 126 while the complete identity remains unchanged;
then admits it only as `restored_exact_but_preexisting_unrunnable`. Every other
unrunnable or malformed baseline remains fail-closed. The newly materialized
candidate must still pass the normal pre-activation `svcops` CLI attestation.

If the installer is interrupted after any publication or broker transition,
the pending transaction remains under the install root. The next invocation
must use the exact same commit-bound helper. Under the install lock it restores
the complete previous identity, restores and attests the prior broker state,
re-attests a normally runnable previous CLI as `svcops`, or revalidates the
exact unchanged 443 restrictive-umask baseline and records
`restored_exact_but_preexisting_unrunnable`, durably retires the transaction,
and then stops. It never continues into a new activation in that invocation; the
operator reruns the installer only after recovery has completed. A failed first
install converges to the exact all-absent baseline.

Recovery finalization uses a distinct root-owned `recovered.complete` identity.
The next installer validates its exact commit-bound manifest, payload digests,
live baseline, and zero staging residue before acknowledging it. A killed
acknowledgement remains restartable under an `acknowledged` or `retired`
identity. Every invocation that observes one of these recovery identities stops
before package installation or a new activation.

The broker service state admitted before release construction is measured again
under the install lock immediately before the journal is created. A change from
active, inactive, or absent during that interval aborts before publication; the
stale state is never written into the transaction as recovery authority.
An already-active broker is then stopped and attested inactive before `current`
can move. The candidate broker unit pins both its condition and `ExecStart` to
the immutable candidate release rather than the mutable `current` link, and its
running process is checked on one stable `MainPID`: the environment release and
the exact three-element argv (`python`, `-m`, broker module) must agree, and the
PID is re-read unchanged before candidate finalization. Recovery restores
`current` and the previous unit before it
restarts an originally active broker, so no broker restart can cross the
publication window under a false release identity.

An entry whose live identity already equals the candidate identity is not
replaced. This preserves the inode of the manifest symlink when its baseline
and candidate target/owner/mode are exactly the same and avoids inventing an
extra crash boundary for a no-op publication.

A successful activation is finalized only after the candidate CLI works as
`svcops` and the root-action broker contract has completed. The previous release
is not pruned before those attestations. Release contents are materialized from
the exact Git commit tree, so dirty tracked files and untracked worktree files
cannot be attributed to the approved commit or enter the installed release.

Every activation path must be an already-normalized absolute path. `current`
and the manifest are fixed children of the install root, managed endpoints and
their fixed staging paths are pairwise disjoint, endpoint parents are
root-owned and nonwritable, and symlinked ancestors are rejected.
A root-owned sticky directory such as `/tmp` may only be a higher ancestor of a
protected endpoint directory; it is never accepted as the endpoint's immediate
parent. The shell validates this layout before bootstrap uses a configured path,
and the commit-bound transaction helper independently revalidates it on begin
and recovery.

Old slot/lane/release files may still exist as migration or compatibility inputs, but new image
rollout verification should use runtime bindings, runtime manifests, and live image truth.
