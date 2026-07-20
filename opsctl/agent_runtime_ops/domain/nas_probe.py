"""마운트됨 ≠ 연결됨 — 실제 I/O 로 가르는 측정기 (7/20).

마운트 테이블은 NAS 가 죽어도 그대로다: 장비가 내려가 있던 동안에도 findmnt 는
cifs 81개를 "mounted" 로 보고했다(실측). 진짜 질문은 "지금 읽히는가"이므로,
마운트마다 시간제한을 건 stat 을 **자식 프로세스**로 던진다 — 죽은 cifs 위의
시스템콜은 프로세스를 D 상태로 매달기 때문에 절대 이 프로세스 안에서 직접
파일시스템을 만지지 않는다. timeout(1) 이 그 안전벽이다.

두 층을 잰다:
  · 호스트 층: NAS 의 SMB 포트(445)에 TCP 가 열리는가 — 장비/서비스 생존.
  · 마운트 층: 각 마운트에서 statfs 가 제한시간 안에 돌아오는가 — 세션 생존.
호스트가 살아도 개별 cifs 세션이 재접속에 실패해 죽어 있을 수 있고(복구 직후),
그 반대는 없다 — 그래서 두 층이 다 필요하다.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor

from .common import run_text

PROBE_TIMEOUT_S = 3
HOST_PORT = 445
HOST_TIMEOUT_S = 2
_MAX_WORKERS = 12

_SMB_HOST_RE = re.compile(r"^//([^/]+)/")


def smb_host_of(source: str) -> str:
    """findmnt SOURCE (//host/share 또는 //host/share/sub) → host. 아니면 ""."""
    match = _SMB_HOST_RE.match(source.strip())
    return match.group(1) if match else ""


def classify_probe(rc: int, stderr: str) -> tuple[bool, str]:
    """timeout(1) 규약: 124 = 제한시간 초과(매달림). 0 = 응답. 그 외 = I/O 에러."""
    if rc == 0:
        return True, ""
    if rc == 124:
        return False, "timeout"
    return False, (stderr or f"rc={rc}").strip().splitlines()[-1][:120] if stderr else f"rc={rc}"


def probe_mount(target: str, timeout_s: int = PROBE_TIMEOUT_S) -> tuple[bool, str]:
    """마운트 하나의 실제 읽기 생존 — statfs 가 서버 왕복을 강제한다."""
    proc = run_text(["timeout", str(timeout_s), "stat", "-f", "--format=%T", target])
    return classify_probe(proc.returncode, proc.stderr or "")


def probe_host(host: str, port: int = HOST_PORT, timeout_s: int = HOST_TIMEOUT_S) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def probe_mounts(rows: list[dict[str, str]], probe=probe_mount) -> list[dict[str, str]]:
    """cifs 마운트 목록 전체를 병렬로 잰다. 반환 행: target, source, alive, reason."""
    targets = [row.get("target", "") for row in rows]
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(targets))) as pool:
        results = list(pool.map(probe, targets))
    out = []
    for row, (alive, reason) in zip(rows, results):
        out.append({
            "target": row.get("target", ""),
            "source": row.get("source", ""),
            "alive": "yes" if alive else "no",
            "reason": reason,
        })
    return out
