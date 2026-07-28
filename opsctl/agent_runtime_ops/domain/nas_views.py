"""Per-user NAS slot views (kakao-work).

A view gives one slot read-only access to exactly one user's slice of a share:

    /srv/kw-nas/slots/{slot}/master   <- full share, CIFS ro, uid={slot},
                                         hidden behind a root-only (0700) parent
    /srv/kw-nas/slots/{slot}/view/
      package/                        <- bind ro -> master/users/{package dir}
      media/{room}/                   <- bind ro -> master/media/{room}
                                         (only rooms in the user's membership.json)
    /home/{slot}/nas_docs/kw          <- bind ro -> view/

The slot never sees the master mountpoint (0700 parent blocks traversal); binds
expose only the allowed subtrees. Rewiring slot<->user is detach + assign — no
NAS-side changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import sqlite3
import re
from pathlib import Path

from ..host.fstab import managed_fstab_marker
from ..nas import SmbShare, check_nas_policy
from ..paths import state_path
from ..routing import validate_linux_account
from ..yamlio import dump_yaml, load_yaml

VIEWS_STATE_NAME = "nas-views.yaml"
VIEWS_ROOT = Path("/srv/kw-nas/slots")
SAFE_USER_ID_RE = re.compile(r"^[A-Za-z0-9.@_-]{1,64}$")
SAFE_ROOM_ID_RE = re.compile(r"^[A-Za-z0-9.@_-]{1,80}$")


# ── corpus registry ───────────────────────────────────────────────────
# 한 슬롯은 그 사람의 소스 "전부"를 봐야 한다(카카오·그룹웨어·와츠앱…). 코퍼스마다
# 디스크 레이아웃이 다르므로 뷰 계획은 여기서 갈린다:
#   kakao_package — users/{이름}_{직함}_{user_id} 패키지 + membership.json 의 방 바인드
#   granted_paths — 무엇을 붙일지 opsctl 이 스스로 정하지 않는다. 호출자(리컨실러)가
#                   경로를 명시로 넘긴다. 그룹웨어에서 "이 사람이 볼 경로"의 진실은
#                   grant 원장(g5_dashboard_nas_grant)이고 운영자가 편집 페이지에서
#                   폴더를 직접 고른다 — mails/{mb_id} 같은 규칙은 편의 기본값일 뿐
#                   진실이 아니다(approval 은 표시이름 폴더라 규칙으로는 안 잡힌다).
#                   opsctl 은 DB 를 모른 채 "받은 경로만" 마운트한다.
# PRIMARY(kakao)의 경로는 고객 슬롯에 이미 살아 있으므로 절대 바꾸지 않는다:
# master/view 는 slots/{slot}/ 바로 아래, 진입점은 nas_docs/kw 그대로. 새 코퍼스는
# slots/{slot}/{corpus}/ 와 nas_docs/{entry} 로 나란히 선다.
PRIMARY_CORPUS = "kakao"


@dataclass(frozen=True)
class Corpus:
    name: str
    entry_name: str          # /home/{slot}/nas_docs/{entry_name}
    layout: str              # "kakao_package" | "granted_paths"


CORPORA: dict[str, Corpus] = {
    "kakao-work": Corpus(PRIMARY_CORPUS, "kw", "kakao_package"),
    "hanpass_groupware": Corpus("groupware", "groupware", "granted_paths"),
    "whatsapp": Corpus("whatsapp", "whatsapp", "whatsapp_author"),
}


def corpus_for_share(share_source: str) -> Corpus:
    """share → Corpus. 모르는 share 는 조용히 기본값으로 흐르지 않고 거부한다 —
    미등록 코퍼스를 카카오 레이아웃으로 마운트하려다 엉뚱한 폴더를 노출하는 것보다
    붙지 않는 편이 안전하다."""
    name = str(share_source).strip().rstrip("/").rsplit("/", 1)[-1]
    corpus = CORPORA.get(name)
    if corpus is None:
        known = ", ".join(sorted(CORPORA))
        raise ValueError(f"unknown corpus share {name!r} — declare it in CORPORA (known: {known})")
    return corpus


def corpus_named(name: str) -> tuple[str, Corpus]:
    matches = [(share, corpus) for share, corpus in CORPORA.items() if corpus.name == name]
    if len(matches) != 1:
        raise ValueError(f"unknown or ambiguous corpus name: {name!r}")
    return matches[0]


def validate_user_id(user_id: str) -> str:
    value = str(user_id).strip()
    if not SAFE_USER_ID_RE.match(value) or value in {".", ".."}:
        raise ValueError(f"unsafe user_id: {user_id!r}")
    return value


def validate_room_id(room_id: str) -> str:
    value = str(room_id).strip()
    if not SAFE_ROOM_ID_RE.match(value) or value in {".", ".."}:
        raise ValueError(f"unsafe conversation_id: {room_id!r}")
    return value


def fstab_boot_entry_present(slot: str, share: str, fstab_text: str) -> bool:
    """True when the managed fstab pair (marker + cifs entry) survives for this view.

    write_managed_fstab_entry always writes the marker comment immediately
    followed by the entry line — a marker with anything else after it means the
    entry was hand-edited away and the master will not mount at boot."""
    marker = managed_fstab_marker(slot, share)
    lines = fstab_text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != marker:
            continue
        if index + 1 >= len(lines):
            return False
        entry = lines[index + 1].strip()
        return bool(entry) and not entry.startswith("#") and " cifs " in f" {entry} "
    return False


def shared_master_fstab_entry_present(share: str, master: Path, fstab_text: str) -> bool:
    """True for an exact non-comment CIFS fstab entry for a shared master.

    Unlike a per-slot master this entry is not stamped by opsctl, so it has no
    managed marker.  Only the exact source/target/fstype triple is relevant;
    options and credential material are intentionally neither returned nor
    logged here.
    """
    expected_target = master.as_posix()
    for raw in fstab_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[2] != "cifs":
            continue
        if _fstab_unescape(fields[0]) == share and _fstab_unescape(fields[1]) == expected_target:
            return True
    return False


_MANAGED_MARKER_RE = re.compile(r"^# agent-runtime-ops nas slot=(?P<slot>\S+) source=(?P<share>\S+)$")


def _fstab_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def managed_fstab_mount_targets(fstab_text: str) -> list[tuple[str, str, str]]:
    """(slot, share, mount target) for every managed fstab pair in the file.

    Registration is not boot success: after the 2026-07-07 power cut every
    managed pair existed while none of the mounts did (boot race + nofail
    silence). Callers compare these declared targets against live mounts."""
    entries: list[tuple[str, str, str]] = []
    lines = fstab_text.splitlines()
    for index, line in enumerate(lines):
        match = _MANAGED_MARKER_RE.match(line.strip())
        if not match or index + 1 >= len(lines):
            continue
        entry = lines[index + 1]
        fields = entry.split()
        if len(fields) >= 3 and not entry.lstrip().startswith("#") and fields[2] == "cifs":
            entries.append((match.group("slot"), match.group("share"), _fstab_unescape(fields[1])))
    return entries


def crontab_has_reboot_restore(crontab_text: str) -> bool:
    """True when an active @reboot line runs `nas view restore`."""
    for line in crontab_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@reboot") and "nas view restore" in stripped:
            return True
    return False


def slot_views_root(slot: str, corpus: str = PRIMARY_CORPUS) -> Path:
    base = VIEWS_ROOT / validate_linux_account(slot)
    # PRIMARY 는 기존 경로 그대로(라이브 슬롯 무변경), 나머지는 코퍼스 하위로.
    return base if corpus == PRIMARY_CORPUS else base / _safe_corpus(corpus)


def _safe_corpus(corpus: str) -> str:
    value = str(corpus).strip()
    if not SAFE_USER_ID_RE.match(value) or value in {".", ".."}:
        raise ValueError(f"unsafe corpus: {corpus!r}")
    return value


def hidden_master(slot: str, corpus: str = PRIMARY_CORPUS) -> Path:
    return slot_views_root(slot, corpus) / "master"


def view_root(slot: str, corpus: str = PRIMARY_CORPUS) -> Path:
    return slot_views_root(slot, corpus) / "view"


def _entry_name(corpus: str) -> str:
    for spec in CORPORA.values():
        if spec.name == corpus:
            return spec.entry_name
    raise ValueError(f"unknown corpus: {corpus!r}")


def slot_entry(slot: str, corpus: str = PRIMARY_CORPUS) -> Path:
    return Path("/home") / validate_linux_account(slot) / "nas_docs" / _entry_name(corpus)


def find_user_package(master: Path, user_id: str) -> Path:
    """users/{name}_{title}_{user_id} — resolved by the _{user_id} suffix."""
    user_id = validate_user_id(user_id)
    users_dir = master / "users"
    if not users_dir.is_dir():
        raise FileNotFoundError(f"users/ not found under master mount: {users_dir}")
    matches = [
        path
        for path in sorted(users_dir.iterdir())
        if path.is_dir() and not path.is_symlink() and path.name.endswith(f"_{user_id}")
    ]
    if not matches:
        raise FileNotFoundError(f"no users/ package with suffix _{user_id} under {users_dir}")
    if len(matches) > 1:
        names = ", ".join(path.name for path in matches)
        raise ValueError(f"ambiguous user_id {user_id}: {names}")
    return matches[0]


def load_membership_rooms(package_dir: Path) -> list[str]:
    membership_path = package_dir / "membership.json"
    data = json.loads(membership_path.read_text(encoding="utf-8"))
    rooms = data.get("conversation_ids")
    if not isinstance(rooms, list) or not rooms:
        raise ValueError(f"membership.json has no conversation_ids: {membership_path}")
    return [validate_room_id(room) for room in rooms]


def load_package_room_summary(package_dir: Path) -> list[dict[str, object]]:
    """List the real rooms published in a Kakao package without reading messages."""
    allowed = set(load_membership_rooms(package_dir))
    sqlite_path = package_dir / "messages.sqlite"
    if not sqlite_path.is_file() or sqlite_path.is_symlink():
        raise FileNotFoundError(f"messages.sqlite not found in package: {package_dir}")
    conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT conversation_id, MAX(room_name) AS room_name, COUNT(*) AS message_count, "
            "MAX(sent_time) AS latest_sent_time FROM messages "
            "GROUP BY conversation_id ORDER BY latest_sent_time DESC"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "conversation_id": str(cid), "room_name": str(name or ""),
            "message_count": int(count), "latest_sent_time": int(latest or 0),
        }
        for cid, name, count, latest in rows if str(cid) in allowed
    ]


def load_whatsapp_rooms(master: Path, user_id: str) -> list[str]:
    """Return rooms in which the verified WhatsApp identity actually authored a message.

    The collector publishes no participant/membership ledger.  Authorship is therefore a
    conservative external observation: it cannot invent access, but silent rooms may be
    absent.  The operator-verified mb_id -> @lid link remains the identity authority.
    """
    user_id = validate_user_id(user_id)
    db = master / "whatsapp.db"
    if not db.is_file() or db.is_symlink():
        raise FileNotFoundError(f"whatsapp.db not found under master mount: {db}")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT DISTINCT chat_id FROM messages "
            "WHERE is_group=1 AND (author=? OR (author IS NULL AND from_addr=?)) "
            "ORDER BY chat_id",
            (user_id, user_id),
        ).fetchall()
    finally:
        conn.close()
    return [validate_room_id(str(row[0])) for row in rows]


def validate_relative_path(value: str) -> str:
    """마운트할 상대경로 검증 — 절대경로·상위탈출·빈 조각을 막는다.

    이 경로는 grant 원장에서 오고 운영자가 폴더 브라우저로 고른 값이다. 그래도
    opsctl 은 받은 값을 믿지 않는다: master 밖으로 새는 경로는 여기서 끊는다."""
    text = str(value).strip()
    # 절대경로는 앞 '/' 를 벗겨 상대경로로 봐주지 않는다 — 입력을 말없이 다른 뜻으로
    # 바꾸면 운영자가 고른 것과 실제 붙는 것이 갈린다. 거부해서 다시 고르게 한다.
    if text.startswith("/"):
        raise ValueError(f"path must be corpus-relative, got absolute: {value!r}")
    raw = text.rstrip("/")
    if not raw or len(raw) > 512 or "\\" in raw:
        raise ValueError(f"unsafe path: {value!r}")
    parts = [p for p in raw.split("/")]
    if any(p in {"", ".", ".."} for p in parts):
        raise ValueError(f"unsafe path: {value!r}")
    return "/".join(parts)


def path_alias(rel_path: str) -> str:
    """view/ 아래 붙일 이름 — 경로를 납작하게. mails/bkkim -> mails_bkkim.
    폴더명이 겹쳐도(mails/kim vs approval/kim) 서로 덮지 않게 전체 경로를 쓴다."""
    return validate_relative_path(rel_path).replace("/", "_")


def resolve_granted_dirs(master: Path, paths: list[str]) -> tuple[list[tuple[Path, Path]], list[str]]:
    """(바인드쌍, 없는 경로들). 없는 경로는 실패가 아니라 '못 붙은 것'으로 보고한다 —
    grant 는 있는데 폴더가 아직 없는 사람이 실제로 있고(측정 7/21: 65명 중 27명),
    그 한 건 때문에 나머지 소스까지 안 붙으면 안 된다."""
    binds: list[tuple[Path, Path]] = []
    missing: list[str] = []
    view_names: set[str] = set()
    for raw in paths:
        rel = validate_relative_path(raw)
        source = master / rel
        current = master
        symlink = None
        for part in rel.split("/"):
            current /= part
            if current.is_symlink():
                symlink = current
                break
        if symlink is not None:
            raise ValueError(f"granted path contains symlink: {rel}")
        if not source.is_dir():
            missing.append(rel)
            continue
        try:
            master_real = master.resolve(strict=True)
            source_real = source.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"granted path cannot be resolved safely: {rel}: {exc}") from exc
        if source_real != master_real and master_real not in source_real.parents:
            raise ValueError(f"granted path escaped master: {rel}")
        alias = path_alias(rel)
        if alias in view_names:
            raise ValueError(f"granted path alias collision: {rel} -> {alias}")
        view_names.add(alias)
        binds.append((source, Path(alias)))
    return binds, missing


@dataclass(frozen=True)
class ViewPlan:
    slot: str
    user_id: str
    share: SmbShare
    master: Path
    view: Path
    entry: Path
    # granted_paths 코퍼스는 단일 패키지가 없다(경로 여러 개) — package_* 는 None.
    package_dir: Path | None = None
    package_bind: Path | None = None
    room_binds: list[tuple[Path, Path]] = field(default_factory=list)
    missing_rooms: list[str] = field(default_factory=list)
    corpus: str = PRIMARY_CORPUS
    paths: list[str] = field(default_factory=list)


def build_view_plan(
    slot: str,
    user_id: str,
    share_source: str,
    state_root: Path,
    paths: list[str] | None = None,
    *,
    master_override: Path | None = None,
) -> ViewPlan:
    """Requires its selected master to be mounted already (package discovery reads it).

    코퍼스 레이아웃별로 갈린다(CORPORA). 카카오는 users/ 패키지 + 방 바인드,
    그룹웨어는 grant-selected paths.  ``master_override`` is the validated
    root-policy collector mount; without it the legacy hidden per-slot master
    remains unchanged. 경로는 코퍼스별이라 한 슬롯에 카카오와 그룹웨어가 나란히 설
    수 있다."""
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    slot = decision.slot
    user_id = validate_user_id(user_id)
    spec = corpus_for_share(decision.share.source)
    master = master_override if master_override is not None else hidden_master(slot, spec.name)
    view = view_root(slot, spec.name)
    room_binds: list[tuple[Path, Path]] = []
    missing: list[str] = []
    package_dir: Path | None = None
    package_bind: Path | None = None
    used_paths: list[str] = []
    if spec.layout == "kakao_package":
        package_dir = find_user_package(master, user_id)
        package_bind = view / "package"
        for room in load_membership_rooms(package_dir):
            source = master / "media" / room
            if source.is_dir() and not source.is_symlink():
                room_binds.append((source, view / "media" / room))
            else:
                missing.append(room)
    elif spec.layout == "granted_paths":
        # 무엇을 붙일지는 호출자가 정한다(그룹웨어 = grant 원장). 빈 목록이면 붙일 게
        # 없다는 뜻이므로 조용히 빈 뷰를 만들지 않고 거부한다.
        if not paths:
            raise ValueError(f"corpus {spec.name!r} needs explicit --path (granted prefixes); none given")
        resolved, missing = resolve_granted_dirs(master, paths)
        if not resolved:
            raise FileNotFoundError(f"none of the granted paths exist under master: {', '.join(missing)}")
        room_binds = [(source, view / alias) for source, alias in resolved]
        used_paths = [validate_relative_path(p) for p in paths]
    elif spec.layout == "whatsapp_author":
        rooms = load_whatsapp_rooms(master, user_id)
        if not rooms:
            raise FileNotFoundError(f"no authored WhatsApp rooms for identity {user_id!r}")
        for room in rooms:
            message_file = master / "messages" / f"{room}.json"
            media_dir = master / "media" / room
            if message_file.is_file() and not message_file.is_symlink():
                room_binds.append((message_file, view / "messages" / f"{room}.json"))
            else:
                missing.append(f"messages/{room}.json")
            if media_dir.is_dir() and not media_dir.is_symlink():
                room_binds.append((media_dir, view / "media" / room))
    else:
        raise ValueError(f"unknown corpus layout: {spec.layout!r}")
    return ViewPlan(
        slot=slot,
        user_id=user_id,
        share=decision.share,
        master=master,
        view=view,
        entry=slot_entry(slot, spec.name),
        package_dir=package_dir,
        package_bind=package_bind,
        room_binds=room_binds,
        missing_rooms=missing,
        corpus=spec.name,
        paths=used_paths,
    )


def load_views_state(state_root: Path) -> dict:
    data = load_yaml(state_path(state_root, VIEWS_STATE_NAME), default={}) or {}
    if not isinstance(data, dict):
        data = {}
    if not isinstance(data.get("views"), dict):
        data["views"] = {}
    # 카카오(PRIMARY)는 기존 스키마 그대로 views[slot] 에 남는다 — 이미 배포된 상태
    # 파일을 마이그레이션하지 않는다. 추가 코퍼스만 여기 살아, 구 opsctl 이 읽어도
    # 카카오 뷰는 그대로 보인다(전방·후방 호환).
    if not isinstance(data.get("corpus_views"), dict):
        data["corpus_views"] = {}
    return data


def iter_view_records(views: dict):
    """(slot, corpus, record) — PRIMARY 와 코퍼스 뷰 전부. 상태를 읽는 쪽(status·
    restore·리컨실러)이 한 소스만 보고 나머지를 놓치는 일이 없게 한 자리로 모은다."""
    for slot, record in sorted((views.get("views") or {}).items()):
        yield slot, PRIMARY_CORPUS, record
    for slot, by_corpus in sorted((views.get("corpus_views") or {}).items()):
        for corpus, record in sorted((by_corpus or {}).items()):
            yield slot, corpus, record


def get_view_record(views: dict, slot: str, corpus: str = PRIMARY_CORPUS) -> dict | None:
    if corpus == PRIMARY_CORPUS:
        return (views.get("views") or {}).get(slot)
    return ((views.get("corpus_views") or {}).get(slot) or {}).get(corpus)


def put_view_record(views: dict, slot: str, corpus: str, record: dict) -> None:
    if corpus == PRIMARY_CORPUS:
        views.setdefault("views", {})[slot] = record
        return
    views.setdefault("corpus_views", {}).setdefault(slot, {})[corpus] = record


def drop_view_record(views: dict, slot: str, corpus: str = PRIMARY_CORPUS) -> bool:
    if corpus == PRIMARY_CORPUS:
        return (views.get("views") or {}).pop(slot, None) is not None
    by_slot = (views.get("corpus_views") or {}).get(slot) or {}
    removed = by_slot.pop(corpus, None) is not None
    if removed and not by_slot:
        (views.get("corpus_views") or {}).pop(slot, None)
    return removed


def save_views_state(state_root: Path, data: dict) -> None:
    data.setdefault("meta", {"schema_version": 1})
    path = state_path(state_root, VIEWS_STATE_NAME)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(dump_yaml(data))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    if hasattr(os, "O_DIRECTORY"):
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
