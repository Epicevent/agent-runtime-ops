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
import re
from pathlib import Path

from ..host.fstab import managed_fstab_marker
from ..nas import SmbShare, check_nas_policy
from ..paths import state_path
from ..routing import validate_linux_account
from ..yamlio import dump_yaml, load_yaml

VIEWS_STATE_NAME = "nas-views.yaml"
VIEWS_ROOT = Path("/srv/kw-nas/slots")
SAFE_USER_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_ROOM_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


# ── corpus registry ───────────────────────────────────────────────────
# 한 슬롯은 그 사람의 소스 "전부"를 봐야 한다(카카오·그룹웨어·와츠앱…). 코퍼스마다
# 디스크 레이아웃이 다르므로 뷰 계획은 여기서 갈린다:
#   kakao_package — users/{이름}_{직함}_{user_id} 패키지 + membership.json 의 방 바인드
#   person_dir    — {person_root}/{user_id} 사람 폴더 하나. 방 개념 없음(그룹웨어)
# PRIMARY(kakao)의 경로는 고객 슬롯에 이미 살아 있으므로 절대 바꾸지 않는다:
# master/view 는 slots/{slot}/ 바로 아래, 진입점은 nas_docs/kw 그대로. 새 코퍼스는
# slots/{slot}/{corpus}/ 와 nas_docs/{entry} 로 나란히 선다.
PRIMARY_CORPUS = "kakao"


@dataclass(frozen=True)
class Corpus:
    name: str
    entry_name: str          # /home/{slot}/nas_docs/{entry_name}
    layout: str              # "kakao_package" | "person_dir"
    person_root: str = ""    # person_dir: master 아래 사람 폴더들의 부모


CORPORA: dict[str, Corpus] = {
    "kakao-work": Corpus(PRIMARY_CORPUS, "kw", "kakao_package"),
    "hanpass_groupware": Corpus("groupware", "groupware", "person_dir", "groupware/mails"),
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


def find_person_dir(master: Path, person_root: str, user_id: str) -> Path:
    """{person_root}/{user_id} — 사람 폴더가 곧 패키지인 코퍼스(그룹웨어 mails).

    카카오처럼 접미사 탐색을 하지 않는다: 그룹웨어 메일함은 폴더명 == mb_id 라
    정확히 일치하는 하나만 연다(부분일치로 남의 폴더가 걸리는 경로를 아예 없앰)."""
    user_id = validate_user_id(user_id)
    parent = master
    for part in str(person_root).strip("/").split("/"):
        if part in {"", ".", ".."}:
            raise ValueError(f"unsafe person_root: {person_root!r}")
        parent = parent / part
    if not parent.is_dir():
        raise FileNotFoundError(f"person root not found under master mount: {parent}")
    target = parent / user_id
    if not target.is_dir() or target.is_symlink():
        raise FileNotFoundError(f"no person folder {user_id!r} under {parent}")
    return target


@dataclass(frozen=True)
class ViewPlan:
    slot: str
    user_id: str
    share: SmbShare
    master: Path
    view: Path
    entry: Path
    package_dir: Path
    package_bind: Path
    room_binds: list[tuple[Path, Path]] = field(default_factory=list)
    missing_rooms: list[str] = field(default_factory=list)
    corpus: str = PRIMARY_CORPUS


def build_view_plan(slot: str, user_id: str, share_source: str, state_root: Path) -> ViewPlan:
    """Requires the hidden master to be mounted already (package discovery reads it).

    코퍼스 레이아웃별로 갈린다(CORPORA). 카카오는 users/ 패키지 + 방 바인드,
    그룹웨어는 사람 폴더 하나(방 없음). 경로는 코퍼스별이라 한 슬롯에 카카오와
    그룹웨어가 나란히 설 수 있다."""
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    slot = decision.slot
    user_id = validate_user_id(user_id)
    spec = corpus_for_share(decision.share.source)
    master = hidden_master(slot, spec.name)
    view = view_root(slot, spec.name)
    room_binds: list[tuple[Path, Path]] = []
    missing: list[str] = []
    if spec.layout == "kakao_package":
        package_dir = find_user_package(master, user_id)
        for room in load_membership_rooms(package_dir):
            source = master / "media" / room
            if source.is_dir() and not source.is_symlink():
                room_binds.append((source, view / "media" / room))
            else:
                missing.append(room)
    elif spec.layout == "person_dir":
        package_dir = find_person_dir(master, spec.person_root, user_id)
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
        package_bind=view / "package",
        room_binds=room_binds,
        missing_rooms=missing,
        corpus=spec.name,
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
    tmp.write_text(dump_yaml(data), encoding="utf-8")
    tmp.replace(path)
