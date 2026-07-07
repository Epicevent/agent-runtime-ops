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


def slot_views_root(slot: str) -> Path:
    return VIEWS_ROOT / validate_linux_account(slot)


def hidden_master(slot: str) -> Path:
    return slot_views_root(slot) / "master"


def view_root(slot: str) -> Path:
    return slot_views_root(slot) / "view"


def slot_entry(slot: str) -> Path:
    return Path("/home") / validate_linux_account(slot) / "nas_docs" / "kw"


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


def build_view_plan(slot: str, user_id: str, share_source: str, state_root: Path) -> ViewPlan:
    """Requires the hidden master to be mounted already (package discovery reads it)."""
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    slot = decision.slot
    user_id = validate_user_id(user_id)
    master = hidden_master(slot)
    view = view_root(slot)
    package_dir = find_user_package(master, user_id)
    rooms = load_membership_rooms(package_dir)
    room_binds: list[tuple[Path, Path]] = []
    missing: list[str] = []
    for room in rooms:
        source = master / "media" / room
        if source.is_dir() and not source.is_symlink():
            room_binds.append((source, view / "media" / room))
        else:
            missing.append(room)
    return ViewPlan(
        slot=slot,
        user_id=user_id,
        share=decision.share,
        master=master,
        view=view,
        entry=slot_entry(slot),
        package_dir=package_dir,
        package_bind=view / "package",
        room_binds=room_binds,
        missing_rooms=missing,
    )


def load_views_state(state_root: Path) -> dict:
    data = load_yaml(state_path(state_root, VIEWS_STATE_NAME), default={}) or {}
    if not isinstance(data, dict):
        return {}
    views = data.get("views")
    if not isinstance(views, dict):
        data["views"] = {}
    return data


def save_views_state(state_root: Path, data: dict) -> None:
    data.setdefault("meta", {"schema_version": 1})
    path = state_path(state_root, VIEWS_STATE_NAME)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dump_yaml(data), encoding="utf-8")
    tmp.replace(path)
