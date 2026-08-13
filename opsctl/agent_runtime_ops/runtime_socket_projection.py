from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from .host.account_files import runtime_ids
from .host.mounts import is_readonly_mount, mountinfo_under
from .profiles import profile_digest


_SLOT_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_CONTRACT_KEYS = {
    "source_template",
    "target",
    "read_only",
    "supplementary_group",
}


@dataclass(frozen=True)
class RuntimeSocketProjection:
    source: Path
    target: str
    read_only: bool
    supplementary_group: str


def _absolute_normalized_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise ValueError(f"runtime socket {label} must be an absolute normalized path")
    return str(path)


def runtime_socket_projection(profile: Any, slot: str) -> RuntimeSocketProjection | None:
    metadata = getattr(profile, "metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("runtime profile metadata is invalid")
    raw = metadata.get("runtime_socket_projection")
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != _CONTRACT_KEYS:
        raise ValueError("runtime_socket_projection contract fields are invalid")
    if not _SLOT_RE.fullmatch(slot):
        raise ValueError("runtime socket slot is invalid")

    source_template = str(raw.get("source_template") or "")
    if source_template.count("{slot}") != 1:
        raise ValueError("runtime socket source_template must contain exactly one {slot}")
    remainder = source_template.replace("{slot}", "", 1)
    if "{" in remainder or "}" in remainder:
        raise ValueError("runtime socket source_template contains an unknown field")
    source = _absolute_normalized_path(source_template.replace("{slot}", slot, 1), "source")
    target = _absolute_normalized_path(str(raw.get("target") or ""), "target")
    if raw.get("read_only") is not True:
        raise ValueError("runtime socket projection must be read-only")
    if raw.get("supplementary_group") != "runtime_gid":
        raise ValueError("runtime socket projection must use runtime_gid peer grant")
    return RuntimeSocketProjection(
        source=Path(source),
        target=target,
        read_only=True,
        supplementary_group="runtime_gid",
    )


def runtime_group_token(slot: str) -> str:
    try:
        _uid, runtime_gid, _data_gid = runtime_ids(slot)
    except (KeyError, OSError):
        return "${RUNTIME_GID}"
    return str(runtime_gid)


def require_runtime_socket_source(profile: Any, slot: str) -> None:
    projection = runtime_socket_projection(profile, slot)
    if projection is None:
        return
    try:
        parent_stat = projection.source.parent.lstat()
        source_stat = projection.source.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"runtime socket source is missing: {projection.source}") from exc
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
        raise ValueError(f"runtime socket parent is unsafe: {projection.source.parent}")
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISSOCK(source_stat.st_mode):
        raise ValueError(f"runtime socket source is not a socket: {projection.source}")
    _uid, runtime_gid, _data_gid = runtime_ids(slot)
    if source_stat.st_gid != runtime_gid:
        raise ValueError(
            "runtime socket peer group mismatch: "
            f"actual={source_stat.st_gid} expected={runtime_gid}"
        )
    if stat.S_IMODE(source_stat.st_mode) & 0o060 != 0o060:
        raise ValueError("runtime socket peer group lacks read/write access")


def runtime_socket_projection_is_current(profile: Any) -> bool:
    """Return false for a restored backup whose historical profile predates this mount."""

    return str(profile.digest) == profile_digest(Path(profile.path))


def runtime_socket_projection_live_checks(
    profile: Any,
    slot: str,
    info: dict[str, Any],
    container_pid: int,
) -> list[tuple[bool, str, str | None]]:
    projection = runtime_socket_projection(profile, slot)
    if projection is None:
        return []
    if not runtime_socket_projection_is_current(profile):
        return []
    checks: list[tuple[bool, str, str | None]] = []

    try:
        require_runtime_socket_source(profile, slot)
    except Exception as exc:
        checks.append((False, "live_runtime_socket_host_ready", str(exc)))
    else:
        checks.append((True, "live_runtime_socket_host_ready", str(projection.source)))

    mounts = info.get("Mounts") if isinstance(info.get("Mounts"), list) else []
    destination_mounts = [
        item
        for item in mounts
        if isinstance(item, dict) and str(item.get("Destination") or "") == projection.target
    ]
    checks.append(
        (
            len(destination_mounts) == 1,
            "live_runtime_socket_bind_present",
            f"target={projection.target} count={len(destination_mounts)}",
        )
    )
    mount = destination_mounts[0] if len(destination_mounts) == 1 else {}
    checks.extend(
        [
            (
                str(mount.get("Type") or "") == "bind",
                "live_runtime_socket_bind_type",
                f"type={mount.get('Type') or 'missing'}",
            ),
            (
                str(mount.get("Source") or "") == str(projection.source),
                "live_runtime_socket_source_slot_scoped",
                f"source={mount.get('Source') or 'missing'}",
            ),
            (
                mount.get("RW") is False,
                "live_runtime_socket_bind_readonly",
                f"rw={str(mount.get('RW')).lower() if 'RW' in mount else 'missing'}",
            ),
        ]
    )

    expected_group = runtime_group_token(slot)
    host_config = info.get("HostConfig") if isinstance(info.get("HostConfig"), dict) else {}
    group_add = host_config.get("GroupAdd") if isinstance(host_config.get("GroupAdd"), list) else []
    groups = {str(item) for item in group_add}
    checks.append(
        (
            expected_group in groups,
            "live_runtime_socket_peer_group_present",
            f"expected={expected_group} present={'yes' if expected_group in groups else 'no'}",
        )
    )

    mount_rc, mount_error, mount_rows = mountinfo_under(container_pid, projection.target)
    exact_rows = [row for row in mount_rows if row.get("target") == projection.target]
    checks.append(
        (
            mount_rc == 0,
            "live_runtime_socket_mountinfo_readable",
            mount_error if mount_rc != 0 else projection.target,
        )
    )
    checks.append(
        (
            len(exact_rows) == 1,
            "live_runtime_socket_namespace_mounted",
            f"target={projection.target} count={len(exact_rows)}",
        )
    )
    checks.append(
        (
            len(exact_rows) == 1 and is_readonly_mount(exact_rows[0]),
            "live_runtime_socket_namespace_readonly",
            exact_rows[0].get("options") if len(exact_rows) == 1 else None,
        )
    )
    return checks
