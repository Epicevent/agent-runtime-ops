"""Read-only bind mounts for NAS slot views."""

from __future__ import annotations

import stat
from pathlib import Path

from .mounts import _run_text, findmnt_one, findmnt_under


def _is_safe_view_mount(row: dict[str, str]) -> bool:
    options = {part.strip() for part in row.get("options", "").split(",") if part.strip()}
    return {"ro", "nosuid", "nodev"}.issubset(options)


def _reject_existing_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label}_path_symlink:{current}")


def _path_identity(info) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def bind_ro(source: Path, target: Path, *, recursive: bool = False) -> tuple[bool, str]:
    """Bind source onto target and remount it read-only.

    An existing mount at target is never trusted — a failed earlier assign can
    leave a stale bind pointing at another user's slice, and findmnt source
    strings for subtree binds are not reliable to compare — so it is torn down
    and rebuilt. recursive=True uses --rbind so submounts (package/media binds)
    are included."""
    try:
        _reject_existing_symlink_components(source, "bind_source")
        _reject_existing_symlink_components(target, "bind_target")
        source_before = source.lstat()
    except (OSError, ValueError) as exc:
        return False, str(exc)
    if not (stat.S_ISDIR(source_before.st_mode) or stat.S_ISREG(source_before.st_mode)):
        return False, f"bind_source_not_regular_or_directory:{source}"
    rc, _, rows = findmnt_one(target)
    if rc == 0 and rows:
        failed, errors = unmount_tree(target)
        if failed:
            return False, "stale_mount_unmount_failed:" + "; ".join(errors)
    if stat.S_ISREG(source_before.st_mode):
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not target.is_file():
            return False, f"bind_target_type_mismatch:{target}"
        target.touch(exist_ok=True)
    else:
        if target.exists() and not target.is_dir():
            return False, f"bind_target_type_mismatch:{target}"
        target.mkdir(parents=True, exist_ok=True)
    proc = _run_text(["mount", "--rbind" if recursive else "--bind", str(source), str(target)], timeout=30)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    proc = _run_text(["mount", "-o", "remount,ro,nosuid,nodev,bind", str(target)], timeout=30)
    if proc.returncode != 0:
        unmount_tree(target)
        return False, "ro_remount_failed:" + (proc.stderr or proc.stdout).strip()
    try:
        source_after = source.lstat()
    except OSError:
        unmount_tree(target)
        return False, "bind_source_changed_during_mount"
    if _path_identity(source_before) != _path_identity(source_after):
        unmount_tree(target)
        return False, "bind_source_changed_during_mount"
    rc, error, rows = findmnt_one(target)
    if rc != 0 or not rows or not _is_safe_view_mount(rows[0]):
        unmount_tree(target)
        return False, error or "bind_mounted_state_not_ro_nosuid_nodev"
    return True, "ok"


def unmount_tree(root: Path) -> tuple[int, list[str]]:
    """Unmount every mount at or under root, deepest first. Returns (failed, errors)."""
    rc, error, rows = findmnt_under(str(root))
    if rc != 0:
        return 1, [error or "findmnt_failed"]
    targets = sorted({row["target"] for row in rows if row.get("target")}, key=len, reverse=True)
    failures: list[str] = []
    for target in targets:
        proc = _run_text(["umount", target], timeout=60)
        if proc.returncode != 0:
            failures.append(f"{target}: {(proc.stderr or proc.stdout).strip()}")
    return len(failures), failures
