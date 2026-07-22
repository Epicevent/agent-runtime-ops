"""Read-only bind mounts for NAS slot views."""

from __future__ import annotations

from pathlib import Path

from .mounts import _run_text, findmnt_one, findmnt_under, is_readonly_mount


def bind_ro(source: Path, target: Path, *, recursive: bool = False) -> tuple[bool, str]:
    """Bind source onto target and remount it read-only.

    An existing mount at target is never trusted — a failed earlier assign can
    leave a stale bind pointing at another user's slice, and findmnt source
    strings for subtree binds are not reliable to compare — so it is torn down
    and rebuilt. recursive=True uses --rbind so submounts (package/media binds)
    are included."""
    rc, _, rows = findmnt_one(target)
    if rc == 0 and rows:
        failed, errors = unmount_tree(target)
        if failed:
            return False, "stale_mount_unmount_failed:" + "; ".join(errors)
    if not source.exists():
        return False, f"bind_source_missing:{source}"
    if source.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=True)
    else:
        target.mkdir(parents=True, exist_ok=True)
    proc = _run_text(["mount", "--rbind" if recursive else "--bind", str(source), str(target)], timeout=30)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    proc = _run_text(["mount", "-o", "remount,ro,bind", str(target)], timeout=30)
    if proc.returncode != 0:
        unmount_tree(target)
        return False, "ro_remount_failed:" + (proc.stderr or proc.stdout).strip()
    rc, error, rows = findmnt_one(target)
    if rc != 0 or not rows or not is_readonly_mount(rows[0]):
        unmount_tree(target)
        return False, error or "bind_mounted_state_not_readonly"
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
