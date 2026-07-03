"""Read-only bind mounts for NAS slot views."""

from __future__ import annotations

from pathlib import Path

from .mounts import _run_text, findmnt_one, findmnt_under, is_readonly_mount


def bind_ro(source: Path, target: Path) -> tuple[bool, str]:
    """Bind source onto target and remount it read-only. Idempotent."""
    rc, _, rows = findmnt_one(target)
    if rc == 0 and rows:
        if is_readonly_mount(rows[0]):
            return True, "already_mounted"
        return False, "target_has_unexpected_existing_mount"
    if not source.exists():
        return False, f"bind_source_missing:{source}"
    target.mkdir(parents=True, exist_ok=True)
    proc = _run_text(["mount", "--bind", str(source), str(target)], timeout=30)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    proc = _run_text(["mount", "-o", "remount,ro,bind", str(target)], timeout=30)
    if proc.returncode != 0:
        _run_text(["umount", str(target)], timeout=30)
        return False, "ro_remount_failed:" + (proc.stderr or proc.stdout).strip()
    rc, error, rows = findmnt_one(target)
    if rc != 0 or not rows or not is_readonly_mount(rows[0]):
        _run_text(["umount", str(target)], timeout=30)
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
