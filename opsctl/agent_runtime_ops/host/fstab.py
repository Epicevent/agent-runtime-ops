from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil


def fstab_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "")


def managed_fstab_marker(slot: str, share: str) -> str:
    return f"# agent-runtime-ops nas slot={slot} source={share}"


def _lock_exclusive(lock_handle) -> None:
    try:
        import fcntl

        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    except ImportError:
        pass


def _fsync_parent(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup_fstab(fstab_path: Path) -> Path | None:
    if not fstab_path.exists():
        return None
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    backup = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.bak.{stamp}")
    suffix = 1
    while backup.exists():
        suffix += 1
        backup = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.bak.{stamp}.{suffix}")
    shutil.copy2(fstab_path, backup)
    return backup


def _replace_fstab(fstab_path: Path, text: str) -> None:
    tmp = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, fstab_path)
    _fsync_parent(fstab_path)


def write_managed_fstab_entry(
    slot: str,
    share: str,
    mountpoint: Path,
    credential_path: Path,
    *,
    slot_uid_gid: Callable[[str], tuple[int, int]],
    runtime_ids: Callable[[str], tuple[int, int, int]],
    claim_existing_same_source: bool = False,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> None:
    slot_uid, _ = slot_uid_gid(slot)
    _, _, data_gid = runtime_ids(slot)
    escaped_target = fstab_escape(str(mountpoint))
    escaped_source = fstab_escape(share)
    options = ",".join(
        [
            f"credentials={fstab_escape(str(credential_path))}",
            "ro",
            "nosuid",
            "nodev",
            "vers=3.1.1",
            "iocharset=utf8",
            "noserverino",
            f"uid={slot_uid}",
            "forceuid",
            f"gid={data_gid}",
            "forcegid",
            "file_mode=0440",
            "dir_mode=0550",
            "soft",
            "nofail",
            "_netdev",
        ]
    )
    marker = managed_fstab_marker(slot, share)
    entry = f"{escaped_source} {escaped_target} cifs {options} 0 0"

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        _lock_exclusive(lock_handle)
        lines = fstab_path.read_text(encoding="utf-8").splitlines() if fstab_path.exists() else []
        new_lines: list[str] = []
        skip_next = False
        replaced = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                skip_next = True
                if not replaced:
                    new_lines.extend([marker, entry])
                    replaced = True
                continue
            columns = line.split()
            if columns and not line.lstrip().startswith("#") and len(columns) >= 2 and columns[1] == escaped_target:
                if claim_existing_same_source and len(columns) >= 3 and columns[0] == escaped_source and columns[2] == "cifs":
                    new_lines.append("# disabled by agent-runtime-ops nas claim: " + line)
                    continue
                raise ValueError(f"non-managed fstab entry already owns mountpoint: {mountpoint}")
            new_lines.append(line)
        if not replaced:
            if new_lines and new_lines[-1] != "":
                new_lines.append("")
            new_lines.extend([marker, entry])
        _backup_fstab(fstab_path)
        _replace_fstab(fstab_path, "\n".join(new_lines) + "\n")


def remove_managed_fstab_entry(
    slot: str,
    share: str,
    *,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> bool:
    marker = managed_fstab_marker(slot, share)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        _lock_exclusive(lock_handle)
        lines = fstab_path.read_text(encoding="utf-8").splitlines() if fstab_path.exists() else []
        new_lines: list[str] = []
        removed = False
        skip_next = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                removed = True
                skip_next = True
                continue
            new_lines.append(line)
        if not removed:
            return False
        _backup_fstab(fstab_path)
        _replace_fstab(fstab_path, "\n".join(new_lines) + "\n")
        return True
