from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path

from ..host.account_files import slot_uid_gid
from ..nas import history_dir


def move_request(path: Path, slot: str, status: str) -> Path:
    target_dir = history_dir(slot, status)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{datetime.now().strftime('%Y%m%dT%H%M%S')}.{path.name}"
    os.replace(path, target)
    return target


def safe_request_file(path: Path, slot: str) -> None:
    uid, _ = slot_uid_gid(slot)
    if path.is_symlink():
        raise ValueError(f"request file must not be symlink: {path}")
    stat_result = path.stat()
    if stat_result.st_uid != uid:
        raise ValueError(f"request file owner mismatch: {path}")
    if stat_result.st_mode & 0o022:
        raise ValueError(f"request file must not be group/world writable: {path}")
