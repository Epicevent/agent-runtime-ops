from __future__ import annotations

import os
from pathlib import Path


def fsync_parent(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_text(path: Path, text: str, *, mode: int = 0o644) -> None:
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
