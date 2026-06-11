from __future__ import annotations

import json
import os
from pathlib import Path

from .common import now_iso


def append_action_log(state_root: Path, action: str, slot: str, target: str, status: str, detail: str = "") -> None:
    log_path = state_root / "actions.log"
    if state_root.is_symlink():
        raise ValueError(f"action log state root must not be symlink: {state_root}")
    state_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    if log_path.exists() and log_path.is_symlink():
        raise ValueError(f"action log must not be symlink: {log_path}")
    record = {
        "timestamp": now_iso(),
        "action": action,
        "slot": slot,
        "target": target,
        "status": status,
        "detail": str(detail or "")[:500],
    }
    if action.startswith("nas_") or (isinstance(target, str) and target.startswith("//")):
        record["share"] = target
    with log_path.open("a", encoding="utf-8") as handle:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
