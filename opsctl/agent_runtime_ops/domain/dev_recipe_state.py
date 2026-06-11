from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil

from ..host.files import fsync_parent
from ..yamlio import dump_yaml, load_yaml
from .common import now_iso

DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"


def state_meta(source: str | None = None) -> dict[str, object]:
    meta: dict[str, object] = {
        "schema_version": 1,
        "updated_at": now_iso(),
        "scope": "private_server_state",
    }
    if source:
        meta["source"] = source
    return meta


def assert_state_parent_safe(path: Path) -> None:
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError(f"managed state parent must not be symlink: {parent}")
    parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")


def backup_state_file(state_root: Path, path: Path) -> Path | None:
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")
    backup_root = state_root / "backups" / "state"
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"managed backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    backup_path = backup_root / f"{path.name}.{stamp}"
    suffix = 1
    while backup_path.exists():
        suffix += 1
        backup_path = backup_root / f"{path.name}.{stamp}.{suffix}"
    shutil.copy2(path, backup_path)
    return backup_path


def write_state_yaml_file(state_root: Path, name: str, data: dict) -> Path | None:
    path = state_root / name
    assert_state_parent_safe(path)
    backup_path = backup_state_file(state_root, path)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(dump_yaml(data))
            handle.flush()
            os.fsync(handle.fileno())
        if hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return backup_path


def load_dev_recipe_state(state_root: Path) -> dict:
    data = load_yaml(state_root / DEV_RECIPE_STATE_NAME, default={})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("meta", state_meta("opsctl recipe"))
    data.setdefault("recipes", {})
    return data


def write_dev_recipe_state(state_root: Path, data: dict) -> Path | None:
    data["meta"] = state_meta("opsctl recipe")
    data.setdefault("recipes", {})
    return write_state_yaml_file(state_root, DEV_RECIPE_STATE_NAME, data)
