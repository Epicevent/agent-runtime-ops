from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat

from ..host.account_files import atomic_write_key_value, read_key_value_file, runtime_ids, slot_uid_gid
from ..routing import get_runtime_binding

DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"


def safe_existing_directory(value: object, name: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if path.is_symlink():
        raise ValueError(f"{name} must not be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{name} must be an existing directory")
    return resolved


def reject_tree_symlinks(root: Path) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        for name in [*dirs, *files]:
            item = current_path / name
            if item.is_symlink():
                raise ValueError(f"source tree must not contain symlinks: {item}")


def assert_child_of(child: Path, parent: Path) -> None:
    child_resolved = child.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    if child_resolved != parent_resolved and parent_resolved not in child_resolved.parents:
        raise ValueError(f"path escaped managed root: {child}")


def ensure_dev_runtime_dir(slot: str) -> Path:
    uid, gid = slot_uid_gid(slot)
    home = Path("/home") / slot
    if home.is_symlink():
        raise ValueError(f"managed home must not be symlink: {home}")
    if not home.is_dir():
        raise FileNotFoundError(home)
    runtime_dir = home / "openclaw"
    if runtime_dir.exists() and runtime_dir.is_symlink():
        raise ValueError(f"managed runtime dir must not be symlink: {runtime_dir}")
    runtime_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(runtime_dir, uid, gid)
    os.chmod(runtime_dir, 0o750)
    return runtime_dir


def chmod_source_tree(root: Path, uid: int, gid: int) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        os.chown(current_path, uid, gid)
        os.chmod(current_path, 0o750)
        for dirname in dirs:
            path = current_path / dirname
            os.chown(path, uid, gid)
            os.chmod(path, 0o750)
        for filename in files:
            path = current_path / filename
            mode = path.stat().st_mode
            file_mode = 0o750 if mode & stat.S_IXUSR else 0o640
            os.chown(path, uid, gid)
            os.chmod(path, file_mode)


def sync_dev_source_output(slot: str, recipe_name: str, source: Path) -> Path:
    reject_tree_symlinks(source)
    runtime_uid, _, data_gid = runtime_ids(slot)
    home = Path("/home") / slot
    stage_root = home / DEV_RECIPE_STAGE_ROOT
    if stage_root.exists() and stage_root.is_symlink():
        raise ValueError(f"managed source stage root must not be symlink: {stage_root}")
    stage_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(stage_root, runtime_uid, data_gid)
    os.chmod(stage_root, 0o750)
    dest = stage_root / recipe_name
    tmp = stage_root / f".{recipe_name}.tmp.{os.getpid()}"
    backup = stage_root / f".{recipe_name}.previous.{os.getpid()}"
    for path in (dest, tmp, backup):
        assert_child_of(path, stage_root)
    if tmp.exists():
        shutil.rmtree(tmp)
    if backup.exists():
        shutil.rmtree(backup)
    shutil.copytree(source, tmp, symlinks=False)
    chmod_source_tree(tmp, runtime_uid, data_gid)
    if dest.exists():
        if dest.is_symlink():
            raise ValueError(f"managed source stage must not be symlink: {dest}")
        os.replace(dest, backup)
    os.replace(tmp, dest)
    if backup.exists():
        shutil.rmtree(backup)
    return dest


def upsert_runtime_env_file(path: Path, updates: dict[str, str], uid: int, gid: int) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"runtime env file must not be symlink: {path}")
    data = read_key_value_file(path) if path.exists() else {}
    data.update({key: value for key, value in updates.items() if value})
    atomic_write_key_value(path, data, 0o640, uid, gid)


def dev_recipe_runtime_env(desired, state_root: Path) -> dict[str, str]:
    family = str(desired.family or "")
    binding = get_runtime_binding(desired.slot, state_root)
    return {
        "OPENCLAW_RUNTIME_FAMILY": family,
        "OPENCLAW_IMAGE": str(desired.image_spec.get("wrapper_image") or ""),
        "OPENCLAW_GATEWAY_PORT": str(binding.gateway_port),
        "OPENCLAW_BRIDGE_PORT": str(binding.bridge_port),
    }
