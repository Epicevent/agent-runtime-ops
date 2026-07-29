from __future__ import annotations

import json
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import stat

from ..profiles import load_profile
from ..yamlio import load_yaml
from .common import now_iso, run_text_cwd
from .runtime_manifest import desired_from_manifest, read_legacy_slot_manifest
from .docker_compose import docker_compose_command
from .runtime_paths import (
    agent_backup_root,
    agent_compose_path,
    agent_manifest_path,
    state_manifest_path,
)


def backup_agent_runtime_state(slot: str, runtime_dir: Path, state_root: Path) -> Path:
    backup_root = agent_backup_root(runtime_dir)
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o755, exist_ok=True)
    backup_dir = backup_root / datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    suffix = 1
    original_backup_dir = backup_dir
    while backup_dir.exists():
        suffix += 1
        backup_dir = Path(f"{original_backup_dir}.{suffix}")
    backup_dir.mkdir(mode=0o700)

    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, slot)
    env_path = runtime_dir / ".env"
    if env_path.is_symlink() or (env_path.exists() and not env_path.is_file()):
        raise ValueError(f"runtime env must be a regular file: {env_path}")
    env_stat = env_path.stat() if env_path.is_file() else None
    metadata = {
        "created_at": now_iso(),
        "had_compose": compose_path.is_file() and not compose_path.is_symlink(),
        "had_env": env_stat is not None,
        "env_gid": env_stat.st_gid if env_stat is not None else None,
        "env_mode": stat.S_IMODE(env_stat.st_mode) if env_stat is not None else None,
        "env_uid": env_stat.st_uid if env_stat is not None else None,
        "had_manifest": manifest_path.is_file() and not manifest_path.is_symlink(),
        "had_state_manifest": state_manifest_file.is_file() and not state_manifest_file.is_symlink(),
        "state_manifest_path": str(state_manifest_file),
    }
    if metadata["had_compose"]:
        shutil.copy2(compose_path, backup_dir / "docker-compose.agent-runtime.yml")
    if metadata["had_env"]:
        backup_env = backup_dir / ".env"
        shutil.copy2(env_path, backup_env)
        backup_env.chmod(0o600)
    if metadata["had_manifest"]:
        shutil.copy2(manifest_path, backup_dir / ".agent-runtime-manifest")
    if metadata["had_state_manifest"]:
        shutil.copy2(state_manifest_file, backup_dir / "manifest.yaml")
    (backup_dir / "backup.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return backup_dir


def restore_backup_env(runtime_dir: Path, backup_dir: Path) -> None:
    metadata = load_yaml(backup_dir / "backup.json")
    env_path = runtime_dir / ".env"
    if env_path.is_symlink() or (env_path.exists() and not env_path.is_file()):
        raise ValueError(f"runtime env must be a regular file: {env_path}")
    if bool(metadata.get("had_env")):
        backup_env = backup_dir / ".env"
        if backup_env.is_symlink() or not backup_env.is_file():
            raise ValueError(f"backup runtime env must be a regular file: {backup_env}")
        shutil.copy2(backup_env, env_path)
        env_path.chmod(int(metadata.get("env_mode") or 0o600))
        if hasattr(os, "chown"):
            os.chown(
                env_path,
                int(metadata.get("env_uid")),
                int(metadata.get("env_gid")),
            )
    else:
        env_path.unlink(missing_ok=True)


def latest_backup(runtime_dir: Path) -> Path | None:
    backup_root = agent_backup_root(runtime_dir)
    if not backup_root.is_dir():
        return None
    backups = sorted([item for item in backup_root.iterdir() if item.is_dir()])
    return backups[-1] if backups else None


def restore_backup(slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path) -> tuple[bool, str]:
    metadata = load_yaml(backup_dir / "backup.json")
    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, slot, create_parent=True)
    had_compose = bool(metadata.get("had_compose"))
    had_manifest = bool(metadata.get("had_manifest"))
    had_state_manifest = bool(metadata.get("had_state_manifest"))

    restore_backup_env(runtime_dir, backup_dir)

    if had_compose:
        shutil.copy2(backup_dir / "docker-compose.agent-runtime.yml", compose_path)
    else:
        compose_path.unlink(missing_ok=True)
    if had_manifest:
        shutil.copy2(backup_dir / ".agent-runtime-manifest", manifest_path)
    else:
        manifest_path.unlink(missing_ok=True)
    if had_state_manifest:
        shutil.copy2(backup_dir / "manifest.yaml", state_manifest_file)
    else:
        state_manifest_file.unlink(missing_ok=True)

    if not had_compose:
        return False, "no_previous_agent_runtime_compose"

    config = run_text_cwd(docker_compose_command(slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        return False, (config.stderr or config.stdout).strip() or "rollback_compose_config_failed"
    up = run_text_cwd(
        docker_compose_command(slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=180,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "rollback_compose_up_failed"
    return True, "rollback_applied"


def backup_manifest_data(backup_dir: Path) -> dict:
    yaml_manifest = backup_dir / "manifest.yaml"
    if yaml_manifest.is_file():
        data = load_yaml(yaml_manifest)
        if isinstance(data, dict):
            return data
    return read_legacy_slot_manifest(backup_dir / ".agent-runtime-manifest")


def load_backup_runtime_contract(slot: str, backup_dir: Path, state_root: Path):
    manifest = backup_manifest_data(backup_dir)
    desired = desired_from_manifest(slot, manifest, state_root)
    if not desired.runtime_profile:
        raise ValueError("backup manifest is missing runtime_profile")
    return desired, load_profile(desired.runtime_profile)
