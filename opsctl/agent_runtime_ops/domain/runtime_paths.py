from __future__ import annotations

from pathlib import Path

from ..host.files import atomic_write_text
from ..routing import validate_linux_account


def slot_runtime_dir(slot: str) -> Path:
    validate_linux_account(slot)
    target_home = Path("/home") / slot
    runtime_dir = target_home / "openclaw"
    for path in (target_home, runtime_dir):
        if path.is_symlink():
            raise ValueError(f"managed path must not be symlink: {path}")
        if not path.is_dir():
            raise FileNotFoundError(path)
    return runtime_dir


def slot_config_dir(slot: str) -> Path:
    """Host path of the slot's on-disk gateway config dir (``/home/<slot>/.openclaw``).

    This is the bind-mount source that the compose template maps to the container's
    ``/home/node/.openclaw``. Used by the config preflight/migration to run the
    product's own validate/doctor against the real on-disk config.
    """
    validate_linux_account(slot)
    target_home = Path("/home") / slot
    config_dir = target_home / ".openclaw"
    for path in (target_home, config_dir):
        if path.is_symlink():
            raise ValueError(f"managed path must not be symlink: {path}")
        if not path.is_dir():
            raise FileNotFoundError(path)
    return config_dir


def agent_compose_path(runtime_dir: Path) -> Path:
    return runtime_dir / "docker-compose.agent-runtime.yml"


def agent_manifest_path(runtime_dir: Path) -> Path:
    return runtime_dir / ".agent-runtime-manifest"


def runtime_recovery_dir(state_root: Path, slot: str) -> Path:
    validate_linux_account(slot)
    return state_root / "runtime-recovery" / slot


def agent_backup_root(state_root: Path, slot: str) -> Path:
    return runtime_recovery_dir(state_root, slot) / "backups"


def safe_managed_file(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed file must not be symlink: {path}")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"managed parent is not a safe directory: {parent}")


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    safe_managed_file(path)
    atomic_write_text(path, text, mode=mode)


def state_runtime_dir(state_root: Path, slot: str, *, create: bool = False) -> Path:
    runtime_root = state_root / "runtime"
    slot_dir = runtime_root / slot
    for path in (state_root, runtime_root, slot_dir):
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed state path must not be symlink: {path}")
    if create:
        runtime_root.mkdir(mode=0o755, exist_ok=True)
        slot_dir.mkdir(mode=0o755, exist_ok=True)
    return slot_dir


def state_manifest_path(state_root: Path, slot: str, *, create_parent: bool = False) -> Path:
    return state_runtime_dir(state_root, slot, create=create_parent) / "manifest.yaml"
