from __future__ import annotations

import json
from datetime import datetime, timezone
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from ..profiles import load_profile
from ..yamlio import load_yaml
from ..host.files import atomic_write_text, fsync_parent
from .common import now_iso, run_text_cwd
from .runtime_manifest import desired_from_manifest, read_legacy_slot_manifest
from .docker_compose import docker_compose_command
from .runtime_paths import (
    agent_backup_root,
    agent_compose_path,
    agent_manifest_path,
    runtime_recovery_dir,
    state_manifest_path,
)


_BACKUP_NAME = re.compile(
    r"^(?P<timestamp>\d{8}T\d{6}[+-]\d{4})(?:\.(?P<suffix>\d+))?$"
)
_ROLLBACK_TRANSACTION_SCHEMA = "agent-runtime-rollback-transaction/v1"
_ROLLBACK_TRANSACTION_NAME = ".agent-runtime-rollback-transaction.json"
_ROLLBACK_TRANSACTION_KEYS = {
    "backup_metadata_sha256",
    "backup_name",
    "schema",
    "slot",
}
_BACKUP_SCHEMA = "agent-runtime-backup/v2"
_BACKUP_ARTIFACTS = {
    ".agent-runtime-manifest": "had_manifest",
    ".env": "had_env",
    "docker-compose.agent-runtime.yml": "had_compose",
    "manifest.yaml": "had_state_manifest",
}


def _backup_sort_key(path: Path) -> tuple[datetime, int] | None:
    match = _BACKUP_NAME.fullmatch(path.name)
    if match is None:
        return None
    suffix_text = match.group("suffix")
    suffix = int(suffix_text or 1)
    if suffix_text is not None and suffix < 2:
        return None
    return (
        datetime.strptime(match.group("timestamp"), "%Y%m%dT%H%M%S%z"),
        suffix,
    )


def _next_backup_path(backup_root: Path, original_backup_dir: Path) -> Path:
    original_key = _backup_sort_key(original_backup_dir)
    if original_key is None:
        raise ValueError(f"invalid generated backup name: {original_backup_dir.name}")
    same_second_suffixes = [
        sort_key[1]
        for item in backup_root.iterdir()
        if (sort_key := _backup_sort_key(item)) is not None
        and sort_key[0] == original_key[0]
    ]
    if not same_second_suffixes:
        return original_backup_dir
    return Path(f"{original_backup_dir}.{max(same_second_suffixes) + 1}")


def _fsync_regular_file(path: Path) -> None:
    flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _rollback_transaction_path(state_root: Path, slot: str) -> Path:
    return runtime_recovery_dir(state_root, slot) / _ROLLBACK_TRANSACTION_NAME


def _validate_controlled_directory(
    path: Path,
    *,
    exact_mode: int | None = None,
) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"root-controlled path must be a regular directory: {path}")
    path_stat = path.stat()
    mode = stat.S_IMODE(path_stat.st_mode)
    if os.name != "nt":
        if exact_mode is not None and mode != exact_mode:
            raise ValueError(
                f"root-controlled path mode mismatch: {path} mode={mode:04o}"
            )
        if mode & 0o022:
            raise ValueError(
                f"root-controlled path must not be group/other writable: {path}"
            )
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and path_stat.st_uid != geteuid():
        raise ValueError(f"root-controlled path owner mismatch: {path}")
    if os.name != "nt" and path_stat.st_nlink < 2:
        raise ValueError(f"root-controlled directory link count is invalid: {path}")


def _ensure_controlled_directory(path: Path, *, parent: Path) -> bool:
    created = False
    if path.is_symlink():
        raise ValueError(f"root-controlled path must not be symlink: {path}")
    if not path.exists():
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        fsync_parent(path)
        created = True
    _validate_controlled_directory(path, exact_mode=0o700)
    if path.parent != parent:
        raise ValueError(f"root-controlled path parent mismatch: {path}")
    return created


def _ensure_recovery_paths(state_root: Path, slot: str) -> tuple[Path, Path]:
    _validate_controlled_directory(state_root)
    recovery_root = state_root / "runtime-recovery"
    _ensure_controlled_directory(recovery_root, parent=state_root)
    recovery_dir = runtime_recovery_dir(state_root, slot)
    _ensure_controlled_directory(recovery_dir, parent=recovery_root)
    backup_root = agent_backup_root(state_root, slot)
    _ensure_controlled_directory(backup_root, parent=recovery_dir)
    return recovery_dir, backup_root


def _strict_json_object(path: Path, *, maximum_bytes: int = 4096) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"rollback transaction must be a regular file: {path}")
    file_stat = path.stat()
    if file_stat.st_nlink != 1:
        raise ValueError(f"rollback transaction must have one link: {path}")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise ValueError(f"rollback transaction mode must be 0600: {path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and file_stat.st_uid != geteuid():
        raise ValueError(f"rollback transaction owner mismatch: {path}")
    if file_stat.st_size > maximum_bytes:
        raise ValueError(f"rollback transaction is too large: {path}")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate rollback transaction key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"invalid rollback transaction: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError("rollback transaction must be an object")
    return value


def _validate_backup_dir(state_root: Path, slot: str, backup_dir: Path) -> Path:
    recovery_dir = runtime_recovery_dir(state_root, slot)
    _validate_controlled_directory(recovery_dir, exact_mode=0o700)
    backup_root = agent_backup_root(state_root, slot)
    _validate_controlled_directory(backup_root, exact_mode=0o700)
    expected = backup_root / backup_dir.name
    if backup_dir != expected or _backup_sort_key(backup_dir) is None:
        raise ValueError(f"rollback backup is outside the managed backup root: {backup_dir}")
    if backup_dir.is_symlink() or not backup_dir.is_dir():
        raise ValueError(f"rollback backup must be a regular directory: {backup_dir}")
    _validate_controlled_directory(backup_dir, exact_mode=0o700)
    metadata_path = backup_dir / "backup.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError(f"rollback backup metadata must be a regular file: {metadata_path}")
    metadata_stat = metadata_path.stat()
    if metadata_stat.st_nlink != 1:
        raise ValueError(f"rollback backup metadata must have one link: {metadata_path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and metadata_stat.st_uid != geteuid():
        raise ValueError(f"rollback backup metadata owner mismatch: {metadata_path}")
    return backup_dir


def _validate_backup_integrity(
    state_root: Path,
    slot: str,
    backup_dir: Path,
) -> tuple[dict, str]:
    backup_dir = _validate_backup_dir(state_root, slot, backup_dir)
    metadata_path = backup_dir / "backup.json"
    metadata_digest = _sha256_file(metadata_path)
    metadata = load_yaml(metadata_path)
    if not isinstance(metadata, dict) or metadata.get("schema") != _BACKUP_SCHEMA:
        raise ValueError("rollback backup metadata schema is invalid")
    artifact_digests = metadata.get("artifact_sha256")
    if not isinstance(artifact_digests, dict) or set(artifact_digests) != set(
        _BACKUP_ARTIFACTS
    ):
        raise ValueError("rollback backup artifact digest set is invalid")
    geteuid = getattr(os, "geteuid", None)
    for name, marker in _BACKUP_ARTIFACTS.items():
        present = _metadata_boolean(metadata, marker)
        artifact_path = backup_dir / name
        expected_digest = artifact_digests.get(name)
        if present:
            if artifact_path.is_symlink() or not artifact_path.is_file():
                raise ValueError(
                    f"rollback backup artifact must be a regular file: {artifact_path}"
                )
            artifact_stat = artifact_path.stat()
            if artifact_stat.st_nlink != 1:
                raise ValueError(
                    f"rollback backup artifact must have one link: {artifact_path}"
                )
            if geteuid is not None and artifact_stat.st_uid != geteuid():
                raise ValueError(
                    f"rollback backup artifact owner mismatch: {artifact_path}"
                )
            if not isinstance(expected_digest, str) or _sha256_file(
                artifact_path
            ) != expected_digest:
                raise ValueError(
                    f"rollback backup artifact digest mismatch: {artifact_path}"
                )
        elif expected_digest is not None or artifact_path.exists() or artifact_path.is_symlink():
            raise ValueError(
                f"rollback backup absent artifact state mismatch: {artifact_path}"
            )
    return metadata, metadata_digest


def pending_rollback_backup(state_root: Path, slot: str) -> Path | None:
    recovery_dir = runtime_recovery_dir(state_root, slot)
    if not recovery_dir.exists() and not recovery_dir.is_symlink():
        return None
    _validate_controlled_directory(recovery_dir, exact_mode=0o700)
    transaction_path = _rollback_transaction_path(state_root, slot)
    if not transaction_path.exists() and not transaction_path.is_symlink():
        return None
    transaction = _strict_json_object(transaction_path)
    if set(transaction) != _ROLLBACK_TRANSACTION_KEYS:
        raise ValueError("rollback transaction keys do not match the exact schema")
    if transaction.get("schema") != _ROLLBACK_TRANSACTION_SCHEMA:
        raise ValueError("unsupported rollback transaction schema")
    if transaction.get("slot") != slot:
        raise ValueError("rollback transaction slot does not match the requested slot")
    backup_name = transaction.get("backup_name")
    if not isinstance(backup_name, str) or _BACKUP_NAME.fullmatch(backup_name) is None:
        raise ValueError("rollback transaction backup name is invalid")
    backup_dir = _validate_backup_dir(
        state_root,
        slot,
        agent_backup_root(state_root, slot) / backup_name,
    )
    _, metadata_digest = _validate_backup_integrity(state_root, slot, backup_dir)
    if transaction.get("backup_metadata_sha256") != metadata_digest:
        raise ValueError("rollback transaction backup metadata digest mismatch")
    return backup_dir


def _begin_rollback_transaction(
    slot: str,
    state_root: Path,
    backup_dir: Path,
) -> Path:
    validated_backup = _validate_backup_dir(state_root, slot, backup_dir)
    _, metadata_digest = _validate_backup_integrity(
        state_root,
        slot,
        validated_backup,
    )
    existing = pending_rollback_backup(state_root, slot)
    if existing is not None:
        if existing != validated_backup:
            raise RuntimeError(
                f"another rollback transaction is pending: {existing.name}"
            )
        return _rollback_transaction_path(state_root, slot)
    transaction_path = _rollback_transaction_path(state_root, slot)
    payload = {
        "backup_metadata_sha256": metadata_digest,
        "backup_name": validated_backup.name,
        "schema": _ROLLBACK_TRANSACTION_SCHEMA,
        "slot": slot,
    }
    atomic_write_text(
        transaction_path,
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n",
        mode=0o600,
    )
    return transaction_path


def _finish_rollback_transaction(
    slot: str,
    state_root: Path,
    backup_dir: Path,
) -> None:
    pending = pending_rollback_backup(state_root, slot)
    if pending != backup_dir:
        raise RuntimeError("rollback transaction identity changed before completion")
    transaction_path = _rollback_transaction_path(state_root, slot)
    transaction_path.unlink()
    fsync_parent(transaction_path)


def _metadata_boolean(metadata: dict, key: str, *, required: bool = True) -> bool | None:
    if key not in metadata:
        if required:
            raise ValueError(f"backup {key} marker is required")
        return None
    value = metadata[key]
    if not isinstance(value, bool):
        raise ValueError(f"backup {key} marker must be boolean")
    return value


def _validate_managed_target(path: Path) -> None:
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError(f"managed restore parent is unsafe: {path.parent}")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"managed restore target must be a regular file: {path}")


def _restore_regular_file(
    source: Path,
    target: Path,
    *,
    mode: int | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"backup restore source must be a regular file: {source}")
    _validate_managed_target(target)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.restore-",
        dir=target.parent,
    )
    os.close(handle)
    temporary_path = Path(temporary_name)
    try:
        shutil.copy2(source, temporary_path)
        if mode is not None:
            temporary_path.chmod(mode)
        if uid is not None or gid is not None:
            if uid is None or gid is None:
                raise ValueError("backup restore owner identity is incomplete")
            if hasattr(os, "chown"):
                os.chown(temporary_path, uid, gid)
        _fsync_regular_file(temporary_path)
        os.replace(temporary_path, target)
        fsync_parent(target)
    finally:
        temporary_path.unlink(missing_ok=True)


def _remove_regular_file(target: Path) -> None:
    _validate_managed_target(target)
    if target.exists():
        target.unlink()
        fsync_parent(target)


def _validate_env_restore_inputs(
    runtime_dir: Path,
    backup_dir: Path,
    metadata: dict,
) -> bool | None:
    had_env = _metadata_boolean(metadata, "had_env", required=False)
    env_path = runtime_dir / ".env"
    _validate_managed_target(env_path)
    if had_env:
        backup_env = backup_dir / ".env"
        if backup_env.is_symlink() or not backup_env.is_file():
            raise ValueError(
                f"backup runtime env must be a regular file: {backup_env}"
            )
        for key in ("env_mode", "env_uid", "env_gid"):
            value = metadata.get(key)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"backup {key} must be an integer")
    return had_env


def backup_agent_runtime_state(slot: str, runtime_dir: Path, state_root: Path) -> Path:
    _, backup_root = _ensure_recovery_paths(state_root, slot)
    pending = pending_rollback_backup(state_root, slot)
    if pending is not None:
        raise RuntimeError(
            f"rollback transaction must be completed before a new apply: {pending.name}"
        )
    original_backup_dir = backup_root / datetime.now(timezone.utc).astimezone().strftime(
        "%Y%m%dT%H%M%S%z"
    )

    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, slot)
    env_path = runtime_dir / ".env"
    if env_path.is_symlink() or (env_path.exists() and not env_path.is_file()):
        raise ValueError(f"runtime env must be a regular file: {env_path}")
    env_stat = env_path.stat() if env_path.is_file() else None
    metadata = {
        "schema": _BACKUP_SCHEMA,
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
    staging_dir = Path(tempfile.mkdtemp(prefix=".staging-", dir=backup_root))
    staging_dir.chmod(0o700)
    try:
        if metadata["had_compose"]:
            shutil.copy2(
                compose_path, staging_dir / "docker-compose.agent-runtime.yml"
            )
        if metadata["had_env"]:
            backup_env = staging_dir / ".env"
            shutil.copy2(env_path, backup_env)
            backup_env.chmod(0o600)
        if metadata["had_manifest"]:
            shutil.copy2(manifest_path, staging_dir / ".agent-runtime-manifest")
        if metadata["had_state_manifest"]:
            shutil.copy2(state_manifest_file, staging_dir / "manifest.yaml")
        metadata["artifact_sha256"] = {
            name: (
                _sha256_file(staging_dir / name)
                if metadata[marker]
                else None
            )
            for name, marker in _BACKUP_ARTIFACTS.items()
        }
        (staging_dir / "backup.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        staged_files = sorted(
            item
            for item in staging_dir.iterdir()
            if not item.is_symlink() and item.is_file()
        )
        for staged_file in staged_files:
            _fsync_regular_file(staged_file)
        _fsync_directory(staging_dir)

        backup_dir = _next_backup_path(backup_root, original_backup_dir)
        suffix = _backup_sort_key(backup_dir)
        if suffix is None:
            raise ValueError(f"invalid backup path: {backup_dir}")
        next_suffix = suffix[1]
        while True:
            try:
                staging_dir.rename(backup_dir)
                _fsync_directory(backup_root)
                return backup_dir
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                next_suffix += 1
                backup_dir = Path(f"{original_backup_dir}.{next_suffix}")
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise


def restore_backup_env(runtime_dir: Path, backup_dir: Path) -> None:
    metadata = load_yaml(backup_dir / "backup.json")
    if not isinstance(metadata, dict):
        raise ValueError("backup metadata must be an object")
    had_env = _validate_env_restore_inputs(runtime_dir, backup_dir, metadata)
    if had_env is None:
        return
    env_path = runtime_dir / ".env"
    if had_env:
        backup_env = backup_dir / ".env"
        mode_value = metadata.get("env_mode")
        uid_value = metadata.get("env_uid")
        gid_value = metadata.get("env_gid")
        if not isinstance(mode_value, int) or isinstance(mode_value, bool):
            raise ValueError("backup env_mode must be an integer")
        if not isinstance(uid_value, int) or isinstance(uid_value, bool):
            raise ValueError("backup env_uid must be an integer")
        if not isinstance(gid_value, int) or isinstance(gid_value, bool):
            raise ValueError("backup env_gid must be an integer")
        _restore_regular_file(
            backup_env,
            env_path,
            mode=mode_value,
            uid=uid_value,
            gid=gid_value,
        )
    else:
        _remove_regular_file(env_path)


def latest_backup(state_root: Path, slot: str) -> Path | None:
    backup_root = agent_backup_root(state_root, slot)
    if not backup_root.is_dir():
        return None
    _validate_controlled_directory(backup_root, exact_mode=0o700)
    backups = sorted(
        [
            (item, sort_key)
            for item in backup_root.iterdir()
            if (sort_key := _backup_sort_key(item)) is not None
            and item.is_dir()
            and not item.is_symlink()
            and (item / "backup.json").is_file()
            and not (item / "backup.json").is_symlink()
        ],
        key=lambda item: item[1],
    )
    return backups[-1][0] if backups else None


def restore_backup(slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path) -> tuple[bool, str]:
    backup_dir = _validate_backup_dir(state_root, slot, backup_dir)
    metadata, _ = _validate_backup_integrity(state_root, slot, backup_dir)
    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, slot, create_parent=True)
    had_compose = _metadata_boolean(metadata, "had_compose")
    had_manifest = _metadata_boolean(metadata, "had_manifest")
    had_state_manifest = _metadata_boolean(metadata, "had_state_manifest")
    _validate_env_restore_inputs(runtime_dir, backup_dir, metadata)

    restore_plan = (
        (
            had_compose,
            backup_dir / "docker-compose.agent-runtime.yml",
            compose_path,
        ),
        (had_manifest, backup_dir / ".agent-runtime-manifest", manifest_path),
        (had_state_manifest, backup_dir / "manifest.yaml", state_manifest_file),
    )
    for had_file, source, target in restore_plan:
        _validate_managed_target(target)
        if had_file and (source.is_symlink() or not source.is_file()):
            raise ValueError(f"backup restore source must be a regular file: {source}")

    _begin_rollback_transaction(slot, state_root, backup_dir)

    restore_backup_env(runtime_dir, backup_dir)
    for had_file, source, target in restore_plan:
        if had_file:
            _restore_regular_file(source, target)
        else:
            _remove_regular_file(target)

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


def finish_rollback_transaction(
    slot: str,
    state_root: Path,
    backup_dir: Path,
) -> None:
    _finish_rollback_transaction(slot, state_root, backup_dir)


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
