from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
from typing import Iterator

from ..profiles import load_profile
from ..yamlio import load_yaml
from ..host.files import atomic_write_text, fsync_parent
from .common import now_iso, run_text, run_text_cwd
from .runtime_manifest import desired_from_manifest, read_legacy_slot_manifest
from .docker_compose import compose_project_name, docker_compose_command
from .runtime_paths import (
    agent_backup_root,
    agent_compose_path,
    agent_manifest_path,
    legacy_agent_backup_root,
    runtime_recovery_dir,
    state_manifest_path,
)


_BACKUP_NAME = re.compile(
    r"^(?P<timestamp>\d{8}T\d{6}[+-]\d{4})(?:\.(?P<suffix>\d+))?$"
)
_ROLLBACK_TRANSACTION_SCHEMA = "agent-runtime-rollback-transaction/v1"
_ROLLBACK_TRANSACTION_NAME = ".agent-runtime-rollback-transaction.json"
_RUNTIME_TRANSACTION_LOCK_NAME = ".agent-runtime-transaction.lock"
_RUNTIME_HOST_MUTATION_LOCK_NAME = ".agent-runtime-host-mutation.lock"
_LEGACY_RETRIEVAL_MIGRATION_SCHEMA = "agent-runtime-legacy-retrieval-migration/v1"
_LEGACY_RETRIEVAL_MIGRATION_NAME = ".agent-runtime-legacy-retrieval-migration.json"
_LEGACY_RETRIEVAL_MIGRATION_KEYS = {
    "backup_metadata_sha256",
    "backup_name",
    "consumed_at",
    "schema",
    "slot",
}
_ROLLBACK_TRANSACTION_KEYS = {
    "backup_metadata_sha256",
    "backup_name",
    "schema",
    "slot",
}
_BACKUP_SCHEMA = "agent-runtime-backup/v2"
_LEGACY_BACKUP_IMPORT_SCHEMA = "agent-runtime-legacy-backup-import/v1"
_LEGACY_BACKUP_METADATA_KEYS = {
    "created_at",
    "had_compose",
    "had_manifest",
    "had_state_manifest",
    "state_manifest_path",
}
_LEGACY_BACKUP_ENV_METADATA_KEYS = {
    "env_gid",
    "env_mode",
    "env_uid",
    "had_env",
}
_LEGACY_BACKUP_ARTIFACTS = {
    ".agent-runtime-manifest": "had_manifest",
    "docker-compose.agent-runtime.yml": "had_compose",
    "manifest.yaml": "had_state_manifest",
}
_LEGACY_DIAGNOSTIC_FILES = {
    "error.txt",
    "inspect.json",
    "logs.txt",
    "lookup.txt",
    "ports.txt",
    "top.txt",
}
_LEGACY_BACKUP_MAX_ENTRIES = 256
_LEGACY_BACKUP_MAX_FILE_BYTES = 8 * 1024 * 1024
_LEGACY_BACKUP_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_LEGACY_BACKUP_MAX_ROOT_BYTES = 128 * 1024 * 1024
_BACKUP_ARTIFACTS = {
    ".agent-runtime-manifest": "had_manifest",
    ".env": "had_env",
    "docker-compose.agent-runtime.yml": "had_compose",
    "manifest.yaml": "had_state_manifest",
}
_LEGACY_RETRIEVAL_PROJECTION_FAILURES = {
    "truth_retrieval_binding_matches_expected",
    "truth_retrieval_enabled_declared",
    "truth_retrieval_projection_complete_and_consistent",
}
_WINDOWS_LOCKS: dict[str, threading.Lock] = {}
_WINDOWS_LOCKS_GUARD = threading.Lock()


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


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_legacy_directory_descriptor(
    descriptor: int,
    path: Path,
) -> os.stat_result:
    value = os.fstat(descriptor)
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError(f"legacy backup path must be a directory: {path}")
    if value.st_nlink < 2:
        raise ValueError(f"legacy backup directory link count is invalid: {path}")
    if stat.S_IMODE(value.st_mode) & 0o022:
        raise ValueError(
            f"legacy backup directory must not be group/other writable: {path}"
        )
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and value.st_uid != geteuid():
        raise ValueError(f"legacy backup directory owner mismatch: {path}")
    return value


def _open_legacy_directory(
    path_or_name: Path | str,
    *,
    dir_fd: int | None = None,
) -> tuple[int, os.stat_result]:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("legacy backup import requires POSIX descriptor semantics")
    flags = os.O_RDONLY | os.O_DIRECTORY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    display = Path(path_or_name)
    try:
        descriptor = os.open(path_or_name, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise ValueError(
            f"legacy backup directory could not be opened safely: {display}"
        ) from exc
    try:
        value = _validate_legacy_directory_descriptor(descriptor, display)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, value


def _read_legacy_regular_file(
    dir_descriptor: int,
    name: str,
    *,
    display_parent: Path,
    maximum_bytes: int = _LEGACY_BACKUP_MAX_FILE_BYTES,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    display = display_parent / name
    try:
        descriptor = os.open(name, flags, dir_fd=dir_descriptor)
    except OSError as exc:
        raise ValueError(
            f"legacy backup artifact could not be opened safely: {display}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(
                f"legacy backup artifact must be a regular file: {display}"
            )
        if before.st_nlink != 1:
            raise ValueError(f"legacy backup artifact must have one link: {display}")
        if stat.S_IMODE(before.st_mode) & 0o022:
            raise ValueError(
                f"legacy backup artifact must not be group/other writable: {display}"
            )
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and before.st_uid != geteuid():
            raise ValueError(f"legacy backup artifact owner mismatch: {display}")
        if before.st_size > maximum_bytes:
            raise ValueError(f"legacy backup artifact is too large: {display}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=dir_descriptor, follow_symlinks=False)
        if (
            len(value) != before.st_size
            or _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(linked)
        ):
            raise ValueError(f"legacy backup artifact changed while reading: {display}")
        return value
    finally:
        os.close(descriptor)


def _strict_legacy_metadata(value: bytes, path: Path) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate legacy backup metadata key: {key}")
            result[key] = item
        return result

    try:
        metadata = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError(f"legacy backup metadata is invalid: {path}") from exc
    if not isinstance(metadata, dict):
        raise ValueError(f"legacy backup metadata must be an object: {path}")
    keys = frozenset(metadata)
    if keys not in {
        frozenset(_LEGACY_BACKUP_METADATA_KEYS),
        frozenset(_LEGACY_BACKUP_METADATA_KEYS | _LEGACY_BACKUP_ENV_METADATA_KEYS),
    }:
        raise ValueError(f"legacy backup metadata keys are invalid: {path}")
    for marker in _LEGACY_BACKUP_ARTIFACTS.values():
        if not isinstance(metadata.get(marker), bool):
            raise ValueError(f"legacy backup {marker} marker must be boolean: {path}")
    if not isinstance(metadata.get("created_at"), str) or not metadata["created_at"]:
        raise ValueError(f"legacy backup created_at is invalid: {path}")
    if not isinstance(metadata.get("state_manifest_path"), str):
        raise ValueError(f"legacy backup state_manifest_path is invalid: {path}")
    if "had_env" in metadata:
        had_env = metadata.get("had_env")
        if not isinstance(had_env, bool):
            raise ValueError(f"legacy backup had_env marker must be boolean: {path}")
        for key in ("env_gid", "env_mode", "env_uid"):
            identity = metadata.get(key)
            if had_env:
                if (
                    not isinstance(identity, int)
                    or isinstance(identity, bool)
                    or identity < 0
                ):
                    raise ValueError(f"legacy backup {key} is invalid: {path}")
            elif identity is not None:
                raise ValueError(f"legacy backup absent env {key} must be null: {path}")
        env_mode = metadata.get("env_mode")
        if had_env and isinstance(env_mode, int) and env_mode & ~0o777:
            raise ValueError(f"legacy backup env_mode is invalid: {path}")
    return metadata


def _legacy_source_identity(
    backup_name: str,
    metadata_digest: str,
    artifact_digests: dict[str, str | None],
    diagnostic_digests: dict[str, str],
) -> str:
    payload = {
        "artifact_sha256": artifact_digests,
        "backup_json_sha256": metadata_digest,
        "backup_name": backup_name,
        "diagnostic_sha256": diagnostic_digests,
        "schema": _LEGACY_BACKUP_IMPORT_SCHEMA,
    }
    return _sha256_bytes(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def _rollback_transaction_path(state_root: Path, slot: str) -> Path:
    return runtime_recovery_dir(state_root, slot) / _ROLLBACK_TRANSACTION_NAME


def _runtime_transaction_lock_path(state_root: Path, slot: str) -> Path:
    return runtime_recovery_dir(state_root, slot) / _RUNTIME_TRANSACTION_LOCK_NAME


def _runtime_host_mutation_lock_path(state_root: Path) -> Path:
    return state_root / "runtime-recovery" / _RUNTIME_HOST_MUTATION_LOCK_NAME


def _legacy_retrieval_migration_path(state_root: Path, slot: str) -> Path:
    return runtime_recovery_dir(state_root, slot) / _LEGACY_RETRIEVAL_MIGRATION_NAME


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


def _ensure_recovery_root(state_root: Path) -> Path:
    _validate_controlled_directory(state_root)
    recovery_root = state_root / "runtime-recovery"
    _ensure_controlled_directory(recovery_root, parent=state_root)
    return recovery_root


def _ensure_recovery_paths(state_root: Path, slot: str) -> tuple[Path, Path]:
    recovery_root = _ensure_recovery_root(state_root)
    recovery_dir = runtime_recovery_dir(state_root, slot)
    _ensure_controlled_directory(recovery_dir, parent=recovery_root)
    backup_root = agent_backup_root(state_root, slot)
    _ensure_controlled_directory(backup_root, parent=recovery_dir)
    return recovery_dir, backup_root


@contextmanager
def runtime_host_mutation_lock(state_root: Path) -> Iterator[Path]:
    """Serialize capacity admission with every runtime apply and rollback."""

    recovery_root = _ensure_recovery_root(state_root)
    lock_path = _runtime_host_mutation_lock_path(state_root)
    if lock_path.is_symlink():
        raise ValueError(f"runtime host mutation lock must not be a symlink: {lock_path}")
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    windows_lock: threading.Lock | None = None
    windows_lock_held = False
    posix_lock_held = False
    try:
        _validate_runtime_lock_descriptor(descriptor, lock_path)
        if lock_path.parent != recovery_root:
            raise ValueError(f"runtime host mutation lock parent mismatch: {lock_path}")
        if os.name == "nt":
            key = str(lock_path.resolve(strict=False)).casefold()
            with _WINDOWS_LOCKS_GUARD:
                windows_lock = _WINDOWS_LOCKS.setdefault(key, threading.Lock())
            if not windows_lock.acquire(blocking=False):
                raise RuntimeError("another runtime host mutation is active")
            windows_lock_held = True
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("another runtime host mutation is active") from exc
            posix_lock_held = True
        yield lock_path
    finally:
        if windows_lock_held and windows_lock is not None:
            windows_lock.release()
        if posix_lock_held:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_runtime_lock_descriptor(descriptor: int, path: Path) -> None:
    descriptor_stat = os.fstat(descriptor)
    if not stat.S_ISREG(descriptor_stat.st_mode):
        raise ValueError(f"runtime transaction lock must be a regular file: {path}")
    if descriptor_stat.st_nlink != 1:
        raise ValueError(f"runtime transaction lock must have one link: {path}")
    if os.name != "nt" and stat.S_IMODE(descriptor_stat.st_mode) != 0o600:
        raise ValueError(f"runtime transaction lock mode must be 0600: {path}")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and descriptor_stat.st_uid != geteuid():
        raise ValueError(f"runtime transaction lock owner mismatch: {path}")


@contextmanager
def runtime_transaction_lock(state_root: Path, slot: str) -> Iterator[Path]:
    """Serialize every apply/rollback transaction for one runtime slot.

    The persistent inode is intentional: deleting a lock file after releasing it can
    split concurrent callers across different inodes. Production uses non-blocking
    POSIX flock; Windows gets a process-local fail-closed equivalent for unit tests.
    """

    recovery_dir, _ = _ensure_recovery_paths(state_root, slot)
    lock_path = _runtime_transaction_lock_path(state_root, slot)
    if lock_path.is_symlink():
        raise ValueError(f"runtime transaction lock must not be a symlink: {lock_path}")
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    windows_lock: threading.Lock | None = None
    windows_lock_held = False
    posix_lock_held = False
    try:
        _validate_runtime_lock_descriptor(descriptor, lock_path)
        if lock_path.parent != recovery_dir:
            raise ValueError(f"runtime transaction lock parent mismatch: {lock_path}")
        if os.name == "nt":
            key = str(lock_path.resolve(strict=False)).casefold()
            with _WINDOWS_LOCKS_GUARD:
                windows_lock = _WINDOWS_LOCKS.setdefault(key, threading.Lock())
            if not windows_lock.acquire(blocking=False):
                raise RuntimeError(f"another runtime transaction is active: {slot}")
            windows_lock_held = True
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    f"another runtime transaction is active: {slot}"
                ) from exc
            posix_lock_held = True
        yield lock_path
    finally:
        if windows_lock_held and windows_lock is not None:
            windows_lock.release()
        if posix_lock_held:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


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
        raise ValueError(
            f"rollback backup is outside the managed backup root: {backup_dir}"
        )
    if backup_dir.is_symlink() or not backup_dir.is_dir():
        raise ValueError(f"rollback backup must be a regular directory: {backup_dir}")
    _validate_controlled_directory(backup_dir, exact_mode=0o700)
    metadata_path = backup_dir / "backup.json"
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise ValueError(
            f"rollback backup metadata must be a regular file: {metadata_path}"
        )
    metadata_stat = metadata_path.stat()
    if metadata_stat.st_nlink != 1:
        raise ValueError(
            f"rollback backup metadata must have one link: {metadata_path}"
        )
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
    legacy_import = _legacy_import_metadata(metadata)
    artifact_digests = metadata.get("artifact_sha256")
    if not isinstance(artifact_digests, dict) or set(artifact_digests) != set(
        _BACKUP_ARTIFACTS
    ):
        raise ValueError("rollback backup artifact digest set is invalid")
    geteuid = getattr(os, "geteuid", None)
    for name, marker in _BACKUP_ARTIFACTS.items():
        present = _metadata_boolean(
            metadata,
            marker,
            required=not (legacy_import is not None and marker == "had_env"),
        )
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
            if (
                not isinstance(expected_digest, str)
                or _sha256_file(artifact_path) != expected_digest
            ):
                raise ValueError(
                    f"rollback backup artifact digest mismatch: {artifact_path}"
                )
        elif (
            expected_digest is not None
            or artifact_path.exists()
            or artifact_path.is_symlink()
        ):
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


def begin_rollback_transaction(
    slot: str,
    state_root: Path,
    backup_dir: Path,
) -> Path:
    """Durably bind the pre-mutation recovery point for an apply transaction."""

    return _begin_rollback_transaction(slot, state_root, backup_dir)


def _metadata_boolean(
    metadata: dict, key: str, *, required: bool = True
) -> bool | None:
    if key not in metadata:
        if required:
            raise ValueError(f"backup {key} marker is required")
        return None
    value = metadata[key]
    if not isinstance(value, bool):
        raise ValueError(f"backup {key} marker must be boolean")
    return value


def _legacy_import_metadata(metadata: dict) -> dict[str, str] | None:
    value = metadata.get("legacy_source")
    if value is None:
        return None
    expected_keys = {
        "backup_json_sha256",
        "backup_name",
        "schema",
        "source_identity",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("legacy backup import metadata keys are invalid")
    if value.get("schema") != _LEGACY_BACKUP_IMPORT_SCHEMA:
        raise ValueError("legacy backup import metadata schema is invalid")
    backup_name = value.get("backup_name")
    if not isinstance(backup_name, str) or _BACKUP_NAME.fullmatch(backup_name) is None:
        raise ValueError("legacy backup import name is invalid")
    for key in ("backup_json_sha256", "source_identity"):
        digest = value.get(key)
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise ValueError(f"legacy backup import {key} is invalid")
    return value


def _read_legacy_backup_directory(
    root_descriptor: int,
    legacy_root: Path,
    backup_name: str,
) -> dict[str, object]:
    backup_path = legacy_root / backup_name
    descriptor, before = _open_legacy_directory(backup_name, dir_fd=root_descriptor)
    try:
        entries = set(os.listdir(descriptor))
        allowed = set(_LEGACY_BACKUP_ARTIFACTS) | {
            ".env",
            "backup.json",
            "failed-container",
        }
        unknown = sorted(entries - allowed)
        if unknown:
            raise ValueError(
                f"legacy backup contains unexpected entries: {backup_path} count={len(unknown)}"
            )
        if "backup.json" not in entries:
            raise ValueError(f"legacy backup metadata is missing: {backup_path}")
        metadata_bytes = _read_legacy_regular_file(
            descriptor,
            "backup.json",
            display_parent=backup_path,
            maximum_bytes=64 * 1024,
        )
        metadata = _strict_legacy_metadata(
            metadata_bytes,
            backup_path / "backup.json",
        )
        artifact_bytes: dict[str, bytes | None] = {}
        artifact_digests: dict[str, str | None] = {}
        total_bytes = len(metadata_bytes)
        for name, marker in _LEGACY_BACKUP_ARTIFACTS.items():
            present = bool(metadata[marker])
            if present != (name in entries):
                raise ValueError(
                    f"legacy backup artifact marker mismatch: {backup_path / name}"
                )
            value = (
                _read_legacy_regular_file(
                    descriptor,
                    name,
                    display_parent=backup_path,
                )
                if present
                else None
            )
            artifact_bytes[name] = value
            artifact_digests[name] = _sha256_bytes(value) if value is not None else None
            total_bytes += len(value or b"")

        had_env = metadata.get("had_env") if "had_env" in metadata else None
        if (had_env is True) != (".env" in entries):
            raise ValueError(
                f"legacy backup artifact marker mismatch: {backup_path / '.env'}"
            )
        env_bytes = (
            _read_legacy_regular_file(
                descriptor,
                ".env",
                display_parent=backup_path,
            )
            if had_env is True
            else None
        )
        artifact_bytes[".env"] = env_bytes
        artifact_digests[".env"] = (
            _sha256_bytes(env_bytes) if env_bytes is not None else None
        )
        total_bytes += len(env_bytes or b"")

        diagnostic_bytes: dict[str, bytes] = {}
        diagnostic_digests: dict[str, str] = {}
        if "failed-container" in entries:
            diagnostics_path = backup_path / "failed-container"
            diagnostics_descriptor, diagnostics_before = _open_legacy_directory(
                "failed-container",
                dir_fd=descriptor,
            )
            try:
                diagnostic_entries = set(os.listdir(diagnostics_descriptor))
                unknown_diagnostics = sorted(
                    diagnostic_entries - _LEGACY_DIAGNOSTIC_FILES
                )
                if unknown_diagnostics:
                    raise ValueError(
                        "legacy backup diagnostics contain unexpected entries: "
                        f"{diagnostics_path} count={len(unknown_diagnostics)}"
                    )
                for name in sorted(diagnostic_entries):
                    value = _read_legacy_regular_file(
                        diagnostics_descriptor,
                        name,
                        display_parent=diagnostics_path,
                    )
                    diagnostic_bytes[name] = value
                    diagnostic_digests[name] = _sha256_bytes(value)
                    total_bytes += len(value)
                diagnostics_after = os.fstat(diagnostics_descriptor)
                diagnostics_linked = os.stat(
                    "failed-container",
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if _stat_identity(diagnostics_before) != _stat_identity(
                    diagnostics_after
                ) or _stat_identity(diagnostics_after) != _stat_identity(
                    diagnostics_linked
                ):
                    raise ValueError(
                        f"legacy backup diagnostics changed while reading: {diagnostics_path}"
                    )
            finally:
                os.close(diagnostics_descriptor)
        if total_bytes > _LEGACY_BACKUP_MAX_TOTAL_BYTES:
            raise ValueError(f"legacy backup exceeds total size limit: {backup_path}")

        after = os.fstat(descriptor)
        linked = os.stat(backup_name, dir_fd=root_descriptor, follow_symlinks=False)
        if _stat_identity(before) != _stat_identity(after) or _stat_identity(
            after
        ) != _stat_identity(linked):
            raise ValueError(f"legacy backup changed while reading: {backup_path}")
        metadata_digest = _sha256_bytes(metadata_bytes)
        source_identity = _legacy_source_identity(
            backup_name,
            metadata_digest,
            artifact_digests,
            diagnostic_digests,
        )
        return {
            "artifact_bytes": artifact_bytes,
            "artifact_sha256": artifact_digests,
            "backup_json_sha256": metadata_digest,
            "backup_name": backup_name,
            "diagnostic_bytes": diagnostic_bytes,
            "metadata": metadata,
            "payload_bytes": total_bytes,
            "source_identity": source_identity,
        }
    finally:
        os.close(descriptor)


def _read_all_legacy_backups(runtime_dir: Path) -> list[dict[str, object]]:
    legacy_root = legacy_agent_backup_root(runtime_dir)
    try:
        legacy_lstat = legacy_root.lstat()
    except FileNotFoundError:
        return []
    if not stat.S_ISDIR(legacy_lstat.st_mode):
        raise ValueError(f"legacy backup root must be a directory: {legacy_root}")
    descriptor, before = _open_legacy_directory(legacy_root)
    try:
        entries = sorted(os.listdir(descriptor))
        if len(entries) > _LEGACY_BACKUP_MAX_ENTRIES:
            raise ValueError(
                f"legacy backup root exceeds entry limit: {legacy_root} count={len(entries)}"
            )
        invalid = [name for name in entries if _BACKUP_NAME.fullmatch(name) is None]
        if invalid:
            raise ValueError(
                f"legacy backup root contains unexpected entries: {legacy_root} count={len(invalid)}"
            )
        result: list[dict[str, object]] = []
        total_bytes = 0
        for name in entries:
            source = _read_legacy_backup_directory(descriptor, legacy_root, name)
            payload_bytes = source.get("payload_bytes")
            if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool):
                raise ValueError("legacy backup payload size is invalid")
            total_bytes += payload_bytes
            if total_bytes > _LEGACY_BACKUP_MAX_ROOT_BYTES:
                raise ValueError(
                    "legacy backup root exceeds total size limit: "
                    f"{legacy_root} bytes={total_bytes}"
                )
            result.append(source)
        after = os.fstat(descriptor)
        linked = os.stat(legacy_root, follow_symlinks=False)
        if _stat_identity(before) != _stat_identity(after) or _stat_identity(
            after
        ) != _stat_identity(linked):
            raise ValueError(f"legacy backup root changed while reading: {legacy_root}")
        return result
    finally:
        os.close(descriptor)


def _existing_legacy_imports(
    state_root: Path,
    slot: str,
    backup_root: Path,
) -> dict[str, tuple[str, Path]]:
    result: dict[str, tuple[str, Path]] = {}
    for item in sorted(backup_root.iterdir()):
        if _backup_sort_key(item) is None:
            continue
        metadata, _ = _validate_backup_integrity(state_root, slot, item)
        legacy = _legacy_import_metadata(metadata)
        if legacy is None:
            continue
        backup_name = legacy["backup_name"]
        identity = legacy["source_identity"]
        if backup_name in result and result[backup_name][0] != identity:
            raise ValueError(
                f"conflicting imported legacy backup identity: {backup_name}"
            )
        result[backup_name] = (identity, item)
    return result


def _publish_legacy_backup(
    state_root: Path,
    slot: str,
    backup_root: Path,
    source: dict[str, object],
) -> Path:
    source_name = str(source["backup_name"])
    original_backup_dir = backup_root / source_name
    backup_dir = _next_backup_path(backup_root, original_backup_dir)
    staging_dir = Path(tempfile.mkdtemp(prefix=".legacy-import-", dir=backup_root))
    staging_dir.chmod(0o700)
    try:
        artifact_bytes = source["artifact_bytes"]
        if not isinstance(artifact_bytes, dict):
            raise ValueError("legacy backup artifact payload is invalid")
        for name, value in artifact_bytes.items():
            if value is None:
                continue
            if not isinstance(name, str) or not isinstance(value, bytes):
                raise ValueError("legacy backup artifact payload is invalid")
            path = staging_dir / name
            path.write_bytes(value)
            path.chmod(0o600)

        diagnostic_bytes = source["diagnostic_bytes"]
        if not isinstance(diagnostic_bytes, dict):
            raise ValueError("legacy backup diagnostic payload is invalid")
        if diagnostic_bytes:
            diagnostics_dir = staging_dir / "failed-container"
            diagnostics_dir.mkdir(mode=0o700)
            diagnostics_dir.chmod(0o700)
            for name, value in diagnostic_bytes.items():
                if not isinstance(name, str) or not isinstance(value, bytes):
                    raise ValueError("legacy backup diagnostic payload is invalid")
                path = diagnostics_dir / name
                path.write_bytes(value)
                path.chmod(0o600)
                _fsync_regular_file(path)
            _fsync_directory(diagnostics_dir)

        source_metadata = source["metadata"]
        source_digests = source["artifact_sha256"]
        if not isinstance(source_metadata, dict) or not isinstance(
            source_digests, dict
        ):
            raise ValueError("legacy backup source metadata is invalid")
        metadata = {
            "artifact_sha256": source_digests,
            "created_at": source_metadata["created_at"],
            "had_compose": source_metadata["had_compose"],
            "had_manifest": source_metadata["had_manifest"],
            "had_state_manifest": source_metadata["had_state_manifest"],
            "legacy_source": {
                "backup_json_sha256": source["backup_json_sha256"],
                "backup_name": source_name,
                "schema": _LEGACY_BACKUP_IMPORT_SCHEMA,
                "source_identity": source["source_identity"],
            },
            "schema": _BACKUP_SCHEMA,
            "state_manifest_path": source_metadata["state_manifest_path"],
        }
        if "had_env" in source_metadata:
            metadata.update(
                {
                    "env_gid": source_metadata["env_gid"],
                    "env_mode": source_metadata["env_mode"],
                    "env_uid": source_metadata["env_uid"],
                    "had_env": source_metadata["had_env"],
                }
            )
        metadata_path = staging_dir / "backup.json"
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        metadata_path.chmod(0o600)
        for item in sorted(staging_dir.iterdir()):
            if item.is_file() and not item.is_symlink():
                _fsync_regular_file(item)
        _fsync_directory(staging_dir)
        next_suffix = (_backup_sort_key(backup_dir) or (None, 1))[1]
        while True:
            try:
                staging_dir.rename(backup_dir)
                _fsync_directory(backup_root)
                _validate_backup_integrity(state_root, slot, backup_dir)
                return backup_dir
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                next_suffix += 1
                backup_dir = Path(f"{original_backup_dir}.{next_suffix}")
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise


def import_legacy_agent_runtime_backups(
    slot: str,
    runtime_dir: Path,
    state_root: Path,
) -> list[Path]:
    """Copy old slot-owned-path backups into the durable root recovery plane.

    The legacy source is never removed. Every byte is read through no-follow
    descriptors and revalidated before a root-controlled atomic publication.
    """

    sources = _read_all_legacy_backups(runtime_dir)
    if not sources:
        return []
    _, backup_root = _ensure_recovery_paths(state_root, slot)
    existing = _existing_legacy_imports(state_root, slot, backup_root)
    imported: list[Path] = []
    for source in sources:
        source_name = str(source["backup_name"])
        source_identity = str(source["source_identity"])
        prior = existing.get(source_name)
        if prior is not None:
            if prior[0] != source_identity:
                raise ValueError(f"legacy backup changed after import: {source_name}")
            continue
        published = _publish_legacy_backup(
            state_root,
            slot,
            backup_root,
            source,
        )
        imported.append(published)
        existing[source_name] = (source_identity, published)
    return imported


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


def _empty_baseline_project_residue(slot: str) -> tuple[bool, str]:
    project = compose_project_name(slot)
    observations = (
        (
            "containers",
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.ID}}",
            ],
        ),
        (
            "networks",
            [
                "docker",
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.ID}}",
            ],
        ),
        (
            "volumes",
            [
                "docker",
                "volume",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.Name}}",
            ],
        ),
    )
    for kind, argv in observations:
        result = run_text(argv, timeout=30)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            return False, detail or f"empty_baseline_{kind}_query_failed"
        count = len([line for line in result.stdout.splitlines() if line.strip()])
        if count:
            return False, f"empty_baseline_{kind}_remain:{count}"
    return True, "empty_baseline_project_absent"


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
            raise ValueError(f"backup runtime env must be a regular file: {backup_env}")
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
    original_backup_dir = backup_root / datetime.now(
        timezone.utc
    ).astimezone().strftime("%Y%m%dT%H%M%S%z")

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
        "had_state_manifest": state_manifest_file.is_file()
        and not state_manifest_file.is_symlink(),
        "state_manifest_path": str(state_manifest_file),
    }
    staging_dir = Path(tempfile.mkdtemp(prefix=".staging-", dir=backup_root))
    staging_dir.chmod(0o700)
    try:
        if metadata["had_compose"]:
            shutil.copy2(compose_path, staging_dir / "docker-compose.agent-runtime.yml")
        if metadata["had_env"]:
            backup_env = staging_dir / ".env"
            shutil.copy2(env_path, backup_env)
            backup_env.chmod(0o600)
        if metadata["had_manifest"]:
            shutil.copy2(manifest_path, staging_dir / ".agent-runtime-manifest")
        if metadata["had_state_manifest"]:
            shutil.copy2(state_manifest_file, staging_dir / "manifest.yaml")
        metadata["artifact_sha256"] = {
            name: (_sha256_file(staging_dir / name) if metadata[marker] else None)
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


def restore_backup(
    slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path
) -> tuple[bool, str]:
    backup_dir = _validate_backup_dir(state_root, slot, backup_dir)
    metadata, _ = _validate_backup_integrity(state_root, slot, backup_dir)
    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, slot, create_parent=True)
    had_compose = _metadata_boolean(metadata, "had_compose")
    had_manifest = _metadata_boolean(metadata, "had_manifest")
    had_state_manifest = _metadata_boolean(metadata, "had_state_manifest")
    had_env = _validate_env_restore_inputs(runtime_dir, backup_dir, metadata)

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

    if not had_compose and compose_path.is_file():
        down = run_text_cwd(
            docker_compose_command(
                slot,
                compose_path,
                "down",
                "--remove-orphans",
            ),
            runtime_dir,
            timeout=180,
        )
        if down.returncode != 0:
            return False, (
                down.stderr or down.stdout
            ).strip() or "empty_baseline_compose_down_failed"

    restore_backup_env(runtime_dir, backup_dir)
    for had_file, source, target in restore_plan:
        if had_file:
            _restore_regular_file(source, target)
        else:
            _remove_regular_file(target)

    if not had_compose:
        active_paths = [compose_path, manifest_path, state_manifest_file]
        if had_env is False:
            active_paths.append(runtime_dir / ".env")
        if any(path.exists() or path.is_symlink() for path in active_paths):
            return False, "empty_baseline_active_files_remain"
        clean, reason = _empty_baseline_project_residue(slot)
        if not clean:
            return False, reason
        return True, "rollback_empty_baseline_restored"

    config = run_text_cwd(
        docker_compose_command(slot, compose_path, "config"), runtime_dir, timeout=60
    )
    if config.returncode != 0:
        return False, (
            config.stderr or config.stdout
        ).strip() or "rollback_compose_config_failed"
    up = run_text_cwd(
        docker_compose_command(
            slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"
        ),
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


def _legacy_retrieval_migration_identity(
    state_root: Path,
    slot: str,
    backup_dir: Path,
) -> dict[str, str]:
    validated_backup = _validate_backup_dir(state_root, slot, backup_dir)
    _, metadata_digest = _validate_backup_integrity(
        state_root,
        slot,
        validated_backup,
    )
    return {
        "backup_metadata_sha256": metadata_digest,
        "backup_name": validated_backup.name,
        "schema": _LEGACY_RETRIEVAL_MIGRATION_SCHEMA,
        "slot": slot,
    }


def _load_legacy_retrieval_migration(
    state_root: Path,
    slot: str,
) -> dict[str, object] | None:
    recovery_dir = runtime_recovery_dir(state_root, slot)
    receipt_path = _legacy_retrieval_migration_path(state_root, slot)
    if not receipt_path.exists() and not receipt_path.is_symlink():
        return None
    _validate_controlled_directory(recovery_dir, exact_mode=0o700)
    receipt = _strict_json_object(receipt_path)
    if set(receipt) != _LEGACY_RETRIEVAL_MIGRATION_KEYS:
        raise ValueError(
            "legacy retrieval migration receipt keys do not match the exact schema"
        )
    if receipt.get("schema") != _LEGACY_RETRIEVAL_MIGRATION_SCHEMA:
        raise ValueError("unsupported legacy retrieval migration receipt schema")
    if receipt.get("slot") != slot:
        raise ValueError("legacy retrieval migration receipt slot mismatch")
    backup_name = receipt.get("backup_name")
    if not isinstance(backup_name, str) or _BACKUP_NAME.fullmatch(backup_name) is None:
        raise ValueError("legacy retrieval migration receipt backup name is invalid")
    metadata_digest = receipt.get("backup_metadata_sha256")
    if (
        not isinstance(metadata_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", metadata_digest) is None
    ):
        raise ValueError("legacy retrieval migration receipt digest is invalid")
    consumed_at = receipt.get("consumed_at")
    if not isinstance(consumed_at, str) or not consumed_at:
        raise ValueError("legacy retrieval migration receipt timestamp is invalid")
    return receipt


def _legacy_retrieval_migration_is_available(
    state_root: Path,
    slot: str,
    backup_dir: Path,
) -> bool:
    identity = _legacy_retrieval_migration_identity(state_root, slot, backup_dir)
    receipt = _load_legacy_retrieval_migration(state_root, slot)
    if receipt is None:
        return True
    if any(receipt.get(key) != value for key, value in identity.items()):
        return False
    # A host crash after persisting consumption but before removing the rollback
    # marker must be able to resume the exact same backup. Once that transaction
    # is finished, the receipt permanently blocks a fresh exemption.
    return pending_rollback_backup(state_root, slot) == backup_dir


def consume_legacy_retrieval_projection_exemption(
    state_root: Path,
    slot: str,
    backup_dir: Path,
) -> Path:
    if pending_rollback_backup(state_root, slot) != backup_dir:
        raise RuntimeError(
            "legacy retrieval migration requires the exact pending rollback backup"
        )
    identity = _legacy_retrieval_migration_identity(state_root, slot, backup_dir)
    receipt_path = _legacy_retrieval_migration_path(state_root, slot)
    receipt = _load_legacy_retrieval_migration(state_root, slot)
    if receipt is not None:
        if any(receipt.get(key) != value for key, value in identity.items()):
            raise RuntimeError(
                "legacy retrieval migration exemption was already consumed"
            )
        return receipt_path
    payload = {
        **identity,
        "consumed_at": now_iso(),
    }
    atomic_write_text(
        receipt_path,
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n",
        mode=0o600,
    )
    persisted = _load_legacy_retrieval_migration(state_root, slot)
    if persisted is None or any(
        persisted.get(key) != value for key, value in identity.items()
    ):
        raise RuntimeError("legacy retrieval migration receipt persistence failed")
    return receipt_path


def backup_manifest_data(backup_dir: Path) -> dict:
    yaml_manifest = backup_dir / "manifest.yaml"
    if yaml_manifest.is_file():
        data = load_yaml(yaml_manifest)
        if isinstance(data, dict):
            return data
    return read_legacy_slot_manifest(backup_dir / ".agent-runtime-manifest")


def backup_allows_legacy_retrieval_projection_absence(backup_dir: Path) -> bool:
    """Identify an exact pre-feature backup that could not contain projection labels.

    This narrow migration exception is only consumed while verifying a restored
    backup. Normal live truth continues to require the canonical four projection
    labels, including for capability-absent current deployments.
    """

    manifest = backup_manifest_data(backup_dir)
    if not isinstance(manifest, dict):
        return False
    recipe = manifest.get("recipe")
    if isinstance(recipe, dict) and any(
        key in recipe for key in ("retrieval_contract", "retrieval_binding")
    ):
        return False
    if any(
        key in manifest
        for key in (
            "retrieval_binding_digest",
            "retrieval_component_digest",
            "retrieval_enabled",
        )
    ):
        return False
    compose_path = backup_dir / "docker-compose.agent-runtime.yml"
    if compose_path.is_symlink() or not compose_path.is_file():
        return False
    try:
        compose_text = compose_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return "agent-runtime.retrieval-" not in compose_text


def legacy_retrieval_projection_failures_are_expected(
    state_root: Path,
    slot: str,
    backup_dir: Path,
    failed_checks: set[str],
    truth: dict[str, str],
) -> bool:
    return (
        legacy_retrieval_projection_failures_may_be_expected(
            state_root,
            slot,
            backup_dir,
            failed_checks,
        )
        and truth.get("truth_status") == "ok"
        and truth.get("retrieval_labels_present") == "false"
        and truth.get("retrieval_projection_labels_present") == "false"
    )


def legacy_retrieval_projection_failures_may_be_expected(
    state_root: Path,
    slot: str,
    backup_dir: Path,
    failed_checks: set[str],
) -> bool:
    return (
        bool(failed_checks)
        and failed_checks <= _LEGACY_RETRIEVAL_PROJECTION_FAILURES
        and backup_allows_legacy_retrieval_projection_absence(backup_dir)
        and _legacy_retrieval_migration_is_available(
            state_root,
            slot,
            backup_dir,
        )
    )


def load_backup_runtime_contract(slot: str, backup_dir: Path, state_root: Path):
    manifest = backup_manifest_data(backup_dir)
    desired = desired_from_manifest(slot, manifest, state_root)
    if not desired.runtime_profile:
        raise ValueError("backup manifest is missing runtime_profile")
    return desired, load_profile(desired.runtime_profile)
