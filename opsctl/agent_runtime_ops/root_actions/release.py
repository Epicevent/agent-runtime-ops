"""Pinned standalone release boundary for the root-action broker.

This module is deliberately stdlib-only until a complete standalone release has
been validated.  A root-owned copy is installed outside the release that it
checks, then either execs the broker or creates the existing one-time WebAuthn
bootstrap through the broker's Unix socket.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterable, Iterator


RELEASE_DESCRIPTOR_SCHEMA = "agent-runtime-root-action-standalone-release/v1"
BOOTSTRAP_SECRET_SCHEMA = "agent-runtime-root-action-bootstrap-secret/v1"
BOOTSTRAP_RECEIPT_SCHEMA = "agent-runtime-root-action-bootstrap-receipt/v1"
TREE_DIGEST_DOMAIN = b"agent-runtime-root-action-standalone-tree/v1\x00"
DEFAULT_BROKER_SOCKET = Path("/run/agent-runtime-ops/root-action-broker.sock")
DEFAULT_BOOTSTRAP_SECRET = Path(
    "/run/agent-runtime-ops/root-action-bootstrap.secret.json"
)
MAX_TREE_ENTRIES = 50_000
MAX_TREE_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 16 * 1024
MAX_BOOTSTRAP_FUTURE_SECONDS = 600
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_BOOTSTRAP_ID_RE = re.compile(r"bootstrap-[0-9a-f]{32}")
_BOOTSTRAP_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_PACKAGE_ROOT_RE = re.compile(
    r"\.runtime/lib/python3\.[0-9]+/site-packages/agent_runtime_ops"
)
_FORBIDDEN_STARTUP_NAMES = frozenset(
    {"pyvenv.cfg", "sitecustomize.py", "usercustomize.py"}
)
_BROKER_ENTRY_CODE = (
    "import sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "from agent_runtime_ops.root_actions.service import main;"
    "raise SystemExit(main())"
)
_BROKER_ENVIRONMENT_KEYS = frozenset(
    {
        "ROOT_ACTION_WEBAUTHN_ORIGINS",
        "ROOT_ACTION_WEBAUTHN_RP_ID",
        "ROOT_ACTION_WEBAUTHN_RP_NAME",
        "ROOT_ACTION_WEBAUTHN_USER_ID",
    }
)

_ROOT_ACTION_FILES = frozenset(
    {
        "__init__.py",
        "admission.py",
        "auth_service.py",
        "authorization.py",
        "broker.py",
        "catalog.py",
        "client.py",
        "contracts.py",
        "endpoint.py",
        "execution.py",
        "historical_inventory_v1.json",
        "inventory.py",
        "listener.py",
        "observation.py",
        "posix_store.py",
        "projection.py",
        "protocol.py",
        "public_projection.py",
        "receipts.py",
        "registry.py",
        "release.py",
        "service.py",
        "state.py",
        "storage.py",
        "submission.py",
        "worker.py",
    }
)


class StandaloneReleaseError(RuntimeError):
    """A standalone broker release or invocation failed closed."""


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StandaloneReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_commit(value: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise StandaloneReleaseError("source commit is not an exact Git SHA")
    return value


def _canonical_absolute(path: Path, label: str) -> Path:
    path = Path(path)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or Path(os.path.normpath(str(path))) != path
    ):
        raise StandaloneReleaseError(f"{label} path is not canonical absolute")
    return path


def _validate_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise StandaloneReleaseError(f"{label} is not an exact SHA-256 digest")
    return value


def _mode(value: os.stat_result) -> int:
    return stat.S_IMODE(value.st_mode)


def _validate_directory(
    path: Path,
    *,
    required_uid: int,
    required_gid: int,
) -> os.stat_result:
    try:
        value = path.lstat()
    except OSError as exc:
        raise StandaloneReleaseError(f"required directory is unavailable: {path}") from exc
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_uid != required_uid
        or value.st_gid != required_gid
        or _mode(value) != 0o755
    ):
        raise StandaloneReleaseError(f"directory identity is unsafe: {path}")
    return value


def _validate_controlled_parent_chain(path: Path, *, required_uid: int) -> None:
    current = path.parent
    immediate = True
    while True:
        try:
            value = current.lstat()
        except OSError as exc:
            raise StandaloneReleaseError(
                f"parent directory is unavailable: {current}"
            ) from exc
        mode = _mode(value)
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
            raise StandaloneReleaseError(f"parent path is unsafe: {current}")
        if value.st_uid not in {0, required_uid}:
            raise StandaloneReleaseError(f"parent owner is unsafe: {current}")
        if mode & 0o022:
            if immediate or value.st_uid != 0 or not mode & stat.S_ISVTX:
                raise StandaloneReleaseError(f"parent mode is unsafe: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent
        immediate = False


def _read_regular(
    path: Path,
    *,
    required_uid: int,
    required_gid: int,
    allowed_modes: frozenset[int] = frozenset({0o644, 0o755}),
    allowed_nlinks: frozenset[int] = frozenset({1}),
    maximum: int = MAX_FILE_BYTES,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StandaloneReleaseError(f"required file is unavailable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != required_uid
            or before.st_gid != required_gid
            or _mode(before) not in allowed_modes
            or before.st_nlink not in allowed_nlinks
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise StandaloneReleaseError(f"file identity is unsafe: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise StandaloneReleaseError(f"file was truncated while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise StandaloneReleaseError(f"file grew while reading: {path}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise StandaloneReleaseError(f"file changed while reading: {path}")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _directory_names(path: Path) -> frozenset[str]:
    try:
        return frozenset(entry.name for entry in os.scandir(path))
    except OSError as exc:
        raise StandaloneReleaseError(f"directory cannot be enumerated: {path}") from exc


def _validate_first_party_closure(package_root: Path) -> None:
    if _directory_names(package_root) != frozenset(
        {"__init__.py", "domain", "root_actions"}
    ):
        raise StandaloneReleaseError(
            "standalone agent_runtime_ops package has an unexpected entry"
        )
    if _directory_names(package_root / "domain") != frozenset(
        {"__init__.py", "artifact_probe.py"}
    ):
        raise StandaloneReleaseError("standalone domain package is not minimal")
    if _directory_names(package_root / "root_actions") != _ROOT_ACTION_FILES:
        raise StandaloneReleaseError("standalone root_actions package is not exact")


def _safe_relative_path(relative: str) -> str:
    if (
        not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or any(ord(character) < 0x20 for character in relative)
    ):
        raise StandaloneReleaseError("release contains an unsafe relative path")
    return relative


def _tree_records(
    release_dir: Path,
    *,
    required_uid: int,
    required_gid: int,
) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    total_bytes = 0

    def visit(directory: Path, prefix: str) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise StandaloneReleaseError(
                f"release directory cannot be enumerated: {directory}"
            ) from exc
        for entry in entries:
            relative = _safe_relative_path(
                f"{prefix}/{entry.name}" if prefix else entry.name
            )
            if (
                entry.name in _FORBIDDEN_STARTUP_NAMES
                or entry.name.endswith(".pth")
                or entry.name.endswith(".egg-link")
            ):
                raise StandaloneReleaseError(
                    f"release contains a forbidden startup hook: {relative}"
                )
            path = Path(entry.path)
            try:
                value = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise StandaloneReleaseError(
                    f"release entry cannot be inspected: {relative}"
                ) from exc
            if value.st_uid != required_uid or value.st_gid != required_gid:
                raise StandaloneReleaseError(
                    f"release entry owner is unsafe: {relative}"
                )
            if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
                if _mode(value) != 0o755:
                    raise StandaloneReleaseError(
                        f"release directory mode is unsafe: {relative}"
                    )
                records.append(
                    {
                        "gid": value.st_gid,
                        "kind": "directory",
                        "mode": "0755",
                        "path": relative,
                        "uid": value.st_uid,
                    }
                )
                visit(path, relative)
            elif stat.S_ISREG(value.st_mode):
                raw, stable = _read_regular(
                    path,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
                total_bytes += len(raw)
                if total_bytes > MAX_TREE_BYTES:
                    raise StandaloneReleaseError("release byte count exceeds the bound")
                records.append(
                    {
                        "bytes": len(raw),
                        "gid": stable.st_gid,
                        "kind": "file",
                        "mode": f"{_mode(stable):04o}",
                        "nlink": stable.st_nlink,
                        "path": relative,
                        "sha256": _sha256(raw),
                        "uid": stable.st_uid,
                    }
                )
            else:
                raise StandaloneReleaseError(
                    f"release entry type is unsupported: {relative}"
                )
            if len(records) > MAX_TREE_ENTRIES:
                raise StandaloneReleaseError("release entry count exceeds the bound")

    visit(release_dir, "")
    return records, total_bytes


def _tree_digest(records: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(TREE_DIGEST_DOMAIN)
    for record in records:
        digest.update(_canonical_json(record))
    return "sha256:" + digest.hexdigest()


def _locate_package_root(release_dir: Path) -> Path:
    lib = release_dir / ".runtime" / "lib"
    identity = release_dir.stat()
    _validate_directory(
        lib,
        required_uid=identity.st_uid,
        required_gid=identity.st_gid,
    )
    matches: list[Path] = []
    for python_dir in sorted(lib.iterdir(), key=lambda item: item.name):
        if re.fullmatch(r"python3\.[0-9]+", python_dir.name) is None:
            continue
        candidate = python_dir / "site-packages" / "agent_runtime_ops"
        if candidate.exists() or candidate.is_symlink():
            matches.append(candidate)
    if len(matches) != 1:
        raise StandaloneReleaseError(
            "release must contain exactly one standalone agent_runtime_ops package"
        )
    return matches[0]


def _validate_runtime_bin(release_dir: Path, package_root: Path) -> None:
    python_version = package_root.parts[-3]
    expected = frozenset({"python", "python3", python_version})
    if _directory_names(release_dir / ".runtime" / "bin") != expected:
        raise StandaloneReleaseError(
            "standalone runtime bin directory contains an unexpected entry"
        )


@dataclass(frozen=True)
class ReleaseDescriptor:
    source_commit: str
    release_basename: str
    tree_digest: str
    entry_count: int
    total_file_bytes: int
    python_relpath: str
    package_root_relpath: str
    service_module: str = "agent_runtime_ops.root_actions.service"

    def __post_init__(self) -> None:
        _validate_commit(self.source_commit)
        _validate_digest(self.tree_digest, "release tree digest")
        if self.release_basename != self.source_commit:
            raise StandaloneReleaseError("release basename is not the source commit")
        if (
            isinstance(self.entry_count, bool)
            or not isinstance(self.entry_count, int)
            or self.entry_count < 1
            or self.entry_count > MAX_TREE_ENTRIES
            or isinstance(self.total_file_bytes, bool)
            or not isinstance(self.total_file_bytes, int)
            or self.total_file_bytes < 1
            or self.total_file_bytes > MAX_TREE_BYTES
            or self.python_relpath != ".runtime/bin/python"
            or _PACKAGE_ROOT_RE.fullmatch(self.package_root_relpath) is None
            or self.service_module != "agent_runtime_ops.root_actions.service"
        ):
            raise StandaloneReleaseError("release descriptor fields are invalid")

    def value(self) -> dict[str, Any]:
        return {
            "entry_count": self.entry_count,
            "package_root_relpath": self.package_root_relpath,
            "python_relpath": self.python_relpath,
            "release_basename": self.release_basename,
            "schema": RELEASE_DESCRIPTOR_SCHEMA,
            "service_module": self.service_module,
            "source_commit": self.source_commit,
            "total_file_bytes": self.total_file_bytes,
            "tree_digest": self.tree_digest,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.value())


def describe_release(
    release_dir: Path,
    source_commit: str,
    *,
    required_uid: int = 0,
    required_gid: int = 0,
) -> ReleaseDescriptor:
    source_commit = _validate_commit(source_commit)
    release_dir = _canonical_absolute(release_dir, "release")
    if release_dir.name != source_commit:
        raise StandaloneReleaseError("release path is not commit-pinned")
    _validate_controlled_parent_chain(release_dir, required_uid=required_uid)
    _validate_directory(
        release_dir,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    python = release_dir / ".runtime" / "bin" / "python"
    _read_regular(
        python,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o755}),
    )
    package_root = _locate_package_root(release_dir)
    _validate_directory(
        package_root,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _validate_first_party_closure(package_root)
    _validate_runtime_bin(release_dir, package_root)
    if (release_dir / ".runtime" / "bin" / "opsctl").exists():
        raise StandaloneReleaseError("standalone release contains the retired opsctl")
    records, total_bytes = _tree_records(
        release_dir,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    package_relative = package_root.relative_to(release_dir).as_posix()
    return ReleaseDescriptor(
        source_commit=source_commit,
        release_basename=release_dir.name,
        tree_digest=_tree_digest(records),
        entry_count=len(records),
        total_file_bytes=total_bytes,
        python_relpath=".runtime/bin/python",
        package_root_relpath=package_relative,
    )


def parse_descriptor(raw: bytes) -> ReleaseDescriptor:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except StandaloneReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StandaloneReleaseError("release descriptor is not UTF-8 JSON") from exc
    expected = {
        "entry_count",
        "package_root_relpath",
        "python_relpath",
        "release_basename",
        "schema",
        "service_module",
        "source_commit",
        "total_file_bytes",
        "tree_digest",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != RELEASE_DESCRIPTOR_SCHEMA
        or raw != _canonical_json(value)
    ):
        raise StandaloneReleaseError("release descriptor field set is invalid")
    return ReleaseDescriptor(
        source_commit=value["source_commit"],
        release_basename=value["release_basename"],
        tree_digest=value["tree_digest"],
        entry_count=value["entry_count"],
        total_file_bytes=value["total_file_bytes"],
        python_relpath=value["python_relpath"],
        package_root_relpath=value["package_root_relpath"],
        service_module=value["service_module"],
    )


def validate_runtime_release(
    *,
    release_dir: Path,
    descriptor_path: Path,
    expected_source_commit: str,
    expected_descriptor_sha256: str,
    launcher_path: Path,
    expected_launcher_sha256: str,
    required_uid: int = 0,
    required_gid: int = 0,
) -> ReleaseDescriptor:
    release_dir = _canonical_absolute(release_dir, "release")
    descriptor_path = _canonical_absolute(descriptor_path, "descriptor")
    launcher_path = _canonical_absolute(launcher_path, "launcher")
    for external, label in (
        (descriptor_path, "descriptor"),
        (launcher_path, "launcher"),
    ):
        try:
            external.relative_to(release_dir)
        except ValueError:
            pass
        else:
            raise StandaloneReleaseError(f"{label} must be outside the release tree")
    _validate_digest(expected_descriptor_sha256, "descriptor digest")
    _validate_digest(expected_launcher_sha256, "launcher digest")
    _validate_controlled_parent_chain(launcher_path, required_uid=required_uid)
    _validate_controlled_parent_chain(descriptor_path, required_uid=required_uid)
    launcher, _ = _read_regular(
        launcher_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
        maximum=MAX_FILE_BYTES,
    )
    if _sha256(launcher) != expected_launcher_sha256:
        raise StandaloneReleaseError("standalone launcher digest mismatch")
    descriptor_raw, _ = _read_regular(
        descriptor_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
        maximum=MAX_DESCRIPTOR_BYTES,
    )
    if _sha256(descriptor_raw) != expected_descriptor_sha256:
        raise StandaloneReleaseError("release descriptor digest mismatch")
    descriptor = parse_descriptor(descriptor_raw)
    if descriptor.source_commit != _validate_commit(expected_source_commit):
        raise StandaloneReleaseError("release descriptor source commit mismatch")
    observed = describe_release(
        release_dir,
        expected_source_commit,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    if observed != descriptor:
        raise StandaloneReleaseError("standalone release tree does not match descriptor")
    packaged_launcher, _ = _read_regular(
        release_dir / descriptor.package_root_relpath / "root_actions" / "release.py",
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
    )
    if packaged_launcher != launcher:
        raise StandaloneReleaseError(
            "stable launcher and packaged launcher bytes differ"
        )
    return descriptor


def _release_environment(descriptor: ReleaseDescriptor, release_dir: Path) -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in _BROKER_ENVIRONMENT_KEYS
        if key in os.environ
    }
    environment.update(
        {
            "AGENT_RUNTIME_ROOT_ACTION_RELEASE": str(release_dir),
            "AGENT_RUNTIME_ROOT_ACTION_SOURCE_COMMIT": descriptor.source_commit,
            "AGENT_RUNTIME_ROOT_ACTION_TREE_SHA256": descriptor.tree_digest,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def exec_broker(
    descriptor: ReleaseDescriptor,
    release_dir: Path,
    *,
    execve: Callable[[str, list[str], dict[str, str]], Any] = os.execve,
) -> None:
    python = release_dir / descriptor.python_relpath
    package_parent = (release_dir / descriptor.package_root_relpath).parent
    argv = [
        str(python),
        "-I",
        "-B",
        "-S",
        "-c",
        _BROKER_ENTRY_CODE,
        str(package_parent),
    ]
    execve(str(python), argv, _release_environment(descriptor, release_dir))
    raise StandaloneReleaseError("broker exec unexpectedly returned")


def _write_bootstrap_secret(
    response: dict[str, Any],
    *,
    secret_path: Path = DEFAULT_BOOTSTRAP_SECRET,
    required_uid: int = 0,
    required_gid: int = 0,
    write: Callable[[int, bytes], int] = os.write,
    now: datetime | None = None,
) -> dict[str, Any]:
    expiry = _validate_bootstrap_fields(response, stored=False)
    _bootstrap_freshness(expiry, _trusted_utc_now(now))
    secret_path = Path(secret_path)
    if secret_path != DEFAULT_BOOTSTRAP_SECRET or not secret_path.is_absolute():
        raise StandaloneReleaseError("bootstrap secret path is not the fixed runtime path")
    parent = secret_path.parent
    parent_identity = parent.lstat()
    if (
        not stat.S_ISDIR(parent_identity.st_mode)
        or stat.S_ISLNK(parent_identity.st_mode)
        or parent_identity.st_uid != required_uid
        or _mode(parent_identity) & 0o022
    ):
        raise StandaloneReleaseError("bootstrap secret parent is unsafe")
    secret = _canonical_json(
        {
            "bootstrap_id": response["bootstrap_id"],
            "bootstrap_token": response["bootstrap_token"],
            "expires_at": response["expires_at"],
            "remaining_registrations": response["remaining_registrations"],
            "schema": BOOTSTRAP_SECRET_SCHEMA,
        }
    )
    staging_path = secret_path.with_name(secret_path.name + ".next")
    if os.path.lexists(secret_path) or os.path.lexists(staging_path):
        raise StandaloneReleaseError("bootstrap secret destination is not empty")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(staging_path, flags, 0o600)
    except OSError as exc:
        raise StandaloneReleaseError("bootstrap secret was not published") from exc
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, required_uid, required_gid)
        offset = 0
        while offset < len(secret):
            written = write(descriptor, secret[offset:])
            if written < 1 or written > len(secret) - offset:
                raise StandaloneReleaseError("bootstrap staging write made no progress")
            offset += written
        os.fsync(descriptor)
    except OSError as exc:
        raise StandaloneReleaseError("bootstrap staging write failed") from exc
    finally:
        os.close(descriptor)
    staged, _ = _read_regular(
        staging_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o600}),
        maximum=4 * 1024,
    )
    if staged != secret:
        raise StandaloneReleaseError("bootstrap staging read-back mismatch")
    try:
        os.link(staging_path, secret_path, follow_symlinks=False)
    except OSError as exc:
        raise StandaloneReleaseError("bootstrap secret was not published") from exc
    parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    staging_path.unlink()
    parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    identity = secret_path.lstat()
    if (
        not stat.S_ISREG(identity.st_mode)
        or identity.st_uid != required_uid
        or identity.st_gid != required_gid
        or _mode(identity) != 0o600
        or identity.st_nlink != 1
        or identity.st_size != len(secret)
    ):
        raise StandaloneReleaseError("bootstrap secret identity is unsafe")
    return _bootstrap_receipt(response, secret_path)


def _bootstrap_receipt(value: dict[str, Any], secret_path: Path) -> dict[str, Any]:
    return {
        "bootstrap_id": value["bootstrap_id"],
        "expires_at": value["expires_at"],
        "remaining_registrations": value["remaining_registrations"],
        "schema": BOOTSTRAP_RECEIPT_SCHEMA,
        "secret_path": str(secret_path),
    }


def _parse_bootstrap_secret(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except StandaloneReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StandaloneReleaseError("bootstrap secret is not UTF-8 JSON") from exc
    if (
        not isinstance(value, dict)
        or raw != _canonical_json(value)
    ):
        raise StandaloneReleaseError("bootstrap secret is invalid")
    _validate_bootstrap_fields(value, stored=True)
    return value


def _validate_bootstrap_fields(value: dict[str, Any], *, stored: bool) -> datetime:
    expected = {
        "bootstrap_id",
        "bootstrap_token",
        "expires_at",
        "remaining_registrations",
    }
    if stored:
        expected.add("schema")
    if set(value) != expected or (
        stored and value.get("schema") != BOOTSTRAP_SECRET_SCHEMA
    ):
        raise StandaloneReleaseError("bootstrap response is not exact")
    bootstrap_id = value.get("bootstrap_id")
    token = value.get("bootstrap_token")
    expires_at = value.get("expires_at")
    remaining = value.get("remaining_registrations")
    if (
        not isinstance(bootstrap_id, str)
        or _BOOTSTRAP_ID_RE.fullmatch(bootstrap_id) is None
        or not isinstance(token, str)
        or _BOOTSTRAP_TOKEN_RE.fullmatch(token) is None
        or type(remaining) is not int
        or remaining != 3
        or not isinstance(expires_at, str)
    ):
        raise StandaloneReleaseError("bootstrap response values are invalid")
    try:
        expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise StandaloneReleaseError("bootstrap expiry is invalid") from exc
    if expiry.strftime("%Y-%m-%dT%H:%M:%SZ") != expires_at:
        raise StandaloneReleaseError("bootstrap expiry is not canonical")
    return expiry


def _trusted_utc_now(value: datetime | None) -> datetime:
    observed = value if value is not None else datetime.now(timezone.utc)
    if observed.tzinfo is None or observed.utcoffset() != timezone.utc.utcoffset(observed):
        raise StandaloneReleaseError("trusted bootstrap time is not UTC")
    return observed.astimezone(timezone.utc)


def _bootstrap_freshness(expiry: datetime, now: datetime) -> str:
    remaining = (expiry - now).total_seconds()
    if remaining <= 0:
        return "expired"
    if remaining > MAX_BOOTSTRAP_FUTURE_SECONDS:
        raise StandaloneReleaseError("bootstrap expiry exceeds the trusted future bound")
    return "fresh"


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _bootstrap_publication_lock(
    *,
    secret_path: Path = DEFAULT_BOOTSTRAP_SECRET,
    required_uid: int = 0,
    required_gid: int = 0,
) -> Iterator[None]:
    """Serialize recovery, broker issuance, and durable token publication."""
    if os.name != "posix":
        raise StandaloneReleaseError("bootstrap publication lock requires POSIX")
    import fcntl

    if secret_path != DEFAULT_BOOTSTRAP_SECRET or not secret_path.is_absolute():
        raise StandaloneReleaseError("bootstrap secret path is not the fixed runtime path")
    parent = secret_path.parent
    parent_identity = parent.lstat()
    if (
        not stat.S_ISDIR(parent_identity.st_mode)
        or stat.S_ISLNK(parent_identity.st_mode)
        or parent_identity.st_uid != required_uid
        or _mode(parent_identity) & 0o022
    ):
        raise StandaloneReleaseError("bootstrap secret parent is unsafe")
    lock_path = secret_path.with_name(secret_path.name + ".lock")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise StandaloneReleaseError(
                "bootstrap publication lock is unavailable"
            ) from exc
        try:
            descriptor = os.open(lock_path, os.O_RDWR | nofollow)
        except OSError as open_exc:
            raise StandaloneReleaseError(
                "bootstrap publication lock is unavailable"
            ) from open_exc
    else:
        created = True
    try:
        if created:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, required_uid, required_gid)
            os.fsync(descriptor)
            _fsync_directory(parent)
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != required_uid
            or identity.st_gid != required_gid
            or _mode(identity) != 0o600
            or identity.st_nlink != 1
        ):
            raise StandaloneReleaseError("bootstrap publication lock is unsafe")
        rebound = lock_path.lstat()
        if (rebound.st_dev, rebound.st_ino) != (identity.st_dev, identity.st_ino):
            raise StandaloneReleaseError("bootstrap publication lock identity changed")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        rebound = lock_path.lstat()
        if (rebound.st_dev, rebound.st_ino) != (identity.st_dev, identity.st_ino):
            raise StandaloneReleaseError("bootstrap publication lock identity changed")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _recover_bootstrap_secret(
    *,
    secret_path: Path = DEFAULT_BOOTSTRAP_SECRET,
    required_uid: int = 0,
    required_gid: int = 0,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    observed_now = _trusted_utc_now(now)
    if secret_path != DEFAULT_BOOTSTRAP_SECRET or not secret_path.is_absolute():
        raise StandaloneReleaseError("bootstrap secret path is not the fixed runtime path")
    parent = secret_path.parent
    parent_identity = parent.lstat()
    if (
        not stat.S_ISDIR(parent_identity.st_mode)
        or stat.S_ISLNK(parent_identity.st_mode)
        or parent_identity.st_uid != required_uid
        or _mode(parent_identity) & 0o022
    ):
        raise StandaloneReleaseError("bootstrap secret parent is unsafe")
    staging_path = secret_path.with_name(secret_path.name + ".next")
    final_exists = os.path.lexists(secret_path)
    staging_exists = os.path.lexists(staging_path)
    if final_exists:
        raw, final_identity = _read_regular(
            secret_path,
            required_uid=required_uid,
            required_gid=required_gid,
            allowed_modes=frozenset({0o600}),
            allowed_nlinks=frozenset({1, 2}),
            maximum=4 * 1024,
        )
        value = _parse_bootstrap_secret(raw)
        expiry = _validate_bootstrap_fields(value, stored=True)
        freshness = _bootstrap_freshness(expiry, observed_now)
        if staging_exists:
            staging_identity = staging_path.lstat()
            if (
                final_identity.st_nlink != 2
                or (staging_identity.st_dev, staging_identity.st_ino)
                != (final_identity.st_dev, final_identity.st_ino)
            ):
                raise StandaloneReleaseError("bootstrap staging identity conflicts")
            _fsync_directory(parent)
            staging_path.unlink()
            _fsync_directory(parent)
        elif final_identity.st_nlink != 1:
            raise StandaloneReleaseError("bootstrap final link count is unsafe")
        else:
            _fsync_directory(parent)
        if freshness == "expired":
            secret_path.unlink()
            _fsync_directory(parent)
            return None
        return _bootstrap_receipt(value, secret_path)
    if not staging_exists:
        return None
    try:
        raw, _ = _read_regular(
            staging_path,
            required_uid=required_uid,
            required_gid=required_gid,
            allowed_modes=frozenset({0o600}),
            maximum=4 * 1024,
        )
        value = _parse_bootstrap_secret(raw)
        expiry = _validate_bootstrap_fields(value, stored=True)
    except StandaloneReleaseError:
        identity = staging_path.lstat()
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_uid != required_uid
            or identity.st_gid != required_gid
            or _mode(identity) != 0o600
            or identity.st_nlink != 1
            or identity.st_size > 4 * 1024
        ):
            raise StandaloneReleaseError("bootstrap staging residue is unsafe")
        staging_path.unlink()
        _fsync_directory(parent)
        return None
    if _bootstrap_freshness(expiry, observed_now) == "expired":
        staging_path.unlink()
        _fsync_directory(parent)
        return None
    try:
        os.link(staging_path, secret_path, follow_symlinks=False)
    except OSError as exc:
        raise StandaloneReleaseError("bootstrap staging recovery failed") from exc
    _fsync_directory(parent)
    staging_path.unlink()
    _fsync_directory(parent)
    final, identity = _read_regular(
        secret_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o600}),
        maximum=4 * 1024,
    )
    if final != raw or identity.st_nlink != 1:
        raise StandaloneReleaseError("bootstrap recovered final is unsafe")
    return _bootstrap_receipt(value, secret_path)


def create_auth_bootstrap(
    descriptor: ReleaseDescriptor,
    release_dir: Path,
    *,
    secret_path: Path = DEFAULT_BOOTSTRAP_SECRET,
    client_factory: Callable[..., Any] | None = None,
    required_uid: int = 0,
    required_gid: int = 0,
    now: datetime | None = None,
) -> dict[str, Any]:
    with _bootstrap_publication_lock(
        secret_path=secret_path,
        required_uid=required_uid,
        required_gid=required_gid,
    ):
        observed_now = _trusted_utc_now(now)
        recovered = _recover_bootstrap_secret(
            secret_path=secret_path,
            required_uid=required_uid,
            required_gid=required_gid,
            now=observed_now,
        )
        if recovered is not None:
            return recovered
        package_parent = (release_dir / descriptor.package_root_relpath).parent
        package_python = Path(descriptor.package_root_relpath).parts[2]
        current_python = f"python{sys.version_info.major}.{sys.version_info.minor}"
        if package_python != current_python:
            raise StandaloneReleaseError(
                "bootstrap launcher Python does not match the release package"
            )
        try:
            sys.path.insert(0, str(package_parent))
            if client_factory is None:
                from agent_runtime_ops.root_actions.client import RootActionBrokerClient

                client_factory = RootActionBrokerClient
            response = client_factory(
                socket_path=DEFAULT_BROKER_SOCKET
            ).create_auth_bootstrap()
        finally:
            try:
                sys.path.remove(str(package_parent))
            except ValueError:
                pass
        return _write_bootstrap_secret(
            response,
            secret_path=secret_path,
            required_uid=required_uid,
            required_gid=required_gid,
            now=now,
        )


def _runtime_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-runtime-root-action-release")
    subparsers = parser.add_subparsers(dest="command", required=True)
    describe = subparsers.add_parser("describe")
    describe.add_argument("--release-dir", type=Path, required=True)
    describe.add_argument("--source-commit", required=True)
    for name in ("run", "bootstrap-create"):
        command = subparsers.add_parser(name)
        command.add_argument("--release-dir", type=Path, required=True)
        command.add_argument("--descriptor", type=Path, required=True)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--descriptor-sha256", required=True)
        command.add_argument("--launcher-sha256", required=True)
    return parser


def _require_root() -> None:
    if os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0:
        raise StandaloneReleaseError("standalone broker control requires root")


def _require_isolated_interpreter() -> None:
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
    ):
        raise StandaloneReleaseError(
            "standalone launcher requires Python -I -B -S"
        )


def main(argv: list[str] | None = None) -> int:
    args = _runtime_parser().parse_args(argv)
    try:
        if args.command == "describe":
            _require_root()
            _require_isolated_interpreter()
            descriptor = describe_release(args.release_dir, args.source_commit)
            sys.stdout.buffer.write(descriptor.canonical_bytes())
            return 0
        _require_root()
        _require_isolated_interpreter()
        descriptor = validate_runtime_release(
            release_dir=args.release_dir,
            descriptor_path=args.descriptor,
            expected_source_commit=args.source_commit,
            expected_descriptor_sha256=args.descriptor_sha256,
            launcher_path=Path(__file__),
            expected_launcher_sha256=args.launcher_sha256,
        )
        if args.command == "run":
            exec_broker(descriptor, args.release_dir)
        receipt = create_auth_bootstrap(descriptor, args.release_dir)
        sys.stdout.buffer.write(_canonical_json(receipt))
        return 0
    except StandaloneReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
