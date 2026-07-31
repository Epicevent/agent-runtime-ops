"""Pinned standalone release boundary for the root-action broker.

This module is deliberately stdlib-only until a complete standalone release has
been validated. A root-owned copy is installed outside the release that it
checks, then execs the pinned broker.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
from typing import Any, Callable, Iterable


RELEASE_DESCRIPTOR_SCHEMA = "agent-runtime-root-action-standalone-release/v1"
BUNDLE_MANIFEST_SCHEMA = "agent-runtime-root-action-standalone-bundle/v1"
TREE_DIGEST_DOMAIN = b"agent-runtime-root-action-standalone-tree/v1\x00"
MAX_TREE_ENTRIES = 50_000
MAX_TREE_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 16 * 1024
MAX_GIT_BLOB_BYTES = 16 * 1024 * 1024
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_PACKAGE_ROOT_RE = re.compile(
    r"\.runtime/lib/python3\.[0-9]+/site-packages/agent_runtime_ops"
)
_SYSTEMD_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]+")
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

_SOURCE_PREFIX = "opsctl/agent_runtime_ops"
_DEPENDENCY_LOCK_PATH = "requirements.lock"
_UNIT_TEMPLATE_PATH = (
    "systemd/agent-runtime-root-action-broker-standalone.service"
)
_BUNDLE_RELEASE = "release"
_BUNDLE_CONTROL = "control"
_BUNDLE_DESCRIPTOR = "descriptor.json"
_BUNDLE_LAUNCHER = "release.py"
_BUNDLE_LOCK = "requirements.lock"
_BUNDLE_UNIT = "agent-runtime-root-action-broker-standalone.service"
_BUNDLE_MANIFEST = "bundle.json"
_UNIT_PLACEHOLDERS = frozenset(
    {
        "@@BROKER_RELEASE_DIR@@",
        "@@BROKER_DESCRIPTOR@@",
        "@@BROKER_LAUNCHER@@",
        "@@SOURCE_COMMIT@@",
        "@@DESCRIPTOR_SHA256@@",
        "@@LAUNCHER_SHA256@@",
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


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_exact(
    path: Path,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    os.mkdir(path, 0o755)
    os.chown(path, required_uid, required_gid)
    os.chmod(path, 0o755)
    _fsync_directory(path.parent)


def _write_exact(
    path: Path,
    raw: bytes,
    *,
    mode: int,
    required_uid: int,
    required_gid: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchown(descriptor, required_uid, required_gid)
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise StandaloneReleaseError(f"file write made no progress: {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _checked_command(
    argv: list[str],
    *,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] | None,
    environment: dict[str, str] | None = None,
    maximum_output: int = MAX_GIT_BLOB_BYTES,
) -> bytes:
    if run_command is None:
        result = _run_bounded_process(
            argv,
            environment=environment,
            maximum_output=maximum_output,
        )
    else:
        result = run_command(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=300,
        )
    stdout = bytes(result.stdout or b"")
    stderr = bytes(result.stderr or b"")
    if result.returncode != 0:
        raise StandaloneReleaseError(
            f"bounded build command failed: {Path(argv[0]).name} rc={result.returncode}"
        )
    if len(stdout) > maximum_output or len(stderr) > maximum_output:
        raise StandaloneReleaseError("bounded build command output exceeded its limit")
    return stdout


def _run_bounded_process(
    argv: list[str],
    *,
    environment: dict[str, str] | None,
    maximum_output: int,
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        raise StandaloneReleaseError("bounded build command could not start") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    overflow = threading.Event()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}

    def read_stream(name: str, stream) -> None:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            buffers[name].extend(chunk)
            if len(buffers[name]) > maximum_output:
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                return

    threads = [
        threading.Thread(
            target=read_stream,
            args=("stdout", process.stdout),
            daemon=True,
        ),
        threading.Thread(
            target=read_stream,
            args=("stderr", process.stderr),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=300)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise StandaloneReleaseError("bounded build command timed out") from exc
    finally:
        for thread in threads:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    if overflow.is_set():
        raise StandaloneReleaseError("bounded build command output exceeded its limit")
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
    )


def _git_blob(
    source_repo: Path,
    source_commit: str,
    relative: str,
    *,
    git_executable: Path,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] | None,
) -> bytes:
    relative = _safe_relative_path(relative)
    return _checked_command(
        [
            str(git_executable),
            "--no-replace-objects",
            "-c",
            f"safe.directory={source_repo}",
            "-C",
            str(source_repo),
            "show",
            f"{source_commit}:{relative}",
        ],
        run_command=run_command,
        environment=_git_environment(source_repo),
    )


def _git_environment(source_repo: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_VALUE_0": str(source_repo),
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _require_git_commit_object(
    source_repo: Path,
    source_commit: str,
    *,
    git_executable: Path,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] | None,
) -> None:
    object_kind = _checked_command(
        [
            str(git_executable),
            "--no-replace-objects",
            "-c",
            f"safe.directory={source_repo}",
            "-C",
            str(source_repo),
            "cat-file",
            "-t",
            source_commit,
        ],
        run_command=run_command,
        environment=_git_environment(source_repo),
        maximum_output=128,
    )
    if object_kind != b"commit\n":
        raise StandaloneReleaseError("source object is not an exact Git commit")


def _source_file_map() -> tuple[tuple[str, str], ...]:
    files = [
        (f"{_SOURCE_PREFIX}/__init__.py", "agent_runtime_ops/__init__.py"),
        (
            f"{_SOURCE_PREFIX}/domain/__init__.py",
            "agent_runtime_ops/domain/__init__.py",
        ),
        (
            f"{_SOURCE_PREFIX}/domain/artifact_probe.py",
            "agent_runtime_ops/domain/artifact_probe.py",
        ),
    ]
    files.extend(
        (
            f"{_SOURCE_PREFIX}/root_actions/{name}",
            f"agent_runtime_ops/root_actions/{name}",
        )
        for name in sorted(_ROOT_ACTION_FILES)
    )
    return tuple(files)


def _normalize_materialized_tree(
    root: Path,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in sorted(names):
            path = directory_path / name
            value = path.lstat()
            if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
                raise StandaloneReleaseError("materialized dependency tree has an unsafe directory")
            os.chown(path, required_uid, required_gid)
            os.chmod(path, 0o755)
        for name in sorted(files):
            path = directory_path / name
            value = path.lstat()
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise StandaloneReleaseError("materialized dependency tree has an unsafe file")
            if (
                name in _FORBIDDEN_STARTUP_NAMES
                or name.endswith(".pth")
                or name.endswith(".egg-link")
            ):
                raise StandaloneReleaseError("materialized dependency tree has a startup hook")
            os.chown(path, required_uid, required_gid)
            os.chmod(path, 0o644)
    os.chown(root, required_uid, required_gid)
    os.chmod(root, 0o755)


def _copy_runtime_stdlib(
    source: Path,
    target: Path,
    *,
    source_uid: int,
    source_gid: int,
    required_uid: int,
    required_gid: int,
) -> None:
    _validate_controlled_parent_chain(source, required_uid=source_uid)
    _validate_directory(source, required_uid=source_uid, required_gid=source_gid)

    def copy_directory(source_dir: Path, target_dir: Path, *, top: bool = False) -> None:
        _mkdir_exact(
            target_dir,
            required_uid=required_uid,
            required_gid=required_gid,
        )
        try:
            entries = sorted(os.scandir(source_dir), key=lambda entry: entry.name)
        except OSError as exc:
            raise StandaloneReleaseError("runtime stdlib cannot be enumerated") from exc
        for entry in entries:
            if (
                entry.name == "__pycache__"
                or entry.name.endswith(".pyc")
                or (top and entry.name in {"site-packages", "dist-packages"})
            ):
                continue
            if (
                entry.name in _FORBIDDEN_STARTUP_NAMES
                or entry.name.endswith(".pth")
                or entry.name.endswith(".egg-link")
            ):
                raise StandaloneReleaseError("runtime stdlib contains a startup hook")
            source_path = Path(entry.path)
            target_path = target_dir / entry.name
            value = source_path.lstat()
            if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
                if (
                    value.st_uid != source_uid
                    or value.st_gid != source_gid
                    or _mode(value) & 0o022
                ):
                    raise StandaloneReleaseError("runtime stdlib directory is unsafe")
                copy_directory(source_path, target_path)
            elif stat.S_ISREG(value.st_mode):
                raw, _ = _read_regular(
                    source_path,
                    required_uid=source_uid,
                    required_gid=source_gid,
                )
                _write_exact(
                    target_path,
                    raw,
                    mode=0o644,
                    required_uid=required_uid,
                    required_gid=required_gid,
                )
            else:
                raise StandaloneReleaseError("runtime stdlib entry type is unsafe")

    copy_directory(source, target, top=True)


def _fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        directories.append(directory_path)
        for name in sorted(files):
            path = directory_path / name
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                value = os.fstat(descriptor)
                if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                    raise StandaloneReleaseError("bundle fsync encountered an unsafe file")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for name in sorted(names):
            value = (directory_path / name).lstat()
            if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
                raise StandaloneReleaseError("bundle fsync encountered an unsafe directory")
    for directory in reversed(directories):
        _fsync_directory(directory)


def _render_unit(
    template_raw: bytes,
    *,
    release_dir: Path,
    descriptor_path: Path,
    launcher_path: Path,
    source_commit: str,
    descriptor_sha256: str,
    launcher_sha256: str,
) -> bytes:
    try:
        template = template_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StandaloneReleaseError("unit template is not UTF-8") from exc
    if "\r" in template or not template.endswith("\n"):
        raise StandaloneReleaseError("unit template newline contract is invalid")
    replacements = {
        "@@BROKER_RELEASE_DIR@@": str(release_dir),
        "@@BROKER_DESCRIPTOR@@": str(descriptor_path),
        "@@BROKER_LAUNCHER@@": str(launcher_path),
        "@@SOURCE_COMMIT@@": source_commit,
        "@@DESCRIPTOR_SHA256@@": descriptor_sha256,
        "@@LAUNCHER_SHA256@@": launcher_sha256,
    }
    if set(replacements) != _UNIT_PLACEHOLDERS:
        raise StandaloneReleaseError("unit placeholder implementation is incomplete")
    for placeholder in _UNIT_PLACEHOLDERS:
        if template.count(placeholder) < 1:
            raise StandaloneReleaseError(f"unit template is missing {placeholder}")
        template = template.replace(placeholder, replacements[placeholder])
    if "@@" in template:
        raise StandaloneReleaseError("unit template contains an unknown placeholder")
    return template.encode("utf-8")


def _bundle_manifest(
    *,
    bundle_root: Path,
    descriptor: ReleaseDescriptor,
    descriptor_sha256: str,
    launcher_sha256: str,
    lock_sha256: str,
    unit_sha256: str,
) -> dict[str, Any]:
    return {
        "bundle_root": str(bundle_root),
        "dependency_lock_sha256": lock_sha256,
        "descriptor_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_DESCRIPTOR}",
        "descriptor_sha256": descriptor_sha256,
        "launcher_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_LAUNCHER}",
        "launcher_sha256": launcher_sha256,
        "release_relpath": f"{_BUNDLE_RELEASE}/{descriptor.source_commit}",
        "release_tree_sha256": descriptor.tree_digest,
        "schema": BUNDLE_MANIFEST_SCHEMA,
        "source_commit": descriptor.source_commit,
        "unit_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_UNIT}",
        "unit_sha256": unit_sha256,
    }


def _parse_bundle_manifest(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except StandaloneReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StandaloneReleaseError("bundle manifest is not UTF-8 JSON") from exc
    expected = {
        "bundle_root",
        "dependency_lock_sha256",
        "descriptor_relpath",
        "descriptor_sha256",
        "launcher_relpath",
        "launcher_sha256",
        "release_relpath",
        "release_tree_sha256",
        "schema",
        "source_commit",
        "unit_relpath",
        "unit_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != BUNDLE_MANIFEST_SCHEMA
        or raw != _canonical_json(value)
    ):
        raise StandaloneReleaseError("bundle manifest field set is invalid")
    return value


def validate_materialized_bundle(
    *,
    source_repo: Path,
    source_commit: str,
    bundle_root: Path,
    git_executable: Path = Path("/usr/bin/git"),
    required_uid: int = 0,
    required_gid: int = 0,
    git_required_uid: int = 0,
    git_required_gid: int = 0,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> dict[str, Any]:
    source_commit = _validate_commit(source_commit)
    source_repo = _canonical_absolute(source_repo, "source repository")
    bundle_root = _canonical_absolute(bundle_root, "bundle")
    git_executable = _canonical_absolute(git_executable, "Git executable")
    if bundle_root.name != source_commit:
        raise StandaloneReleaseError("bundle path is not commit-pinned")
    if _SYSTEMD_PATH_RE.fullmatch(str(bundle_root)) is None:
        raise StandaloneReleaseError("bundle path is not systemd-safe")
    _validate_controlled_parent_chain(
        git_executable,
        required_uid=git_required_uid,
    )
    _read_regular(
        git_executable,
        required_uid=git_required_uid,
        required_gid=git_required_gid,
        allowed_modes=frozenset({0o755}),
    )
    _validate_controlled_parent_chain(bundle_root, required_uid=required_uid)
    _validate_directory(
        bundle_root,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _require_git_commit_object(
        source_repo,
        source_commit,
        git_executable=git_executable,
        run_command=run_command,
    )
    control = bundle_root / _BUNDLE_CONTROL
    _validate_directory(control, required_uid=required_uid, required_gid=required_gid)
    if _directory_names(bundle_root) != frozenset({_BUNDLE_CONTROL, _BUNDLE_RELEASE}):
        raise StandaloneReleaseError("bundle root contains an unexpected entry")
    release_parent = bundle_root / _BUNDLE_RELEASE
    _validate_directory(
        release_parent,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    if _directory_names(release_parent) != frozenset({source_commit}):
        raise StandaloneReleaseError("bundle release parent is not exact")
    if _directory_names(control) != frozenset(
        {
            _BUNDLE_DESCRIPTOR,
            _BUNDLE_LAUNCHER,
            _BUNDLE_LOCK,
            _BUNDLE_MANIFEST,
            _BUNDLE_UNIT,
        }
    ):
        raise StandaloneReleaseError("bundle control directory is not exact")
    manifest_raw, _ = _read_regular(
        control / _BUNDLE_MANIFEST,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
        maximum=MAX_DESCRIPTOR_BYTES,
    )
    manifest = _parse_bundle_manifest(manifest_raw)
    expected_relpaths = {
        "descriptor_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_DESCRIPTOR}",
        "launcher_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_LAUNCHER}",
        "release_relpath": f"{_BUNDLE_RELEASE}/{source_commit}",
        "unit_relpath": f"{_BUNDLE_CONTROL}/{_BUNDLE_UNIT}",
    }
    if (
        manifest["bundle_root"] != str(bundle_root)
        or manifest["source_commit"] != source_commit
        or any(manifest[key] != value for key, value in expected_relpaths.items())
    ):
        raise StandaloneReleaseError("bundle manifest target binding is invalid")
    for key in (
        "dependency_lock_sha256",
        "descriptor_sha256",
        "launcher_sha256",
        "release_tree_sha256",
        "unit_sha256",
    ):
        _validate_digest(manifest[key], key)
    release_dir = bundle_root / manifest["release_relpath"]
    descriptor_path = bundle_root / manifest["descriptor_relpath"]
    launcher_path = bundle_root / manifest["launcher_relpath"]
    unit_path = bundle_root / manifest["unit_relpath"]
    descriptor = validate_runtime_release(
        release_dir=release_dir,
        descriptor_path=descriptor_path,
        expected_source_commit=source_commit,
        expected_descriptor_sha256=manifest["descriptor_sha256"],
        launcher_path=launcher_path,
        expected_launcher_sha256=manifest["launcher_sha256"],
        required_uid=required_uid,
        required_gid=required_gid,
    )
    if descriptor.tree_digest != manifest["release_tree_sha256"]:
        raise StandaloneReleaseError("bundle release digest is inconsistent")
    launcher_raw, _ = _read_regular(
        launcher_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
    )
    lock_raw, _ = _read_regular(
        control / _BUNDLE_LOCK,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
        maximum=MAX_GIT_BLOB_BYTES,
    )
    unit_raw, _ = _read_regular(
        unit_path,
        required_uid=required_uid,
        required_gid=required_gid,
        allowed_modes=frozenset({0o644}),
        maximum=MAX_GIT_BLOB_BYTES,
    )
    expected_launcher = _git_blob(
        source_repo,
        source_commit,
        f"{_SOURCE_PREFIX}/root_actions/release.py",
        git_executable=git_executable,
        run_command=run_command,
    )
    expected_lock = _git_blob(
        source_repo,
        source_commit,
        _DEPENDENCY_LOCK_PATH,
        git_executable=git_executable,
        run_command=run_command,
    )
    expected_unit = _render_unit(
        _git_blob(
            source_repo,
            source_commit,
            _UNIT_TEMPLATE_PATH,
            git_executable=git_executable,
            run_command=run_command,
        ),
        release_dir=release_dir,
        descriptor_path=descriptor_path,
        launcher_path=launcher_path,
        source_commit=source_commit,
        descriptor_sha256=manifest["descriptor_sha256"],
        launcher_sha256=manifest["launcher_sha256"],
    )
    if (
        launcher_raw != expected_launcher
        or _sha256(lock_raw) != manifest["dependency_lock_sha256"]
        or lock_raw != expected_lock
        or _sha256(unit_raw) != manifest["unit_sha256"]
        or unit_raw != expected_unit
    ):
        raise StandaloneReleaseError("bundle source or rendered unit binding is invalid")
    return manifest


def materialize_bundle(
    *,
    source_repo: Path,
    source_commit: str,
    bundle_root: Path,
    wheelhouse: Path,
    runtime_python: Path,
    git_executable: Path = Path("/usr/bin/git"),
    required_uid: int = 0,
    required_gid: int = 0,
    runtime_required_uid: int = 0,
    runtime_required_gid: int = 0,
    git_required_uid: int = 0,
    git_required_gid: int = 0,
    run_command: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
) -> dict[str, Any]:
    source_commit = _validate_commit(source_commit)
    source_repo = _canonical_absolute(source_repo, "source repository")
    bundle_root = _canonical_absolute(bundle_root, "bundle")
    wheelhouse = _canonical_absolute(wheelhouse, "wheelhouse")
    runtime_python = _canonical_absolute(runtime_python, "runtime Python")
    git_executable = _canonical_absolute(git_executable, "Git executable")
    if bundle_root.name != source_commit:
        raise StandaloneReleaseError("bundle path is not commit-pinned")
    if _SYSTEMD_PATH_RE.fullmatch(str(bundle_root)) is None:
        raise StandaloneReleaseError("bundle path is not systemd-safe")
    _validate_controlled_parent_chain(bundle_root, required_uid=required_uid)
    _validate_directory(
        bundle_root.parent,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _validate_controlled_parent_chain(wheelhouse, required_uid=required_uid)
    _validate_controlled_parent_chain(
        git_executable,
        required_uid=git_required_uid,
    )
    _read_regular(
        git_executable,
        required_uid=git_required_uid,
        required_gid=git_required_gid,
        allowed_modes=frozenset({0o755}),
    )
    if bundle_root.exists() or bundle_root.is_symlink():
        return validate_materialized_bundle(
            source_repo=source_repo,
            source_commit=source_commit,
            bundle_root=bundle_root,
            git_executable=git_executable,
            required_uid=required_uid,
            required_gid=required_gid,
            git_required_uid=git_required_uid,
            git_required_gid=git_required_gid,
            run_command=run_command,
        )
    _validate_directory(
        wheelhouse,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _validate_controlled_parent_chain(
        runtime_python,
        required_uid=runtime_required_uid,
    )
    runtime_raw, _ = _read_regular(
        runtime_python,
        required_uid=runtime_required_uid,
        required_gid=runtime_required_gid,
        allowed_modes=frozenset({0o755}),
    )
    staging = bundle_root.parent / f".{source_commit}.prepare"
    if staging.exists() or staging.is_symlink():
        raise StandaloneReleaseError("standalone bundle staging already exists")

    _require_git_commit_object(
        source_repo,
        source_commit,
        git_executable=git_executable,
        run_command=run_command,
    )
    version_raw = _checked_command(
        [
            str(runtime_python),
            "-I",
            "-B",
            "-S",
            "-c",
            (
                "import json,sys,sysconfig;"
                "print(json.dumps({'stdlib':sysconfig.get_path('stdlib'),"
                "'version':f'{sys.version_info.major}.{sys.version_info.minor}'},"
                "sort_keys=True,separators=(',',':')))"
            ),
        ],
        run_command=run_command,
        environment={"PYTHONDONTWRITEBYTECODE": "1"},
        maximum_output=4096,
    )
    try:
        runtime_value = json.loads(
            version_raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StandaloneReleaseError("runtime Python layout is invalid") from exc
    if (
        not isinstance(runtime_value, dict)
        or set(runtime_value) != {"stdlib", "version"}
        or version_raw != _canonical_json(runtime_value)
        or not isinstance(runtime_value["stdlib"], str)
        or not isinstance(runtime_value["version"], str)
    ):
        raise StandaloneReleaseError("runtime Python layout is not canonical")
    version = runtime_value["version"]
    match = re.fullmatch(r"3\.([0-9]+)", version)
    if match is None or int(match.group(1)) < 11:
        raise StandaloneReleaseError("runtime Python must be version 3.11 or newer")
    stdlib_path = _canonical_absolute(Path(runtime_value["stdlib"]), "runtime stdlib")

    _mkdir_exact(staging, required_uid=required_uid, required_gid=required_gid)
    release_parent = staging / _BUNDLE_RELEASE
    control = staging / _BUNDLE_CONTROL
    _mkdir_exact(release_parent, required_uid=required_uid, required_gid=required_gid)
    _mkdir_exact(control, required_uid=required_uid, required_gid=required_gid)
    release_dir = release_parent / source_commit
    _mkdir_exact(release_dir, required_uid=required_uid, required_gid=required_gid)
    runtime_root = release_dir / ".runtime"
    bin_dir = runtime_root / "bin"
    lib_dir = runtime_root / "lib"
    python_dir = lib_dir / f"python{version}"
    site_packages = python_dir / "site-packages"
    for path in (runtime_root, bin_dir, lib_dir):
        _mkdir_exact(path, required_uid=required_uid, required_gid=required_gid)
    for name in ("python", "python3", f"python{version}"):
        _write_exact(
            bin_dir / name,
            runtime_raw,
            mode=0o755,
            required_uid=required_uid,
            required_gid=required_gid,
        )
    _copy_runtime_stdlib(
        stdlib_path,
        python_dir,
        source_uid=runtime_required_uid,
        source_gid=runtime_required_gid,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _mkdir_exact(
        site_packages,
        required_uid=required_uid,
        required_gid=required_gid,
    )

    lock_raw = _git_blob(
        source_repo,
        source_commit,
        _DEPENDENCY_LOCK_PATH,
        git_executable=git_executable,
        run_command=run_command,
    )
    lock_path = control / _BUNDLE_LOCK
    _write_exact(
        lock_path,
        lock_raw,
        mode=0o644,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _checked_command(
        [
            str(runtime_python),
            "-I",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--no-input",
            "--no-compile",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-index",
            f"--find-links={wheelhouse}",
            "--target",
            str(site_packages),
            "-r",
            str(lock_path),
        ],
        run_command=run_command,
        environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"},
        maximum_output=1024 * 1024,
    )
    _normalize_materialized_tree(
        site_packages,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    package_root = site_packages / "agent_runtime_ops"
    if package_root.exists() or package_root.is_symlink():
        raise StandaloneReleaseError("dependency install supplied first-party code")
    for path in (
        package_root,
        package_root / "domain",
        package_root / "root_actions",
    ):
        _mkdir_exact(path, required_uid=required_uid, required_gid=required_gid)
    for source_relative, target_relative in _source_file_map():
        raw = _git_blob(
            source_repo,
            source_commit,
            source_relative,
            git_executable=git_executable,
            run_command=run_command,
        )
        _write_exact(
            site_packages / target_relative,
            raw,
            mode=0o644,
            required_uid=required_uid,
            required_gid=required_gid,
        )

    descriptor = describe_release(
        release_dir,
        source_commit,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    descriptor_raw = descriptor.canonical_bytes()
    launcher_raw = _git_blob(
        source_repo,
        source_commit,
        f"{_SOURCE_PREFIX}/root_actions/release.py",
        git_executable=git_executable,
        run_command=run_command,
    )
    descriptor_sha256 = _sha256(descriptor_raw)
    launcher_sha256 = _sha256(launcher_raw)
    final_control = bundle_root / _BUNDLE_CONTROL
    final_release = bundle_root / _BUNDLE_RELEASE / source_commit
    unit_raw = _render_unit(
        _git_blob(
            source_repo,
            source_commit,
            _UNIT_TEMPLATE_PATH,
            git_executable=git_executable,
            run_command=run_command,
        ),
        release_dir=final_release,
        descriptor_path=final_control / _BUNDLE_DESCRIPTOR,
        launcher_path=final_control / _BUNDLE_LAUNCHER,
        source_commit=source_commit,
        descriptor_sha256=descriptor_sha256,
        launcher_sha256=launcher_sha256,
    )
    for path, raw in (
        (control / _BUNDLE_DESCRIPTOR, descriptor_raw),
        (control / _BUNDLE_LAUNCHER, launcher_raw),
        (control / _BUNDLE_UNIT, unit_raw),
    ):
        _write_exact(
            path,
            raw,
            mode=0o644,
            required_uid=required_uid,
            required_gid=required_gid,
        )
    manifest = _bundle_manifest(
        bundle_root=bundle_root,
        descriptor=descriptor,
        descriptor_sha256=descriptor_sha256,
        launcher_sha256=launcher_sha256,
        lock_sha256=_sha256(lock_raw),
        unit_sha256=_sha256(unit_raw),
    )
    _write_exact(
        control / _BUNDLE_MANIFEST,
        _canonical_json(manifest),
        mode=0o644,
        required_uid=required_uid,
        required_gid=required_gid,
    )
    _fsync_tree(staging)
    os.replace(staging, bundle_root)
    _fsync_directory(bundle_root.parent)
    return validate_materialized_bundle(
        source_repo=source_repo,
        source_commit=source_commit,
        bundle_root=bundle_root,
        git_executable=git_executable,
        required_uid=required_uid,
        required_gid=required_gid,
        git_required_uid=git_required_uid,
        git_required_gid=git_required_gid,
        run_command=run_command,
    )


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


def _runtime_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-runtime-root-action-release")
    subparsers = parser.add_subparsers(dest="command", required=True)
    describe = subparsers.add_parser("describe")
    describe.add_argument("--release-dir", type=Path, required=True)
    describe.add_argument("--source-commit", required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--source-repo", type=Path, required=True)
    materialize.add_argument("--source-commit", required=True)
    materialize.add_argument("--bundle-root", type=Path, required=True)
    materialize.add_argument("--wheelhouse", type=Path, required=True)
    materialize.add_argument("--runtime-python", type=Path, required=True)
    materialize.add_argument(
        "--git-executable",
        type=Path,
        default=Path("/usr/bin/git"),
    )
    run = subparsers.add_parser("run")
    run.add_argument("--release-dir", type=Path, required=True)
    run.add_argument("--descriptor", type=Path, required=True)
    run.add_argument("--source-commit", required=True)
    run.add_argument("--descriptor-sha256", required=True)
    run.add_argument("--launcher-sha256", required=True)
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
        if args.command == "materialize":
            _require_root()
            _require_isolated_interpreter()
            manifest = materialize_bundle(
                source_repo=args.source_repo,
                source_commit=args.source_commit,
                bundle_root=args.bundle_root,
                wheelhouse=args.wheelhouse,
                runtime_python=args.runtime_python,
                git_executable=args.git_executable,
            )
            sys.stdout.buffer.write(_canonical_json(manifest))
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
        exec_broker(descriptor, args.release_dir)
    except StandaloneReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
