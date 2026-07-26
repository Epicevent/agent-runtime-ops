from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
from typing import Any, Protocol


ARTIFACT_PROBE_SCHEMA = "agent-runtime-artifact-probe/v1"
KWRAG_IMAGE_BUILDS_ROOT = Path("/srv/kwrag-product/image-builds")
KWRAG_SCOPE = "kwrag-product"
ALLOWED_ARTIFACT_NAMES = (
    "build-metadata.json",
    "service-context-receipt.json",
    "image-build-receipt.json",
)
MAX_MATCHING_DIRECTORIES = 16
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 8 * 1024 * 1024
MAX_DOCKER_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_STDOUT_BYTES = 256 * 1024
DOCKER_TIMEOUT_SECONDS = 8

_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
_DOCKER_LABEL_ALLOWLIST = (
    "io.kwrag.build-input.digest",
    "io.kwrag.index-manifest.digest",
    "io.kwrag.source-archive.digest",
    "org.opencontainers.image.base.digest",
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.source",
    "org.opencontainers.image.version",
)
_CONTEXT_RECEIPT_FIELDS = (
    "schema",
    "source_archive_sha256",
    "source_subdirectory",
    "transform",
    "member_count",
    "context_tar_sha256",
    "context_tar_bytes",
)
_IMAGE_RECEIPT_FIELDS = (
    "schema",
    "version",
    "created_at",
    "source_revision",
    "source_date_epoch",
    "build_input_digest",
    "source_archive_sha256",
    "build_input_receipt_sha256",
    "index_manifest_digest",
    "build_context_receipt_sha256",
    "platform",
    "candidate_tag",
    "build_metadata_image_name",
    "image_id",
    "image_manifest_digest",
    "image_config_digest",
    "image_descriptor_present",
    "image_descriptor_digest",
    "image_descriptor_policy",
    "image_created",
    "image_size_bytes",
    "no_cache",
    "pull_requested",
    "image_attestation_requested",
    "image_attestation_persisted",
    "image_attestation_unavailable_reason",
    "provenance_metadata_level",
    "provenance_metadata_present",
    "sbom_requested",
    "image_pushed",
    "candidate_executed",
    "image_rebuilt_during_finalization",
    "build_metadata_sha256",
    "build_metadata_bytes",
    "build_metadata_mtime_ns",
    "build_context_receipt_bytes",
    "build_context_receipt_mtime_ns",
)


class ArtifactProbeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class DockerCommandRunner(Protocol):
    def __call__(
        self, argv: list[str], *, timeout: int, output_limit: int
    ) -> CommandResult: ...


class Syscalls(Protocol):
    def open(
        self, path: str | Path, flags: int, *, dir_fd: int | None = None
    ) -> int: ...

    def close(self, fd: int) -> None: ...

    def fstat(self, fd: int) -> os.stat_result: ...

    def stat(
        self, path: str, *, dir_fd: int, follow_symlinks: bool
    ) -> os.stat_result: ...

    def listdir(self, fd: int) -> list[str]: ...

    def read(self, fd: int, size: int) -> bytes: ...


class OsSyscalls:
    def open(self, path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
        if dir_fd is None:
            return os.open(path, flags)
        return os.open(path, flags, dir_fd=dir_fd)

    def close(self, fd: int) -> None:
        os.close(fd)

    def fstat(self, fd: int) -> os.stat_result:
        return os.fstat(fd)

    def stat(self, path: str, *, dir_fd: int, follow_symlinks: bool) -> os.stat_result:
        return os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def listdir(self, fd: int) -> list[str]:
        return os.listdir(fd)

    def read(self, fd: int, size: int) -> bytes:
        return os.read(fd, size)


def validate_revision(value: str) -> str:
    if not _REVISION_RE.fullmatch(value):
        raise ArtifactProbeError("invalid_revision")
    return value


def _directory_patterns(revision: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
    escaped = re.escape(revision)
    return (
        re.compile(rf"^\.staging-kwrag-product-{escaped}-\d{{8}}T\d{{6}}Z$"),
        re.compile(rf"^kwrag-product-{escaped}$"),
    )


def _candidate_tag(revision: str) -> str:
    return f"kwrag-product:candidate-{revision[:8]}"


def _directory_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= int(getattr(os, name, 0))
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_CLOEXEC"):
        flags |= int(getattr(os, name, 0))
    return flags


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _public_identity(value: os.stat_result) -> dict[str, object]:
    return {
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
    }


def _open_directory(
    syscalls: Syscalls,
    name_or_path: str | Path,
    *,
    parent_fd: int | None = None,
) -> tuple[int, os.stat_result]:
    fd: int | None = None
    try:
        if parent_fd is None:
            fd = syscalls.open(name_or_path, _directory_flags())
            opened = syscalls.fstat(fd)
        else:
            name = str(name_or_path)
            before = syscalls.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ArtifactProbeError("matching_directory_symlink")
            if not stat.S_ISDIR(before.st_mode):
                raise ArtifactProbeError("matching_entry_not_directory")
            fd = syscalls.open(name, _directory_flags(), dir_fd=parent_fd)
            opened = syscalls.fstat(fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ArtifactProbeError("directory_toctou")
    except ArtifactProbeError:
        if fd is not None:
            syscalls.close(fd)
        raise
    except OSError as exc:
        if fd is not None:
            syscalls.close(fd)
        raise ArtifactProbeError("directory_open_failed") from exc
    if not stat.S_ISDIR(opened.st_mode):
        assert fd is not None
        syscalls.close(fd)
        raise ArtifactProbeError("path_not_directory")
    assert fd is not None
    return fd, opened


def _read_regular_json_file(
    syscalls: Syscalls,
    parent_fd: int,
    name: str,
    *,
    remaining_bytes: int,
) -> tuple[dict[str, object], int, dict[str, Any]]:
    try:
        before_path = syscalls.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ArtifactProbeError("artifact_stat_failed") from exc
    if stat.S_ISLNK(before_path.st_mode):
        raise ArtifactProbeError("artifact_symlink")
    if not stat.S_ISREG(before_path.st_mode):
        raise ArtifactProbeError("artifact_not_regular")
    if before_path.st_nlink != 1:
        raise ArtifactProbeError("artifact_hardlink")
    if before_path.st_size > MAX_FILE_BYTES or before_path.st_size > remaining_bytes:
        raise ArtifactProbeError("artifact_size_limit")

    try:
        fd = syscalls.open(name, _file_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise ArtifactProbeError("artifact_open_failed") from exc
    try:
        before = syscalls.fstat(fd)
        if (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino):
            raise ArtifactProbeError("artifact_toctou")
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactProbeError("artifact_not_regular")
        if before.st_nlink != 1:
            raise ArtifactProbeError("artifact_hardlink")
        if before.st_size > MAX_FILE_BYTES or before.st_size > remaining_bytes:
            raise ArtifactProbeError("artifact_size_limit")

        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = syscalls.read(fd, min(64 * 1024, MAX_FILE_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAX_FILE_BYTES or observed > remaining_bytes:
                raise ArtifactProbeError("artifact_size_limit")
        data = b"".join(chunks)
        after = syscalls.fstat(fd)
        if _identity(before) != _identity(after) or len(data) != before.st_size:
            raise ArtifactProbeError("artifact_toctou")
    finally:
        syscalls.close(fd)

    parsed = _strict_json_object(data)
    observation = {
        "present": True,
        **_public_identity(before),
        "size": len(data),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "jsonParseStatus": "ok",
    }
    return observation, len(data), parsed


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactProbeError("json_duplicate_key")
        result[key] = value
    return result


def _strict_json_object(data: bytes) -> dict[str, Any]:
    def reject_constant(_: str) -> None:
        raise ArtifactProbeError("json_nonfinite_number")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except ArtifactProbeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ArtifactProbeError("json_parse_failed") from exc
    if not isinstance(value, dict):
        raise ArtifactProbeError("json_top_level_not_object")
    return value


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _selected_field(payload: dict[str, Any], key: str) -> dict[str, object]:
    if key not in payload:
        return {"present": False, "type": "missing"}
    value = payload[key]
    result: dict[str, object] = {"present": True, "type": _json_type(value)}
    if isinstance(value, float) and not math.isfinite(value):
        raise ArtifactProbeError("json_nonfinite_number")
    if value is None or isinstance(value, (bool, int, float)):
        result["value"] = value
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 4096:
            raise ArtifactProbeError("selected_json_value_too_large")
        result["value"] = value
    return result


def _selected_object_keys(payload: dict[str, Any], key: str) -> dict[str, object]:
    result = _selected_field(payload, key)
    value = payload.get(key)
    if isinstance(value, dict):
        result["keys"] = sorted(value)
    return result


def _project_artifact(name: str, parsed: dict[str, Any]) -> dict[str, object]:
    if name == "build-metadata.json":
        return {
            "topLevelKeys": sorted(parsed),
            "fields": {
                key: _selected_field(parsed, key)
                for key in (
                    "containerimage.digest",
                    "containerimage.config.digest",
                    "image.name",
                )
            },
            "descriptor": _selected_object_keys(parsed, "containerimage.descriptor"),
            "provenance": _selected_object_keys(parsed, "buildx.build.provenance"),
        }
    allowlist = (
        _CONTEXT_RECEIPT_FIELDS
        if name == "service-context-receipt.json"
        else _IMAGE_RECEIPT_FIELDS
    )
    return {"fields": {key: _selected_field(parsed, key) for key in allowlist}}


def _default_docker_runner(
    argv: list[str], *, timeout: int, output_limit: int
) -> CommandResult:
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise ArtifactProbeError("docker_exec_failed") from exc

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()

    def drain(name: str, stream: Any) -> None:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            buffers[name].extend(chunk)
            if len(buffers[name]) > output_limit:
                overflow.set()
                proc.kill()
                return

    threads = [
        threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        for thread in threads:
            thread.join(timeout=1)
        raise ArtifactProbeError("docker_timeout") from exc
    for thread in threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in threads):
        proc.kill()
        raise ArtifactProbeError("docker_output_drain_failed")
    if overflow.is_set():
        raise ArtifactProbeError("docker_output_limit")
    return CommandResult(returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))


def _checked_docker_run(runner: DockerCommandRunner, argv: list[str]) -> CommandResult:
    result = runner(
        argv, timeout=DOCKER_TIMEOUT_SECONDS, output_limit=MAX_DOCKER_OUTPUT_BYTES
    )
    if (
        len(result.stdout) > MAX_DOCKER_OUTPUT_BYTES
        or len(result.stderr) > MAX_DOCKER_OUTPUT_BYTES
    ):
        raise ArtifactProbeError("docker_output_limit")
    return result


def _docker_observation(
    candidate: str, runner: DockerCommandRunner
) -> dict[str, object]:
    inspect_result = _checked_docker_run(
        runner,
        ["docker", "image", "inspect", candidate],
    )
    image_observation: dict[str, object]
    if inspect_result.returncode != 0:
        image_observation = {
            "exists": None,
            "inspectStatus": "command_nonzero",
            "inspectExitCode": inspect_result.returncode,
        }
    else:
        try:
            images = json.loads(inspect_result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactProbeError("docker_inspect_parse_failed") from exc
        if not isinstance(images, list):
            raise ArtifactProbeError("docker_inspect_shape")
        if len(images) > 1:
            raise ArtifactProbeError("docker_inspect_multiple_matches")
        if not images:
            image_observation = {"exists": False, "inspectStatus": "empty"}
        elif not isinstance(images[0], dict):
            raise ArtifactProbeError("docker_inspect_shape")
        else:
            image = images[0]
            repo_tags = image.get("RepoTags")
            repo_digests = image.get("RepoDigests")
            config = image.get("Config")
            rootfs = image.get("RootFS")
            if repo_tags is not None and not isinstance(repo_tags, list):
                raise ArtifactProbeError("docker_inspect_shape")
            if repo_digests is not None and not isinstance(repo_digests, list):
                raise ArtifactProbeError("docker_inspect_shape")
            if config is not None and not isinstance(config, dict):
                raise ArtifactProbeError("docker_inspect_shape")
            if rootfs is not None and not isinstance(rootfs, dict):
                raise ArtifactProbeError("docker_inspect_shape")
            layers = (rootfs or {}).get("Layers") or []
            if not isinstance(layers, list) or any(
                not isinstance(item, str) or len(item.encode("utf-8")) > 256
                for item in layers
            ):
                raise ArtifactProbeError("docker_inspect_shape")
            labels = (config or {}).get("Labels") or {}
            if not isinstance(labels, dict):
                raise ArtifactProbeError("docker_inspect_shape")
            selected_labels: dict[str, str] = {}
            for key in _DOCKER_LABEL_ALLOWLIST:
                value = labels.get(key)
                if value is None:
                    continue
                if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
                    raise ArtifactProbeError("docker_label_shape")
                selected_labels[key] = value
            image_observation = {
                "exists": True,
                "inspectStatus": "ok",
                "id": image.get("Id") if isinstance(image.get("Id"), str) else None,
                "os": image.get("Os") if isinstance(image.get("Os"), str) else None,
                "architecture": (
                    image.get("Architecture")
                    if isinstance(image.get("Architecture"), str)
                    else None
                ),
                "derivedTagPresent": candidate in (repo_tags or []),
                "repoDigestCount": len(repo_digests or []),
                "created": image.get("Created")
                if isinstance(image.get("Created"), str)
                else None,
                "size": image.get("Size")
                if isinstance(image.get("Size"), int)
                else None,
                "rootfsLayerCount": len(layers),
                "rootfsDiffIds": layers,
                "labels": selected_labels,
            }

    ancestor_result = _checked_docker_run(
        runner,
        [
            "docker",
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"ancestor={candidate}",
            "--format",
            "{{.ID}}",
        ],
    )
    if ancestor_result.returncode != 0:
        raise ArtifactProbeError("docker_ancestor_query_failed")
    try:
        ancestor_lines = [
            line.strip()
            for line in ancestor_result.stdout.decode("ascii").splitlines()
            if line.strip()
        ]
    except UnicodeDecodeError as exc:
        raise ArtifactProbeError("docker_ancestor_output_invalid") from exc
    if any(not _CONTAINER_ID_RE.fullmatch(line) for line in ancestor_lines):
        raise ArtifactProbeError("docker_ancestor_output_invalid")
    if len(set(ancestor_lines)) != len(ancestor_lines):
        raise ArtifactProbeError("docker_ancestor_output_invalid")
    return {
        "localReadOnly": True,
        "image": image_observation,
        "ancestorContainerCount": len(ancestor_lines),
    }


def probe_kwrag_product_artifact(
    revision: str,
    *,
    build_root: Path = KWRAG_IMAGE_BUILDS_ROOT,
    syscalls: Syscalls | None = None,
    docker_runner: DockerCommandRunner = _default_docker_runner,
    observed_at: str | None = None,
) -> dict[str, object]:
    validate_revision(revision)
    syscalls = syscalls or OsSyscalls()
    candidate = _candidate_tag(revision)
    root_fd, root_stat = _open_directory(syscalls, build_root)
    try:
        try:
            root_entries = syscalls.listdir(root_fd)
        except OSError as exc:
            raise ArtifactProbeError("directory_list_failed") from exc
        patterns = _directory_patterns(revision)
        matching = sorted(
            name
            for name in root_entries
            if any(pattern.fullmatch(name) for pattern in patterns)
        )
        if len(matching) > MAX_MATCHING_DIRECTORIES:
            raise ArtifactProbeError("matching_directory_limit")

        total_bytes = 0
        directories: list[dict[str, object]] = []
        for name in matching:
            child_fd, child_stat = _open_directory(syscalls, name, parent_fd=root_fd)
            try:
                try:
                    child_entries = syscalls.listdir(child_fd)
                except OSError as exc:
                    raise ArtifactProbeError("artifact_directory_list_failed") from exc
                child_entry_set = set(child_entries)
                artifacts: list[dict[str, object]] = []
                for artifact_name in ALLOWED_ARTIFACT_NAMES:
                    if artifact_name not in child_entry_set:
                        artifacts.append({"name": artifact_name, "present": False})
                        continue
                    observation, consumed, parsed = _read_regular_json_file(
                        syscalls,
                        child_fd,
                        artifact_name,
                        remaining_bytes=MAX_TOTAL_FILE_BYTES - total_bytes,
                    )
                    total_bytes += consumed
                    observation["name"] = artifact_name
                    observation["selectedJson"] = _project_artifact(
                        artifact_name, parsed
                    )
                    artifacts.append(observation)
                directories.append(
                    {
                        "name": name,
                        "kind": "staging" if name.startswith(".staging-") else "final",
                        "identity": _public_identity(child_stat),
                        "unrelatedEntryCount": len(
                            child_entry_set - set(ALLOWED_ARTIFACT_NAMES)
                        ),
                        "artifacts": artifacts,
                    }
                )
            finally:
                syscalls.close(child_fd)
    finally:
        syscalls.close(root_fd)

    payload = {
        "schema": ARTIFACT_PROBE_SCHEMA,
        "observedAt": observed_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": KWRAG_SCOPE,
        "revision": revision,
        "derived": {
            "imageBuildsRoot": str(build_root),
            "candidateTag": candidate,
        },
        "directoryObservation": {
            "rootIdentity": _public_identity(root_stat),
            "matchingCount": len(matching),
            "unrelatedEntryCount": len(root_entries) - len(matching),
            "directories": directories,
        },
        "dockerObservation": _docker_observation(candidate, docker_runner),
        "writes": 0,
    }
    serialize_probe_payload(payload)
    return payload


def serialize_probe_payload(payload: dict[str, object]) -> str:
    text = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    )
    if len(text.encode("utf-8")) > MAX_STDOUT_BYTES:
        raise ArtifactProbeError("stdout_size_limit")
    return text


def error_payload(*, revision: str, code: str) -> dict[str, object]:
    return {
        "schema": ARTIFACT_PROBE_SCHEMA,
        "scope": KWRAG_SCOPE,
        "revision": revision,
        "error": {"code": code},
        "writes": 0,
    }
