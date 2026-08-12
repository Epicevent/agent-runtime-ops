from dataclasses import asdict, dataclass
import errno as errno_codes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import select
import signal
import stat
import subprocess
import time
from typing import Iterable

from .nas_views import (
    corpus_for_share,
    get_view_record,
    load_views_state,
    path_alias,
    requested_and_effective_granted_paths,
    slot_entry,
)
from .runtime_truth import find_gateway_container_by_binding
from ..host.mounts import is_readonly_mount, mountinfo_under
from ..paths import DEFAULT_STATE_ROOT
from ..profiles import load_profile
from ..routing import RuntimeBinding, get_runtime_binding
from ..state import load_runtime_target


RAW_SCHEMA = "agent-runtime-groupware-runtime-observation/v2"
DESIRED_DOMAIN = b"agent-runtime-groupware-runtime-desired/v2\x00"
CONTAINER_IDENTITY_DOMAIN = b"agent-runtime-container-identity/v2\x00"
MAX_DECLARED_PATHS = 32
MAX_DIRECTORY_ENTRIES = 64
MAX_PROBE_ENTRIES = 256
MAX_PROBE_DEPTH = 2
PROBE_TIMEOUT_SECONDS = 15.0
HOST_MOUNT_NAMESPACE_PID = 1
_INSPECT_TEMPLATE = '{{.State.Pid}}\n{{.State.Running}}\n{{index .Config.Labels "agent-runtime.profile"}}'

HEALTHY = "HEALTHY"
MOUNT_MISSING = "MOUNT_MISSING"
SOURCE_MISMATCH = "SOURCE_MISMATCH"
ACCESS_DENIED = "ACCESS_DENIED"
EMPTY_READABLE = "EMPTY_READABLE"
OBSERVER_CONTRACT_MISMATCH = "OBSERVER_CONTRACT_MISMATCH"
PATH_CARDINALITY_MISMATCH = "PATH_CARDINALITY_MISMATCH"


class GroupwareRuntimeObservationError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ServicePrincipal:
    host_pid: int
    uid: int
    gid: int
    groups: tuple[int, ...]
    identity_digest: str


@dataclass(frozen=True)
class DeclaredPathProbe:
    index: int
    host_mount_present: bool | None
    host_mount_source_match: bool | None
    host_mount_readonly: bool | None
    container_mount_present: bool | None
    container_mount_source_match: bool | None
    container_mount_readonly: bool | None
    list_ok: bool | None
    open_read_ok: bool | None
    errno: int | None
    representative: str

    def mount_failure_class(self) -> str | None:
        present = (self.host_mount_present, self.container_mount_present)
        if any(value is None for value in present):
            return OBSERVER_CONTRACT_MISMATCH
        if not all(present):
            return MOUNT_MISSING
        sources = (
            self.host_mount_source_match,
            self.container_mount_source_match,
        )
        if any(value is None for value in sources):
            return OBSERVER_CONTRACT_MISMATCH
        if not all(sources):
            return SOURCE_MISMATCH
        readonly = (self.host_mount_readonly, self.container_mount_readonly)
        if any(value is not True for value in readonly):
            return OBSERVER_CONTRACT_MISMATCH
        return None

    def bounded_probe_outcome(self) -> str:
        if self.list_ok is True and self.open_read_ok is True:
            return HEALTHY
        if self.errno in {errno_codes.EACCES, errno_codes.EPERM}:
            return ACCESS_DENIED
        if (
            self.list_ok is True
            and self.open_read_ok is False
            and self.errno is None
            and self.representative == "no_regular_file_within_bound"
        ):
            return EMPTY_READABLE
        return OBSERVER_CONTRACT_MISMATCH

    def failure_class(self) -> str:
        return self.mount_failure_class() or self.bounded_probe_outcome()


@dataclass(frozen=True)
class RuntimeObservation:
    slot: str
    runtime_profile_digest: str
    requested_path_count: int | None
    effective_path_count: int | None
    desired_digest: str
    container_identity_digest: str
    status: str
    reason_code: str
    principal: ServicePrincipal | None
    probes: tuple[DeclaredPathProbe, ...]

    def raw_bytes(self) -> bytes:
        principal = self.principal
        return _canonical_json(
            {
                "schema": RAW_SCHEMA,
                "slot": self.slot,
                "corpus": "groupware",
                "runtime_profile_digest": self.runtime_profile_digest,
                "requested_path_count": self.requested_path_count,
                "effective_path_count": self.effective_path_count,
                "desired_digest": self.desired_digest,
                "container_identity_digest": self.container_identity_digest,
                "status": self.status,
                "reason_code": self.reason_code,
                "writes": 0,
                "principal": None
                if principal is None
                else {
                    "identity_digest": principal.identity_digest,
                    "uid": principal.uid,
                    "gid": principal.gid,
                    "supplementary_group_count": len(principal.groups),
                    "supplementary_groups_digest": _digest(list(principal.groups)),
                },
                "declared_paths": [asdict(item) for item in self.probes],
            }
        )

    def public_facts(self) -> tuple[tuple[str, str], ...]:
        principal = self.principal

        def public_count(value: int | None) -> str:
            return (
                str(value)
                if isinstance(value, int) and not isinstance(value, bool)
                else "unavailable"
            )

        def count(field: str) -> str:
            return str(sum(getattr(item, field) is True for item in self.probes))

        def class_count(value: str) -> str:
            return str(sum(item.failure_class() == value for item in self.probes))

        def probe_count(value: str) -> str:
            return str(
                sum(item.bounded_probe_outcome() == value for item in self.probes)
            )

        return (
            ("observation_schema", RAW_SCHEMA),
            ("status", self.status),
            ("slot", self.slot),
            ("corpus", "groupware"),
            ("runtime_profile_digest", self.runtime_profile_digest),
            ("requested_path_count", public_count(self.requested_path_count)),
            ("effective_path_count", public_count(self.effective_path_count)),
            ("desired_digest", self.desired_digest),
            ("container_identity_digest", self.container_identity_digest),
            ("reason_code", self.reason_code),
            # v1 compatibility: a declared probe row represented an effective
            # path, not every requested path.
            ("declared_path_count", str(len(self.probes))),
            ("host_mount_present_count", count("host_mount_present")),
            ("host_mount_source_match_count", count("host_mount_source_match")),
            ("host_mount_readonly_count", count("host_mount_readonly")),
            (
                "host_mount_verified_count",
                str(
                    sum(
                        item.host_mount_present is True
                        and item.host_mount_source_match is True
                        and item.host_mount_readonly is True
                        for item in self.probes
                    )
                ),
            ),
            ("container_mount_present_count", count("container_mount_present")),
            (
                "container_mount_source_match_count",
                count("container_mount_source_match"),
            ),
            ("container_mount_readonly_count", count("container_mount_readonly")),
            (
                "container_mount_verified_count",
                str(
                    sum(
                        item.container_mount_present is True
                        and item.container_mount_source_match is True
                        and item.container_mount_readonly is True
                        for item in self.probes
                    )
                ),
            ),
            ("failure_class", self.failure_class()),
            ("mount_missing_count", class_count(MOUNT_MISSING)),
            ("source_mismatch_count", class_count(SOURCE_MISMATCH)),
            ("access_denied_count", class_count(ACCESS_DENIED)),
            ("empty_readable_count", class_count(EMPTY_READABLE)),
            (
                "observer_contract_mismatch_count",
                class_count(OBSERVER_CONTRACT_MISMATCH),
            ),
            ("bounded_probe_open_read_count", probe_count(HEALTHY)),
            ("bounded_probe_access_denied_count", probe_count(ACCESS_DENIED)),
            ("bounded_probe_empty_readable_count", probe_count(EMPTY_READABLE)),
            (
                "bounded_probe_contract_mismatch_count",
                probe_count(OBSERVER_CONTRACT_MISMATCH),
            ),
            ("principal_resolved", str(principal is not None).lower()),
            ("principal_uid", str(principal.uid) if principal else "unavailable"),
            ("principal_gid", str(principal.gid) if principal else "unavailable"),
            (
                "principal_supplementary_group_count",
                str(len(principal.groups)) if principal else "unavailable",
            ),
            ("list_verified_count", count("list_ok")),
            ("open_read_verified_count", count("open_read_ok")),
            ("writes", "0"),
        )

    def failure_class(self) -> str:
        if (
            self.requested_path_count is not None
            and self.effective_path_count is not None
            and self.requested_path_count != self.effective_path_count
        ):
            return PATH_CARDINALITY_MISMATCH
        return _aggregate_failure_class(self.probes)


@dataclass(frozen=True)
class ResolvedRuntime:
    binding: RuntimeBinding
    container: str
    container_pid: int
    runtime_profile: str
    runtime_profile_digest: str
    container_nas_root: str
    host_nas_root: str
    requested_paths: tuple[str, ...]
    effective_paths: tuple[str, ...]
    aliases: tuple[str, ...]
    expected_sources: tuple[str, ...]
    desired_digest: str
    container_identity_digest: str


@dataclass(frozen=True)
class GroupwareDesiredContract:
    binding: RuntimeBinding
    runtime_profile: str
    runtime_profile_digest: str
    container_nas_root: str
    host_nas_root: str
    requested_paths: tuple[str, ...]
    effective_paths: tuple[str, ...]
    aliases: tuple[str, ...]
    expected_sources: tuple[str, ...]
    desired_digest: str


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(value: object, domain: bytes = b"") -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical_json(value)).hexdigest()


def _aggregate_failure_class(probes: tuple[DeclaredPathProbe, ...]) -> str:
    if not probes:
        return OBSERVER_CONTRACT_MISMATCH
    failures = {item.failure_class() for item in probes} - {HEALTHY}
    if not failures:
        return HEALTHY
    if len(failures) == 1:
        return next(iter(failures))
    return OBSERVER_CONTRACT_MISMATCH


def _container_path(root: str, alias: str) -> str:
    base = PurePosixPath(root)
    if not base.is_absolute() or base == PurePosixPath("/"):
        raise GroupwareRuntimeObservationError("container_nas_root_invalid")
    return (base / "groupware" / alias).as_posix()


def _container_state(container: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", _INSPECT_TEMPLATE, container],
            stdin=subprocess.DEVNULL, text=True, capture_output=True,
            timeout=10, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise GroupwareRuntimeObservationError("container_inspect_unavailable") from exc
    values = proc.stdout.splitlines()
    if proc.returncode or len(proc.stdout.encode()) > 4096 or len(values) != 3:
        raise GroupwareRuntimeObservationError("container_inspect_unavailable")
    try:
        pid = int(values[0])
    except ValueError as exc:
        raise GroupwareRuntimeObservationError("container_state_invalid") from exc
    if values[1] != "true" or pid <= 0 or not values[2]:
        raise GroupwareRuntimeObservationError("container_not_running")
    return pid, values[2]


def _read_proc(pid: int, name: str, *, binary: bool = False):
    path = Path("/proc") / str(pid) / name
    try:
        return path.read_bytes() if binary else path.read_text(encoding="utf-8")
    except OSError:
        return b"" if binary else ""


def _matches_service(family: str, argv: tuple[str, ...]) -> bool:
    if not argv or Path(argv[0]).name != "node":
        return False
    if family == "hermes":
        return any(Path(item).name == "server-entry.js" for item in argv[1:])
    return family == "openclaw" and len(argv) > 2 and argv[1].endswith("dist/index.js") and argv[2] == "gateway" and any(
        argv[i : i + 2] == ("--port", "18789") for i in range(3, len(argv) - 1)
    )


def _service_principal(runtime: ResolvedRuntime) -> ServicePrincipal:
    candidates: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        cgroup = _read_proc(pid, "cgroup")
        raw = _read_proc(pid, "cmdline", binary=True)
        try:
            argv = tuple(item.decode() for item in raw.split(b"\0") if item)
        except UnicodeDecodeError:
            continue
        if len(runtime.container) >= 12 and runtime.container in cgroup and _matches_service(runtime.binding.family, argv):
            candidates.append(pid)
    if len(candidates) != 1:
        reason = "service_process_not_unique" if candidates else "service_process_not_found"
        raise GroupwareRuntimeObservationError(reason)
    pid = candidates[0]
    try:
        if os.stat(f"/proc/{pid}/ns/mnt").st_ino != os.stat(f"/proc/{runtime.container_pid}/ns/mnt").st_ino:
            raise GroupwareRuntimeObservationError("service_mount_namespace_mismatch")
        fields = {
            key: raw.split()
            for line in _read_proc(pid, "status").splitlines()
            for key, separator, raw in (line.partition(":"),)
            if separator and key in {"Uid", "Gid", "Groups"}
        }
        uid, gid = int(fields["Uid"][1]), int(fields["Gid"][1])
        groups = tuple(sorted({int(item) for item in fields.get("Groups", [])}))
    except (OSError, KeyError, IndexError, ValueError) as exc:
        raise GroupwareRuntimeObservationError("service_status_unavailable") from exc
    identity = _digest({"uid": uid, "gid": gid, "groups": list(groups)}, b"agent-runtime-service-principal/v1\x00")
    return ServicePrincipal(pid, uid, gid, groups, identity)


def _bounded_read(root_fd: int) -> tuple[bool, bool, int | None, str]:
    seen = 0

    def walk(fd: int, depth: int) -> tuple[bool, bool, int | None, str]:
        nonlocal seen
        try:
            with os.scandir(fd) as iterator:
                entries = []
                for entry in iterator:
                    seen += 1
                    if seen > MAX_PROBE_ENTRIES:
                        return True, False, None, "search_bound_reached"
                    entries.append(entry)
                    if len(entries) >= MAX_DIRECTORY_ENTRIES:
                        break
        except OSError as exc:
            return False, False, exc.errno, "scan_failed"
        for entry in entries:
            try:
                if not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    continue
                file_fd = os.open(entry.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                try:
                    os.read(file_fd, 1)
                finally:
                    os.close(file_fd)
                return True, True, None, "regular_file"
            except OSError as exc:
                return True, False, exc.errno, "open_failed"
        if depth < MAX_PROBE_DEPTH:
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                except OSError:
                    continue
                try:
                    result = walk(child_fd, depth + 1)
                finally:
                    os.close(child_fd)
                if result[1] or result[3] not in {"no_regular_file_within_bound", "search_bound_reached"}:
                    return result
        return True, False, None, "no_regular_file_within_bound"

    return walk(root_fd, 0)


def _unknown_rows(count: int, reason: str) -> list[dict[str, object]]:
    return [
        {"index": i, "list_ok": None, "open_read_ok": None, "errno": None, "representative": reason}
        for i in range(count)
    ]


def _assume_service_principal(principal: ServicePrincipal) -> None:
    os.setgroups(list(principal.groups))
    os.setgid(principal.gid)
    os.setuid(principal.uid)


def _probe_namespace(container_pid: int, principal: ServicePrincipal, paths: tuple[str, ...]) -> tuple[dict[str, object], ...]:
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - exercised through the parent contract
        os.close(read_fd)
        try:
            ns_fd = os.open(f"/proc/{container_pid}/ns/mnt", os.O_RDONLY)
            root_fd = os.open(f"/proc/{container_pid}/root", os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.setns(ns_fd, 0)
                os.fchdir(root_fd)
                os.chroot(".")
                os.chdir("/")
            finally:
                os.close(ns_fd)
                os.close(root_fd)
            _assume_service_principal(principal)
            rows = []
            for index, path in enumerate(paths):
                try:
                    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        listed, opened, error, representative = _bounded_read(directory_fd)
                    finally:
                        os.close(directory_fd)
                    rows.append({"index": index, "list_ok": listed, "open_read_ok": opened, "errno": error, "representative": representative})
                except OSError as exc:
                    rows.append({"index": index, "list_ok": False, "open_read_ok": False, "errno": exc.errno, "representative": "directory_open_failed"})
        except BaseException:
            rows = _unknown_rows(len(paths), "namespace_probe_failed")
        with os.fdopen(write_fd, "wb") as stream:
            stream.write(_canonical_json(rows))
        os._exit(0)
    os.close(write_fd)
    chunks: list[bytes] = []
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            os.close(read_fd)
            return tuple(_unknown_rows(len(paths), "namespace_probe_timeout"))
        readable, _, _ = select.select([read_fd], [], [], remaining)
        if not readable:
            continue
        chunk = os.read(read_fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
        if sum(map(len, chunks)) > 65536:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            os.close(read_fd)
            raise GroupwareRuntimeObservationError("namespace_probe_output_too_large")
    os.close(read_fd)
    os.waitpid(child, 0)
    try:
        rows = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GroupwareRuntimeObservationError("namespace_probe_output_invalid") from exc
    if not isinstance(rows, list) or len(rows) != len(paths):
        raise GroupwareRuntimeObservationError("namespace_probe_cardinality_mismatch")
    return tuple(rows)


def _groupware_desired_contract(
    binding: RuntimeBinding,
    state_root: Path,
    container_nas_root: str,
    runtime_profile: str,
    runtime_profile_digest: str,
) -> GroupwareDesiredContract:
    if binding.upstream_kind != "managed-rootful":
        raise GroupwareRuntimeObservationError("rootless_runtime_unsupported")
    record = get_view_record(load_views_state(state_root), binding.linux_account, "groupware")
    if not isinstance(record, dict):
        raise GroupwareRuntimeObservationError("groupware_view_not_declared")
    try:
        share = str(record.get("share") or "").rstrip("/")
        corpus = corpus_for_share(share)
        requested_paths, effective_paths = requested_and_effective_granted_paths(record)
        requested = tuple(requested_paths)
        effective = tuple(effective_paths)
        aliases = tuple(path_alias(item) for item in effective)
        expected_sources = tuple(
            f"{share}[/{PurePosixPath(item).as_posix().lstrip('/')}]"
            for item in effective
        )
    except ValueError as exc:
        raise GroupwareRuntimeObservationError("groupware_view_invalid") from exc
    if (
        corpus.name != "groupware"
        or not requested
        or len(requested) > MAX_DECLARED_PATHS
        or len(effective) > MAX_DECLARED_PATHS
    ):
        raise GroupwareRuntimeObservationError("groupware_view_invalid")
    if len(set(aliases)) != len(aliases):
        raise GroupwareRuntimeObservationError("groupware_alias_collision")
    host_root = slot_entry(binding.linux_account, corpus.name).as_posix()
    for alias in aliases:
        _container_path(container_nas_root, alias)
    desired = {
        "slot": binding.linux_account,
        "instance_id": binding.instance_id,
        "corpus": "groupware",
        "runtime_profile": runtime_profile,
        "runtime_profile_digest": runtime_profile_digest,
        "container_nas_root": container_nas_root,
        "host_nas_root": host_root,
        "requested_paths": sorted(requested),
        "effective_paths": sorted(effective),
        "aliases": sorted(aliases),
        "expected_sources": sorted(expected_sources),
    }
    return GroupwareDesiredContract(
        binding,
        runtime_profile,
        runtime_profile_digest,
        container_nas_root,
        host_root,
        requested,
        effective,
        aliases,
        expected_sources,
        _digest(desired, DESIRED_DOMAIN),
    )


def groupware_runtime_desired_contract(
    slot: str,
    state_root: Path,
    container_nas_root: str,
    runtime_profile: str,
    runtime_profile_digest: str,
) -> GroupwareDesiredContract:
    """Build the digest-bound observer contract without probing runtime state."""
    return _groupware_desired_contract(
        get_runtime_binding(slot, Path(state_root)),
        Path(state_root),
        container_nas_root,
        runtime_profile,
        runtime_profile_digest,
    )


def _resolve_runtime(slot: str, state_root: Path) -> ResolvedRuntime:
    target = load_runtime_target(slot, state_root)
    binding = target.route
    container, lookup = find_gateway_container_by_binding(binding)
    if not container or lookup != "instance_label":
        raise GroupwareRuntimeObservationError("container_identity_unverified")
    container_pid, profile_name = _container_state(container)
    if profile_name != target.runtime_profile:
        raise GroupwareRuntimeObservationError("container_profile_mismatch")
    profile = load_profile(profile_name)
    if not target.runtime_profile_digest:
        raise GroupwareRuntimeObservationError("runtime_profile_digest_missing")
    if profile.digest != target.runtime_profile_digest:
        raise GroupwareRuntimeObservationError("runtime_profile_digest_mismatch")
    if (
        profile.metadata.get("family") != binding.family
        or profile.metadata.get("slot_class") != binding.runtime_class
    ):
        raise GroupwareRuntimeObservationError("container_profile_mismatch")
    contract = _groupware_desired_contract(
        binding,
        state_root,
        str(profile.metadata.get("container_nas_root") or ""),
        profile.name,
        profile.digest,
    )
    return ResolvedRuntime(
        binding,
        container,
        container_pid,
        contract.runtime_profile,
        contract.runtime_profile_digest,
        contract.container_nas_root,
        contract.host_nas_root,
        contract.requested_paths,
        contract.effective_paths,
        contract.aliases,
        contract.expected_sources,
        contract.desired_digest,
        _digest(
            {
                "instance_id": binding.instance_id,
                "container": container,
                "runtime_profile": contract.runtime_profile,
                "runtime_profile_digest": contract.runtime_profile_digest,
            },
            CONTAINER_IDENTITY_DOMAIN,
        ),
    )


def _mount(
    rows: Iterable[dict[str, str]], target: str, expected_source: str
) -> tuple[bool | None, bool | None, bool | None]:
    matched = [row for row in rows if row.get("target") == target]
    if not matched:
        return False, None, None
    if len(matched) != 1 or matched[0].get("fstype") != "cifs":
        return None, None, None
    row = matched[0]
    return True, row.get("source") == expected_source, is_readonly_mount(row)


def observe_groupware_runtime(slot: str, state_root: Path = DEFAULT_STATE_ROOT) -> RuntimeObservation:
    runtime = _resolve_runtime(slot, Path(state_root))
    principal = _service_principal(runtime)
    host_root = runtime.host_nas_root.rstrip("/")
    container_root = f"{runtime.container_nas_root.rstrip('/')}/groupware"
    # ProtectHome=yes isolates the standalone broker's own /home view. Read
    # the host mount namespace through the existing bounded mountinfo parser
    # instead of weakening the unit sandbox or accepting a caller path.
    host_rc, _, host_rows = mountinfo_under(HOST_MOUNT_NAMESPACE_PID, host_root)
    container_rc, _, container_rows = mountinfo_under(runtime.container_pid, container_root)
    destinations = tuple(_container_path(runtime.container_nas_root, alias) for alias in runtime.aliases)
    results = _probe_namespace(runtime.container_pid, principal, destinations)
    probes = []
    for index, (alias, target, expected_source, result) in enumerate(
        zip(runtime.aliases, destinations, runtime.expected_sources, results)
    ):
        host_mount = (
            _mount(host_rows, f"{host_root}/{alias}", expected_source)
            if host_rc == 0
            else (None, None, None)
        )
        container_mount = (
            _mount(container_rows, target, expected_source)
            if container_rc == 0
            else (None, None, None)
        )
        probes.append(
            DeclaredPathProbe(
                index,
                *host_mount,
                *container_mount,
                result.get("list_ok") if isinstance(result.get("list_ok"), bool) else None,
                result.get("open_read_ok") if isinstance(result.get("open_read_ok"), bool) else None,
                result.get("errno") if type(result.get("errno")) is int else None,
                str(result.get("representative") or "unobserved"),
            )
        )
    requested_path_count = len(runtime.requested_paths)
    effective_path_count = len(runtime.effective_paths)
    if requested_path_count != effective_path_count:
        failure_class = PATH_CARDINALITY_MISMATCH
    else:
        failure_class = _aggregate_failure_class(tuple(probes))
    if failure_class == HEALTHY:
        status, reason = "healthy", "runtime_observation_healthy"
    elif failure_class in {
        MOUNT_MISSING,
        SOURCE_MISMATCH,
        ACCESS_DENIED,
        PATH_CARDINALITY_MISMATCH,
    }:
        status, reason = "unhealthy", f"runtime_{failure_class.lower()}"
    else:
        status, reason = "unknown", f"runtime_{failure_class.lower()}"
    return RuntimeObservation(
        runtime.binding.linux_account,
        runtime.runtime_profile_digest,
        requested_path_count,
        effective_path_count,
        runtime.desired_digest,
        runtime.container_identity_digest,
        status,
        reason,
        principal,
        tuple(probes),
    )


def unresolved_observation(slot: str, reason: str) -> RuntimeObservation:
    return RuntimeObservation(
        slot,
        "unavailable",
        None,
        None,
        "unavailable",
        "unavailable",
        "unknown",
        reason,
        None,
        (),
    )
