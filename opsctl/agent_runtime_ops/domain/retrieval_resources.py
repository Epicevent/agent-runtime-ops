from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_CEILING
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time
from typing import Callable

from .common import run_text
from .retrieval_contract import canonical_digest


_MEMORY_VALUE = re.compile(
    r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>B|kB|MB|GB|KiB|MiB|GiB)$"
)
_CPU_PERCENT = re.compile(r"^(?P<value>\d+(?:\.\d+)?)%$")
_MAX_DOCKER_STATS_BYTES = 64 * 1024
_MEMORY_UNITS = {
    "B": 1,
    "kB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
}
_RESOURCE_KEYS = {
    "cpuReservationMillicores",
    "gpuAccess",
    "memoryReservationBytes",
    "pidsReservation",
    "profileDigest",
}


def _decimal_ceiling(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _parse_memory_usage(value: object) -> int:
    current = str(value or "").split("/", 1)[0].strip()
    match = _MEMORY_VALUE.fullmatch(current)
    if match is None:
        raise ValueError("retrieval container memory usage is invalid")
    try:
        amount = Decimal(match.group("value"))
    except InvalidOperation as exc:
        raise ValueError("retrieval container memory usage is invalid") from exc
    return _decimal_ceiling(amount * _MEMORY_UNITS[match.group("unit")])


def _parse_cpu_usage(value: object) -> int:
    match = _CPU_PERCENT.fullmatch(str(value or "").strip())
    if match is None:
        raise ValueError("retrieval container CPU usage is invalid")
    try:
        percent = Decimal(match.group("value"))
    except InvalidOperation as exc:
        raise ValueError("retrieval container CPU usage is invalid") from exc
    # Docker's 100% is one full logical CPU, i.e. 1000 millicores.
    return _decimal_ceiling(percent * 10)


def _parse_pids_usage(value: object) -> int:
    text = str(value or "").strip()
    if re.fullmatch(r"\d+", text) is None:
        raise ValueError("retrieval container PID usage is invalid")
    return int(text)


def _container_usage(
    container: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = run_text,
) -> dict[str, int]:
    result = runner(
        [
            "docker",
            "stats",
            "--no-stream",
            "--format",
            "{{json .}}",
            container,
        ],
        timeout=15,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError(
            "retrieval container resource observation failed"
            + (f": {detail[:512]}" if detail else "")
        )
    stdout = (result.stdout or "").encode("utf-8")
    if len(stdout) > _MAX_DOCKER_STATS_BYTES:
        raise ValueError("retrieval container resource observation is too large")
    lines = [line for line in stdout.decode("utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(
            "retrieval container resource observation must contain one row"
        )
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("retrieval container resource observation is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("retrieval container resource observation must be an object")
    return {
        "cpu_used_millicores": _parse_cpu_usage(value.get("CPUPerc")),
        "memory_used_bytes": _parse_memory_usage(value.get("MemUsage")),
        "pids_used": _parse_pids_usage(value.get("PIDs")),
    }


def _cpu_counters(raw: str) -> tuple[int, int]:
    first_line = raw.splitlines()[0] if raw.splitlines() else ""
    parts = first_line.split()
    if len(parts) < 9 or parts[0] != "cpu" or any(
        re.fullmatch(r"\d+", item) is None for item in parts[1:9]
    ):
        raise ValueError("host CPU counter observation is invalid")
    values = [int(item) for item in parts[1:9]]
    total = sum(values)
    idle = values[3] + values[4]
    return total, idle


def _read_ascii(path: Path) -> str:
    return path.read_text(encoding="ascii")


def _read_optional_ascii(path: Path) -> str | None:
    try:
        return _read_ascii(path)
    except FileNotFoundError:
        return None


def _cgroup_pid_location(raw: str) -> tuple[Path, tuple[str, ...]]:
    for line in raw.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            raise ValueError("host cgroup PID observation is invalid")
        hierarchy, controllers, relative_raw = parts
        controller_set = set(controllers.split(",")) if controllers else set()
        if (hierarchy == "0" and not controller_set) or "pids" in controller_set:
            relative = PurePosixPath(relative_raw)
            if not relative.is_absolute() or any(
                part in {"", ".", ".."} for part in relative.parts[1:]
            ):
                raise ValueError("host cgroup PID path is invalid")
            root = (
                Path("/sys/fs/cgroup")
                if hierarchy == "0" and not controller_set
                else Path("/sys/fs/cgroup/pids")
            )
            return root, tuple(relative.parts[1:])
    raise ValueError("host cgroup PID controller is unavailable")


def _cgroup_pid_availability(raw: str, *, skip_leaf: bool = False) -> int:
    root, relative_parts = _cgroup_pid_location(raw)
    current = root.joinpath(*relative_parts)
    if skip_leaf and current != root:
        current = current.parent
    observed = False
    available_limits: list[int] = []
    while True:
        maximum_raw = _read_optional_ascii(current / "pids.max")
        usage_raw = _read_optional_ascii(current / "pids.current")
        if (maximum_raw is None) != (usage_raw is None):
            raise ValueError("host cgroup PID observation is incomplete")
        if maximum_raw is not None and usage_raw is not None:
            observed = True
            maximum = maximum_raw.strip()
            usage = usage_raw.strip()
            if re.fullmatch(r"\d+", usage) is None:
                raise ValueError("host cgroup PID usage is invalid")
            if maximum != "max":
                if re.fullmatch(r"\d+", maximum) is None:
                    raise ValueError("host cgroup PID limit is invalid")
                available_limits.append(max(0, int(maximum) - int(usage)))
        if current == root:
            break
        if root not in current.parents:
            raise ValueError("host cgroup PID path escaped its fixed root")
        current = current.parent
    if not observed:
        raise ValueError("host cgroup PID observation is unavailable")
    return min(available_limits) if available_limits else 2**63 - 1


def _container_pid(
    container: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = run_text,
) -> int:
    result = runner(
        ["docker", "inspect", "--format", "{{.State.Pid}}", container],
        timeout=10,
    )
    if result.returncode != 0:
        raise ValueError("retrieval container PID observation failed")
    raw = (result.stdout or "").strip()
    if len(raw) > 32 or re.fullmatch(r"[1-9]\d*", raw) is None:
        raise ValueError("retrieval container PID observation is invalid")
    return int(raw)


def _fixed_host_headroom(
    container: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = run_text,
) -> dict[str, int]:
    meminfo_path = Path("/proc/meminfo")
    loadavg_path = Path("/proc/loadavg")
    pid_max_path = Path("/proc/sys/kernel/pid_max")
    threads_max_path = Path("/proc/sys/kernel/threads-max")
    container_pid = _container_pid(container, runner=runner)
    cgroup_path = Path("/proc") / str(container_pid) / "cgroup"
    stat_path = Path("/proc/stat")
    stat_before = _read_ascii(stat_path)
    time.sleep(0.1)
    stat_after = _read_ascii(stat_path)
    meminfo = _read_ascii(meminfo_path)
    loadavg = _read_ascii(loadavg_path).strip()
    pid_max_text = _read_ascii(pid_max_path).strip()
    threads_max_text = _read_ascii(threads_max_path).strip()
    cgroup_text = _read_ascii(cgroup_path)
    if (
        len(stat_before) > 64 * 1024
        or len(stat_after) > 64 * 1024
        or len(meminfo) > 64 * 1024
        or len(loadavg) > 1024
        or len(pid_max_text) > 64
        or len(threads_max_text) > 64
        or len(cgroup_text) > 64 * 1024
    ):
        raise ValueError("host resource observation exceeds fixed bounds")
    available_match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", meminfo, re.MULTILINE)
    load_parts = loadavg.split()
    if available_match is None or len(load_parts) < 4:
        raise ValueError("host resource observation is incomplete")
    task_match = re.fullmatch(r"\d+/(\d+)", load_parts[3])
    if (
        task_match is None
        or re.fullmatch(r"\d+", pid_max_text) is None
        or re.fullmatch(r"\d+", threads_max_text) is None
    ):
        raise ValueError("host PID observation is invalid")
    cpu_count = os.cpu_count()
    if not isinstance(cpu_count, int) or cpu_count < 1:
        raise ValueError("host CPU capacity is unavailable")
    total_millicores = cpu_count * 1000
    total_before, idle_before = _cpu_counters(stat_before)
    total_after, idle_after = _cpu_counters(stat_after)
    total_delta = total_after - total_before
    idle_delta = idle_after - idle_before
    if total_delta < 1 or not 0 <= idle_delta <= total_delta:
        raise ValueError("host CPU counter delta is invalid")
    available_millicores = (total_millicores * idle_delta) // total_delta
    pid_max = int(pid_max_text)
    threads_max = int(threads_max_text)
    tasks = int(task_match.group(1))
    cgroup_pid_available = _cgroup_pid_availability(cgroup_text, skip_leaf=True)
    return {
        "cpu_available_millicores": available_millicores,
        "memory_available_bytes": int(available_match.group(1)) * 1024,
        "pids_available": min(
            max(0, pid_max - tasks),
            max(0, threads_max - tasks),
            cgroup_pid_available,
        ),
    }


def _resource_envelope(image_spec: dict[str, object]) -> dict[str, object]:
    contract = image_spec.get("retrieval_contract")
    resource = contract.get("resource") if isinstance(contract, dict) else None
    if not isinstance(resource, dict) or set(resource) != _RESOURCE_KEYS:
        raise ValueError("retrieval resource envelope is unavailable")
    for key in (
        "cpuReservationMillicores",
        "memoryReservationBytes",
        "pidsReservation",
    ):
        value = resource.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"retrieval resource {key} is invalid")
    if resource.get("gpuAccess") != "none":
        raise ValueError(
            "enabled retrieval promotion requires a direct GPU headroom observer"
        )
    profile_digest = resource.get("profileDigest")
    if (
        not isinstance(profile_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", profile_digest) is None
    ):
        raise ValueError("retrieval resource profileDigest is invalid")
    digest_payload = {
        key: resource[key] for key in _RESOURCE_KEYS if key != "profileDigest"
    }
    if canonical_digest(digest_payload) != profile_digest:
        raise ValueError(
            "retrieval resource profileDigest does not match its canonical fields"
        )
    return resource


def measure_retrieval_promotion_headroom(
    container: str,
    image_spec: dict[str, object],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = run_text,
    host_observer: Callable[[], dict[str, int]] | None = None,
) -> dict[str, object]:
    """Fail closed unless source usage and one target reservation fit now.

    This is an instantaneous promotion gate, not a capacity guarantee. Promotion
    re-runs it before every target so later host pressure stops further mutation.
    """

    if image_spec.get("retrieval_enabled") is not True:
        raise ValueError("retrieval headroom is only defined for enabled intent")
    resource = _resource_envelope(image_spec)
    container_usage = _container_usage(container, runner=runner)
    host = (
        host_observer()
        if host_observer is not None
        else _fixed_host_headroom(container, runner=runner)
    )
    required = {
        "cpu_required_millicores": int(resource["cpuReservationMillicores"]),
        "memory_required_bytes": int(resource["memoryReservationBytes"]),
        "pids_required": int(resource["pidsReservation"]),
    }
    for key in (
        "cpu_available_millicores",
        "memory_available_bytes",
        "pids_available",
    ):
        value = host.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"host resource observation {key} is invalid")
    comparisons = (
        (
            container_usage["cpu_used_millicores"],
            required["cpu_required_millicores"],
            "container CPU usage exceeds retrieval reservation",
        ),
        (
            container_usage["memory_used_bytes"],
            required["memory_required_bytes"],
            "container memory usage exceeds retrieval reservation",
        ),
        (
            container_usage["pids_used"],
            required["pids_required"],
            "container PID usage exceeds retrieval reservation",
        ),
    )
    for used, limit, message in comparisons:
        if used > limit:
            raise ValueError(message)
    headroom_checks = (
        (
            int(host["cpu_available_millicores"]),
            required["cpu_required_millicores"],
            "host CPU headroom is below retrieval reservation",
        ),
        (
            int(host["memory_available_bytes"]),
            required["memory_required_bytes"],
            "host memory headroom is below retrieval reservation",
        ),
        (
            int(host["pids_available"]),
            required["pids_required"],
            "host PID headroom is below retrieval reservation",
        ),
    )
    for available, needed, message in headroom_checks:
        if available < needed:
            raise ValueError(message)
    observation: dict[str, object] = {
        "containerCpuUsedMillicores": container_usage["cpu_used_millicores"],
        "containerMemoryUsedBytes": container_usage["memory_used_bytes"],
        "containerPidsUsed": container_usage["pids_used"],
        "hostCpuAvailableMillicores": host["cpu_available_millicores"],
        "hostMemoryAvailableBytes": host["memory_available_bytes"],
        "hostPidsAvailable": host["pids_available"],
        "profileDigest": resource["profileDigest"],
        "requiredCpuMillicores": required["cpu_required_millicores"],
        "requiredMemoryBytes": required["memory_required_bytes"],
        "requiredPids": required["pids_required"],
        "schema": "agent-runtime-retrieval-headroom/v1",
        "status": "within_required_headroom",
    }
    observation["observationDigest"] = canonical_digest(observation)
    return observation
