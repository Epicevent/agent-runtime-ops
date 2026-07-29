from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from agent_runtime_ops.domain.retrieval_contract import canonical_digest
from agent_runtime_ops.domain.retrieval_resources import (
    _fixed_host_headroom,
    measure_retrieval_promotion_headroom,
)


def resource_envelope(*, gpu_access: str = "none") -> dict[str, object]:
    value: dict[str, object] = {
        "cpuReservationMillicores": 500,
        "gpuAccess": gpu_access,
        "memoryReservationBytes": 512 * 1024 * 1024,
        "pidsReservation": 64,
    }
    value["profileDigest"] = canonical_digest(value)
    return value


def image_spec(*, gpu_access: str = "none") -> dict[str, object]:
    return {
        "retrieval_enabled": True,
        "retrieval_contract": {"resource": resource_envelope(gpu_access=gpu_access)},
    }


def completed(
    stdout: str = '{"CPUPerc":"12.5%","MemUsage":"128MiB / 512MiB","PIDs":"12"}\n',
    *,
    returncode: int = 0,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["docker", "stats"], returncode, stdout, stderr)


def host_headroom() -> dict[str, int]:
    return {
        "cpu_available_millicores": 4000,
        "memory_available_bytes": 8 * 1024 * 1024 * 1024,
        "pids_available": 1000,
    }


def test_direct_observation_accepts_usage_and_host_headroom() -> None:
    commands: list[tuple[list[str], int]] = []

    def runner(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        commands.append((command, timeout))
        return completed()

    observation = measure_retrieval_promotion_headroom(
        "openclaw-oc3-gateway-1",
        image_spec(),
        runner=runner,
        host_observer=host_headroom,
    )

    assert commands == [
        (
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                "openclaw-oc3-gateway-1",
            ],
            15,
        )
    ]
    assert observation == {
        "containerCpuUsedMillicores": 125,
        "containerMemoryUsedBytes": 128 * 1024 * 1024,
        "containerPidsUsed": 12,
        "hostCpuAvailableMillicores": 4000,
        "hostMemoryAvailableBytes": 8 * 1024 * 1024 * 1024,
        "hostPidsAvailable": 1000,
        "observationDigest": observation["observationDigest"],
        "profileDigest": resource_envelope()["profileDigest"],
        "requiredCpuMillicores": 500,
        "requiredMemoryBytes": 512 * 1024 * 1024,
        "requiredPids": 64,
        "schema": "agent-runtime-retrieval-headroom/v1",
        "status": "within_required_headroom",
    }
    unsigned = dict(observation)
    digest = unsigned.pop("observationDigest")
    assert digest == canonical_digest(unsigned)


def test_fixed_host_observer_uses_bounded_proc_cpu_delta() -> None:
    stat_values = iter(
        [
            "cpu  100 0 100 700 100 0 0 0\n",
            "cpu  115 0 115 760 110 0 0 0\n",
        ]
    )

    def read_text(path: object) -> str:
        name = str(path).replace("\\", "/")
        if name.endswith("/proc/stat"):
            return next(stat_values)
        if name.endswith("/proc/meminfo"):
            return "MemAvailable:       4096 kB\n"
        if name.endswith("/proc/loadavg"):
            return "0.00 0.00 0.00 2/100 1\n"
        if name.endswith("/proc/sys/kernel/pid_max"):
            return "1000\n"
        if name.endswith("/proc/sys/kernel/threads-max"):
            return "800\n"
        if name.endswith("/proc/4321/cgroup"):
            return "0::/system.slice/agent.service\n"
        raise AssertionError(name)

    def read_optional_text(path: object) -> str | None:
        name = str(path).replace("\\", "/")
        if name.endswith("/system.slice/pids.max"):
            return "600\n"
        if name.endswith("/system.slice/pids.current"):
            return "50\n"
        if name.endswith("/pids.max"):
            return "max\n"
        if name.endswith("/pids.current"):
            return "200\n"
        raise AssertionError(name)

    inspect_commands: list[tuple[list[str], int]] = []

    def inspect_runner(
        command: list[str], *, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        inspect_commands.append((command, timeout))
        return completed("4321\n")

    with (
        patch("agent_runtime_ops.domain.retrieval_resources._read_ascii", side_effect=read_text),
        patch(
            "agent_runtime_ops.domain.retrieval_resources._read_optional_ascii",
            side_effect=read_optional_text,
        ),
        patch("agent_runtime_ops.domain.retrieval_resources.time.sleep") as sleeper,
        patch("agent_runtime_ops.domain.retrieval_resources.os.cpu_count", return_value=4),
    ):
        observed = _fixed_host_headroom("container-1", runner=inspect_runner)

    sleeper.assert_called_once_with(0.1)
    assert inspect_commands == [
        (
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Pid}}",
                "container-1",
            ],
            10,
        )
    ]
    assert observed == {
        "cpu_available_millicores": 2800,
        "memory_available_bytes": 4096 * 1024,
        "pids_available": 550,
    }


@pytest.mark.parametrize(
    ("stdout", "message"),
    [
        (
            '{"CPUPerc":"50.1%","MemUsage":"128MiB / 512MiB","PIDs":"12"}\n',
            "container CPU usage exceeds retrieval reservation",
        ),
        (
            '{"CPUPerc":"1%","MemUsage":"513MiB / 1GiB","PIDs":"12"}\n',
            "container memory usage exceeds retrieval reservation",
        ),
        (
            '{"CPUPerc":"1%","MemUsage":"1MiB / 512MiB","PIDs":"65"}\n',
            "container PID usage exceeds retrieval reservation",
        ),
    ],
)
def test_container_usage_above_declared_reservation_fails_closed(
    stdout: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        measure_retrieval_promotion_headroom(
            "container-1",
            image_spec(),
            runner=lambda *args, **kwargs: completed(stdout),
            host_observer=host_headroom,
        )


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("cpu_available_millicores", 499, "host CPU headroom"),
        ("memory_available_bytes", 512 * 1024 * 1024 - 1, "host memory headroom"),
        ("pids_available", 63, "host PID headroom"),
    ],
)
def test_host_capacity_below_one_target_reservation_fails_closed(
    key: str, value: int, message: str
) -> None:
    host = host_headroom()
    host[key] = value
    with pytest.raises(ValueError, match=message):
        measure_retrieval_promotion_headroom(
            "container-1",
            image_spec(),
            runner=lambda *args, **kwargs: completed(),
            host_observer=lambda: host,
        )


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (completed(returncode=1, stderr="denied"), "observation failed"),
        (completed("not-json\n"), "observation is invalid"),
        (completed("{}\n{}\n"), "must contain one row"),
        (completed("x" * (64 * 1024 + 1)), "observation is too large"),
    ],
)
def test_docker_stats_failure_shape_and_output_bounds_fail_closed(
    result: subprocess.CompletedProcess[str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        measure_retrieval_promotion_headroom(
            "container-1",
            image_spec(),
            runner=lambda *args, **kwargs: result,
            host_observer=host_headroom,
        )


def test_timeout_and_unmeasured_gpu_headroom_fail_closed() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        measure_retrieval_promotion_headroom(
            "container-1",
            image_spec(),
            runner=lambda *args, **kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired("docker", 15)
            ),
            host_observer=host_headroom,
        )
    with pytest.raises(ValueError, match="direct GPU headroom observer"):
        measure_retrieval_promotion_headroom(
            "container-1",
            image_spec(gpu_access="shared_stateless"),
            runner=lambda *args, **kwargs: completed(),
            host_observer=host_headroom,
        )


def test_tampered_profile_digest_and_disabled_intent_fail_closed() -> None:
    tampered = image_spec()
    contract = tampered["retrieval_contract"]
    assert isinstance(contract, dict)
    resource = contract["resource"]
    assert isinstance(resource, dict)
    resource["memoryReservationBytes"] = 1
    with pytest.raises(ValueError, match="does not match its canonical fields"):
        measure_retrieval_promotion_headroom(
            "container-1",
            tampered,
            runner=lambda *args, **kwargs: completed(),
            host_observer=host_headroom,
        )

    disabled = image_spec()
    disabled["retrieval_enabled"] = False
    with pytest.raises(ValueError, match="only defined for enabled intent"):
        measure_retrieval_promotion_headroom(
            "container-1",
            disabled,
            runner=lambda *args, **kwargs: completed(),
            host_observer=host_headroom,
        )
