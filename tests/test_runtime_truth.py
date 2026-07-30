from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from agent_runtime_ops.domain import common, runtime_truth


PS_ARGV = [
    "docker",
    "ps",
    "-a",
    "--filter",
    "label=agent-runtime.instance-id=fixture",
    "--format",
    "{{.ID}}",
]


@pytest.mark.parametrize(
    "argv",
    [
        ["docker", "exec", "container", "true"],
        ["docker", "kill", "container"],
        ["docker", "rm", "container"],
        ["docker", "inspect", "bad\ncontainer"],
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        ["sh", "-c", "docker ps"],
    ],
)
def test_readonly_docker_rejects_every_non_ps_or_inspect_argv_before_spawn(
    argv: list[str],
) -> None:
    with (
        patch("agent_runtime_ops.domain.common.subprocess.Popen") as popen,
        pytest.raises(ValueError, match="readonly_docker"),
    ):
        common.run_readonly_docker(argv)
    popen.assert_not_called()


def _substitute_process(script: str):
    real_popen = subprocess.Popen

    def spawn(_command: list[str], **kwargs: object):
        return real_popen([sys.executable, "-c", script], **kwargs)

    return spawn


def test_readonly_docker_times_out_and_returns_without_unbounded_wait() -> None:
    started = time.monotonic()
    with patch(
        "agent_runtime_ops.domain.common.subprocess.Popen",
        side_effect=_substitute_process("import time; time.sleep(30)"),
    ):
        result = common.run_readonly_docker(PS_ARGV, timeout=1)
    assert time.monotonic() - started < 5
    assert result.returncode == 124
    assert result.stdout == ""
    assert result.stderr == "readonly_command_timeout"


def test_readonly_docker_caps_each_stream_before_returning_to_parser() -> None:
    with patch(
        "agent_runtime_ops.domain.common.subprocess.Popen",
        side_effect=_substitute_process(
            "import os; os.write(1, b'x' * 8192); os.write(2, b'y' * 8192)"
        ),
    ):
        result = common.run_readonly_docker(
            PS_ARGV,
            timeout=5,
            maximum_stream_bytes=1024,
        )
    assert result.returncode == 125
    assert result.stdout == ""
    assert result.stderr in {
        "readonly_stdout_exceeds_bound",
        "readonly_stderr_exceeds_bound",
    }


def test_readonly_docker_preserves_bounded_valid_utf8_output() -> None:
    with patch(
        "agent_runtime_ops.domain.common.subprocess.Popen",
        side_effect=_substitute_process("print('container-id')"),
    ):
        result = common.run_readonly_docker(PS_ARGV, timeout=5)
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["container-id"]
    assert result.stderr == ""


def test_live_runtime_truth_uses_only_the_bounded_readonly_runner() -> None:
    assert runtime_truth.run_text is common.run_readonly_docker
    source = Path(runtime_truth.__file__).read_text(encoding="utf-8")
    assert "run_readonly_docker" in source
    assert "subprocess" not in source
    for forbidden in (
        '"exec"',
        '"kill"',
        '"rm"',
        '"restart"',
        '"stop"',
        '"start"',
    ):
        assert forbidden not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group contract")
def test_timeout_uses_a_new_process_session_for_group_cleanup() -> None:
    real_popen = subprocess.Popen
    observed: dict[str, object] = {}

    def spawn(_command: list[str], **kwargs: object):
        observed.update(kwargs)
        return real_popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            **kwargs,
        )

    with patch(
        "agent_runtime_ops.domain.common.subprocess.Popen",
        side_effect=spawn,
    ):
        result = common.run_readonly_docker(PS_ARGV, timeout=1)
    assert result.returncode == 124
    assert observed["start_new_session"] is True
