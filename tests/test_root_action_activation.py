from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from agent_runtime_ops.commands.root_action import cmd_root_action_auth_activate
from agent_runtime_ops.root_action_activation import (
    ROOT_ACTION_BROKER_SERVICE,
    RootActionActivationConfig,
    RootActionActivationError,
    activate_root_action_broker,
)


CONFIG = RootActionActivationConfig(
    rp_id="ops.ji-tech.co.kr", origin="https://ops.ji-tech.co.kr"
)


class CommandRecorder:
    def __init__(self, *, fail_at: int | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail_at = fail_at

    def __call__(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        return subprocess.CompletedProcess(
            command,
            1 if self.fail_at == len(self.commands) else 0,
            stdout="4242\n" if command[1] == "show" else "",
            stderr="not exposed",
        )


class DelayedAttestationRecorder:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.round = 0

    def __call__(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        returncode = 0
        stdout = ""
        if command[1] == "is-enabled":
            self.round += 1
        elif command[1] == "is-active" and self.round == 1:
            returncode = 1
        elif command[1] == "show":
            stdout = "0\n" if self.round == 2 else "4242\n"
        return subprocess.CompletedProcess(
            command,
            returncode,
            stdout=stdout,
            stderr="not exposed",
        )


class PersistentPostRestartFailureRecorder(CommandRecorder):
    def __call__(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        return subprocess.CompletedProcess(
            command,
            1 if command[1] == "is-active" else 0,
            stdout="4242\n" if command[1] == "show" else "",
            stderr="not exposed",
        )


def activation_runtime(tmp_path: Path) -> dict[str, object]:
    release = tmp_path / "release-under-test"
    return {
        "expected_release": release,
        "read_running_environment": lambda pid: (
            f"AGENT_RUNTIME_OPS_RELEASE={release}\0MAINPID={pid}\0".encode("utf-8")
        ),
    }


@pytest.mark.parametrize(
    ("rp_id", "origin"),
    [
        ("text.ji-tech.co.kr", "https://ops.ji-tech.co.kr"),
        ("ops.ji-tech.co.kr", "https://ops.ji-tech.co.kr/"),
        ("ops.ji-tech.co.kr", "http://ops.ji-tech.co.kr"),
        ("ops.ji-tech.co.kr", "https://ops.ji-tech.co.kr:443"),
        ("OPS.ji-tech.co.kr", "https://OPS.ji-tech.co.kr"),
    ],
)
def test_activation_config_rejects_cross_origin_and_noncanonical_values(
    rp_id: str, origin: str
) -> None:
    with pytest.raises(RootActionActivationError):
        RootActionActivationConfig(rp_id=rp_id, origin=origin)


def test_activation_creates_root_only_policy_and_runs_exact_systemd_sequence(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    env_path = parent / "root-action-webauthn.env"
    recorder = CommandRecorder()
    result = activate_root_action_broker(
        CONFIG,
        env_path=env_path,
        expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
        enforce_posix_permissions=os.name == "posix",
        run_command=recorder,
        **activation_runtime(tmp_path),
    )
    raw = env_path.read_text(encoding="utf-8")
    assert "ROOT_ACTION_WEBAUTHN_RP_ID=ops.ji-tech.co.kr\n" in raw
    assert "ROOT_ACTION_WEBAUTHN_ORIGINS=https://ops.ji-tech.co.kr\n" in raw
    user_id_line = next(
        line
        for line in raw.splitlines()
        if line.startswith("ROOT_ACTION_WEBAUTHN_USER_ID=")
    )
    assert len(user_id_line.split("=", 1)[1]) == 64
    if os.name == "posix":
        assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    assert result["environment_created"] is True
    assert result["origin"] == "https://ops.ji-tech.co.kr"
    assert result["user_id_fingerprint"].startswith("sha256:")
    assert user_id_line.split("=", 1)[1] not in json.dumps(result)
    assert recorder.commands == [
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "restart", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-enabled", "--quiet", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-active", "--quiet", ROOT_ACTION_BROKER_SERVICE),
        (
            "systemctl",
            "show",
            "--property=MainPID",
            "--value",
            ROOT_ACTION_BROKER_SERVICE,
        ),
    ]
    assert result["restart_performed"] is True
    assert result["running_release"] == str(tmp_path / "release-under-test")


def test_activation_is_idempotent_but_refuses_policy_replacement(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    env_path = parent / "root-action-webauthn.env"
    owner = os.getuid() if hasattr(os, "getuid") else 0
    first = activate_root_action_broker(
        CONFIG,
        env_path=env_path,
        expected_owner_uid=owner,
        enforce_posix_permissions=os.name == "posix",
        run_command=CommandRecorder(),
        **activation_runtime(tmp_path),
    )
    original = env_path.read_bytes()
    second = activate_root_action_broker(
        CONFIG,
        env_path=env_path,
        expected_owner_uid=owner,
        enforce_posix_permissions=os.name == "posix",
        run_command=CommandRecorder(),
        **activation_runtime(tmp_path),
    )
    assert env_path.read_bytes() == original
    assert second["environment_created"] is False
    assert second["user_id_fingerprint"] == first["user_id_fingerprint"]
    with pytest.raises(RootActionActivationError):
        activate_root_action_broker(
            RootActionActivationConfig(
                rp_id="other.ji-tech.co.kr",
                origin="https://other.ji-tech.co.kr",
            ),
            env_path=env_path,
            expected_owner_uid=owner,
            enforce_posix_permissions=os.name == "posix",
            run_command=CommandRecorder(),
            **activation_runtime(tmp_path),
        )


def test_activation_reports_systemd_failure_without_exposing_output(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    env_path = parent / "root-action-webauthn.env"
    with pytest.raises(RootActionActivationError, match="failed closed"):
        activate_root_action_broker(
            CONFIG,
            env_path=env_path,
            expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
            enforce_posix_permissions=os.name == "posix",
            run_command=CommandRecorder(fail_at=2),
            **activation_runtime(tmp_path),
        )
    assert env_path.exists()


def test_activation_retries_only_post_restart_attestation_until_all_facts_match(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    release = tmp_path / "release-under-test"
    recorder = DelayedAttestationRecorder()
    sleeps: list[float] = []

    def delayed_environment(_pid: int) -> bytes:
        if recorder.round == 3:
            return b"AGENT_RUNTIME_OPS_RELEASE=/opt/old-release\0"
        return f"AGENT_RUNTIME_OPS_RELEASE={release}\0".encode("utf-8")

    result = activate_root_action_broker(
        CONFIG,
        env_path=parent / "root-action-webauthn.env",
        expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
        enforce_posix_permissions=os.name == "posix",
        run_command=recorder,
        expected_release=release,
        read_running_environment=delayed_environment,
        attestation_attempts=4,
        attestation_interval_seconds=0.25,
        sleep=sleeps.append,
    )

    assert result["running_release"] == str(release)
    assert recorder.round == 4
    assert sleeps == [0.25, 0.25, 0.25]
    for mutation in ("daemon-reload", "enable", "restart"):
        assert sum(command[1] == mutation for command in recorder.commands) == 1
    assert sum(command[1] == "is-enabled" for command in recorder.commands) == 4
    assert sum(command[1] == "is-active" for command in recorder.commands) == 4
    assert sum(command[1] == "show" for command in recorder.commands) == 4


def test_activation_fails_closed_after_bounded_persistent_post_restart_command_failure(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    recorder = PersistentPostRestartFailureRecorder()
    sleeps: list[float] = []
    with pytest.raises(RootActionActivationError, match="attestation failed closed"):
        activate_root_action_broker(
            CONFIG,
            env_path=parent / "root-action-webauthn.env",
            expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
            enforce_posix_permissions=os.name == "posix",
            run_command=recorder,
            expected_release=tmp_path / "expected-release",
            read_running_environment=lambda _pid: (
                b"AGENT_RUNTIME_OPS_RELEASE=/opt/old-release\0"
            ),
            attestation_attempts=3,
            attestation_interval_seconds=0.25,
            sleep=sleeps.append,
        )
    assert sleeps == [0.25, 0.25]
    for mutation in ("daemon-reload", "enable", "restart"):
        assert sum(command[1] == mutation for command in recorder.commands) == 1
    assert sum(command[1] == "is-active" for command in recorder.commands) == 3


def test_activation_fails_closed_after_bounded_persistent_release_mismatch(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    recorder = CommandRecorder()
    sleeps: list[float] = []
    with pytest.raises(RootActionActivationError, match="attestation failed closed"):
        activate_root_action_broker(
            CONFIG,
            env_path=parent / "root-action-webauthn.env",
            expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
            enforce_posix_permissions=os.name == "posix",
            run_command=recorder,
            expected_release=tmp_path / "expected-release",
            read_running_environment=lambda _pid: (
                b"AGENT_RUNTIME_OPS_RELEASE=/opt/old-release\0"
            ),
            attestation_attempts=3,
            attestation_interval_seconds=0.25,
            sleep=sleeps.append,
        )
    assert sleeps == [0.25, 0.25]
    assert sum(command[1] == "restart" for command in recorder.commands) == 1
    assert sum(command[1] == "show" for command in recorder.commands) == 3


def test_activation_fails_if_running_process_is_not_the_installed_release(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "agent-runtime-ops"
    parent.mkdir(mode=0o700)
    with pytest.raises(RootActionActivationError, match="attestation failed closed"):
        activate_root_action_broker(
            CONFIG,
            env_path=parent / "root-action-webauthn.env",
            expected_owner_uid=os.getuid() if hasattr(os, "getuid") else 0,
            enforce_posix_permissions=os.name == "posix",
            run_command=CommandRecorder(),
            expected_release=tmp_path / "expected-release",
            read_running_environment=lambda _pid: (
                b"AGENT_RUNTIME_OPS_RELEASE=/opt/agent-runtime-ops/releases/old\0"
            ),
            attestation_attempts=1,
            attestation_interval_seconds=0,
        )


def test_cli_activation_requires_root_and_emits_only_bounded_receipt(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    args = argparse.Namespace(
        rp_id="ops.ji-tech.co.kr", origin="https://ops.ji-tech.co.kr"
    )
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.os.geteuid",
        lambda: 1002,
        raising=False,
    )
    assert cmd_root_action_auth_activate(args) == 2
    assert json.loads(capfd.readouterr().out)["reason_code"] == (
        "root_action_auth_activation_requires_root"
    )
    monkeypatch.setattr("agent_runtime_ops.commands.root_action.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.activate_root_action_broker",
        lambda _config: {
            "schema": "agent-runtime-root-action-activation/v1",
            "rp_id": "ops.ji-tech.co.kr",
            "origin": "https://ops.ji-tech.co.kr",
            "environment": "/etc/agent-runtime-ops/root-action-webauthn.env",
            "environment_created": True,
            "user_id_fingerprint": "sha256:" + "a" * 64,
            "service": ROOT_ACTION_BROKER_SERVICE,
            "enabled": True,
            "active": True,
            "restart_performed": True,
            "running_release": "/opt/agent-runtime-ops/releases/tested",
        },
    )
    assert cmd_root_action_auth_activate(args) == 0
    result = json.loads(capfd.readouterr().out)
    assert result["activation"]["active"] is True
    assert "ROOT_ACTION_WEBAUTHN_USER_ID" not in json.dumps(result)
