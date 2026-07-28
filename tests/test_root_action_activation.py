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
            stdout="not exposed",
            stderr="not exposed",
        )


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
    )
    raw = env_path.read_text(encoding="utf-8")
    assert "ROOT_ACTION_WEBAUTHN_RP_ID=ops.ji-tech.co.kr\n" in raw
    assert "ROOT_ACTION_WEBAUTHN_ORIGINS=https://ops.ji-tech.co.kr\n" in raw
    user_id_line = next(
        line for line in raw.splitlines() if line.startswith("ROOT_ACTION_WEBAUTHN_USER_ID=")
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
        ("systemctl", "enable", "--now", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-enabled", "--quiet", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-active", "--quiet", ROOT_ACTION_BROKER_SERVICE),
    ]


def test_activation_is_idempotent_but_refuses_policy_replacement(tmp_path: Path) -> None:
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
    )
    original = env_path.read_bytes()
    second = activate_root_action_broker(
        CONFIG,
        env_path=env_path,
        expected_owner_uid=owner,
        enforce_posix_permissions=os.name == "posix",
        run_command=CommandRecorder(),
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
        )
    assert env_path.exists()


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
        },
    )
    assert cmd_root_action_auth_activate(args) == 0
    result = json.loads(capfd.readouterr().out)
    assert result["activation"]["active"] is True
    assert "ROOT_ACTION_WEBAUTHN_USER_ID" not in json.dumps(result)
