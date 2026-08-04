from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "systemd" / "agent-runtime-root-action-broker-standalone.service"
SERVICE = ROOT / "opsctl" / "agent_runtime_ops" / "root_actions" / "service.py"
COMMIT = "a" * 40
TREE = "sha256:" + "b" * 64
RELEASE = f"/opt/agent-runtime-root-action-broker/releases/{COMMIT}"


def _rendered_unit() -> str:
    return (
        UNIT.read_text(encoding="utf-8")
        .replace("@@BROKER_RELEASE_DIR@@", RELEASE)
        .replace("@@SOURCE_COMMIT@@", COMMIT)
        .replace("@@BROKER_TREE_SHA256@@", TREE)
    )


def test_standalone_unit_pins_one_immutable_release_without_opsctl() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert unit.count("ExecStart=") == 1
    assert (
        "ExecStart=@@BROKER_RELEASE_DIR@@/.venv/bin/python -I -B -m "
        "agent_runtime_ops.root_actions.service"
    ) in unit
    assert "Environment=AGENT_RUNTIME_ROOT_ACTION_RELEASE=@@BROKER_RELEASE_DIR@@" in unit
    assert "Environment=AGENT_RUNTIME_ROOT_ACTION_SOURCE_COMMIT=@@SOURCE_COMMIT@@" in unit
    assert "Environment=AGENT_RUNTIME_ROOT_ACTION_TREE_SHA256=@@BROKER_TREE_SHA256@@" in unit
    assert "@@CURRENT" not in unit
    assert "opsctl" not in unit.lower()
    assert "install.sh" not in unit
    assert "release.py" not in unit


def test_standalone_unit_keeps_the_existing_broker_security_boundary() -> None:
    unit = UNIT.read_text(encoding="utf-8")
    for expected in (
        "User=root",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX",
        "ReadWritePaths=/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops",
        "EnvironmentFile=/etc/agent-runtime-ops/root-action-webauthn.env",
        "ConditionFileIsExecutable=@@BROKER_RELEASE_DIR@@/.venv/bin/python",
        "ConditionPathExists=/etc/agent-runtime-ops/root-action-webauthn.env",
    ):
        assert expected in unit
    assert "WantedBy=multi-user.target" in unit


def test_standalone_unit_targets_the_existing_broker_not_a_new_control_plane() -> None:
    service = SERVICE.read_text(encoding="utf-8")
    assert "RootActionAuthorizationService" in service
    assert "TypedRootActionBroker" in service
    assert "RootActionExecutionWorker" in service
    assert "RootActionUnixListener" in service
    assert "def main() -> int:" in service
    assert not (SERVICE.parent / "release.py").exists()


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd unavailable")
def test_rendered_standalone_unit_is_accepted_by_systemd(tmp_path: Path) -> None:
    rendered = tmp_path / "agent-runtime-root-action-broker-standalone.service"
    syntax_only = _rendered_unit().replace(
        f"ExecStart={RELEASE}/.venv/bin/python -I -B -m "
        "agent_runtime_ops.root_actions.service",
        "ExecStart=/bin/true",
    )
    rendered.write_text(syntax_only, encoding="utf-8")
    result = subprocess.run(
        ["systemd-analyze", "verify", str(rendered)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
