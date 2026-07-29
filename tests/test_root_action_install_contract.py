from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import time

import pytest


def test_install_places_fixed_root_action_contract_without_activation_or_new_sudo() -> (
    None
):
    install = Path("install.sh").read_text(encoding="utf-8")
    start = install.index("install_root_action_broker_contract()")
    end = install.index("\n}\n", start) + 3
    function = install[start:end]
    assert 'ROOT_ACTION_STATE_ROOT="/var/lib/agent-runtime-ops/root-actions"' in install
    assert 'ROOT_ACTION_PRIVATE_ROOT="$ROOT_ACTION_STATE_ROOT/private"' in install
    assert 'ROOT_ACTION_PUBLIC_ROOT="$ROOT_ACTION_STATE_ROOT/public"' in install
    assert 'ROOT_ACTION_RUNTIME_ROOT="/run/agent-runtime-ops"' in install
    assert 'install -d -o root -g root -m 0700 "$ROOT_ACTION_PRIVATE_ROOT"' in function
    assert 'ROOT_ACTION_TRUSTED_ACCOUNT="svcops"' in install
    assert 'getent passwd "$ROOT_ACTION_TRUSTED_ACCOUNT"' in function
    assert (
        'install -d -o root -g "$ROOT_ACTION_TRUSTED_ACCOUNT" -m 0750 '
        '"$ROOT_ACTION_PUBLIC_ROOT"'
    ) in function
    assert 'install -o root -g root -m 0644 "$unit_tmp"' in function
    assert 'current_path="$install_root_real/current"' in function
    assert '[[ "$current_path" =~ ^/[A-Za-z0-9._/-]+$ ]]' in function
    assert '-e "s|@@CURRENT_LINK@@|$current_path|g"' in function
    assert '-e "s|@@RELEASE_DIR@@|$release_dir|g"' in function
    assert "systemctl enable" not in function
    assert "systemctl start" not in function
    assert 'systemctl is-active --quiet "$service_name"' in function
    assert 'systemctl restart "$service_name"' in function
    assert 'wait_for_root_action_broker_release "$service_name" "$release_dir"' in function
    assert "active_restarted_release_verified" in function
    assert "ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS=40" in install
    assert "ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS=0.25" in install
    assert "ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=30" in install
    assert "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1" in install
    assert "/usr/bin/timeout --kill-after=1" in install
    assert 'systemctl show --property=MainPID --value "$service_name"' in install
    assert 'grep -Fzqx "AGENT_RUNTIME_OPS_RELEASE=$release_dir"' in install
    sudoers_start = install.index("install_ops_sudoers()")
    sudoers_end = install.index("\n}\n", sudoers_start) + 3
    sudoers = install[sudoers_start:sudoers_end]
    assert "root-action" not in sudoers


def _install_attestation_functions() -> str:
    install = Path("install.sh").read_text(encoding="utf-8")
    start = install.index("root_action_broker_release_attested()")
    end = install.index("\ninstall_root_action_broker_contract()", start)
    return install[start:end]


def _run_install_attestation_harness(tmp_path: Path, *, succeed_at: int) -> list[str]:
    if os.name != "posix":
        pytest.skip("POSIX process semantics are required for this harness")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("POSIX bash is required for the install attestation harness")
    functions = _install_attestation_functions()
    trace = tmp_path / "trace"
    harness = tmp_path / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS=4\n"
        "ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS=0\n"
        f"TRACE={trace!s}\n"
        f"SUCCEED_AT={succeed_at}\n"
        + functions
        + "\n"
        + "round=0\n"
        + "root_action_broker_release_attested() {\n"
        + "  round=$((round + 1))\n"
        + "  printf 'attempt:%s\\n' \"$round\" >>\"$TRACE\"\n"
        + "  [[ \"$round\" -ge \"$SUCCEED_AT\" ]]\n"
        + "}\n"
        + "wait_for_root_action_broker_release broker.service /release\n"
        + "printf 'result:success\\n' >>\"$TRACE\"\n",
        encoding="utf-8",
        newline="\n",
    )
    completed = subprocess.run(
        [bash, str(harness)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    lines = trace.read_text(encoding="utf-8").splitlines()
    if succeed_at <= 4:
        assert completed.returncode == 0, completed.stderr
    else:
        assert completed.returncode != 0
    return lines


def test_install_attestation_waits_for_delayed_valid_state(tmp_path: Path) -> None:
    assert _run_install_attestation_harness(tmp_path, succeed_at=3) == [
        "attempt:1",
        "attempt:2",
        "attempt:3",
        "result:success",
    ]


def test_install_attestation_fails_closed_after_fixed_attempts(tmp_path: Path) -> None:
    assert _run_install_attestation_harness(tmp_path, succeed_at=5) == [
        "attempt:1",
        "attempt:2",
        "attempt:3",
        "attempt:4",
    ]


def test_install_attestation_times_out_a_truly_hanging_systemctl(
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX process semantics are required for this harness")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("POSIX bash is required for the install attestation harness")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/usr/bin/env bash\nexec /usr/bin/sleep 10\n",
        encoding="utf-8",
        newline="\n",
    )
    systemctl.chmod(0o755)
    harness = tmp_path / "hanging-systemctl.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS=2\n"
        "ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS=0\n"
        "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=0.1\n"
        + _install_attestation_functions()
        + "\nwait_for_root_action_broker_release broker.service /release\n",
        encoding="utf-8",
        newline="\n",
    )
    started = time.monotonic()
    completed = subprocess.run(
        [bash, str(harness)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"},
    )
    elapsed = time.monotonic() - started
    assert completed.returncode != 0
    assert elapsed < 3


def test_service_is_root_owned_webauthn_broker_and_uses_fixed_paths() -> None:
    unit = Path("systemd/agent-runtime-root-action-broker.service").read_text(
        encoding="utf-8"
    )
    assert "User=root" in unit
    assert "agent_runtime_ops.root_actions.service" in unit
    assert (
        "ReadWritePaths=/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops"
        in unit
    )
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "RuntimeDirectory=agent-runtime-ops" in unit
    assert "EnvironmentFile=/etc/agent-runtime-ops/root-action-webauthn.env" in unit
    assert "Environment=AGENT_RUNTIME_OPS_RELEASE=@@RELEASE_DIR@@" in unit
    assert "ConditionPathIsFile=/etc/agent-runtime-ops/root-action-webauthn.env" in unit
    assert "PAM" not in unit
    assert "sudo" not in unit.lower()


def test_custom_install_root_materializes_a_functional_absolute_unit_path() -> None:
    template = Path("systemd/agent-runtime-root-action-broker.service").read_text(
        encoding="utf-8"
    )
    custom_current = "/srv/jitech-agent-runtime/current"
    custom_release = "/srv/jitech-agent-runtime/releases/tested"
    materialized = template.replace("@@CURRENT_LINK@@", custom_current).replace(
        "@@RELEASE_DIR@@", custom_release
    )
    assert f"ConditionPathIsDirectory={custom_current}" in materialized
    assert (
        f"ExecStart={custom_current}/.venv/bin/python "
        "-m agent_runtime_ops.root_actions.service"
    ) in materialized
    assert "@@CURRENT_LINK@@" not in materialized
    assert "@@RELEASE_DIR@@" not in materialized
    assert f"Environment=AGENT_RUNTIME_OPS_RELEASE={custom_release}" in materialized
    assert "/opt/agent-runtime-ops/current" not in template
