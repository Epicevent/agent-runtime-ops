from __future__ import annotations

from pathlib import Path


def test_install_places_fixed_root_action_contract_without_activation_or_new_sudo() -> None:
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
    assert 'sed "s|@@CURRENT_LINK@@|$current_path|g"' in function
    assert "systemctl enable" not in function
    assert "systemctl start" not in function
    assert "systemctl restart" not in function
    sudoers_start = install.index("install_ops_sudoers()")
    sudoers_end = install.index("\n}\n", sudoers_start) + 3
    sudoers = install[sudoers_start:sudoers_end]
    assert "root-action" not in sudoers


def test_service_is_submission_publication_only_and_uses_fixed_paths() -> None:
    unit = Path("systemd/agent-runtime-root-action-broker.service").read_text(
        encoding="utf-8"
    )
    assert "User=root" in unit
    assert "agent_runtime_ops.root_actions.service" in unit
    assert "ReadWritePaths=/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "RuntimeDirectory=agent-runtime-ops" in unit
    assert "PAM" not in unit
    assert "sudo" not in unit.lower()
    assert "worker" not in unit.lower()


def test_custom_install_root_materializes_a_functional_absolute_unit_path() -> None:
    template = Path("systemd/agent-runtime-root-action-broker.service").read_text(
        encoding="utf-8"
    )
    custom_current = "/srv/jitech-agent-runtime/current"
    materialized = template.replace("@@CURRENT_LINK@@", custom_current)
    assert f"ConditionPathIsDirectory={custom_current}" in materialized
    assert (
        f"ExecStart={custom_current}/.venv/bin/python "
        "-m agent_runtime_ops.root_actions.service"
    ) in materialized
    assert "@@CURRENT_LINK@@" not in materialized
    assert "/opt/agent-runtime-ops/current" not in template
