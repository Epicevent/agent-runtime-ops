from __future__ import annotations

import os
from pathlib import Path
import socket
from types import SimpleNamespace
from unittest.mock import patch
import uuid

import pytest

from agent_runtime_ops.compose_contract import validate_compose_contract
from agent_runtime_ops.domain.runtime_apply import _apply_desired_slot_locked
from agent_runtime_ops.profiles import RuntimeProfile, load_profile
from agent_runtime_ops.renderer import render_compose
from agent_runtime_ops.routing import RuntimeBinding
from agent_runtime_ops.runtime_socket_projection import (
    require_runtime_socket_source,
    runtime_socket_projection_is_current,
    runtime_socket_projection_live_checks,
)
from agent_runtime_ops.state import RuntimeTarget


def _desired(slot: str = "oc20") -> RuntimeTarget:
    digest = "sha256:" + "a" * 64
    return RuntimeTarget(
        target=slot,
        family="hermes",
        runtime_class="customer",
        image_name="direct-image",
        image_spec={
            "family": "hermes",
            "wrapper_image": f"ghcr.io/epicevent/agent-runtime-hermes@{digest}",
            "product_image": f"ghcr.io/epicevent/hermes-runtime@{digest}",
            "digest": digest,
        },
        runtime_profile="hermes-runtime-customer",
        route=RuntimeBinding(
            instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, slot)),
            linux_account=slot,
            public_host=f"{slot}.ji-tech.co.kr",
            family="hermes",
            runtime_class="customer",
            gateway_port=30689,
            bridge_port=30690,
        ),
    )


def _socket_profile(tmp_path: Path, *, digest: str = "sha256:" + "b" * 64):
    return SimpleNamespace(
        metadata={
            "runtime_socket_projection": {
                "source_template": str(tmp_path / "{slot}.sock"),
                "target": "/run/kwrag/shared-gpu.sock",
                "read_only": True,
                "supplementary_group": "runtime_gid",
            }
        },
        path=tmp_path,
        digest=digest,
    )


def _bound_socket(path: Path) -> socket.socket:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    path.chmod(0o660)
    return server


def test_hermes_runtime_customer_renders_exact_readonly_slot_socket() -> None:
    profile = load_profile("hermes-runtime-customer")
    desired = _desired()
    with (
        patch("agent_runtime_ops.renderer._runtime_ids", return_value=("1026", "963", "1047")),
        patch("agent_runtime_ops.runtime_socket_projection.runtime_ids", return_value=(1026, 963, 1047)),
    ):
        rendered = render_compose(profile, desired)
        checks = {
            item.name: item.ok
            for item in validate_compose_contract(profile, desired, rendered.text)
        }

    assert '/run/kwrag-gpu/oc20.sock' in rendered.text
    assert 'target: /run/kwrag/shared-gpu.sock' in rendered.text
    assert '      - "963"' in rendered.text
    assert checks["compose_runtime_socket_bind_present"]
    assert checks["compose_runtime_socket_bind_type"]
    assert checks["compose_runtime_socket_source_slot_scoped"]
    assert checks["compose_runtime_socket_readonly"]
    assert checks["compose_runtime_socket_peer_group_present"]


@pytest.mark.parametrize(
    ("old", "new", "failed_check"),
    [
        (
            'source: "/run/kwrag-gpu/oc20.sock"',
            'source: "/run/kwrag-gpu/oc16.sock"',
            "compose_runtime_socket_source_slot_scoped",
        ),
        (
            "        target: /run/kwrag/shared-gpu.sock\n        read_only: true",
            "        target: /run/kwrag/shared-gpu.sock\n        read_only: false",
            "compose_runtime_socket_readonly",
        ),
        (
            '      - "963"\n',
            "",
            "compose_runtime_socket_peer_group_present",
        ),
    ],
)
def test_compose_contract_rejects_socket_projection_drift(
    old: str,
    new: str,
    failed_check: str,
) -> None:
    profile = load_profile("hermes-runtime-customer")
    desired = _desired()
    with (
        patch("agent_runtime_ops.renderer._runtime_ids", return_value=("1026", "963", "1047")),
        patch("agent_runtime_ops.runtime_socket_projection.runtime_ids", return_value=(1026, 963, 1047)),
    ):
        rendered = render_compose(profile, desired).text
        assert rendered.count(old) == 1
        checks = {
            item.name: item.ok
            for item in validate_compose_contract(
                profile,
                desired,
                rendered.replace(old, new, 1),
            )
        }
    assert checks[failed_check] is False


def test_socket_source_preflight_requires_socket_peer_group(tmp_path: Path) -> None:
    profile = _socket_profile(tmp_path)
    source = tmp_path / "oc20.sock"
    server = _bound_socket(source)
    try:
        with patch(
            "agent_runtime_ops.runtime_socket_projection.runtime_ids",
            return_value=(os.getuid(), os.getgid(), os.getgid()),
        ):
            require_runtime_socket_source(profile, "oc20")

        with patch(
            "agent_runtime_ops.runtime_socket_projection.runtime_ids",
            return_value=(os.getuid(), os.getgid() + 1, os.getgid()),
        ), pytest.raises(ValueError, match="peer group mismatch"):
            require_runtime_socket_source(profile, "oc20")
    finally:
        server.close()


def test_socket_source_preflight_rejects_missing_and_regular_file(tmp_path: Path) -> None:
    profile = _socket_profile(tmp_path)
    with pytest.raises(ValueError, match="source is missing"):
        require_runtime_socket_source(profile, "oc20")
    (tmp_path / "oc20.sock").write_text("not a socket", encoding="utf-8")
    with pytest.raises(ValueError, match="source is not a socket"):
        require_runtime_socket_source(profile, "oc20")


def test_apply_rejects_missing_socket_before_host_or_backup_mutation(tmp_path: Path) -> None:
    desired = _desired()
    profile = load_profile("hermes-runtime-customer")
    rendered = SimpleNamespace(text="services: {}\n", sha256="sha256:" + "c" * 64)
    with (
        patch("agent_runtime_ops.domain.runtime_apply.render_compose", return_value=rendered),
        patch("agent_runtime_ops.domain.runtime_apply.run_static_slot_checks", return_value=[]),
        patch(
            "agent_runtime_ops.domain.runtime_apply.require_runtime_socket_source",
            side_effect=ValueError("runtime socket source is missing"),
        ),
        patch("agent_runtime_ops.domain.runtime_apply.ensure_nas_workspace_dir") as ensure_workspace,
        patch("agent_runtime_ops.domain.runtime_apply.backup_agent_runtime_state") as backup,
        patch("agent_runtime_ops.domain.runtime_apply.append_action_log"),
    ):
        rc = _apply_desired_slot_locked(
            desired=desired,
            profile=profile,
            state_root=tmp_path,
            allow_first_apply=True,
        )

    assert rc == 1
    ensure_workspace.assert_not_called()
    backup.assert_not_called()


def test_live_checks_verify_exact_bind_readonly_namespace_and_peer_group(
    tmp_path: Path,
) -> None:
    profile = _socket_profile(tmp_path)
    source = tmp_path / "oc20.sock"
    server = _bound_socket(source)
    info = {
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(source),
                "Destination": "/run/kwrag/shared-gpu.sock",
                "RW": False,
            }
        ],
        "HostConfig": {"GroupAdd": [str(os.getgid())]},
    }
    try:
        with (
            patch(
                "agent_runtime_ops.runtime_socket_projection.runtime_ids",
                return_value=(os.getuid(), os.getgid(), os.getgid()),
            ),
            patch(
                "agent_runtime_ops.runtime_socket_projection.profile_digest",
                return_value=profile.digest,
            ),
            patch(
                "agent_runtime_ops.runtime_socket_projection.mountinfo_under",
                return_value=(
                    0,
                    "",
                    [
                        {
                            "target": "/run/kwrag/shared-gpu.sock",
                            "source": "tmpfs[/oc20.sock]",
                            "fstype": "tmpfs",
                            "options": "ro,nosuid,nodev",
                            "propagation": "private",
                        }
                    ],
                ),
            ),
        ):
            checks = runtime_socket_projection_live_checks(profile, "oc20", info, 749599)
    finally:
        server.close()

    assert checks
    assert all(ok for ok, _name, _detail in checks), checks


def test_live_checks_fail_closed_for_missing_projection(tmp_path: Path) -> None:
    profile = _socket_profile(tmp_path)
    with (
        patch(
            "agent_runtime_ops.runtime_socket_projection.profile_digest",
            return_value=profile.digest,
        ),
        patch(
            "agent_runtime_ops.runtime_socket_projection.mountinfo_under",
            return_value=(0, "", []),
        ),
    ):
        checks = runtime_socket_projection_live_checks(
            profile,
            "oc20",
            {"Mounts": [], "HostConfig": {"GroupAdd": []}},
            749599,
        )
    results = {name: ok for ok, name, _detail in checks}
    assert results["live_runtime_socket_host_ready"] is False
    assert results["live_runtime_socket_bind_present"] is False
    assert results["live_runtime_socket_source_slot_scoped"] is False
    assert results["live_runtime_socket_bind_readonly"] is False
    assert results["live_runtime_socket_peer_group_present"] is False
    assert results["live_runtime_socket_namespace_mounted"] is False
    assert results["live_runtime_socket_namespace_readonly"] is False


def test_historical_profile_digest_suppresses_new_projection_during_rollback() -> None:
    current = load_profile("hermes-runtime-customer")
    historical = RuntimeProfile(
        name=current.name,
        path=current.path,
        metadata=current.metadata,
        digest="sha256:" + "0" * 64,
    )
    assert runtime_socket_projection_is_current(current) is True
    assert runtime_socket_projection_is_current(historical) is False
    assert runtime_socket_projection_live_checks(historical, "oc20", {}, 749599) == []
