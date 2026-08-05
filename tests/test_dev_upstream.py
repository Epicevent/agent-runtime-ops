from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.commands.dev_upstream import _inspect_rootless, cmd_dev_upstream
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings, load_runtime_bindings


def binding(**updates) -> RuntimeBinding:
    values = dict(
        instance_id="11111111-1111-4111-8111-111111111111",
        linux_account="dev-hermess",
        public_host="dev-hermess.ji-tech.co.kr",
        family="hermes",
        runtime_class="dev",
        gateway_port=30001,
        bridge_port=30101,
    )
    values.update(updates)
    return RuntimeBinding(**values)


def test_rootless_binding_is_canonical_runtime_truth(tmp_path: Path) -> None:
    row = binding(
        gateway_port=31889,
        upstream_kind="developer-rootless",
        upstream_owner="atelier",
        upstream_container="atelier-hermes-src",
    )
    (tmp_path / "runtime-bindings.json").write_text(dump_runtime_bindings([row]))
    assert load_runtime_bindings(tmp_path) == [row]


def test_rootless_container_must_be_owned_identity() -> None:
    try:
        _inspect_rootless("atelier", "some-other-container")
    except ValueError as exc:
        assert "OWNER-hermes-src" in str(exc)
    else:
        raise AssertionError("foreign container identity accepted")


def test_state_persistence_failure_precedes_binding_and_apache_mutation(tmp_path: Path) -> None:
    desired = SimpleNamespace(
        route=binding(), family="hermes", runtime_class="dev", runtime_profile="hermes-runtime-dev"
    )
    args = argparse.Namespace(
        target="dev-hermess",
        dev_upstream_command="apply",
        state_root=str(tmp_path),
        container="atelier-hermes-src",
    )
    with (
        patch("agent_runtime_ops.commands.dev_upstream._target", return_value=desired),
        patch("agent_runtime_ops.commands.dev_upstream.parse_apache_route", return_value=SimpleNamespace(gateway_port=30001)),
        patch("agent_runtime_ops.commands.dev_upstream.is_root", return_value=True),
        patch("agent_runtime_ops.commands.dev_upstream.sudo_user", return_value="atelier"),
        patch("agent_runtime_ops.commands.dev_upstream._inspect_rootless", return_value=(31889, "a" * 40)),
        patch("agent_runtime_ops.commands.dev_upstream.urllib.request.urlopen") as urlopen,
        patch("agent_runtime_ops.commands.dev_upstream._write_state", side_effect=OSError("disk full")),
        patch("agent_runtime_ops.commands.dev_upstream._write_runtime_bindings_file") as write_bindings,
        patch("agent_runtime_ops.commands.dev_upstream.set_apache_proxy_port") as set_port,
    ):
        urlopen.return_value.__enter__.return_value.status = 200
        urlopen.return_value.__enter__.return_value.read.return_value = b"Hermes Workspace"
        assert cmd_dev_upstream(args) == 1
    write_bindings.assert_not_called()
    set_port.assert_not_called()


def test_apache_failure_restores_binding_and_removes_prepared_intent(tmp_path: Path) -> None:
    desired = SimpleNamespace(
        route=binding(), family="hermes", runtime_class="dev", runtime_profile="hermes-runtime-dev"
    )
    args = argparse.Namespace(
        target="dev-hermess",
        dev_upstream_command="apply",
        state_root=str(tmp_path),
        container="atelier-hermes-src",
        authorization_check=False,
    )
    current = {"value": desired}

    def write_state(path: Path, value: dict[str, object]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(__import__("json").dumps(value), encoding="utf-8")

    with (
        patch("agent_runtime_ops.commands.dev_upstream._target", side_effect=lambda *_: current["value"]),
        patch("agent_runtime_ops.commands.dev_upstream.parse_apache_route", return_value=SimpleNamespace(gateway_port=30001)),
        patch("agent_runtime_ops.commands.dev_upstream.is_root", return_value=True),
        patch("agent_runtime_ops.commands.dev_upstream.sudo_user", return_value="atelier"),
        patch("agent_runtime_ops.commands.dev_upstream._inspect_rootless", return_value=(31889, "a" * 40)),
        patch("agent_runtime_ops.commands.dev_upstream.urllib.request.urlopen") as urlopen,
        patch("agent_runtime_ops.commands.dev_upstream._write_state", side_effect=write_state),
        patch("agent_runtime_ops.commands.dev_upstream.load_runtime_bindings", return_value=[desired.route]),
        patch("agent_runtime_ops.commands.dev_upstream.replace_runtime_binding", side_effect=lambda rows, _id, row: [row]),
        patch("agent_runtime_ops.commands.dev_upstream._write_runtime_bindings_file") as write_bindings,
        patch("agent_runtime_ops.commands.dev_upstream.set_apache_proxy_port", side_effect=ValueError("apache failed")),
    ):
        urlopen.return_value.__enter__.return_value.status = 200
        urlopen.return_value.__enter__.return_value.read.return_value = b"Hermes Workspace"
        assert cmd_dev_upstream(args) == 1
    assert write_bindings.call_count == 2
    assert not (tmp_path / "dev-upstreams" / "dev-hermess.json").exists()


def test_apply_recovers_exact_prepared_intent_from_previous_abort(tmp_path: Path) -> None:
    desired = SimpleNamespace(
        route=binding(), family="hermes", runtime_class="dev", runtime_profile="hermes-runtime-dev"
    )
    state_path = tmp_path / "dev-upstreams" / "dev-hermess.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        __import__("json").dumps(
            {
                "status": "prepared",
                "target": "dev-hermess",
                "instance_id": desired.route.instance_id,
                "rollback_binding": desired.route.to_json(),
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        target="dev-hermess",
        dev_upstream_command="apply",
        state_root=str(tmp_path),
        container="atelier-hermes-src",
        authorization_check=False,
    )
    with (
        patch("agent_runtime_ops.commands.dev_upstream._target", return_value=desired),
        patch("agent_runtime_ops.commands.dev_upstream.parse_apache_route", return_value=SimpleNamespace(gateway_port=30001)),
        patch("agent_runtime_ops.commands.dev_upstream.is_root", return_value=True),
        patch("agent_runtime_ops.commands.dev_upstream.sudo_user", return_value="atelier"),
        patch("agent_runtime_ops.commands.dev_upstream._inspect_rootless", side_effect=ValueError("stop after recovery")),
    ):
        assert cmd_dev_upstream(args) == 1
    assert not state_path.exists()


def test_authorization_check_is_mutation_free() -> None:
    args = SimpleNamespace(
        target="dev-attest",
        dev_upstream_command="apply",
        state_root=None,
        container="attest",
        authorization_check=True,
    )
    with (
        patch("agent_runtime_ops.commands.dev_upstream.is_root", return_value=True),
        patch("agent_runtime_ops.commands.dev_upstream.sudo_user", return_value="atelier"),
        patch("agent_runtime_ops.commands.dev_upstream._target") as target,
        patch("agent_runtime_ops.commands.dev_upstream._write_state") as write_state,
        patch("agent_runtime_ops.commands.dev_upstream._write_runtime_bindings_file") as write_bindings,
        patch("agent_runtime_ops.commands.dev_upstream.set_apache_proxy_port") as set_port,
    ):
        assert cmd_dev_upstream(args) == 0
    target.assert_not_called()
    write_state.assert_not_called()
    write_bindings.assert_not_called()
    set_port.assert_not_called()
