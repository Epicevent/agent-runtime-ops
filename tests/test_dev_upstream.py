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
