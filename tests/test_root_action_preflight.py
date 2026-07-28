from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from agent_runtime_ops.commands.root_action import cmd_root_action_preflight
from agent_runtime_ops.root_action_preflight import (
    ROOT_ACTION_PREFLIGHT_SCHEMA,
    _path_snapshot,
    _read_unit_directives,
    evaluate_root_action_preflight,
)


def _path(path: str, kind: str, uid: int, gid: int, mode: str) -> dict:
    return {
        "path": path,
        "exists": True,
        "kind": kind,
        "uid": uid,
        "gid": gid,
        "mode": mode,
        "nlink": 1,
    }


def _missing(path: str) -> dict:
    return {
        "path": path,
        "exists": False,
        "kind": "unavailable",
        "uid": "unavailable",
        "gid": "unavailable",
        "mode": "unavailable",
        "nlink": "unavailable",
    }


def snapshot(*, socket_present: bool = True, catalog_present: bool = True) -> dict:
    gid = 1002
    return {
        "platform": {"os_name": "posix", "so_peercred": True, "effective_uid": gid},
        "identity": {
            "account": "svcops",
            "present": True,
            "uid": gid,
            "primary_gid": gid,
            "group_gid": gid,
        },
        "paths": {
            "unit": _path(
                "/etc/systemd/system/agent-runtime-root-action-broker.service",
                "regular_file",
                0,
                0,
                "0644",
            ),
            "state_root": _path(
                "/var/lib/agent-runtime-ops/root-actions",
                "directory",
                0,
                gid,
                "0750",
            ),
            "private_root": _path(
                "/var/lib/agent-runtime-ops/root-actions/private",
                "directory",
                0,
                0,
                "0700",
            ),
            "public_root": _path(
                "/var/lib/agent-runtime-ops/root-actions/public",
                "directory",
                0,
                gid,
                "0750",
            ),
            "runtime_root": _path(
                "/run/agent-runtime-ops", "directory", 0, gid, "0750"
            ),
            "broker_socket": (
                _path(
                    "/run/agent-runtime-ops/root-action-broker.sock",
                    "socket",
                    0,
                    gid,
                    "0660",
                )
                if socket_present
                else _missing("/run/agent-runtime-ops/root-action-broker.sock")
            ),
            "public_catalog": (
                _path(
                    "/var/lib/agent-runtime-ops/root-actions/public/catalog.json",
                    "regular_file",
                    0,
                    gid,
                    "0640",
                )
                if catalog_present
                else _missing(
                    "/var/lib/agent-runtime-ops/root-actions/public/catalog.json"
                )
            ),
        },
        "unit": {
            "read_status": "read",
            "placeholder_count": 0,
            "directives": {
                "User": ["root"],
                "Group": ["root"],
                "ExecStart": [
                    "/opt/agent-runtime-ops/current/.venv/bin/python "
                    "-m agent_runtime_ops.root_actions.service"
                ],
                "ReadWritePaths": [
                    "/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops"
                ],
                "RestrictAddressFamilies": ["AF_UNIX"],
            },
        },
    }


def test_preflight_preserves_exact_observations_without_claiming_runtime_e2e() -> None:
    value = evaluate_root_action_preflight(
        snapshot(), observed_at="2026-07-28T00:00:00+00:00"
    )
    assert value["schema"] == ROOT_ACTION_PREFLIGHT_SCHEMA
    assert value["read_only"] is True
    assert value["mutations_performed"] is False
    assert value["network_calls_performed"] is False
    assert value["secrets_included"] is False
    assert value["gates"] == {
        "install_contract": "match",
        "activation_surface": "match",
        "publication_surface": "match",
    }
    assert "requester_terminal_receipt_round_trip" in value["proof_boundary"][
        "does_not_prove"
    ]
    assert "strong_reauthentication" in value["proof_boundary"]["does_not_prove"]


def test_absent_activation_artifacts_are_observed_not_manufactured_failures() -> None:
    value = evaluate_root_action_preflight(
        snapshot(socket_present=False, catalog_present=False),
        observed_at="2026-07-28T00:00:00+00:00",
    )
    assert value["gates"] == {
        "install_contract": "match",
        "activation_surface": "not_observed",
        "publication_surface": "not_observed",
    }
    by_id = {row["id"]: row for row in value["checks"]}
    assert by_id["endpoint.broker_socket"]["status"] == "not_observed"
    assert by_id["publication.catalog"]["status"] == "not_observed"


def test_unsafe_observed_socket_is_a_safety_mismatch() -> None:
    raw = snapshot()
    raw["paths"]["broker_socket"]["mode"] = "0666"
    value = evaluate_root_action_preflight(
        raw, observed_at="2026-07-28T00:00:00+00:00"
    )
    assert value["gates"]["activation_surface"] == "mismatch"


def test_untrusted_unit_execstart_is_an_install_mismatch() -> None:
    raw = snapshot()
    raw["unit"]["directives"]["ExecStart"] = ["/bin/false"]
    value = evaluate_root_action_preflight(
        raw, observed_at="2026-07-28T00:00:00+00:00"
    )
    assert value["gates"]["install_contract"] == "mismatch"


@pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow read contract"
)
def test_unit_reader_executes_bounded_success_and_catch_fixtures(
    tmp_path: Path,
) -> None:
    path = tmp_path / "broker.service"
    path.write_text(
        "[Service]\n"
        "User=root\n"
        "Group=root\n"
        "ExecStart=/opt/agent-runtime-ops/current/.venv/bin/python "
        "-m agent_runtime_ops.root_actions.service\n"
        "ReadWritePaths=/var/lib/agent-runtime-ops/root-actions "
        "/run/agent-runtime-ops\n"
        "RestrictAddressFamilies=AF_UNIX\n",
        encoding="utf-8",
    )
    observed = _path_snapshot(path)
    result = _read_unit_directives(path, observed)
    assert result["read_status"] == "read"
    assert result["placeholder_count"] == 0
    assert result["directives"]["User"] == ["root"]

    path.write_bytes(b"x" * (64 * 1024 + 1))
    result = _read_unit_directives(path, _path_snapshot(path))
    assert result == {"read_status": "too_large", "directives": {}}


def test_cli_emits_canonical_machine_receipt(monkeypatch, capfd) -> None:
    value = evaluate_root_action_preflight(
        snapshot(), observed_at="2026-07-28T00:00:00+00:00"
    )
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.root_action_preflight", lambda: value
    )
    assert cmd_root_action_preflight(argparse.Namespace()) == 0
    emitted = capfd.readouterr().out
    assert json.loads(emitted) == value
    assert emitted.endswith("\n")


def test_preflight_source_is_fixed_scope_read_only() -> None:
    source = Path(
        "opsctl/agent_runtime_ops/root_action_preflight.py"
    ).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "os.listdir" not in source
    assert ".glob(" not in source
    assert ".connect(" not in source
    assert "os.O_WRONLY" not in source
    assert "os.O_RDWR" not in source
    assert "os.remove" not in source
    assert ".unlink(" not in source
