from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.commands.observation import (
    MAX_READONLY_OBSERVATION_BYTES,
    READONLY_OBSERVATION_SCHEMA,
    ReadonlyObservationError,
    _canonical,
    cmd_observation_status,
)
from agent_runtime_ops.routing import RuntimeBinding
from agent_runtime_ops.state import RuntimeTarget


MODULE = "agent_runtime_ops.commands.observation"
PRODUCT = "ghcr.io/epicevent/hermes-runtime@sha256:" + "1" * 64
WRAPPER = "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "2" * 64
COMPONENT = "sha256:" + "3" * 64
BINDING = "sha256:" + "4" * 64
RESOURCE = "sha256:" + "5" * 64
RECIPE = "sha256:" + "6" * 64
OPS_SHA = "7" * 40


def runtime_binding(*, enabled: bool = True) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id="445fca38-1fbb-4223-84f4-8c43e4437c57",
        linux_account="dev-hermes-img",
        public_host="dev-hermes-img.ji-tech.co.kr",
        family="hermes",
        runtime_class="customer",
        gateway_port=30989,
        bridge_port=30990,
        enabled=enabled,
    )


def runtime_target() -> RuntimeTarget:
    binding = runtime_binding()
    return RuntimeTarget(
        target=binding.linux_account,
        family=binding.family,
        runtime_class=binding.runtime_class,
        image_name="direct-image",
        image_spec={
            "wrapper_image": WRAPPER,
            "product_image": PRODUCT,
            "retrieval_enabled": False,
            "retrieval_component_digest": COMPONENT,
            "retrieval_binding_digest": BINDING,
        },
        runtime_profile="hermes-fast",
        route=binding,
    )


def approvals() -> dict[str, object]:
    return {
        "hermes:product": {
            "approved_ref": PRODUCT,
            "approved_digest": "sha256:" + "1" * 64,
            "source_commit": "8" * 40,
            "image_revision": "8" * 40,
        },
        "hermes:wrapper": {
            "approved_ref": WRAPPER,
            "approved_digest": "sha256:" + "2" * 64,
            "source_commit": "9" * 40,
            "image_revision": "9" * 40,
        },
    }


def runtime_truth() -> tuple[dict[str, str], list[tuple[bool, str, str | None]]]:
    return (
        {
            "instance_id": runtime_binding().instance_id,
            "linux_account": "dev-hermes-img",
            "truth_source": "live_image",
            "truth_status": "ok",
            "family": "hermes",
            "runtime_class": "customer",
            "enabled": "yes",
            "gateway_port": "30989",
            "bridge_port": "30990",
            "wrapper_image": WRAPPER,
            "product_image": PRODUCT,
            "runtime_profile": "hermes-fast",
            "runtime_contract": "hermes-fast/v1",
            "canonical_recipe_name": "hermes-runtime",
            "canonical_recipe_digest": RECIPE,
            "ops_repo_commit": OPS_SHA,
            "container_nas_root": "/workspace/nas_docs",
            "nas_read_only": "true",
            "retrieval_labels_present": "true",
            "retrieval_contract_complete": "true",
            "retrieval_projection_labels_present": "true",
            "retrieval_projection_complete": "true",
            "retrieval_projection_consistent": "true",
            "retrieval_schema": "jitech-embedded-retrieval/v1",
            "retrieval_transport": "in_process",
            "retrieval_default_enabled": "false",
            "retrieval_enabled": "false",
            "retrieval_component_digest": COMPONENT,
            "retrieval_binding_digest": BINDING,
            "retrieval_expected_binding_digest": BINDING,
            "retrieval_resource_profile_digest": RESOURCE,
            "credential": "must-not-be-projected",
        },
        [
            (True, "truth_container_lookup", "container-secret-detail"),
            (True, "truth_image_labeled", "another-raw-detail"),
        ],
    )


def args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(state_root=str(tmp_path), target="dev-hermes-img")


def contract_patches(
    *, truth=None, binding=None, target=None, approval=None, pending_transaction=None
):
    return (
        patch(f"{MODULE}._is_root", return_value=True),
        patch(f"{MODULE}.get_runtime_binding", return_value=binding or runtime_binding()),
        patch(f"{MODULE}.installed_source_commit", return_value=OPS_SHA),
        patch(
            f"{MODULE}.approved_update_from_policy",
            return_value=("https://github.com/Epicevent/agent-runtime-ops.git", OPS_SHA),
        ),
        patch(f"{MODULE}.validate_update_target"),
        patch(
            f"{MODULE}.load_image_approvals",
            return_value=approval if approval is not None else approvals(),
        ),
        patch(
            f"{MODULE}.load_runtime_target",
            return_value=target or runtime_target(),
        ),
        patch(f"{MODULE}.live_runtime_truth", return_value=truth or runtime_truth()),
        patch(
            f"{MODULE}.load_canonical_recipe",
            return_value=SimpleNamespace(
                digest=RECIPE,
                data={
                    "family": "hermes",
                    "container_nas_root": "/workspace/nas_docs",
                    "runtime_contracts": {"customer": "hermes-fast/v1"},
                    "runtime_profiles": {"customer": "hermes-fast"},
                },
            ),
        ),
        patch(
            f"{MODULE}.pending_rollback_identity",
            return_value=pending_transaction,
        ),
    )


def run_observation(
    capsys,
    tmp_path: Path,
    patches,
    *,
    requested_target: str = "dev-hermes-img",
) -> tuple[int, str, dict]:
    request = args(tmp_path)
    request.target = requested_target
    with ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        rc = cmd_observation_status(request)
    raw = capsys.readouterr().out
    return rc, raw, json.loads(raw)


@pytest.mark.skipif(os.name != "posix", reason="the production CLI imports POSIX pwd")
def test_parser_exposes_only_target_not_path_shell_or_receipt() -> None:
    from agent_runtime_ops.cli import build_parser

    parser = build_parser()
    parsed = parser.parse_args(["observation", "status", "dev-hermes-img"])
    assert parsed.target == "dev-hermes-img"
    assert parsed.func is cmd_observation_status
    for forbidden in ("--path", "--shell", "--receipt", "--docker-exec"):
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["observation", "status", "dev-hermes-img", forbidden, "x"]
            )


def test_non_root_fails_with_bounded_sanitized_schema(capsys, tmp_path: Path) -> None:
    with patch(f"{MODULE}._is_root", return_value=False):
        assert cmd_observation_status(args(tmp_path)) == 2
    value = json.loads(capsys.readouterr().out)
    assert value == {
        "schema": READONLY_OBSERVATION_SCHEMA,
        "result": "error",
        "reason_code": "root_observation_required",
        "writes": 0,
        "network": False,
        "local_docker_read_only": True,
        "preexisting_or_product_process_signals": 0,
    }


def test_runtime_observation_does_not_claim_canary_completion_without_terminal_identity(
    capsys, tmp_path: Path
) -> None:
    rc, raw, value = run_observation(capsys, tmp_path, contract_patches())
    assert rc == 0
    assert len(raw.encode("utf-8")) <= MAX_READONLY_OBSERVATION_BYTES
    assert value["schema"] == READONLY_OBSERVATION_SCHEMA
    assert value["result"] == "observed"
    assert value["runtime_state"] == "healthy"
    assert value["transaction_state"] == "no_pending_transaction"
    assert value["terminal_state"] == "unknown"
    assert value["canary_completion_claimed"] is False
    assert value["claim_scope"] == "runtime_observation_only"
    assert value["writes"] == 0
    assert value["network"] is False
    assert value["local_docker_read_only"] is True
    assert value["preexisting_or_product_process_signals"] == 0
    runtime = value["observations"]["runtime"]
    assert runtime["fields"]["retrieval_enabled"] == "false"
    assert runtime["fields"]["retrieval_component_digest"] == COMPONENT
    assert runtime["fields"]["retrieval_resource_profile_digest"] == RESOURCE
    assert {
        "name": "observation_retrieval_projection_identity",
        "passed": True,
    } in runtime["checks"]
    assert "credential" not in runtime["fields"]
    assert "container-secret-detail" not in raw
    assert "another-raw-detail" not in raw


def test_dev_owned_image_target_does_not_require_prior_image_approval(
    capsys, tmp_path: Path
) -> None:
    rc, _raw, value = run_observation(
        capsys,
        tmp_path,
        contract_patches(approval={}),
    )
    assert rc == 0
    assert value["result"] == "observed"
    assert value["observations"]["images"] == {
        "status": "not_required",
        "family": "hermes",
        "approval_required": False,
        "binding_status": "not_required_dev_target",
        "product": {"status": "not_approved"},
        "wrapper": {"status": "not_approved"},
    }


def test_dev_owned_image_target_does_not_read_malformed_approval_policy(
    capsys, tmp_path: Path
) -> None:
    patches = list(contract_patches())
    patches[5] = patch(
        f"{MODULE}.load_image_approvals",
        side_effect=ValueError("malformed approval policy"),
    )
    rc, raw, value = run_observation(capsys, tmp_path, tuple(patches))
    assert rc == 0
    assert value["result"] == "observed"
    assert value["observations"]["images"]["status"] == "not_required"
    assert "malformed approval policy" not in raw


def test_production_target_requires_approvals_matching_exact_rollout_digests(
    capsys, tmp_path: Path
) -> None:
    binding = replace(
        runtime_binding(),
        linux_account="oc20",
        public_host="oc20.ji-tech.co.kr",
    )
    target = replace(runtime_target(), target="oc20", route=binding)
    truth, checks = runtime_truth()
    truth["linux_account"] = "oc20"

    rc, _raw, value = run_observation(
        capsys,
        tmp_path,
        contract_patches(
            binding=binding,
            target=target,
            truth=(truth, checks),
        ),
        requested_target="oc20",
    )
    assert rc == 0
    assert value["observations"]["images"]["approval_required"] is True
    assert value["observations"]["images"]["binding_status"] == "exact"

    stale = approvals()
    stale_wrapper = "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "a" * 64
    stale["hermes:wrapper"]["approved_ref"] = stale_wrapper
    stale["hermes:wrapper"]["approved_digest"] = "sha256:" + "a" * 64
    rc, _raw, value = run_observation(
        capsys,
        tmp_path,
        contract_patches(
            binding=binding,
            target=target,
            truth=(truth, checks),
            approval=stale,
        ),
        requested_target="oc20",
    )
    assert rc == 1
    assert value["result"] == "degraded"
    assert value["observations"]["images"]["binding_status"] == "digest_mismatch"

    rc, _raw, value = run_observation(
        capsys,
        tmp_path,
        contract_patches(
            binding=binding,
            target=target,
            truth=(truth, checks),
            approval={},
        ),
        requested_target="oc20",
    )
    assert rc == 1
    assert value["result"] == "degraded"
    assert value["observations"]["images"]["binding_status"] == "approval_missing"


@pytest.mark.parametrize(
    "field",
    [
        "retrieval_component_digest",
        "retrieval_binding_digest",
        "retrieval_expected_binding_digest",
        "retrieval_resource_profile_digest",
    ],
)
def test_default_off_rejects_empty_or_unbound_projection_identity(
    capsys, tmp_path: Path, field: str
) -> None:
    truth, checks = runtime_truth()
    truth[field] = ""
    rc, _raw, value = run_observation(
        capsys, tmp_path, contract_patches(truth=(truth, checks))
    )
    assert rc == 1
    runtime = value["observations"]["runtime"]
    assert runtime["status"] == "degraded"
    assert {
        "name": "observation_retrieval_projection_identity",
        "passed": False,
    } in runtime["checks"]


def test_runtime_check_failure_is_observed_without_raw_detail(
    capsys, tmp_path: Path
) -> None:
    truth, checks = runtime_truth()
    checks.append((False, "truth_nas_read_only", "/secret/host/path"))
    rc, raw, value = run_observation(
        capsys, tmp_path, contract_patches(truth=(truth, checks))
    )
    assert rc == 1
    assert value["observations"]["runtime"]["status"] == "degraded"
    assert {"name": "truth_nas_read_only", "passed": False} in value[
        "observations"
    ]["runtime"]["checks"]
    assert "/secret/host/path" not in raw


def test_pending_rollback_is_incomplete_even_when_runtime_is_healthy(
    capsys, tmp_path: Path
) -> None:
    pending = {
        "backup_metadata_sha256": "sha256:" + "a" * 64,
        "backup_name": "20260730T010203+0900",
        "marker_sha256": "sha256:" + "b" * 64,
        "transaction_id": "c" * 64,
    }
    rc, raw, value = run_observation(
        capsys,
        tmp_path,
        contract_patches(pending_transaction=pending),
    )
    assert rc == 1
    assert value["result"] == "incomplete"
    assert value["runtime_state"] == "healthy"
    assert value["transaction_state"] == "pending"
    assert value["terminal_state"] == "unknown"
    assert value["canary_completion_claimed"] is False
    assert value["observations"]["transaction"] == {
        "status": "observed",
        "state": "pending",
        "pending_marker": True,
        **pending,
    }
    assert '"result":"complete"' not in raw


def test_control_or_oversized_runtime_field_fails_surface_closed(
    capsys, tmp_path: Path
) -> None:
    truth, checks = runtime_truth()
    truth["wrapper_image"] = "x" * 4096 + "\nsecret"
    rc, raw, value = run_observation(
        capsys, tmp_path, contract_patches(truth=(truth, checks))
    )
    assert rc == 1
    assert value["observations"]["runtime"] == {
        "status": "unavailable",
        "reason_code": "runtime_truth_invalid",
    }
    assert "secret" not in raw


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("wrapper_image", "DEMO_SECRET@sha256:not-a-digest"),
        ("product_image", "ghcr.io/epicevent/product@sha256:not-a-digest"),
        ("truth_status", "DEMO_SECRET_VALUE"),
        ("runtime_contract", "DEMO_SECRET_VALUE"),
        ("canonical_recipe_name", "DEMO_SECRET_VALUE"),
        ("retrieval_schema", "attacker-controlled/v9"),
        ("retrieval_transport", "attacker_controlled"),
        ("container_nas_root", "/attacker/controlled/path"),
    ],
)
def test_malformed_label_controlled_runtime_fields_fail_closed_without_relay(
    capsys, tmp_path: Path, field: str, value: str
) -> None:
    truth, checks = runtime_truth()
    truth[field] = value
    rc, raw, result = run_observation(
        capsys, tmp_path, contract_patches(truth=(truth, checks))
    )
    assert rc == 1
    assert result["observations"]["runtime"] == {
        "status": "unavailable",
        "reason_code": "runtime_truth_invalid",
    }
    assert "DEMO_SECRET" not in raw
    assert "not-a-digest" not in raw


def test_runtime_recipe_identity_must_match_root_owned_canonical_contract(
    capsys, tmp_path: Path
) -> None:
    patches = list(contract_patches())
    patches[-2] = patch(
        f"{MODULE}.load_canonical_recipe",
        side_effect=ValueError("unknown recipe"),
    )
    rc, raw, result = run_observation(capsys, tmp_path, tuple(patches))
    assert rc == 1
    assert result["observations"]["runtime"] == {
        "status": "unavailable",
        "reason_code": "runtime_truth_invalid",
    }
    assert "unknown recipe" not in raw


def test_disabled_or_alias_target_is_rejected_before_live_observation(
    capsys, tmp_path: Path
) -> None:
    cases = (
        (runtime_binding(enabled=False), "dev-hermes-img", "target_disabled"),
        (runtime_binding(), "dev-hermes-img-alias", "target_alias_not_allowed"),
    )
    for binding, requested_target, reason in cases:
        request = args(tmp_path)
        request.target = requested_target
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}.get_runtime_binding", return_value=binding),
            patch(f"{MODULE}.live_runtime_truth") as live,
        ):
            assert cmd_observation_status(request) == 2
            live.assert_not_called()
        assert json.loads(capsys.readouterr().out)["reason_code"] == reason


def test_manifest_target_mismatch_is_degraded_without_leak(
    capsys, tmp_path: Path
) -> None:
    wrong = replace(runtime_target(), target="oc1", runtime_profile="secret\nprofile")
    rc, raw, value = run_observation(
        capsys, tmp_path, contract_patches(target=wrong)
    )
    assert rc == 1
    assert value["observations"]["rollout"] == {
        "status": "unavailable",
        "reason_code": "runtime_manifest_invalid",
    }
    assert "secret" not in raw


@pytest.mark.parametrize(
    "field",
    ("wrapper_image", "product_image"),
)
def test_malformed_rollout_image_digest_fails_closed_without_relay(
    capsys, tmp_path: Path, field: str
) -> None:
    target = runtime_target()
    target.image_spec[field] = "DEMO_SECRET@sha256:not-a-digest"
    rc, raw, value = run_observation(
        capsys, tmp_path, contract_patches(target=target)
    )
    assert rc == 1
    assert value["observations"]["rollout"] == {
        "status": "unavailable",
        "reason_code": "runtime_manifest_invalid",
    }
    assert "DEMO_SECRET" not in raw
    assert "not-a-digest" not in raw


def test_routing_or_manifest_change_during_observation_is_explicitly_degraded(
    capsys, tmp_path: Path
) -> None:
    first_binding = runtime_binding()
    changed_binding = replace(first_binding, gateway_port=first_binding.gateway_port + 1)
    patches = list(contract_patches())
    patches[1] = patch(
        f"{MODULE}.get_runtime_binding",
        side_effect=[first_binding, changed_binding],
    )
    rc, _raw, value = run_observation(capsys, tmp_path, tuple(patches))
    assert rc == 1
    assert value["result"] == "degraded"
    assert value["observations"]["coherence"] == {
        "status": "changed_during_observation"
    }


def test_transaction_change_during_observation_is_not_mixed_into_one_snapshot(
    capsys, tmp_path: Path
) -> None:
    pending = {
        "backup_metadata_sha256": "sha256:" + "a" * 64,
        "backup_name": "20260730T010203+0900",
        "marker_sha256": "sha256:" + "b" * 64,
        "transaction_id": "c" * 64,
    }
    patches = list(contract_patches())
    patches[-1] = patch(
        f"{MODULE}.pending_rollback_identity",
        side_effect=[pending, None],
    )
    rc, _raw, value = run_observation(capsys, tmp_path, tuple(patches))
    assert rc == 1
    assert value["result"] == "degraded"
    assert value["observations"]["coherence"] == {
        "status": "changed_during_observation"
    }


def test_malformed_approval_does_not_leak_raw_value(capsys, tmp_path: Path) -> None:
    bad = approvals()
    bad["hermes:wrapper"] = {
        "approved_ref": "SECRET\nVALUE",
        "approved_digest": "sha256:" + "2" * 64,
    }
    rc, raw, value = run_observation(
        capsys, tmp_path, contract_patches(approval=bad)
    )
    assert rc == 0
    assert value["result"] == "observed"
    assert value["observations"]["images"]["binding_status"] == (
        "not_required_dev_target"
    )
    assert value["observations"]["images"]["wrapper"] == {
        "status": "not_approved",
    }
    assert "SECRET" not in raw


def test_unexpected_failure_is_generic_and_does_not_leak(capsys, tmp_path: Path) -> None:
    with (
        patch(f"{MODULE}._is_root", return_value=True),
        patch(f"{MODULE}.build_readonly_observation", side_effect=OSError("SECRET")),
    ):
        assert cmd_observation_status(args(tmp_path)) == 2
    raw = capsys.readouterr().out
    assert json.loads(raw)["reason_code"] == "observation_failed_closed"
    assert "SECRET" not in raw


def test_canonical_output_enforces_total_bound() -> None:
    with pytest.raises(ReadonlyObservationError, match="output_bound"):
        _canonical({"payload": "x" * MAX_READONLY_OBSERVATION_BYTES})


def test_command_and_installer_expose_no_generic_execution_or_write_surface() -> None:
    source = (
        Path(__file__).parents[1]
        / "opsctl"
        / "agent_runtime_ops"
        / "commands"
        / "observation.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "docker exec",
        "os.remove",
        "os.unlink",
        "os.replace",
        'open("w',
        "Path.write_",
    ):
        assert forbidden not in source
    install = (Path(__file__).parents[1] / "install.sh").read_text(encoding="utf-8")
    exact = "NOPASSWD: %s observation status *"
    assert install.count(exact) == 1
    assert "observation *" not in install
