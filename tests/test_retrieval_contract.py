from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_runtime_ops.domain.artifact_probe import CommandResult
from agent_runtime_ops.domain.retrieval_contract import (
    RETRIEVAL_LABEL_PREFIX,
    RETRIEVAL_SCHEMA,
    RETRIEVAL_STATUS_SCHEMA,
    bind_retrieval_intent,
    canonical_digest,
    load_retrieval_approvals,
    matched_retrieval_contract,
    retrieval_contract_from_labels,
    retrieval_contract_is_approved,
    run_retrieval_status_probe,
    validate_retrieval_status,
    validate_retrieval_target_binding,
    write_retrieval_approval,
)
from agent_runtime_ops.domain import image_specs
from agent_runtime_ops.state import image_spec_from_manifest


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
REVISION = "8" * 40
HERMES_COMPATIBILITY_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "kwrag_embedded_retrieval"
    / "hermes-compatibility-v1.json"
)


def resource_envelope() -> dict[str, object]:
    values: dict[str, object] = {
        "cpuReservationMillicores": 500,
        "gpuAccess": "none",
        "memoryReservationBytes": 536_870_912,
        "pidsReservation": 64,
    }
    values["profileDigest"] = canonical_digest(values)
    return values


def retrieval_labels(**overrides: str) -> dict[str, str]:
    values = {
        "schema": RETRIEVAL_SCHEMA,
        "component-digest": DIGEST_B,
        "component-manifest-digest": DIGEST_A,
        "contract-digest": DIGEST_C,
        "source-archive-digest": DIGEST_D,
        "source-revision": REVISION,
        "transport": "in_process",
        "default-enabled": "false",
        "host-port-count": "0",
        "nas-read-only": "true",
        "resource.json": json.dumps(resource_envelope(), sort_keys=True, separators=(",", ":")),
        "verify-command.json": json.dumps(
            ["python", "-m", "kwrag.runtime_verify", "--json"], separators=(",", ":")
        ),
    }
    values.update(overrides)
    return {RETRIEVAL_LABEL_PREFIX + key: value for key, value in values.items()}


def capable_spec(*, enabled: bool) -> dict[str, object]:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    return bind_retrieval_intent(
        {"retrieval_contract": contract},
        instance_id="11111111-1111-4111-8111-111111111111",
        family="openclaw",
        runtime_profile_digest=DIGEST_D,
        container_nas_root="/home/node/nas_docs",
        enabled=enabled,
    )


def status_payload(spec: dict[str, object], *, enabled: bool) -> dict[str, object]:
    contract = spec["retrieval_contract"]
    assert isinstance(contract, dict)
    resource = contract["resource"]
    assert isinstance(resource, dict)
    return {
        "schema": RETRIEVAL_STATUS_SCHEMA,
        "componentDigest": contract["component_digest"],
        "bindingDigest": spec["retrieval_binding_digest"],
        "resourceProfileDigest": resource["profileDigest"],
        "consumerHealth": "healthy" if enabled else "disabled",
        "hostPortCount": 0,
        "mountReadOnly": True,
        "resourceStatus": "within_declared_reservation" if enabled else "unavailable",
        "gpuAccessStatus": "none",
        "linkageStatus": "complete" if enabled else "not_applicable",
        "operationReceiptDigest": DIGEST_A if enabled else None,
        "resultReceiptDigest": DIGEST_B if enabled else None,
        "consumptionReceiptDigest": DIGEST_C if enabled else None,
        "revocationStatus": None if enabled else "complete",
    }


def test_exact_hermes_compatibility_fixture_matches_product_and_ops_contract() -> None:
    raw = HERMES_COMPATIBILITY_FIXTURE.read_text(encoding="utf-8")
    fixture = json.loads(raw)
    assert raw == json.dumps(
        fixture,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    assert set(fixture) == {
        "capabilityContractSourceRevision",
        "capabilityLabels",
        "componentManifest",
        "fixtureSchema",
        "productFamily",
        "productSourceRevision",
        "statusFixtures",
        "verificationBoundary",
        "verifierArgv",
    }
    assert fixture["fixtureSchema"] == (
        "jitech-embedded-retrieval-hermes-compatibility-fixture/v1"
    )
    assert fixture["productFamily"] == "hermes"
    assert fixture["capabilityContractSourceRevision"] == (
        "78bd91c3139fa6ba64c021252a81ad3ec628ca3d"
    )
    assert fixture["productSourceRevision"] == (
        "cb1611b44d0c66848a3d9931c9f6ccd7577e9b26"
    )

    labels = fixture["capabilityLabels"]
    contract = matched_retrieval_contract(labels, labels)
    assert contract is not None
    assert contract["component_digest"] == (
        "sha256:7f6e4ace39c8d868e0517040be0a82742b791dd44744afdae66d54e596b25478"
    )
    assert contract["component_manifest_digest"] == (
        "sha256:c1e0e8ed1462db8663d8063e4e97ba4530c4f1a7bf3f24a514807eb56c19baf6"
    )
    assert contract["source_archive_digest"] == (
        "sha256:6c04a7d297410708a0300b3ab3193e047c950c924bc7edc6d4ae7ae127efb97a"
    )
    assert contract["contract_digest"] == (
        "sha256:ccf826f0fe6f7edc36b6d5eacdee87277859d2f6dae3a4ea4cab5f51cba183db"
    )
    assert contract["resource"]["profileDigest"] == (
        "sha256:2d4ff46a2d76e712421a9758ecb0ae1d262e2d42ea00cee888c103477e6709ed"
    )
    assert contract["verify_argv"] == fixture["verifierArgv"] == [
        "hermes",
        "kwrag-slot",
        "status",
        "--json",
    ]

    manifest = fixture["componentManifest"]
    manifest_raw = (
        json.dumps(
            manifest,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    assert "sha256:" + hashlib.sha256(manifest_raw).hexdigest() == (
        contract["component_manifest_digest"]
    )
    assert manifest["component_wheel"]["sha256"] == contract["component_digest"]
    assert manifest["component_source_archive"]["sha256"] == (
        contract["source_archive_digest"]
    )
    assert manifest["contract_collection_digest"] == contract["contract_digest"]
    assert manifest["component_source_revision"] == contract["source_revision"]

    status_fixtures = fixture["statusFixtures"]
    common = {
        "expected_component_digest": contract["component_digest"],
        "expected_binding_digest": "sha256:" + "d" * 64,
        "expected_resource_profile_digest": contract["resource"]["profileDigest"],
        "expected_gpu_access": "none",
    }
    validate_retrieval_status(status_fixtures["enabledContract"], enabled=True, **common)
    validate_retrieval_status(status_fixtures["disabled"], enabled=False, **common)
    assert fixture["verificationBoundary"] == {
        "canaryTargetSelected": False,
        "liveEnabledInvocationObserved": False,
        "localNetworklessInvocationObserved": True,
        "runtimeMutationObserved": False,
    }


def test_hermes_enabled_compatibility_fixture_does_not_relax_live_evidence_gate() -> None:
    fixture = json.loads(HERMES_COMPATIBILITY_FIXTURE.read_text(encoding="utf-8"))
    labels = fixture["capabilityLabels"]
    contract = retrieval_contract_from_labels(labels)
    assert contract is not None
    unavailable = dict(fixture["statusFixtures"]["enabledContract"])
    unavailable["resourceStatus"] = "unavailable"
    with pytest.raises(ValueError, match="resource observation is unavailable"):
        validate_retrieval_status(
            unavailable,
            expected_component_digest=contract["component_digest"],
            expected_binding_digest="sha256:" + "d" * 64,
            expected_resource_profile_digest=contract["resource"]["profileDigest"],
            expected_gpu_access="none",
            enabled=True,
        )


def test_capability_is_default_off_in_process_and_resource_digest_bound() -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    assert contract["default_enabled"] is False
    assert contract["transport"] == "in_process"
    assert contract["host_port_count"] == 0
    assert contract["nas_read_only"] is True
    assert contract["resource"] == resource_envelope()


@pytest.mark.parametrize(
    "overrides",
    [
        {"transport": "http"},
        {"default-enabled": "true"},
        {"host-port-count": "1"},
        {"nas-read-only": "false"},
        {"verify-command.json": '["sh","-c","curl example.com"]'},
    ],
)
def test_capability_rejects_transport_network_and_shell_shapes(overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        retrieval_contract_from_labels(retrieval_labels(**overrides))


def test_resource_profile_digest_cannot_be_claimed_without_matching_fields() -> None:
    resource = resource_envelope()
    resource["memoryReservationBytes"] = int(resource["memoryReservationBytes"]) + 1
    with pytest.raises(ValueError, match="profileDigest"):
        retrieval_contract_from_labels(
            retrieval_labels(
                **{"resource.json": json.dumps(resource, sort_keys=True, separators=(",", ":"))}
            )
        )


def test_partial_unknown_and_noncanonical_capability_labels_fail_closed() -> None:
    partial = retrieval_labels()
    partial.pop(RETRIEVAL_LABEL_PREFIX + "schema")
    with pytest.raises(ValueError, match="incomplete"):
        retrieval_contract_from_labels(partial)
    unknown = retrieval_labels()
    unknown[RETRIEVAL_LABEL_PREFIX + "backend"] = "dense"
    with pytest.raises(ValueError, match="unexpected"):
        retrieval_contract_from_labels(unknown)
    noncanonical = retrieval_labels(
        **{"verify-command.json": '["python", "-m", "kwrag.runtime_verify", "--json"]'}
    )
    with pytest.raises(ValueError, match="canonical"):
        retrieval_contract_from_labels(noncanonical)


def test_binding_is_target_specific_and_enabling_requires_capability() -> None:
    left = capable_spec(enabled=True)
    right = bind_retrieval_intent(
        {"retrieval_contract": left["retrieval_contract"]},
        instance_id="22222222-2222-4222-8222-222222222222",
        family="openclaw",
        runtime_profile_digest=DIGEST_D,
        container_nas_root="/home/node/nas_docs",
        enabled=True,
    )
    assert left["retrieval_binding_digest"] != right["retrieval_binding_digest"]
    assert left["retrieval_component_digest"] == DIGEST_B
    with pytest.raises(ValueError, match="declares no capability"):
        bind_retrieval_intent(
            {},
            instance_id="x",
            family="openclaw",
            runtime_profile_digest=DIGEST_D,
            container_nas_root="/home/node/nas_docs",
            enabled=True,
        )
    validate_retrieval_target_binding(
        left,
        instance_id="11111111-1111-4111-8111-111111111111",
        family="openclaw",
        runtime_profile_digest=DIGEST_D,
        container_nas_root="/home/node/nas_docs",
    )
    with pytest.raises(ValueError, match="instanceId"):
        validate_retrieval_target_binding(
            left,
            instance_id="33333333-3333-4333-8333-333333333333",
            family="openclaw",
            runtime_profile_digest=DIGEST_D,
            container_nas_root="/home/node/nas_docs",
        )


def test_direct_image_tuple_requires_exact_wrapper_product_component_contract() -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    recipe = {
        "family": "openclaw",
        "product_component": "openclaw-control",
        "wrapper_component": "openclaw-wrapper",
        "canonical_recipe_name": "openclaw-control",
        "canonical_recipe_digest": DIGEST_D,
        "runtime_profiles": {"customer": "openclaw-customer", "dev": "openclaw-dev"},
        "retrieval_contract": contract,
    }
    wrapper = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "1" * 64
    product = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "2" * 64
    with (
        patch.object(image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe),
        patch.object(image_specs, "image_recipe_labels_from_wrapper", return_value=retrieval_labels()),
    ):
        spec = image_specs.image_spec_from_direct_images(wrapper, product)
    assert spec["retrieval_contract"] == contract

    product_labels = retrieval_labels(**{"component-digest": DIGEST_A})
    with (
        patch.object(image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe),
        patch.object(image_specs, "image_recipe_labels_from_wrapper", return_value=product_labels),
        pytest.raises(ValueError, match="do not match"),
    ):
        image_specs.image_spec_from_direct_images(wrapper, product)


def test_status_is_content_free_exact_and_distinguishes_linkage_from_revocation() -> None:
    enabled = capable_spec(enabled=True)
    assert validate_retrieval_status(
        status_payload(enabled, enabled=True),
        expected_component_digest=DIGEST_B,
        expected_binding_digest=str(enabled["retrieval_binding_digest"]),
        expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
        expected_gpu_access="none",
        enabled=True,
    )["linkageStatus"] == "complete"
    disabled = capable_spec(enabled=False)
    assert validate_retrieval_status(
        status_payload(disabled, enabled=False),
        expected_component_digest=DIGEST_B,
        expected_binding_digest=str(disabled["retrieval_binding_digest"]),
        expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
        expected_gpu_access="none",
        enabled=False,
    )["revocationStatus"] == "complete"
    raw = status_payload(enabled, enabled=True)
    raw["query"] = "must never cross the boundary"
    with pytest.raises(ValueError, match="unexpected fields"):
        validate_retrieval_status(
            raw,
            expected_component_digest=DIGEST_B,
            expected_binding_digest=str(enabled["retrieval_binding_digest"]),
            expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
            expected_gpu_access="none",
            enabled=True,
        )


def test_private_runtime_manifest_round_trips_component_binding_without_public_schema_change() -> None:
    spec = capable_spec(enabled=True)
    manifest = {
        "family": "openclaw",
        "image_name": "direct-image",
        "wrapper_image": "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "1" * 64,
        "product_image": "ghcr.io/epicevent/openclaw-jitech@sha256:" + "2" * 64,
        "retrieval_component_digest": spec["retrieval_component_digest"],
        "retrieval_enabled": True,
        "retrieval_binding_digest": spec["retrieval_binding_digest"],
        "recipe": {
            "retrieval_contract": spec["retrieval_contract"],
            "retrieval_binding": spec["retrieval_binding"],
            "retrieval_binding_digest": spec["retrieval_binding_digest"],
            "retrieval_enabled": True,
        },
    }
    loaded = image_spec_from_manifest(manifest)
    assert loaded["retrieval_contract"] == spec["retrieval_contract"]
    assert loaded["retrieval_binding"] == spec["retrieval_binding"]
    assert loaded["retrieval_binding_digest"] == spec["retrieval_binding_digest"]
    assert loaded["retrieval_enabled"] is True

    tampered_contract = dict(spec["retrieval_contract"])
    tampered_contract["verify_argv"] = ["sh", "-c", "cat /run/secrets/*"]
    manifest["recipe"] = dict(manifest["recipe"])
    manifest["recipe"]["retrieval_contract"] = tampered_contract
    with pytest.raises(ValueError):
        image_spec_from_manifest(manifest)

    manifest["recipe"]["retrieval_contract"] = spec["retrieval_contract"]
    manifest["retrieval_binding_digest"] = DIGEST_A
    with pytest.raises(ValueError, match="canonical digest"):
        image_spec_from_manifest(manifest)


def test_every_runtime_profile_projects_same_in_process_binding_labels() -> None:
    profile_root = Path(__file__).parents[1] / "profiles" / "runtime"
    templates = sorted(profile_root.glob("*/compose.yml.tpl"))
    assert len(templates) == 8
    required = {
        'agent-runtime.retrieval-enabled: "{{ retrieval_enabled }}"',
        'agent-runtime.retrieval-component-digest: "{{ retrieval_component_digest }}"',
        'agent-runtime.retrieval-binding-digest: "{{ retrieval_binding_digest }}"',
        'agent-runtime.retrieval-resource-profile-digest: "{{ retrieval_resource_profile_digest }}"',
    }
    for template in templates:
        text = template.read_text(encoding="utf-8")
        assert all(item in text for item in required)
        assert "retrieval_image" not in text
        assert "kwrag_net" not in text


def test_probe_uses_fixed_docker_exec_argv_and_bounded_content_free_output() -> None:
    spec = capable_spec(enabled=True)
    seen: list[object] = []

    def runner(argv: list[str], *, timeout: int, output_limit: int) -> CommandResult:
        seen.extend([argv, timeout, output_limit])
        return CommandResult(
            0,
            json.dumps(
                status_payload(spec, enabled=True),
                sort_keys=True,
                separators=(",", ":"),
            ).encode(),
            b"",
        )

    result = run_retrieval_status_probe("container-id", spec, runner=runner)
    assert result is not None and result["consumerHealth"] == "healthy"
    assert seen[0] == [
        "docker",
        "exec",
        "container-id",
        "python",
        "-m",
        "kwrag.runtime_verify",
        "--json",
    ]
    assert seen[1] == 15
    assert seen[2] == 64 * 1024


def test_component_approval_is_separate_exact_product_binding(tmp_path: Path) -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    write_retrieval_approval(
        tmp_path, "openclaw", contract, product_image_digest=DIGEST_D
    )
    approvals = load_retrieval_approvals(tmp_path)
    assert approvals["openclaw"]["component_digest"] == DIGEST_B
    assert retrieval_contract_is_approved(
        tmp_path, "openclaw", contract, product_image_digest=DIGEST_D
    )
    assert not retrieval_contract_is_approved(
        tmp_path, "openclaw", contract, product_image_digest=DIGEST_A
    )


def test_cli_surface_has_enable_flag_but_no_third_image_or_policy_inputs() -> None:
    cli_source = (
        Path(__file__).parents[1] / "opsctl" / "agent_runtime_ops" / "cli.py"
    ).read_text(encoding="utf-8")
    assert cli_source.count('"--retrieval-enabled"') == 3
    assert "retrieval-image" not in cli_source
    assert "retrieval-network" not in cli_source
    assert "retrieval-backend" not in cli_source
    assert "retrieval-query" not in cli_source


def test_apply_and_rollback_gate_terminal_receipts_before_success() -> None:
    repo = Path(__file__).parents[1]
    apply_source = (
        repo / "opsctl" / "agent_runtime_ops" / "domain" / "runtime_apply.py"
    ).read_text(encoding="utf-8")
    probe_index = apply_source.index("run_retrieval_status_probe(")
    manifest_index = apply_source.index("write_slot_manifests(", probe_index)
    success_index = apply_source.index('print("apply_status=ok")', manifest_index)
    assert probe_index < manifest_index < success_index
    assert "retrieval_postcondition_failed" in apply_source
    assert "restore_backup(desired.slot, runtime_dir, backup_dir, state_root)" in apply_source[
        probe_index:manifest_index
    ]

    rollback_source = (
        repo / "opsctl" / "agent_runtime_ops" / "commands" / "apply.py"
    ).read_text(encoding="utf-8")
    rollback_probe = rollback_source.index("run_retrieval_status_probe(")
    rollback_success = rollback_source.index('print("rollback_status=ok")')
    assert rollback_probe < rollback_success
    assert "retrieval_disable_observation_failed" in rollback_source
