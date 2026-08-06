from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.domain.artifact_probe import CommandResult
from agent_runtime_ops.domain.retrieval_contract import (
    ATTACHMENT_PROOF_MODE,
    BINDING_V2_SCHEMA,
    RETRIEVAL_LABEL_PREFIX,
    RETRIEVAL_ATTACHMENT_STATUS_SCHEMA,
    RETRIEVAL_SCHEMA,
    RETRIEVAL_STATUS_SCHEMA,
    bind_retrieval_attachment_intent,
    bind_retrieval_intent,
    canonical_digest,
    load_retrieval_approvals,
    matched_retrieval_contract,
    parse_retrieval_status_output,
    retrieval_attachment_contract_from_labels,
    retrieval_contract_from_labels,
    retrieval_contract_is_approved,
    retrieval_env,
    require_retrieval_approval,
    run_retrieval_status_probe,
    validate_bound_retrieval_spec,
    validate_retrieval_attachment_status,
    validate_retrieval_status_for_spec,
    validate_retrieval_status,
    validate_retrieval_target_binding,
    write_retrieval_approval,
)
from agent_runtime_ops.domain import image_specs, runtime_targets
from agent_runtime_ops.commands.retrieval import cmd_retrieval_approve
from agent_runtime_ops.domain.runtime_manifest import desired_from_runtime_manifest
from agent_runtime_ops.routing import RuntimeBinding
from agent_runtime_ops.state import RuntimeTarget
from agent_runtime_ops.state import image_spec_from_manifest


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
DIGEST_F = "sha256:" + "f" * 64
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
        "resource.json": json.dumps(
            resource_envelope(), sort_keys=True, separators=(",", ":")
        ),
        "verify-command.json": json.dumps(
            ["hermes", "kwrag-slot", "status", "--json"], separators=(",", ":")
        ),
    }
    values.update(overrides)
    return {RETRIEVAL_LABEL_PREFIX + key: value for key, value in values.items()}


def hermes_p1_labels(**overrides: str) -> dict[str, str]:
    values = {
        "attachment-decision-digest": (
            "sha256:fd4d1068407d0b28d41e7813f8cef7b193a5fe43f39db166588911e6fde3bbb5"
        ),
        "caller-explicit": "true",
        "component-manifest-digest": DIGEST_E,
        "component-wheel-digest": DIGEST_F,
        "default-enabled": "false",
        "status-schema": RETRIEVAL_ATTACHMENT_STATUS_SCHEMA,
        "verify-command.json": json.dumps(
            ["hermes", "kwrag-slot", "p1-attachment-status", "--json"],
            separators=(",", ":"),
        ),
    }
    values.update(overrides)
    return {
        "com.epicevent.hermes.kwrag.p1." + key: value for key, value in values.items()
    }


def openclaw_p1_labels(**overrides: str) -> dict[str, str]:
    values = {
        key.removeprefix("com.epicevent.hermes.kwrag.p1."): value
        for key, value in hermes_p1_labels().items()
    }
    values.update(
        {
            "python-runtime-digest": "sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b",
            "python-version": "3.12.13",
            "verify-command.json": '["openclaw","kwrag-p0","p1-attachment-status","--json"]',
            **overrides,
        }
    )
    return {
        "com.epicevent.openclaw.kwrag.p1." + key: value for key, value in values.items()
    }


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


def p1_identity() -> dict[str, object]:
    return {
        "status": "research_selected_p1_attachment_probe_candidate",
        "pipelineFactoryDigest": (
            "sha256:0dbe54f5a8bc56a6c821e181a0dc6cfda85d25be8cea6a01235cb5e347782f0e"
        ),
        "backendId": "slot-local-fts5-trigram-or-attachment-v1",
        "pipelineFingerprint": (
            "sha256:53e14752cc9d147dfb4129e00234d1c7fb9f6558df00da7c03189db8da8e4606"
        ),
        "researchDecisionDigest": (
            "sha256:81e6f4d83e6cde6a9c83a9aa435c65354a1122dded735bf607462c3497e9b25d"
        ),
    }


def attachment_data() -> dict[str, object]:
    return {
        "databaseSha256": DIGEST_A,
        "indexManifestDigest": DIGEST_B,
        "sourceSnapshotDigest": DIGEST_C,
        "readOnlyAuthorityReceiptDigest": DIGEST_D,
        "slotRuntimeBindingDigest": "sha256:" + "e" * 64,
    }


def attachment_spec(*, enabled: bool) -> dict[str, object]:
    contract = retrieval_contract_from_labels(retrieval_labels())
    attachment_contract = retrieval_attachment_contract_from_labels(
        hermes_p1_labels(), family="hermes"
    )
    assert contract is not None and attachment_contract is not None
    return bind_retrieval_attachment_intent(
        {
            "retrieval_contract": contract,
            "retrieval_attachment_contract": attachment_contract,
        },
        instance_id="11111111-1111-4111-8111-111111111111",
        family="hermes",
        runtime_profile_digest=DIGEST_D,
        container_nas_root="/workspace/nas_docs",
        enabled=enabled,
        p1_identity=p1_identity(),
        attachment_data=attachment_data() if enabled else None,
        expected_source_generation=DIGEST_C,
    )


def attachment_status_payload(
    spec: dict[str, object], *, enabled: bool
) -> dict[str, object]:
    binding = spec["retrieval_binding"]
    assert isinstance(binding, dict)
    data = binding["attachmentData"]
    return {
        "schema": RETRIEVAL_ATTACHMENT_STATUS_SCHEMA,
        "proofMode": ATTACHMENT_PROOF_MODE,
        "enabled": enabled,
        "componentDigest": binding["componentDigest"],
        "bindingDigest": spec["retrieval_binding_digest"],
        "resourceProfileDigest": binding["resourceProfileDigest"],
        "p1IdentityDigest": canonical_digest(binding["p1Identity"]),
        "attachmentDataDigest": canonical_digest(data) if enabled else None,
        "hostPortCount": 0,
        "mountReadOnly": True,
        "attachmentHealth": "healthy" if enabled else "disabled",
        "resourceStatus": ("within_declared_reservation" if enabled else "unavailable"),
        "gpuAccessStatus": "none",
        "operationReceiptDigest": DIGEST_A if enabled else None,
        "resultReceiptDigest": DIGEST_B if enabled else None,
        "consumptionReceiptDigest": DIGEST_C if enabled else None,
        "consumptionStatus": "not_consumed" if enabled else "not_applicable",
        "linkageStatus": "complete" if enabled else "not_applicable",
        "revocationStatus": None if enabled else "complete",
    }


def test_exact_hermes_compatibility_fixture_matches_product_and_ops_contract() -> None:
    raw = HERMES_COMPATIBILITY_FIXTURE.read_text(encoding="utf-8")
    fixture = json.loads(raw)
    assert (
        raw
        == json.dumps(
            fixture,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
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
        "3bb3a11478818022e7e9a2f30be79b4d0406c956"
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
    assert (
        contract["verify_argv"]
        == fixture["verifierArgv"]
        == [
            "hermes",
            "kwrag-slot",
            "status",
            "--json",
        ]
    )

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
    assert (
        "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
        == (contract["component_manifest_digest"])
    )
    assert manifest["component_wheel"]["sha256"] == contract["component_digest"]
    assert (
        manifest["component_source_archive"]["sha256"]
        == (contract["source_archive_digest"])
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
    validate_retrieval_status(
        status_fixtures["enabledContract"], enabled=True, **common
    )
    validate_retrieval_status(status_fixtures["disabled"], enabled=False, **common)
    assert fixture["verificationBoundary"] == {
        "canaryTargetSelected": False,
        "liveEnabledInvocationObserved": False,
        "localNetworklessInvocationObserved": True,
        "runtimeMutationObserved": False,
    }


def test_hermes_wrapper_workflow_executes_optional_disabled_retrieval_contract() -> (
    None
):
    workflow = (
        Path(__file__).parent.parent
        / ".github"
        / "workflows"
        / "publish-hermes-wrapper.yml"
    ).read_text(encoding="utf-8")
    assert "retrieval_label_count" in workflow
    assert "agent-runtime[.]retrieval[.]" in workflow
    assert "if (( retrieval_label_count > 0 )); then" in workflow
    assert "retrieval_schema=" not in workflow
    assert (
        "matched_retrieval_contract(labels(sys.argv[1]), labels(sys.argv[2]))"
        in workflow
    )
    assert (
        'contract["verify_argv"] != ["hermes", "kwrag-slot", "status", "--json"]'
        in workflow
    )
    assert 'docker pull "${{ inputs.product_image }}" >/dev/null' in workflow
    assert "--network none" in workflow
    assert "--read-only" in workflow
    assert "dst=/workspace/nas_docs,readonly" in workflow
    assert "JITECH_RETRIEVAL_ENABLED=false" in workflow
    assert '"$image_ref" kwrag-slot status --json > retrieval-status.json' in workflow
    assert "validate_retrieval_status(" in workflow
    assert 'parse_retrieval_status_output(open(sys.argv[2], "rb").read())' in workflow
    assert "enabled=False" in workflow


def test_hermes_enabled_compatibility_fixture_does_not_relax_live_evidence_gate() -> (
    None
):
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
        {"verify-command.json": '["sh","-c","id"]'},
    ],
)
def test_capability_rejects_transport_network_and_shell_shapes(
    overrides: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        retrieval_contract_from_labels(retrieval_labels(**overrides))


def test_resource_profile_digest_cannot_be_claimed_without_matching_fields() -> None:
    resource = resource_envelope()
    resource["memoryReservationBytes"] = int(resource["memoryReservationBytes"]) + 1
    with pytest.raises(ValueError, match="profileDigest"):
        retrieval_contract_from_labels(
            retrieval_labels(
                **{
                    "resource.json": json.dumps(
                        resource, sort_keys=True, separators=(",", ":")
                    )
                }
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
        **{"verify-command.json": '["hermes", "kwrag-slot", "status", "--json"]'}
    )
    with pytest.raises(ValueError, match="canonical"):
        retrieval_contract_from_labels(noncanonical)


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "id"],
        ["python", "-m", "kwrag.runtime_verify", "--json"],
        ["curl", "https://example.com"],
        ["cat", "/etc/shadow"],
    ],
)
def test_capability_rejects_unapproved_product_verifier_argv(argv: list[str]) -> None:
    with pytest.raises(ValueError, match="allowed product verifier"):
        retrieval_contract_from_labels(
            retrieval_labels(
                **{"verify-command.json": json.dumps(argv, separators=(",", ":"))}
            )
        )


def test_capability_accepts_only_exact_hermes_product_verifier() -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    assert contract["verify_argv"] == ["hermes", "kwrag-slot", "status", "--json"]


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


@pytest.mark.parametrize("enabled", [False, True])
def test_attachment_binding_v2_is_exact_private_and_canonical(enabled: bool) -> None:
    spec = attachment_spec(enabled=enabled)
    binding = spec["retrieval_binding"]
    assert isinstance(binding, dict)
    assert binding["schema"] == BINDING_V2_SCHEMA
    assert binding["proofMode"] == ATTACHMENT_PROOF_MODE
    assert binding["expected_source_generation"] == DIGEST_C
    assert binding["p1Identity"] == p1_identity()
    assert binding["attachmentData"] == (attachment_data() if enabled else None)
    assert spec["retrieval_binding_digest"] == canonical_digest(binding)
    validate_bound_retrieval_spec(spec)


@pytest.mark.parametrize("enabled", [False, True])
def test_attachment_binding_v2_requires_generation_pin(enabled: bool) -> None:
    spec = attachment_spec(enabled=enabled)
    binding = dict(spec["retrieval_binding"])
    binding.pop("expected_source_generation")
    spec["retrieval_binding"] = binding
    spec["retrieval_binding_digest"] = canonical_digest(binding)
    with pytest.raises(ValueError, match="unexpected fields"):
        validate_bound_retrieval_spec(spec)


def test_attachment_binding_v2_rejects_generation_mismatch() -> None:
    spec = attachment_spec(enabled=True)
    binding = dict(spec["retrieval_binding"])
    binding["expected_source_generation"] = DIGEST_D
    spec["retrieval_binding"] = binding
    spec["retrieval_binding_digest"] = canonical_digest(binding)
    with pytest.raises(ValueError, match="does not match attachment"):
        validate_bound_retrieval_spec(spec)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("proofMode", "prompt_consumed", "proof mode"),
        ("containerNasRoot", "/tmp/nas", "container NAS root"),
        ("mountReadOnly", False, "read-only"),
        ("hostPortCount", 1, "host-port"),
    ],
)
def test_attachment_binding_v2_rejects_boundary_drift(
    field: str, value: object, message: str
) -> None:
    spec = attachment_spec(enabled=True)
    binding = dict(spec["retrieval_binding"])
    binding[field] = value
    spec["retrieval_binding"] = binding
    spec["retrieval_binding_digest"] = canonical_digest(binding)
    with pytest.raises(ValueError, match=message):
        validate_bound_retrieval_spec(spec)


def test_attachment_binding_v2_rejects_mixed_and_disabled_live_data() -> None:
    enabled = attachment_spec(enabled=True)
    binding = dict(enabled["retrieval_binding"])
    binding.pop("p1Identity")
    binding["consumerHealth"] = "healthy"
    enabled["retrieval_binding"] = binding
    enabled["retrieval_binding_digest"] = canonical_digest(binding)
    with pytest.raises(ValueError, match="unexpected fields"):
        validate_bound_retrieval_spec(enabled)

    disabled = attachment_spec(enabled=False)
    disabled_binding = dict(disabled["retrieval_binding"])
    disabled_binding["attachmentData"] = attachment_data()
    disabled["retrieval_binding"] = disabled_binding
    disabled["retrieval_binding_digest"] = canonical_digest(disabled_binding)
    with pytest.raises(ValueError, match="must not contain attachment data"):
        validate_bound_retrieval_spec(disabled)


def test_attachment_binding_v2_rejects_selected_p1_identity_drift() -> None:
    spec = attachment_spec(enabled=True)
    binding = dict(spec["retrieval_binding"])
    identity = dict(binding["p1Identity"])
    identity["backendId"] = "another-backend"
    binding["p1Identity"] = identity
    spec["retrieval_binding"] = binding
    spec["retrieval_binding_digest"] = canonical_digest(binding)
    with pytest.raises(ValueError, match="selected contract"):
        validate_bound_retrieval_spec(spec)


@pytest.mark.parametrize("enabled", [False, True])
def test_attachment_status_is_exact_diagnostic_checkpoint_not_canary_success(
    enabled: bool,
) -> None:
    spec = attachment_spec(enabled=enabled)
    status = attachment_status_payload(spec, enabled=enabled)
    validated = validate_retrieval_attachment_status(status, image_spec=spec)
    assert validated["consumptionStatus"] == (
        "not_consumed" if enabled else "not_applicable"
    )
    assert "canarySuccess" not in validated
    assert validate_retrieval_status_for_spec(status, spec) == validated

    generic = status_payload(capable_spec(enabled=enabled), enabled=enabled)
    with pytest.raises(ValueError, match="unexpected fields"):
        validate_retrieval_status_for_spec(generic, spec)
    status["unexpectedSensitiveField"] = "must-not-escape"
    with pytest.raises(ValueError, match="unexpected fields"):
        validate_retrieval_attachment_status(status, image_spec=spec)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("p1IdentityDigest", DIGEST_D, "p1IdentityDigest"),
        ("attachmentDataDigest", DIGEST_D, "data digest"),
        ("mountReadOnly", False, "port/mount"),
        ("consumptionStatus", "prompt_consumed", "overclaims"),
        ("linkageStatus", "not_applicable", "linkage"),
    ],
)
def test_enabled_attachment_status_rejects_identity_boundary_and_claim_drift(
    field: str, value: object, message: str
) -> None:
    spec = attachment_spec(enabled=True)
    status = attachment_status_payload(spec, enabled=True)
    status[field] = value
    with pytest.raises(ValueError, match=message):
        validate_retrieval_attachment_status(status, image_spec=spec)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("componentDigest", None),
        ("bindingDigest", None),
        ("resourceProfileDigest", None),
        ("p1IdentityDigest", None),
        ("attachmentDataDigest", DIGEST_A),
        ("operationReceiptDigest", DIGEST_A),
        ("mountReadOnly", False),
    ],
)
def test_disabled_attachment_status_requires_capability_and_zero_dispatch(
    field: str, value: object
) -> None:
    spec = attachment_spec(enabled=False)
    status = attachment_status_payload(spec, enabled=False)
    status[field] = value
    with pytest.raises(ValueError):
        validate_retrieval_attachment_status(status, image_spec=spec)


def test_attachment_probe_uses_exact_landed_hermes_product_interface() -> None:
    spec = attachment_spec(enabled=False)
    calls: list[list[str]] = []

    def runner(argv: list[str], **_: object) -> CommandResult:
        calls.append(argv)
        return CommandResult(
            0,
            json.dumps(
                attachment_status_payload(spec, enabled=False),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            + b"\n",
            b"",
        )

    status = run_retrieval_status_probe("container-id", spec, runner=runner)
    assert status is not None and status["attachmentHealth"] == "disabled"
    assert calls == [
        [
            "docker",
            "exec",
            "container-id",
            "hermes",
            "kwrag-slot",
            "p1-attachment-status",
            "--json",
        ]
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("caller-explicit", "false"),
        ("default-enabled", "true"),
        ("status-schema", RETRIEVAL_STATUS_SCHEMA),
        ("verify-command.json", '["sh","-c","id"]'),
    ],
)
def test_hermes_attachment_label_contract_rejects_policy_or_argv_drift(
    field: str, value: str
) -> None:
    with pytest.raises(ValueError):
        retrieval_attachment_contract_from_labels(
            hermes_p1_labels(**{field: value}), family="hermes"
        )


def test_openclaw_attachment_label_contract_binds_python_and_fixed_argv() -> None:
    contract = retrieval_attachment_contract_from_labels(
        openclaw_p1_labels(), family="openclaw"
    )
    assert contract is not None
    assert contract["verify_argv"] == [
        "openclaw",
        "kwrag-p0",
        "p1-attachment-status",
        "--json",
    ]
    with pytest.raises(ValueError, match="Python runtime identity"):
        retrieval_attachment_contract_from_labels(
            openclaw_p1_labels(**{"python-version": "3.12.14"}),
            family="openclaw",
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
        patch.object(
            image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe
        ),
        patch.object(
            image_specs,
            "image_recipe_labels_from_wrapper",
            return_value=retrieval_labels(),
        ),
    ):
        spec = image_specs.image_spec_from_direct_images(wrapper, product)
    assert spec["retrieval_contract"] == contract

    product_labels = retrieval_labels(**{"component-digest": DIGEST_A})
    with (
        patch.object(
            image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe
        ),
        patch.object(
            image_specs, "image_recipe_labels_from_wrapper", return_value=product_labels
        ),
        pytest.raises(ValueError, match="do not match"),
    ):
        image_specs.image_spec_from_direct_images(wrapper, product)


def test_direct_hermes_image_tuple_requires_matching_landed_attachment_contract() -> (
    None
):
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    recipe = {
        "family": "hermes",
        "product_component": "hermes-runtime",
        "wrapper_component": "hermes-wrapper",
        "canonical_recipe_name": "hermes-runtime",
        "canonical_recipe_digest": DIGEST_D,
        "runtime_profiles": {
            "customer": "hermes-runtime-customer",
            "dev": "hermes-runtime-dev",
        },
        "retrieval_contract": contract,
    }
    wrapper = "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "1" * 64
    product = "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64
    exact_labels = retrieval_labels() | hermes_p1_labels()
    with (
        patch.object(
            image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe
        ),
        patch.object(
            image_specs,
            "image_recipe_labels_from_wrapper",
            side_effect=[exact_labels, exact_labels],
        ),
    ):
        spec = image_specs.image_spec_from_direct_images(wrapper, product)
    assert spec["retrieval_attachment_contract"]["verify_argv"] == [
        "hermes",
        "kwrag-slot",
        "p1-attachment-status",
        "--json",
    ]
    assert (
        spec["retrieval_attachment_contract"]["component_wheel_digest"]
        != spec["retrieval_contract"]["component_digest"]
    )
    assert (
        spec["retrieval_attachment_contract"]["component_manifest_digest"]
        != spec["retrieval_contract"]["component_manifest_digest"]
    )

    drifted_product = retrieval_labels() | hermes_p1_labels(
        **{"component-wheel-digest": DIGEST_C}
    )
    with (
        patch.object(
            image_specs, "image_recipe_from_wrapper_image_auto", return_value=recipe
        ),
        patch.object(
            image_specs,
            "image_recipe_labels_from_wrapper",
            side_effect=[exact_labels, drifted_product],
        ),
        pytest.raises(ValueError, match="attachment provenance"),
    ):
        image_specs.image_spec_from_direct_images(wrapper, product)


def test_direct_hermes_target_projects_disabled_v2_and_requires_enabled_data(
    tmp_path: Path,
) -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    attachment_contract = retrieval_attachment_contract_from_labels(
        hermes_p1_labels(), family="hermes"
    )
    assert contract is not None and attachment_contract is not None
    spec = {
        "family": "hermes",
        "retrieval_contract": contract,
        "retrieval_attachment_contract": attachment_contract,
        "image_recipe": {
            "family": "hermes",
            "runtime_profiles": {"customer": "hermes-runtime-customer"},
        },
    }
    route = RuntimeBinding(
        instance_id="11111111-1111-4111-8111-111111111111",
        linux_account="oc20",
        public_host="oc20.ji-tech.co.kr",
        family="hermes",
        runtime_class="customer",
        gateway_port=30689,
        bridge_port=30690,
    )
    profile = SimpleNamespace(
        name="hermes-runtime-customer",
        digest=DIGEST_D,
        metadata={
            "family": "hermes",
            "slot_class": "customer",
            "container_nas_root": "/workspace/nas_docs",
        },
    )
    with (
        patch.object(runtime_targets, "get_runtime_binding", return_value=route),
        patch.object(runtime_targets, "load_profile", return_value=profile),
    ):
        disabled, _ = runtime_targets.desired_from_direct_images(
            "oc20", spec, tmp_path, retrieval_source_generation=DIGEST_C
        )
        assert disabled.image_spec["retrieval_binding"]["schema"] == BINDING_V2_SCHEMA
        assert disabled.image_spec["retrieval_binding"]["attachmentData"] is None
        with pytest.raises(ValueError, match="unexpected fields"):
            runtime_targets.desired_from_direct_images(
                "oc20",
                spec,
                tmp_path,
                retrieval_enabled=True,
                retrieval_source_generation=DIGEST_C,
            )
        enabled, _ = runtime_targets.desired_from_direct_images(
            "oc20",
            spec,
            tmp_path,
            retrieval_enabled=True,
            retrieval_attachment_data=attachment_data(),
            retrieval_source_generation=DIGEST_C,
        )
    assert enabled.image_spec["retrieval_binding"]["attachmentData"] == attachment_data()


def test_status_is_content_free_exact_and_distinguishes_linkage_from_revocation() -> (
    None
):
    enabled = capable_spec(enabled=True)
    assert (
        validate_retrieval_status(
            status_payload(enabled, enabled=True),
            expected_component_digest=DIGEST_B,
            expected_binding_digest=str(enabled["retrieval_binding_digest"]),
            expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
            expected_gpu_access="none",
            enabled=True,
        )["linkageStatus"]
        == "complete"
    )
    disabled = capable_spec(enabled=False)
    assert (
        validate_retrieval_status(
            status_payload(disabled, enabled=False),
            expected_component_digest=DIGEST_B,
            expected_binding_digest=str(disabled["retrieval_binding_digest"]),
            expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
            expected_gpu_access="none",
            enabled=False,
        )["revocationStatus"]
        == "complete"
    )
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


@pytest.mark.parametrize("host_port_count", [False, 0.0])
def test_status_rejects_non_integer_zero_host_port_count(
    host_port_count: object,
) -> None:
    disabled = capable_spec(enabled=False)
    raw = status_payload(disabled, enabled=False)
    raw["hostPortCount"] = host_port_count

    with pytest.raises(ValueError, match="slot-local port/mount boundary"):
        validate_retrieval_status(
            raw,
            expected_component_digest=DIGEST_B,
            expected_binding_digest=str(disabled["retrieval_binding_digest"]),
            expected_resource_profile_digest=str(resource_envelope()["profileDigest"]),
            expected_gpu_access="none",
            enabled=False,
        )


def test_private_runtime_manifest_round_trips_component_binding_without_public_schema_change() -> (
    None
):
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


@pytest.mark.parametrize("enabled", [False, True])
def test_private_runtime_manifest_round_trips_binding_v2_without_schema_coercion(
    enabled: bool,
) -> None:
    spec = attachment_spec(enabled=enabled)
    manifest = {
        "family": "hermes",
        "image_name": "direct-image",
        "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "1" * 64,
        "product_image": "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64,
        "retrieval_component_digest": spec["retrieval_component_digest"],
        "retrieval_enabled": enabled,
        "retrieval_binding_digest": spec["retrieval_binding_digest"],
        "recipe": {
            "retrieval_contract": spec["retrieval_contract"],
            "retrieval_binding": spec["retrieval_binding"],
            "retrieval_attachment_contract": spec["retrieval_attachment_contract"],
            "retrieval_binding_digest": spec["retrieval_binding_digest"],
            "retrieval_enabled": enabled,
        },
    }
    loaded = image_spec_from_manifest(manifest)
    assert loaded["retrieval_binding"] == spec["retrieval_binding"]
    assert loaded["retrieval_attachment_contract"] == spec["retrieval_attachment_contract"]
    assert loaded["retrieval_binding"]["schema"] == BINDING_V2_SCHEMA
    assert loaded["retrieval_binding_digest"] == spec["retrieval_binding_digest"]
    assert loaded["retrieval_enabled"] is enabled

    mixed = dict(spec["retrieval_binding"])
    mixed["schema"] = "agent-runtime-retrieval-binding/v1"
    manifest["recipe"] = dict(manifest["recipe"])
    manifest["recipe"]["retrieval_binding"] = mixed
    manifest["retrieval_binding_digest"] = canonical_digest(mixed)
    with pytest.raises(ValueError, match="unexpected fields"):
        image_spec_from_manifest(manifest)


@pytest.mark.parametrize("enabled", [False, True])
def test_binding_v2_env_projects_only_exact_capability_and_binding_digests(
    enabled: bool,
) -> None:
    spec = attachment_spec(enabled=enabled)
    binding = spec["retrieval_binding"]
    assert isinstance(binding, dict)
    assert retrieval_env(spec) == {
        "JITECH_RETRIEVAL_ENABLED": "true" if enabled else "false",
        "JITECH_RETRIEVAL_COMPONENT_DIGEST": binding["componentDigest"],
        "JITECH_RETRIEVAL_BINDING_DIGEST": spec["retrieval_binding_digest"],
        "JITECH_RETRIEVAL_RESOURCE_PROFILE_DIGEST": binding["resourceProfileDigest"],
    }


def _legacy_runtime_target(image_spec: dict[str, object]) -> RuntimeTarget:
    return RuntimeTarget(
        target="dev-hermes-img",
        family="hermes",
        runtime_class="customer",
        image_name="direct-image",
        image_spec=image_spec,
        runtime_profile="hermes-runtime-customer",
        route=RuntimeBinding(
            instance_id="11111111-1111-4111-8111-111111111111",
            linux_account="dev-hermes-img",
            public_host="dev-hermes-img.ji-tech.co.kr",
            family="hermes",
            runtime_class="customer",
            gateway_port=30089,
            bridge_port=30090,
        ),
    )


def test_apply_migrates_pre_projection_manifest_to_exact_disabled_binding(
    tmp_path: Path,
) -> None:
    target = _legacy_runtime_target(
        {
            "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:"
            + "1" * 64,
            "product_image": "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64,
            "retrieval_component_digest": "",
            "retrieval_enabled": False,
            "retrieval_binding_digest": "",
        }
    )
    profile = SimpleNamespace(
        digest=DIGEST_D,
        metadata={
            "family": "hermes",
            "slot_class": "customer",
            "container_nas_root": "/workspace/nas_docs",
        },
    )

    with (
        patch(
            "agent_runtime_ops.domain.runtime_manifest.load_runtime_target",
            return_value=target,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_manifest.load_profile",
            return_value=profile,
        ),
    ):
        migrated, loaded_profile = desired_from_runtime_manifest(
            "dev-hermes-img",
            tmp_path,
        )

    assert loaded_profile is profile
    assert migrated.image_spec["retrieval_enabled"] is False
    assert migrated.image_spec["retrieval_component_digest"] == ""
    assert migrated.image_spec["retrieval_binding_digest"] == canonical_digest(
        migrated.image_spec["retrieval_binding"]
    )
    assert migrated.image_spec["retrieval_binding_digest"] != ""
    validate_retrieval_target_binding(
        migrated.image_spec,
        instance_id=target.route.instance_id,
        family="hermes",
        runtime_profile_digest=DIGEST_D,
        container_nas_root="/workspace/nas_docs",
    )


@pytest.mark.parametrize(
    "partial",
    [
        {"retrieval_component_digest": DIGEST_A},
        {"retrieval_enabled": True},
        {"retrieval_binding_digest": DIGEST_B},
        {"retrieval_contract": {"schema": RETRIEVAL_SCHEMA}},
    ],
)
def test_apply_rejects_incomplete_retrieval_projection_migration(
    tmp_path: Path,
    partial: dict[str, object],
) -> None:
    target = _legacy_runtime_target(
        {
            "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@sha256:"
            + "1" * 64,
            "product_image": "ghcr.io/epicevent/hermes-runtime@sha256:" + "2" * 64,
            **partial,
        }
    )
    profile = SimpleNamespace(
        digest=DIGEST_D,
        metadata={
            "family": "hermes",
            "slot_class": "customer",
            "container_nas_root": "/workspace/nas_docs",
        },
    )
    with (
        patch(
            "agent_runtime_ops.domain.runtime_manifest.load_runtime_target",
            return_value=target,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_manifest.load_profile",
            return_value=profile,
        ),
        pytest.raises(ValueError, match="incomplete retrieval projection migration"),
    ):
        desired_from_runtime_manifest("dev-hermes-img", tmp_path)


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


def test_every_hermes_profile_isolates_p1_state_by_binding_digest() -> None:
    profile_root = Path(__file__).parents[1] / "profiles" / "runtime"
    for template in sorted(profile_root.glob("hermes*/compose.yml.tpl")):
        text = template.read_text(encoding="utf-8")
        assert (
            'source: "{{ target_home }}/.hermes/agent-runtime/kwrag-p1-state/'
            '{{ retrieval_binding_path_component }}"' in text
        )
        assert "target: /opt/data/kwrag-p1-attachment" in text


def test_openclaw_profiles_mount_only_binding_scoped_p1_state() -> None:
    profile_root = Path(__file__).parents[1] / "profiles" / "runtime"
    for template in sorted(profile_root.glob("openclaw-*/compose.yml.tpl")):
        text = template.read_text(encoding="utf-8")
        assert (
            'source: "{{ target_home }}/.openclaw/agent-runtime/kwrag-p1-state/'
            '{{ retrieval_binding_path_component }}"' in text
        )
        assert "target: /run/kwrag" in text
        assert "read_only: true" in text


def test_hermes_profiles_make_managed_retrieval_intent_authoritative() -> None:
    profile_root = Path(__file__).parents[1] / "profiles" / "runtime"
    hermes_templates = sorted(profile_root.glob("hermes-*/compose.yml.tpl"))
    assert len(hermes_templates) == 6
    required_environment = {
        'JITECH_RETRIEVAL_ENABLED: "{{ retrieval_enabled }}"',
        'JITECH_RETRIEVAL_COMPONENT_DIGEST: "{{ retrieval_component_digest }}"',
        'JITECH_RETRIEVAL_BINDING_DIGEST: "{{ retrieval_binding_digest }}"',
        'JITECH_RETRIEVAL_RESOURCE_PROFILE_DIGEST: "{{ retrieval_resource_profile_digest }}"',
    }
    for template in hermes_templates:
        text = template.read_text(encoding="utf-8")
        assert '      - "{{ target_home }}/.hermes/.env"' in text
        assert all(item in text for item in required_environment)
        assert 'JITECH_RETRIEVAL_ENABLED: "${' not in text


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
            ).encode()
            + b"\n",
            b"",
        )

    result = run_retrieval_status_probe("container-id", spec, runner=runner)
    assert result is not None and result["consumerHealth"] == "healthy"
    assert seen[0] == [
        "docker",
        "exec",
        "container-id",
        "hermes",
        "kwrag-slot",
        "status",
        "--json",
    ]
    assert seen[1] == 15
    assert seen[2] == 64 * 1024


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"x"}\n\n',
        b' {"schema":"x"}',
        b'{"schema":"x"}\r\n',
        b"\xff",
    ],
)
def test_retrieval_status_output_rejects_noncanonical_bytes(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_retrieval_status_output(raw)


def test_component_approval_is_separate_exact_product_binding(tmp_path: Path) -> None:
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None
    with patch(
        "agent_runtime_ops.domain.retrieval_contract.os.chown",
        create=True,
    ) as chown:
        write_retrieval_approval(
            tmp_path,
            "openclaw",
            contract,
            product_image_digest=DIGEST_D,
        )
    chown.assert_called_once()
    assert chown.call_args.args[1] == 0
    approvals = load_retrieval_approvals(tmp_path)
    assert approvals["openclaw"]["component_digest"] == DIGEST_B
    assert retrieval_contract_is_approved(
        tmp_path, "openclaw", contract, product_image_digest=DIGEST_D
    )
    assert not retrieval_contract_is_approved(
        tmp_path, "openclaw", contract, product_image_digest=DIGEST_A
    )


def test_enabled_production_retrieval_requires_current_exact_approval(
    tmp_path: Path,
) -> None:
    spec = capable_spec(enabled=True)
    spec["product_image"] = "ghcr.io/epicevent/openclaw-jitech@" + DIGEST_D
    spec["wrapper_image"] = "ghcr.io/epicevent/agent-runtime-openclaw@" + DIGEST_A
    desired = SimpleNamespace(slot="oc20", family="openclaw", image_spec=spec)
    with patch(
        "agent_runtime_ops.domain.image_approval_policy.is_image_ref_approved",
        return_value=True,
    ):
        with pytest.raises(ValueError, match="requires exact component approval"):
            require_retrieval_approval(desired, tmp_path)

    contract = spec["retrieval_contract"]
    assert isinstance(contract, dict)
    with patch(
        "agent_runtime_ops.domain.retrieval_contract.os.chown",
        create=True,
    ):
        write_retrieval_approval(
            tmp_path,
            "openclaw",
            contract,
            product_image_digest=DIGEST_D,
        )
    with patch(
        "agent_runtime_ops.domain.image_approval_policy.is_image_ref_approved",
        return_value=True,
    ):
        require_retrieval_approval(desired, tmp_path)

    desired.image_spec["product_image"] = (
        "ghcr.io/epicevent/openclaw-jitech@" + DIGEST_A
    )
    with patch(
        "agent_runtime_ops.domain.image_approval_policy.is_image_ref_approved",
        return_value=True,
    ):
        with pytest.raises(ValueError, match="requires exact component approval"):
            require_retrieval_approval(desired, tmp_path)


def test_enabled_production_retrieval_requires_product_and_wrapper_approvals(
    tmp_path: Path,
) -> None:
    spec = capable_spec(enabled=True)
    spec["product_image"] = "ghcr.io/epicevent/openclaw-jitech@" + DIGEST_D
    spec["wrapper_image"] = "ghcr.io/epicevent/agent-runtime-openclaw@" + DIGEST_A
    desired = SimpleNamespace(slot="oc20", family="openclaw", image_spec=spec)

    with patch(
        "agent_runtime_ops.domain.image_approval_policy.is_image_ref_approved",
        side_effect=lambda _root, _family, role, _image: role == "product",
    ):
        with pytest.raises(ValueError, match="wrapper image approval"):
            require_retrieval_approval(desired, tmp_path)

    with patch(
        "agent_runtime_ops.domain.image_approval_policy.is_image_ref_approved",
        side_effect=lambda _root, _family, role, _image: role == "wrapper",
    ):
        with pytest.raises(ValueError, match="product image approval"):
            require_retrieval_approval(desired, tmp_path)


def test_disabled_and_dev_retrieval_do_not_require_production_approval(
    tmp_path: Path,
) -> None:
    disabled = SimpleNamespace(
        slot="oc20",
        family="openclaw",
        image_spec=capable_spec(enabled=False),
    )
    require_retrieval_approval(disabled, tmp_path)

    dev = SimpleNamespace(
        slot="dev-oc-img",
        family="openclaw",
        image_spec=capable_spec(enabled=True),
    )
    require_retrieval_approval(dev, tmp_path)


def test_retrieval_approval_rotation_uses_shared_runtime_mutation_lock(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    product_image = "ghcr.io/epicevent/openclaw-jitech@" + DIGEST_D
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None

    @contextmanager
    def locked(_state_root: Path):
        events.append("lock_enter")
        yield
        events.append("lock_exit")

    def write(*_args: object, **_kwargs: object) -> Path:
        events.append("policy_write")
        return tmp_path / "retrieval-component-approved.yaml"

    with (
        patch("agent_runtime_ops.commands.retrieval._is_root", return_value=True),
        patch(
            "agent_runtime_ops.commands.retrieval.runtime_host_mutation_lock",
            side_effect=locked,
        ),
        patch(
            "agent_runtime_ops.commands.retrieval.is_image_ref_approved",
            return_value=True,
        ),
        patch(
            "agent_runtime_ops.commands.retrieval.image_recipe_labels_from_wrapper",
            return_value=retrieval_labels(),
        ),
        patch(
            "agent_runtime_ops.commands.retrieval.write_retrieval_approval",
            side_effect=write,
        ),
    ):
        rc = cmd_retrieval_approve(
            argparse.Namespace(
                state_root=str(tmp_path),
                family="openclaw",
                product_image=product_image,
            )
        )

    assert rc == 0
    assert events == ["lock_enter", "policy_write", "lock_exit"]


@pytest.mark.parametrize(
    "existing",
    [
        {
            "meta": {
                "schema": "unsupported/v0",
                "scope": "private_server_state",
                "updated_at": "2026-07-29T00:00:00+00:00",
            },
            "components": {},
        },
        {
            "meta": {
                "schema": "jitech-retrieval-component-approval/v1",
                "scope": "private_server_state",
                "updated_at": "2026-07-29T00:00:00+00:00",
            },
            "components": {
                "openclaw": {
                    "component_digest": DIGEST_A,
                }
            },
        },
    ],
)
def test_approval_update_rejects_invalid_existing_policy_without_rewriting(
    tmp_path: Path,
    existing: dict[str, object],
) -> None:
    policy = tmp_path / "retrieval-component-approved.yaml"
    original = json.dumps(existing, sort_keys=True) + "\n"
    policy.write_text(original, encoding="utf-8")
    contract = retrieval_contract_from_labels(retrieval_labels())
    assert contract is not None

    with pytest.raises(ValueError, match="approval"):
        write_retrieval_approval(
            tmp_path,
            "hermes",
            contract,
            product_image_digest=DIGEST_D,
        )

    assert policy.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("original", ["", "false\n", "[]\n", "{}\n"])
def test_existing_falsey_approval_document_is_not_treated_as_absent(
    tmp_path: Path,
    original: str,
) -> None:
    policy = tmp_path / "retrieval-component-approved.yaml"
    policy.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="approval policy is invalid"):
        load_retrieval_approvals(tmp_path)

    assert policy.read_text(encoding="utf-8") == original


def test_missing_approval_document_is_the_only_empty_policy_state(
    tmp_path: Path,
) -> None:
    assert load_retrieval_approvals(tmp_path) == {}


@pytest.mark.parametrize(
    "original",
    [
        "components: {}\ncomponents: {}\n",
        "meta:\n  schema: jitech-retrieval-component-approval/v1\n  schema: duplicate\n",
        "components:\n  hermes:\n    component_digest: sha256:"
        + "a" * 64
        + "\n    component_digest: sha256:"
        + "b" * 64
        + "\n",
    ],
)
def test_approval_policy_rejects_duplicate_keys_at_every_mapping_level(
    tmp_path: Path,
    original: str,
) -> None:
    policy = tmp_path / "retrieval-component-approved.yaml"
    policy.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate key"):
        load_retrieval_approvals(tmp_path)


def test_cli_surface_has_enable_flag_but_no_third_image_or_policy_inputs() -> None:
    cli_source = (
        Path(__file__).parents[1] / "opsctl" / "agent_runtime_ops" / "cli.py"
    ).read_text(encoding="utf-8")
    assert cli_source.count('"--retrieval-enabled"') == 3
    assert cli_source.count('"--retrieval-runtime-capsule-sha256"') == 1
    assert "retrieval-image" not in cli_source
    assert "retrieval-runtime-capsule-path" not in cli_source
    assert "retrieval-network" not in cli_source
    assert "retrieval-backend" not in cli_source
    assert "retrieval-query" not in cli_source


def test_apply_and_rollback_gate_terminal_receipts_before_success() -> None:
    repo = Path(__file__).parents[1]
    apply_source = (
        repo / "opsctl" / "agent_runtime_ops" / "domain" / "runtime_apply.py"
    ).read_text(encoding="utf-8")
    probe_index = apply_source.index(
        "run_retrieval_status_probe(\n                container, desired.image_spec"
    )
    manifest_index = apply_source.index("write_slot_manifests(", probe_index)
    success_index = apply_source.index('print("apply_status=ok")', manifest_index)
    assert probe_index < manifest_index < success_index
    assert "retrieval_postcondition_failed" in apply_source
    assert "_restore_and_verify_backup(" in apply_source[probe_index:manifest_index]

    rollback_source = (
        repo / "opsctl" / "agent_runtime_ops" / "commands" / "apply.py"
    ).read_text(encoding="utf-8")
    rollback_probe = rollback_source.index("run_retrieval_status_probe(")
    rollback_finish = rollback_source.index(
        "finish_rollback_transaction(",
        rollback_probe,
    )
    rollback_success = rollback_source.index(
        'print("rollback_status=ok")',
        rollback_finish,
    )
    assert rollback_probe < rollback_finish < rollback_success
    assert "retrieval_disable_observation_failed" in rollback_source
