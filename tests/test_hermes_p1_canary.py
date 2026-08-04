from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.commands import rollout
from agent_runtime_ops.domain.hermes_p1_canary import (
    CANARY_CORPUS,
    P1_PIPELINE_FINGERPRINT,
    _validate_positive_proof,
    build_hermes_p1_canary_inputs,
    publish_hermes_p1_runtime_inputs,
    run_hermes_p1_canary_probe,
)
from agent_runtime_ops.domain.retrieval_contract import canonical_digest
from agent_runtime_ops.domain import runtime_targets, runtime_truth
from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.renderer import render_compose
from agent_runtime_ops.routing import RuntimeBinding
from agent_runtime_ops.state import RuntimeTarget


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64


def _desired(prepared) -> SimpleNamespace:
    return SimpleNamespace(
        slot="oc20",
        route=SimpleNamespace(instance_id="instance-oc20"),
        image_spec={
            "retrieval_enabled": True,
            "retrieval_binding_digest": DIGEST_B,
            "retrieval_binding": {
                "componentDigest": DIGEST_A,
                "attachmentData": prepared.attachment_data,
            },
        },
    )


def _negative_proof() -> dict[str, object]:
    return {
        "schema": "jitech-hermes-kwrag-p1-attachment-proof/v1",
        "operationReceiptDigest": DIGEST_A,
        "resultReceiptDigest": DIGEST_B,
        "consumptionReceiptDigest": DIGEST_C,
        "resultStatus": "zero_hits",
        "resultCount": 0,
    }


def _positive_proof(prepared) -> dict[str, object]:
    return {
        "schema": "jitech-hermes-kwrag-p1-attachment-proof/v1",
        "operationReceiptDigest": DIGEST_A,
        "resultReceiptDigest": DIGEST_B,
        "consumptionReceiptDigest": DIGEST_C,
        "resultStatus": "hits",
        "resultCount": 1,
        "conversationAttestation": {
            "schema": "jitech-hermes-kwrag-consumption-attestation/v1",
            "componentDigest": DIGEST_A,
            "runtimeBindingDigest": prepared.attachment_data[
                "slotRuntimeBindingDigest"
            ],
            "indexManifestDigest": prepared.attachment_data["indexManifestDigest"],
            "resultStatus": "hits",
            "operationReceiptDigest": DIGEST_A,
            "resultReceiptDigest": DIGEST_B,
            "consumptionReceiptDigest": DIGEST_D,
            "providerAttemptId": 1,
            "providerCallId": "11111111-1111-4111-8111-111111111111",
            "providerAttemptBindingDigest": DIGEST_D,
            "providerAttemptOutcomeReceiptDigest": DIGEST_E,
            "evidenceProjectionStatus": "verified_hits",
            "dispatchHandoffStatus": "evidence_dispatch_handoff_committed",
            "transportOutcomeStatus": "response_observed",
            "providerAttestationStatus": "unavailable",
            "billingStatus": "unavailable",
        },
    }


def test_canary_inputs_are_synthetic_bounded_and_sqlite_fts(tmp_path: Path) -> None:
    prepared = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    database = tmp_path / "room.meta.sqlite"
    database.write_bytes(prepared.database)
    import sqlite3

    connection = sqlite3.connect(database)
    try:
        row = connection.execute("SELECT text FROM turns WHERE turn_id=1").fetchone()
        assert row and "cobalt orchard" in row[0]
    finally:
        connection.close()
    assert prepared.runtime_binding["mount_root"] == "/workspace/nas_docs"
    assert prepared.runtime_binding["pipeline_fingerprint"] == P1_PIPELINE_FINGERPRINT
    assert prepared.index_manifest["rooms"][CANARY_CORPUS]["conversation_id"] == (
        CANARY_CORPUS
    )
    assert prepared.attachment_data["indexManifestDigest"] == canonical_digest(
        prepared.index_manifest
    )
    assert b"cobalt orchard" not in prepared.conversation_message


def test_enabled_canary_inputs_get_fresh_rollback_isolated_binding() -> None:
    first = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    second = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    assert (
        first.attachment_data["sourceSnapshotDigest"]
        != second.attachment_data["sourceSnapshotDigest"]
    )
    assert (
        first.runtime_binding["index_manifest_relative"]
        != second.runtime_binding["index_manifest_relative"]
    )
    for prepared in (first, second):
        snapshot = prepared.attachment_data["sourceSnapshotDigest"].removeprefix(
            "sha256:"
        )
        assert prepared.runtime_binding["index_manifest_relative"] == (
            f".jitech-kwrag-canary/{snapshot}/manifest.json"
        )


def test_canary_probe_runs_zero_hit_then_actual_conversation_and_tamper() -> None:
    prepared = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    desired = _desired(prepared)
    negative = _negative_proof()
    positive = _positive_proof(prepared)
    writes: list[tuple[Path, object]] = []
    with (
        patch(
            "agent_runtime_ops.domain.hermes_p1_canary._write_resource_observation",
            return_value={"observationDigest": DIGEST_A},
        ) as observe,
        patch(
            "agent_runtime_ops.domain.hermes_p1_canary._write_json",
            side_effect=lambda path, value, **_kwargs: writes.append((path, value)),
        ),
        patch(
            "agent_runtime_ops.domain.hermes_p1_canary._run_product_probe",
            side_effect=[negative, positive],
        ) as product_probe,
        patch("agent_runtime_ops.domain.hermes_p1_canary._tamper_control") as tamper,
    ):
        proof = run_hermes_p1_canary_probe("container-1", desired, prepared)

    observe.assert_called_once()
    assert [item.args[0] for item in product_probe.call_args_list] == [
        "container-1",
        "container-1",
    ]
    assert [item.kwargs["conversation"] for item in product_probe.call_args_list] == [
        False,
        True,
    ]
    tamper.assert_called_once()
    assert proof["negative"]["resultStatus"] == "zero_hits"
    assert proof["positive"]["conversationAttestation"]["dispatchHandoffStatus"] == (
        "evidence_dispatch_handoff_committed"
    )
    assert proof["positive"]["conversationAttestation"]["transportOutcomeStatus"] == (
        "response_observed"
    )
    assert proof["tamperStatus"] == "rejected"
    assert writes[-1][0].name == "canary-proof.json"
    assert "cobalt orchard" not in json.dumps(proof)


def test_positive_probe_rejects_unobserved_transport() -> None:
    prepared = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    desired = _desired(prepared)
    proof = _positive_proof(prepared)
    proof["conversationAttestation"]["transportOutcomeStatus"] = "unknown"
    with pytest.raises(ValueError, match="conversation attestation"):
        _validate_positive_proof(proof, desired=desired, prepared=prepared)


def test_rollout_builds_private_attachment_only_for_enabled_p1() -> None:
    image_spec = {
        "family": "hermes",
        "retrieval_attachment_contract": {"schema": "fixture"},
    }
    disabled = SimpleNamespace(
        slot="oc20", route=SimpleNamespace(instance_id="instance-oc20")
    )
    enabled = SimpleNamespace(slot="oc20")
    profile = SimpleNamespace(name="profile", digest=DIGEST_A)
    prepared = build_hermes_p1_canary_inputs(slot="oc20", instance_id="instance-oc20")
    with (
        patch.object(
            rollout,
            "_desired_from_direct_images",
            side_effect=[(disabled, profile), (enabled, profile)],
        ) as desired_from_images,
        patch.object(
            rollout,
            "build_hermes_p1_canary_inputs",
            return_value=prepared,
        ),
    ):
        actual, actual_profile, actual_prepared = (
            rollout._desired_with_hermes_p1_canary(
                "oc20", image_spec, Path("state"), retrieval_enabled=True
            )
        )
    assert (
        actual is enabled and actual_profile is profile and actual_prepared is prepared
    )
    assert desired_from_images.call_args_list[0].kwargs["retrieval_enabled"] is False
    assert desired_from_images.call_args_list[1].kwargs == {
        "retrieval_enabled": True,
        "retrieval_attachment_data": prepared.attachment_data,
    }


def test_rollout_disabled_p1_has_no_product_probe_input() -> None:
    image_spec = {
        "family": "hermes",
        "retrieval_attachment_contract": {"schema": "fixture"},
    }
    disabled = SimpleNamespace(slot="oc20")
    profile = SimpleNamespace(name="profile", digest=DIGEST_A)
    with patch.object(
        rollout,
        "_desired_from_direct_images",
        return_value=(disabled, profile),
    ) as desired_from_images:
        actual, actual_profile, prepared = rollout._desired_with_hermes_p1_canary(
            "oc20", image_spec, Path("state"), retrieval_enabled=False
        )
    assert actual is disabled and actual_profile is profile and prepared is None
    desired_from_images.assert_called_once_with(
        "oc20", image_spec, Path("state"), retrieval_enabled=False
    )


def test_runtime_input_publication_creates_missing_managed_state_parent(
    tmp_path: Path,
) -> None:
    home_root = tmp_path / "home"
    slot_home = home_root / "oc20"
    (slot_home / ".hermes").mkdir(parents=True)
    (slot_home / "nas_docs").mkdir()
    state_root = (
        slot_home / ".hermes" / "agent-runtime" / "kwrag-p1-state" / "binding-b"
    )
    desired = SimpleNamespace(
        slot="oc20",
        image_spec={
            "retrieval_binding": {
                "schema": "agent-runtime-retrieval-binding/v2",
                "family": "hermes",
                "enabled": False,
            }
        },
    )
    real_path = Path

    def path_factory(value: object) -> Path:
        return home_root if value == "/home" else real_path(value)

    class PosixOsProxy:
        name = "posix"

        @staticmethod
        def chown(*_args: object) -> None:
            return None

        @staticmethod
        def fchown(*_args: object) -> None:
            return None

        @staticmethod
        def fchmod(*_args: object) -> None:
            return None

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

    with (
        patch("agent_runtime_ops.domain.hermes_p1_canary.Path", side_effect=path_factory),
        patch("agent_runtime_ops.domain.hermes_p1_canary.os", PosixOsProxy()),
        patch(
            "agent_runtime_ops.domain.hermes_p1_canary._host_state_root",
            return_value=state_root,
        ),
    ):
        publish_hermes_p1_runtime_inputs(desired, None)

    assert (slot_home / ".hermes" / "agent-runtime").is_dir()
    assert (state_root / "binding-v2.json").is_file()


def test_live_binding_v2_rejects_persisted_attachment_contract_drift() -> None:
    live_contract = {"status_schema": "live"}
    persisted = SimpleNamespace(
        image_spec={
            "wrapper_image": "wrapper",
            "product_image": "product",
            "retrieval_enabled": True,
            "retrieval_binding": {"schema": "agent-runtime-retrieval-binding/v2"},
            "retrieval_attachment_contract": {"status_schema": "stale"},
        }
    )
    with (
        patch.object(
            runtime_targets,
            "live_runtime_truth",
            return_value=(
                {
                    "truth_status": "ok",
                    "wrapper_image": "wrapper",
                    "product_image": "product",
                    "retrieval_enabled": "true",
                },
                [(True, "live", "ok")],
            ),
        ),
        patch.object(
            runtime_targets,
            "image_spec_from_direct_images",
            return_value={"retrieval_attachment_contract": live_contract},
        ),
        patch(
            "agent_runtime_ops.domain.runtime_manifest.desired_from_runtime_manifest",
            return_value=(persisted, SimpleNamespace()),
        ),
        pytest.raises(ValueError, match="live binding-v2 tuple"),
    ):
        runtime_targets.desired_from_live_image_truth("oc20", Path("state"))


def test_live_runtime_truth_rejects_attachment_contract_drift() -> None:
    route = SimpleNamespace(
        linux_account="oc20",
        instance_id="instance-oc20",
        family="hermes",
        runtime_class="customer",
        public_host="oc20.ji-tech.co.kr",
        gateway_port=30689,
        bridge_port=30690,
    )
    live_contract = {"status_schema": "live"}
    persisted = SimpleNamespace(
        image_spec={
            "wrapper_image": "wrapper",
            "product_image": "product",
            "retrieval_enabled": True,
            "retrieval_binding": {
                "schema": "agent-runtime-retrieval-binding/v2"
            },
            "retrieval_attachment_contract": {"status_schema": "stale"},
        }
    )
    truth = {
        "truth_status": "ok",
        "wrapper_image": "wrapper",
        "product_image": "product",
        "retrieval_enabled": "true",
        "runtime_profile": "hermes-runtime-customer",
        "image_family": "hermes",
        "retrieval_labels_present": "true",
        "retrieval_contract_complete": "true",
        "retrieval_projection_complete": "true",
        "retrieval_projection_consistent": "true",
        "retrieval_binding_digest": DIGEST_A,
        "retrieval_schema": "jitech-embedded-retrieval/v1",
        "retrieval_transport": "in_process",
    }
    inspect = SimpleNamespace(returncode=0, stdout="[{}]", stderr="")
    with (
        patch.object(runtime_truth, "get_runtime_binding", return_value=route),
        patch.object(runtime_truth, "parse_apache_route", return_value=route),
        patch.object(runtime_truth, "apache_route_checks", return_value=[]),
        patch.object(
            runtime_truth,
            "find_gateway_container_by_binding",
            return_value=("container-1", "instance_label"),
        ),
        patch.object(runtime_truth, "run_text", return_value=inspect),
        patch.object(runtime_truth, "live_image_truth_from_info", return_value=truth),
        patch.object(
            runtime_truth,
            "retrieval_attachment_contract_from_labels",
            return_value=live_contract,
        ),
        patch.object(
            runtime_truth,
            "load_profile",
            return_value=SimpleNamespace(
                digest=DIGEST_B,
                metadata={"container_nas_root": "/workspace/nas_docs"},
            ),
        ),
        patch.object(runtime_truth, "load_runtime_target", return_value=persisted),
        patch.object(
            runtime_truth,
            "local_canonical_recipe_check_from_truth",
            return_value=(True, "truth_canonical_recipe_digest_matches_local", "ok"),
        ),
    ):
        _, checks = runtime_truth.live_runtime_truth("oc20", Path("state"))
    failure = next(
        detail
        for ok, name, detail in checks
        if name == "truth_retrieval_binding_matches_expected" and not ok
    )
    assert failure == "retrieval binding v2 manifest does not match live tuple"


def test_compose_mounts_only_attachment_capable_binding_state() -> None:
    route = RuntimeBinding(
        instance_id="instance-oc20",
        linux_account="oc20",
        public_host="oc20.ji-tech.co.kr",
        family="hermes",
        runtime_class="customer",
        gateway_port=30689,
        bridge_port=30690,
    )
    spec = {
        "wrapper_image": "ghcr.io/epicevent/agent-runtime-hermes@" + DIGEST_A,
        "retrieval_binding_digest": DIGEST_B,
        "retrieval_attachment_contract": {"schema": "fixture"},
    }
    desired = RuntimeTarget(
        target="oc20",
        family="hermes",
        runtime_class="customer",
        image_name="direct-image",
        image_spec=spec,
        runtime_profile="hermes-runtime-customer",
        route=route,
    )
    profile = load_profile("hermes-runtime-customer")
    rendered = render_compose(profile, desired).text
    assert f"kwrag-p1-state/{DIGEST_B}" in rendered
    plain = RuntimeTarget(
        target="oc20",
        family="hermes",
        runtime_class="customer",
        image_name="direct-image",
        image_spec={
            key: value
            for key, value in spec.items()
            if key != "retrieval_attachment_contract"
        },
        runtime_profile="hermes-runtime-customer",
        route=route,
    )
    assert "kwrag-p1-state" not in render_compose(profile, plain).text
