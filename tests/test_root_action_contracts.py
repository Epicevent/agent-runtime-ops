from __future__ import annotations

import copy
import json
import unittest

from agent_runtime_ops.root_actions import (
    DEFAULT_REGISTRY,
    MANIFEST_SCHEMA,
    ManifestValidationError,
    REGISTRY_VERSION,
    seal_typed_manifest,
)
from agent_runtime_ops.root_actions.registry import RegistryValidationError


DIGEST_A = "sha256:" + "a" * 64


def valid_manifest() -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "registry_version": REGISTRY_VERSION,
        "job_id": "ra-20260727-001",
        "operation_id": "audit.verify",
        "operation_version": 1,
        "request": {
            "request_id": "request-001",
            "lineage_id": "lineage-001",
            "reply_target": "codex-task-001",
            "submitted_at": "2026-07-27T05:00:00Z",
        },
        "parameters": {
            "target_identity": "runtime-evidence",
            "expected_schema": "runtime-evidence-v1",
            "freshness_seconds": 300,
            "allowlisted_fields": ["image_id", "source_revision"],
        },
        "expected_pre_state": {"kind": "required", "digest": DIGEST_A},
        "review": {
            "purpose": "Verify a bounded runtime receipt.",
            "premises": [
                {
                    "claim": "The runtime identity was directly observed.",
                    "basis": "direct_observation",
                    "anchor": {
                        "source": "runtime receipt 001",
                        "quote": "target=runtime-evidence",
                    },
                    "falsifier": "A different runtime identity is observed.",
                }
            ],
            "targets": ["runtime evidence receipt"],
            "changes": ["No persistent state is intended."],
            "recovery": ["No rollback is needed for the read-only operation."],
            "risk_delta": {
                "baseline": "No root action is executed.",
                "added": [],
                "removed": [],
                "maximum_consequence": "Read-only observation can fail without host mutation.",
            },
        },
    }


def encoded(value: dict[str, object], *, sort_keys: bool = False) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=sort_keys).encode("utf-8")


class RootActionManifestContractTests(unittest.TestCase):
    def test_key_order_does_not_change_canonical_identity(self) -> None:
        value = valid_manifest()
        first = seal_typed_manifest(encoded(value, sort_keys=False))
        second = seal_typed_manifest(encoded(value, sort_keys=True))
        self.assertEqual(first.job_digest, second.job_digest)
        self.assertEqual(first.canonical_manifest, second.canonical_manifest)
        self.assertTrue(first.canonical_manifest.endswith(b"\n"))

    def test_one_parameter_byte_changes_job_identity(self) -> None:
        first_value = valid_manifest()
        second_value = copy.deepcopy(first_value)
        second_value["parameters"]["target_identity"] = "kwrag-candidate-2"  # type: ignore[index]
        first = seal_typed_manifest(encoded(first_value))
        second = seal_typed_manifest(encoded(second_value))
        self.assertNotEqual(first.job_digest, second.job_digest)

    def test_unknown_top_level_and_execution_fields_are_rejected(self) -> None:
        for field in ("command", "argv", "path", "env", "payload"):
            with self.subTest(field=field):
                value = valid_manifest()
                value[field] = "forbidden"
                with self.assertRaisesRegex(
                    ManifestValidationError, "field set mismatch"
                ):
                    seal_typed_manifest(encoded(value))

        value = valid_manifest()
        value["parameters"]["shell"] = "/bin/bash"  # type: ignore[index]
        with self.assertRaisesRegex(
            ManifestValidationError, "parameters field set mismatch"
        ):
            seal_typed_manifest(encoded(value))

    def test_duplicate_json_key_is_rejected_before_canonicalization(self) -> None:
        raw = encoded(valid_manifest())
        duplicate = raw[:-1] + b',"job_id":"ra-replaced"}'
        with self.assertRaisesRegex(ManifestValidationError, "duplicate JSON key"):
            seal_typed_manifest(duplicate)

    def test_terminal_control_text_is_rejected(self) -> None:
        value = valid_manifest()
        value["review"]["purpose"] = "safe\x1b[2Junsafe"  # type: ignore[index]
        with self.assertRaisesRegex(ManifestValidationError, "control character"):
            seal_typed_manifest(encoded(value))

    def test_nonexistent_calendar_timestamp_is_rejected(self) -> None:
        value = valid_manifest()
        value["request"]["submitted_at"] = "2026-02-31T05:00:00Z"  # type: ignore[index]
        with self.assertRaisesRegex(ManifestValidationError, "real RFC3339"):
            seal_typed_manifest(encoded(value))

    def test_unknown_premise_must_not_claim_an_anchor(self) -> None:
        value = valid_manifest()
        premise = value["review"]["premises"][0]  # type: ignore[index]
        premise["basis"] = "unknown"
        with self.assertRaisesRegex(ManifestValidationError, "anchor must be null"):
            seal_typed_manifest(encoded(value))

        premise["anchor"] = None
        sealed = seal_typed_manifest(encoded(value))
        self.assertEqual(sealed.job_id, value["job_id"])

    def test_registry_projection_is_exact_and_contains_no_executor_surface(
        self,
    ) -> None:
        projection = DEFAULT_REGISTRY.projection()
        self.assertEqual(projection["schema"], REGISTRY_VERSION)
        self.assertEqual(len(projection["operations"]), 3)
        forbidden = {"command", "argv", "path", "env", "payload", "shell"}
        for operation in projection["operations"]:
            self.assertFalse(forbidden & set(operation["parameters"]))

    def test_all_registered_parameter_contracts_have_valid_examples(self) -> None:
        examples = {
            "audit.verify": {
                "target_identity": "runtime-evidence",
                "expected_schema": "runtime-evidence-v1",
                "freshness_seconds": 300,
                "allowlisted_fields": ["image_id", "source_revision"],
            },
            "projection.staging_selftest": {
                "fixture_id": "projection-posix-v1",
                "expected_contract_digest": DIGEST_A,
            },
            "agent_loop.campaign_run": {
                "campaign_id": "campaign-a-d",
                "image_digest": DIGEST_A,
                "input_digest": "sha256:" + "b" * 64,
                "runtime_seconds": 600,
                "memory_mib": 4096,
            },
        }
        self.assertEqual(set(examples), set(DEFAULT_REGISTRY.operation_ids))
        for operation_id, parameters in examples.items():
            with self.subTest(operation_id=operation_id):
                DEFAULT_REGISTRY.validate(operation_id, 1, parameters)

        with self.assertRaisesRegex(RegistryValidationError, "version mismatch"):
            DEFAULT_REGISTRY.validate("audit.verify", 2, examples["audit.verify"])
        with self.assertRaisesRegex(RegistryValidationError, "not registered"):
            DEFAULT_REGISTRY.validate("unregistered.operation", 1, {})


if __name__ == "__main__":
    unittest.main()
