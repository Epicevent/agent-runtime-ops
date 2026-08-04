from __future__ import annotations

import copy
import json
import unittest

from agent_runtime_ops.root_actions.nas_observe_oc_slots import (
    PROFILE,
    RECEIPT_SCHEMA,
    SOURCE_CONTRACT_DIGEST,
    NasObservationValidationError,
    public_facts,
    validate_public_facts,
    validate_public_projection,
)
from agent_runtime_ops.root_actions.observation import (
    ObservationValidationError,
    validate_public_observation_facts,
)


D = "sha256:" + "a" * 64


def _slot(slot: str, ordinals: list[int]) -> dict[str, object]:
    count = len(ordinals)
    return {
        "slot": slot,
        "alias_count": count,
        "alias_ordinals": ordinals,
        "alias_target_digests": [D] * count,
        "mount_exact_bits": [True] * count,
        "mount_readonly_bits": [True] * count,
        "exists_bits": [True] * count,
        "directory_bits": [True] * count,
        "readable_bits": [True] * count,
        "count_complete_bits": [True] * count,
        "entry_uid_values": [1022] * count,
        "entry_gid_values": [1043] * count,
        "entry_mode_values": [488] * count,
        "file_counts": [2] * count,
        "directory_counts": [1] * count,
        "symlink_counts": [0] * count,
        "other_counts": [0] * count,
        "container_identity_digest": D,
        "image_identity_digest": D,
        "host_bind_identity_digest": D,
        "container_bind_identity_digest": D,
        "issues": [],
    }


def valid_projection() -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "profile": PROFILE,
        "source_contract_digest": SOURCE_CONTRACT_DIGEST,
        "expected_nonroot_prestate_digest": D,
        "observed_nonroot_prestate_match": True,
        "observation_complete": True,
        "operational_verdict": "red",
        "writes": 0,
        "oc16": _slot("oc16", [1, 2]),
        "oc20": _slot("oc20", [3, 4, 5]),
        "oc17": {
            "ops_release_matches": True,
            "ops_release_digest": D,
            "mount_count": 37,
            "mount_identity_digest": D,
            "container_mount_count": 37,
            "container_mount_identity_digest": D,
            "logical_record_count": 2,
            "logical_record_identity_digest": D,
            "intent_status": "present",
            "assignment_count": 2,
            "recreation_blocker_count": 0,
            "recreation_blocker_digest": D,
            "workspace_mount_count": 1,
            "workspace_identity_digest": D,
            "other_slot_mount_identity_digest": D,
            "session_count": 1,
            "session_identity_digest": D,
            "process_count": 1,
            "process_identity_digest": D,
            "gpu_process_count": 1,
            "gpu_identity_digest": D,
            "credential_count": 2,
            "credential_metadata_digests": [D, D],
            "protected_read_guard_stable": True,
            "reason_codes": ["detach_prestate_present"],
        },
        "component_receipt_digests": {"oc16_20_groupware": D, "oc17_prestate": D},
    }


class NasObservePublicContractTests(unittest.TestCase):
    def test_exact_projection_round_trips_as_bounded_canonical_facts(self) -> None:
        projection = valid_projection()
        self.assertIs(validate_public_projection(projection), projection)
        facts = public_facts(projection)
        validate_public_facts(facts)
        validate_public_observation_facts(facts)
        self.assertTrue(all(len(value.encode("utf-8")) <= 4096 for _, value in facts))

    def test_red_observation_is_complete_evidence_not_handler_failure(self) -> None:
        projection = valid_projection()
        projection["oc16"]["mount_readonly_bits"][0] = False
        projection["oc16"]["issues"] = ["mount_not_readonly"]
        self.assertEqual(validate_public_projection(projection)["operational_verdict"], "red")

    def test_request_and_public_source_contract_cannot_drift(self) -> None:
        projection = valid_projection()
        projection["source_contract_digest"] = D
        with self.assertRaisesRegex(NasObservationValidationError, "fixed values"):
            validate_public_projection(projection)

    def test_extra_missing_wrong_typed_and_raw_fact_shapes_fail_closed(self) -> None:
        cases = []
        extra = valid_projection()
        extra["raw_path"] = "/srv/private"
        cases.append(extra)
        missing = valid_projection()
        del missing["oc17"]["protected_read_guard_stable"]
        cases.append(missing)
        wrong_type = valid_projection()
        wrong_type["oc20"]["file_counts"][0] = True
        cases.append(wrong_type)
        for case in cases:
            with self.subTest(case=list(case)):
                with self.assertRaises(NasObservationValidationError):
                    validate_public_projection(case)

    def test_fact_reorder_noncanonical_json_and_partial_set_are_rejected(self) -> None:
        facts = public_facts(valid_projection())
        for invalid in (facts[:-1], tuple(reversed(facts))):
            with self.assertRaises(NasObservationValidationError):
                validate_public_facts(invalid)
        noncanonical = list(facts)
        noncanonical[0] = (noncanonical[0][0], json.dumps(json.loads(noncanonical[0][1])))
        with self.assertRaisesRegex(NasObservationValidationError, "canonical"):
            validate_public_facts(tuple(noncanonical))

    def test_receipt_envelope_validator_rejects_mixed_generic_and_nas_facts(self) -> None:
        facts = public_facts(valid_projection())
        with self.assertRaisesRegex(ObservationValidationError, "nas observation"):
            validate_public_observation_facts((("writes", "0"), *facts))

    def test_identity_drift_in_alias_or_component_digest_is_rejected(self) -> None:
        for path in ("alias", "component"):
            projection = copy.deepcopy(valid_projection())
            if path == "alias":
                projection["oc16"]["alias_target_digests"][0] = "not-a-digest"
            else:
                projection["component_receipt_digests"]["oc17_prestate"] = "sha256:ABC"
            with self.assertRaisesRegex(NasObservationValidationError, "digest"):
                validate_public_projection(projection)


if __name__ == "__main__":
    unittest.main()
