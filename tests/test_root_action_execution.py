from __future__ import annotations

import json
import unittest

from agent_runtime_ops.root_actions import (
    DEFAULT_EXECUTION_POLICIES,
    DEFAULT_OPERATION_HANDLERS,
    KwragProductArtifactProbeHandler,
    NasObserveOcSlotsHandler,
    OperationAvailability,
    OperationHandlerRegistry,
    seal_typed_manifest,
)
from agent_runtime_ops.root_actions.execution import HandlerResult
from tests.test_root_action_contracts import encoded, valid_manifest


def artifact_job():
    value = valid_manifest()
    value["operation_id"] = "artifact.probe_kwrag_product"
    value["parameters"] = {"revision": "1" * 40}
    return seal_typed_manifest(encoded(value))


class RootActionExecutionRegistryTests(unittest.TestCase):
    def test_nas_observation_handler_redacts_and_preserves_projection_verdict(self) -> None:
        from tests.test_root_action_nas_observe_oc_slots import valid_projection

        value = valid_manifest()
        value["operation_id"] = "nas.observe_oc_slots"
        value["parameters"] = {}
        result = NasObserveOcSlotsHandler(probe=valid_projection).run(
            seal_typed_manifest(encoded(value))
        )
        self.assertEqual(result.public_status, "red")
        self.assertEqual(result.terminal_outcome, "succeeded")
        self.assertEqual(result.public_facts[0][0], "nas_observation_header")

    def test_nas_observation_timeout_is_durable_terminal(self) -> None:
        value = valid_manifest()
        value["operation_id"] = "nas.observe_oc_slots"
        value["parameters"] = {}

        def timeout():
            raise TimeoutError

        result = NasObserveOcSlotsHandler(probe=timeout).run(
            seal_typed_manifest(encoded(value))
        )
        self.assertEqual(result.terminal_outcome, "timed_out")
        self.assertEqual(result.exit_code, 124)

    def test_handler_result_admits_bounded_terminal_timeout(self) -> None:
        result = HandlerResult(
            raw_bytes=b'{"deadline":"operation"}\n',
            public_status="timed_out",
            public_facts=(("writes", "0"),),
            terminal_outcome="timed_out",
            reason_code="operation_deadline_exceeded",
            exit_code=124,
        )
        self.assertEqual(result.terminal_outcome, "timed_out")
        self.assertEqual(result.exit_code, 124)

    def test_historical_coverage_and_executable_handlers_are_separate(self) -> None:
        self.assertEqual(
            DEFAULT_EXECUTION_POLICIES.enabled_operation_ids,
            ("artifact.probe_kwrag_product",),
        )
        self.assertIn(
            "kwrag.network_ensure",
            DEFAULT_EXECUTION_POLICIES.disabled_operation_ids,
        )
        self.assertEqual(
            DEFAULT_EXECUTION_POLICIES.policy("kwrag.network_ensure").availability,
            OperationAvailability.DISABLED_BY_PRODUCT_BOUNDARY,
        )
        with self.assertRaises(KeyError):
            DEFAULT_OPERATION_HANDLERS.handler("kwrag.network_ensure")

    def test_disabled_operation_cannot_be_registered_as_a_handler(self) -> None:
        class ForbiddenNetworkHandler:
            operation_id = "kwrag.network_ensure"
            operation_version = 1

            def run(self, job):  # pragma: no cover - construction must fail
                raise AssertionError

        with self.assertRaisesRegex(ValueError, "disabled operation"):
            OperationHandlerRegistry((ForbiddenNetworkHandler(),))

    def test_artifact_probe_handler_uses_only_the_revision_and_projects_facts(
        self,
    ) -> None:
        calls: list[str] = []

        def probe(revision: str):
            calls.append(revision)
            return {
                "schema": "agent-runtime-artifact-probe/v1",
                "observedAt": "2026-07-27T00:00:00+00:00",
                "scope": "kwrag-product",
                "revision": revision,
                "derived": {
                    "imageBuildsRoot": "/srv/kwrag-product/image-builds",
                    "candidateTag": "kwrag-product:candidate-11111111",
                },
                "directoryObservation": {
                    "rootIdentity": {},
                    "matchingCount": 1,
                    "unrelatedEntryCount": 0,
                    "directories": [],
                },
                "dockerObservation": {
                    "localReadOnly": True,
                    "image": {"exists": True, "id": "sha256:" + "a" * 64},
                    "ancestorContainerCount": 0,
                },
                "writes": 0,
            }

        result = KwragProductArtifactProbeHandler(probe=probe).run(artifact_job())
        self.assertEqual(calls, ["1" * 40])
        self.assertEqual(result.public_status, "pass")
        self.assertIn(("writes", "0"), result.public_facts)
        self.assertEqual(json.loads(result.raw_bytes)["revision"], "1" * 40)


if __name__ == "__main__":
    unittest.main()
