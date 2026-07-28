from __future__ import annotations

import unittest

from agent_runtime_ops.root_actions import (
    MAX_PROVIDER_OBSERVATION_COUNT,
    ObservationValidationError,
    SanitizedExecutionObservation,
)


class SanitizedExecutionObservationTests(unittest.TestCase):
    def test_measured_observation_has_fixed_sanitized_fact_shape(self) -> None:
        observation = SanitizedExecutionObservation(
            dispatch_started=True,
            dispatch_completed=True,
            provider_request_count=24,
            provider_reservation_count=24,
            preserved_snapshot_path="/srv/kwrag-agent-loop/runtime-inputs/snapshot-1",
            staging_path="/srv/kwrag-agent-loop/staging/job-1",
        )

        self.assertEqual(
            observation.public_facts(
                allowed_path_roots=(
                    "/srv/kwrag-agent-loop/runtime-inputs",
                    "/srv/kwrag-agent-loop/staging",
                )
            ),
            (
                ("dispatch_started", "true"),
                ("dispatch_completed", "true"),
                ("provider_request_count", "24"),
                ("provider_reservation_count", "24"),
                (
                    "preserved_snapshot_path",
                    "/srv/kwrag-agent-loop/runtime-inputs/snapshot-1",
                ),
                ("staging_path", "/srv/kwrag-agent-loop/staging/job-1"),
            ),
        )

    def test_unmeasured_values_are_not_inferred_as_false_or_zero(self) -> None:
        facts = dict(
            SanitizedExecutionObservation(
                dispatch_started=None,
                dispatch_completed=None,
                provider_request_count=None,
                provider_reservation_count=None,
                preserved_snapshot_path=None,
                staging_path=None,
            ).public_facts(allowed_path_roots=())
        )

        self.assertEqual(set(facts.values()), {"unavailable"})
        self.assertNotIn("terminal_status", facts)

    def test_completed_dispatch_requires_observed_start(self) -> None:
        with self.assertRaisesRegex(
            ObservationValidationError,
            "dispatch_completed=true requires dispatch_started=true",
        ):
            SanitizedExecutionObservation(
                dispatch_started=None,
                dispatch_completed=True,
                provider_request_count=None,
                provider_reservation_count=None,
                preserved_snapshot_path=None,
                staging_path=None,
            )

    def test_provider_counts_are_bounded_and_do_not_accept_booleans(self) -> None:
        for value in (-1, True, MAX_PROVIDER_OBSERVATION_COUNT + 1):
            with self.subTest(value=value), self.assertRaisesRegex(
                ObservationValidationError, "public count bound"
            ):
                SanitizedExecutionObservation(
                    dispatch_started=False,
                    dispatch_completed=False,
                    provider_request_count=value,
                    provider_reservation_count=0,
                    preserved_snapshot_path=None,
                    staging_path=None,
                )

    def test_paths_must_be_canonical_and_inside_handler_roots(self) -> None:
        for value in (
            "relative/staging",
            "/srv/kwrag-agent-loop/staging/../private",
            "/srv/kwrag-agent-loop//staging/job-1",
            "/srv/kwrag-agent-loop/staging/job 1",
        ):
            with self.subTest(value=value), self.assertRaises(
                ObservationValidationError
            ):
                SanitizedExecutionObservation(
                    dispatch_started=False,
                    dispatch_completed=False,
                    provider_request_count=0,
                    provider_reservation_count=0,
                    preserved_snapshot_path=None,
                    staging_path=value,
                )

        observation = SanitizedExecutionObservation(
            dispatch_started=False,
            dispatch_completed=False,
            provider_request_count=0,
            provider_reservation_count=0,
            preserved_snapshot_path=None,
            staging_path="/srv/kwrag-agent-loop/private/job-1",
        )
        with self.assertRaisesRegex(
            ObservationValidationError, "outside its public path roots"
        ):
            observation.public_facts(
                allowed_path_roots=("/srv/kwrag-agent-loop/staging",)
            )

    def test_path_root_allowlist_is_bounded_and_unique(self) -> None:
        observation = SanitizedExecutionObservation(
            dispatch_started=False,
            dispatch_completed=False,
            provider_request_count=0,
            provider_reservation_count=0,
            preserved_snapshot_path=None,
            staging_path=None,
        )
        with self.assertRaisesRegex(ObservationValidationError, "must be unique"):
            observation.public_facts(allowed_path_roots=("/srv/one", "/srv/one"))
        with self.assertRaisesRegex(ObservationValidationError, "bounded tuple"):
            observation.public_facts(
                allowed_path_roots=tuple(f"/srv/root-{index}" for index in range(17))
            )


if __name__ == "__main__":
    unittest.main()
