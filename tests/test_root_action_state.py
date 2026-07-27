from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest

from agent_runtime_ops.root_actions import seal_typed_manifest
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.projection import ProjectionError, history_projection
from agent_runtime_ops.root_actions.state import (
    JobState,
    ReplayBlocked,
    StaleRevision,
    StateTransitionError,
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from tests.test_root_action_contracts import encoded, valid_manifest
from agent_runtime_ops.root_actions.storage import StorageConflict


def event(
    job,
    event_id: str,
    revision: int,
    kind: TransitionKind,
    *,
    outcome: TerminalOutcome | None = None,
    reason: str | None = None,
    second: int = 1,
) -> TransitionEvent:
    return TransitionEvent(
        event_id=event_id,
        job_id=job.job_id,
        job_digest=job.job_digest,
        expected_revision=revision,
        kind=kind,
        occurred_at=f"2026-07-27T05:00:{second:02d}Z",
        outcome=outcome,
        reason_code=reason,
    )


class RootActionStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.job = seal_typed_manifest(encoded(valid_manifest()))
        self.store = LocalRootActionFixture()
        self.pending = self.store.seal_pending(
            self.job,
            event_id="event-sealed",
            occurred_at="2026-07-27T05:00:00Z",
        )

    def test_state_surface_is_decision_independent_and_exact(self) -> None:
        self.assertEqual(
            {state.value for state in JobState},
            {"pending", "running", "terminal", "unknown"},
        )
        self.assertNotIn("approved", {state.value for state in JobState})
        self.assertNotIn("authenticating", {state.value for state in JobState})

    def test_one_execution_claim_then_terminal(self) -> None:
        running = self.store.compare_and_append(
            event(self.job, "event-claim", 0, TransitionKind.CLAIM_EXECUTION)
        )
        self.assertEqual(running.state, JobState.RUNNING)
        self.assertEqual(running.execution_count, 1)

        terminal = self.store.compare_and_append(
            event(
                self.job,
                "event-complete",
                1,
                TransitionKind.COMPLETE_EXECUTION,
                outcome=TerminalOutcome.SUCCEEDED,
                reason="exit-zero",
                second=2,
            )
        )
        self.assertEqual(terminal.state, JobState.TERMINAL)
        self.assertEqual(terminal.execution_count, 1)
        self.assertEqual(len(self.store.read_ledger(self.job.job_id)), 3)

        with self.assertRaises(ReplayBlocked):
            self.store.compare_and_append(
                event(
                    self.job,
                    "event-replay",
                    2,
                    TransitionKind.CLAIM_EXECUTION,
                    second=3,
                )
            )

    def test_parallel_claims_execute_at_most_once(self) -> None:
        events = [
            event(self.job, f"event-claim-{index}", 0, TransitionKind.CLAIM_EXECUTION)
            for index in range(20)
        ]

        def claim(item: TransitionEvent) -> str:
            try:
                self.store.compare_and_append(item)
                return "claimed"
            except (StaleRevision, ReplayBlocked):
                return "blocked"

        with ThreadPoolExecutor(max_workers=20) as executor:
            outcomes = list(executor.map(claim, events))
        self.assertEqual(outcomes.count("claimed"), 1)
        self.assertEqual(outcomes.count("blocked"), 19)
        self.assertEqual(self.store.read_record(self.job.job_id).execution_count, 1)

    def test_unknown_never_reopens_execution(self) -> None:
        self.store.compare_and_append(
            event(self.job, "event-claim", 0, TransitionKind.CLAIM_EXECUTION)
        )
        unknown = self.store.compare_and_append(
            event(
                self.job,
                "event-unknown",
                1,
                TransitionKind.MARK_UNKNOWN,
                reason="host-outcome-uncertain",
                second=2,
            )
        )
        self.assertEqual(unknown.state, JobState.UNKNOWN)
        with self.assertRaises(ReplayBlocked):
            self.store.compare_and_append(
                event(
                    self.job,
                    "event-replay",
                    2,
                    TransitionKind.CLAIM_EXECUTION,
                    second=3,
                )
            )

        terminal = self.store.compare_and_append(
            event(
                self.job,
                "event-reconciled",
                2,
                TransitionKind.RECONCILE_UNKNOWN,
                outcome=TerminalOutcome.FAILED,
                reason="poststate-confirms-failure",
                second=4,
            )
        )
        self.assertEqual(terminal.execution_count, 1)
        self.assertEqual(terminal.state, JobState.TERMINAL)

    def test_pending_can_close_without_consuming_execution(self) -> None:
        terminal = self.store.compare_and_append(
            event(
                self.job,
                "event-expired",
                0,
                TransitionKind.CLOSE_PENDING,
                outcome=TerminalOutcome.EXPIRED,
                reason="pending-ttl-expired",
            )
        )
        self.assertEqual(terminal.state, JobState.TERMINAL)
        self.assertEqual(terminal.execution_count, 0)

    def test_identity_and_revision_mismatch_are_rejected(self) -> None:
        mismatch = event(self.job, "event-mismatch", 0, TransitionKind.CLAIM_EXECUTION)
        mismatch = TransitionEvent(
            **{**mismatch.__dict__, "job_digest": "sha256:" + "f" * 64}
        )
        with self.assertRaisesRegex(StateTransitionError, "identity mismatch"):
            self.store.compare_and_append(mismatch)
        with self.assertRaises(StaleRevision):
            self.store.compare_and_append(
                event(self.job, "event-stale", 99, TransitionKind.CLAIM_EXECUTION)
            )

    def test_forged_enum_and_boolean_counter_types_fail_closed(self) -> None:
        forged_state = replace(self.pending, state="pending")
        with self.assertRaisesRegex(StateTransitionError, "must be a JobState"):
            self.store.create_pending(forged_state)  # type: ignore[arg-type]

        forged_count = replace(self.pending, execution_count=False)
        with self.assertRaisesRegex(StateTransitionError, "counter invariant"):
            self.store.create_pending(forged_count)

        forged_record_outcome = replace(
            self.pending, terminal_outcome="succeeded"
        )
        with self.assertRaisesRegex(StateTransitionError, "must be a TerminalOutcome"):
            self.store.create_pending(forged_record_outcome)  # type: ignore[arg-type]

        forged_revision = event(
            self.job, "event-bool-revision", False, TransitionKind.CLAIM_EXECUTION
        )
        with self.assertRaisesRegex(StateTransitionError, "non-negative integer"):
            self.store.compare_and_append(forged_revision)

        forged_kind = replace(
            event(self.job, "event-string-kind", 0, TransitionKind.CLAIM_EXECUTION),
            kind="claim_execution",
        )
        with self.assertRaisesRegex(StateTransitionError, "must be a TransitionKind"):
            self.store.compare_and_append(forged_kind)  # type: ignore[arg-type]

        self.store.compare_and_append(
            event(self.job, "event-claim", 0, TransitionKind.CLAIM_EXECUTION)
        )
        forged_outcome = replace(
            event(
                self.job,
                "event-string-outcome",
                1,
                TransitionKind.COMPLETE_EXECUTION,
                outcome=TerminalOutcome.SUCCEEDED,
                reason="exit-zero",
                second=2,
            ),
            outcome="succeeded",
        )
        with self.assertRaisesRegex(StateTransitionError, "must be a TerminalOutcome"):
            self.store.compare_and_append(forged_outcome)  # type: ignore[arg-type]

    def test_ledger_rejects_a_nonadjacent_event_id_replay(self) -> None:
        self.store.compare_and_append(
            event(self.job, "event-claim", 0, TransitionKind.CLAIM_EXECUTION)
        )
        self.store.compare_and_append(
            event(
                self.job,
                "event-unknown",
                1,
                TransitionKind.MARK_UNKNOWN,
                reason="host-outcome-uncertain",
                second=2,
            )
        )
        replay = event(
            self.job,
            "event-claim",
            2,
            TransitionKind.RECONCILE_UNKNOWN,
            outcome=TerminalOutcome.FAILED,
            reason="poststate-confirms-failure",
            second=3,
        )
        with self.assertRaisesRegex(StorageConflict, "event_id replay"):
            self.store.compare_and_append(replay)

    def test_forged_sealed_job_metadata_is_rejected(self) -> None:
        forged = replace(self.job, job_digest="sha256:" + "f" * 64)
        other_store = LocalRootActionFixture()
        with self.assertRaisesRegex(StorageConflict, "metadata does not match"):
            other_store.seal_pending(
                forged,
                event_id="event-forged",
                occurred_at="2026-07-27T05:00:00Z",
            )

    def test_history_projection_is_identity_bound_and_contiguous(self) -> None:
        self.store.compare_and_append(
            event(self.job, "event-claim", 0, TransitionKind.CLAIM_EXECUTION)
        )
        history = history_projection(self.job, self.store.read_ledger(self.job.job_id))
        self.assertEqual(history["job_digest"], self.job.job_digest)
        self.assertEqual([item["record_revision"] for item in history["events"]], [0, 1])

        entries = list(self.store.read_ledger(self.job.job_id))
        entries[1] = replace(entries[1], record_revision=3)
        with self.assertRaisesRegex(ProjectionError, "projection mismatch"):
            history_projection(self.job, tuple(entries))

        entries = list(self.store.read_ledger(self.job.job_id))
        entries[1] = replace(entries[1], next_state="terminal")
        with self.assertRaisesRegex(ProjectionError, "projection mismatch"):
            history_projection(self.job, tuple(entries))


if __name__ == "__main__":
    unittest.main()
