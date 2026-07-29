from __future__ import annotations

from copy import deepcopy
import json

import pytest

from agent_runtime_ops.root_actions import (
    BrokerPeerIdentity,
    CIRCUIT_BREAKER_REASON_CODE,
    SubmissionPolicy,
    TypedRootActionBroker,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.state import (
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from agent_runtime_ops.root_actions.storage import SubmissionMetadata
from tests.test_root_action_contracts import valid_manifest


PEER = BrokerPeerIdentity(uid=1027, gid=1048, pid=200)


class Events:
    def __init__(self, values: list[tuple[str, str]]) -> None:
        self.values = iter(values)

    def next_event(self) -> tuple[str, str]:
        return next(self.values)


class MemoryPublicSink:
    def __init__(self) -> None:
        self.bundles = {}
        self.catalogs = []

    def publish(self, bundle) -> None:
        self.bundles[bundle.job_id] = bundle

    def publish_catalog(self, bundles, *, authority_job_count=None) -> None:
        self.catalogs.append(bundles)


def manifest(
    job_id: str,
    *,
    lineage_id: str = "lineage-a",
    submitted_at: str = "2026-07-27T12:00:00Z",
) -> bytes:
    value = deepcopy(valid_manifest())
    value["job_id"] = job_id
    value["request"]["request_id"] = "request-" + job_id
    value["request"]["lineage_id"] = lineage_id
    value["request"]["reply_target"] = "reply-" + job_id
    value["request"]["submitted_at"] = submitted_at
    value["operation_id"] = "artifact.probe_kwrag_product"
    value["operation_version"] = 1
    value["parameters"] = {"revision": "a" * 40}
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def add_terminal(
    store: LocalRootActionFixture,
    job_id: str,
    *,
    received_at: str,
    lineage_id: str = "lineage-a",
    outcome: TerminalOutcome = TerminalOutcome.FAILED,
    reason_code: str = "handler_failed",
) -> None:
    job = seal_typed_manifest(
        manifest(job_id, lineage_id=lineage_id, submitted_at=received_at)
    )
    store.seal_pending(
        job,
        event_id="pending-" + job_id,
        occurred_at=received_at,
        submission=SubmissionMetadata(PEER.uid, PEER.gid, PEER.pid, received_at),
    )
    if outcome in {TerminalOutcome.SUCCEEDED, TerminalOutcome.FAILED}:
        running = store.compare_and_append(
            TransitionEvent(
                event_id="claim-" + job_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at=received_at,
            )
        )
        store.compare_and_append(
            TransitionEvent(
                event_id="complete-" + job_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=running.revision,
                kind=TransitionKind.COMPLETE_EXECUTION,
                occurred_at=received_at,
                outcome=outcome,
                reason_code=reason_code,
            )
        )
    else:
        store.compare_and_append(
            TransitionEvent(
                event_id="close-" + job_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLOSE_PENDING,
                occurred_at=received_at,
                outcome=outcome,
                reason_code=reason_code,
            )
        )


def broker(store: LocalRootActionFixture) -> TypedRootActionBroker:
    return TypedRootActionBroker(
        store,
        events=Events(
            [
                ("event-third-pending", "2026-07-27T12:00:00Z"),
                ("event-third-circuit", "2026-07-27T12:00:01Z"),
            ]
        ),
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({PEER.uid}),
            allowed_gids=frozenset({PEER.gid}),
        ),
    )


def test_two_typed_technical_failures_atomically_close_third_prestart() -> None:
    store = LocalRootActionFixture()
    add_terminal(store, "job-failure-one", received_at="2026-07-27T10:00:00Z")
    add_terminal(store, "job-failure-two", received_at="2026-07-27T11:00:00Z")

    submitted = broker(store).submit(manifest("job-third"), peer=PEER)

    state = submitted.status["state"]
    assert state == {
        "name": "terminal",
        "revision": 1,
        "execution_count": 0,
        "terminal_outcome": "prestart_failed",
        "reason_code": CIRCUIT_BREAKER_REASON_CODE,
        "last_changed_at": "2026-07-27T12:00:01Z",
    }
    assert submitted.status["lineage_24h"]["technical_failure_count"] == 2
    notice = store.retrieve(submitted.job_id, submitted.job_digest).receipt_copy()
    assert notice["request_id"] == "request-job-third"
    assert notice["reply_target"] == "reply-job-third"
    assert len(store.read_ledger(submitted.job_id)) == 2


@pytest.mark.parametrize(
    ("outcome", "reason_code"),
    [
        (TerminalOutcome.SUCCEEDED, "completed"),
        (TerminalOutcome.REJECTED, "disabled_by_product_boundary"),
        (TerminalOutcome.CANCELED, "user_canceled"),
        (TerminalOutcome.PRESTART_FAILED, CIRCUIT_BREAKER_REASON_CODE),
        (TerminalOutcome.FAILED, "user_input_invalid"),
    ],
)
def test_nontechnical_or_nonfailure_outcomes_do_not_trip_circuit(
    outcome: TerminalOutcome,
    reason_code: str,
) -> None:
    store = LocalRootActionFixture()
    add_terminal(
        store,
        "job-control-one",
        received_at="2026-07-27T10:00:00Z",
        outcome=outcome,
        reason_code=reason_code,
    )
    add_terminal(
        store,
        "job-control-two",
        received_at="2026-07-27T11:00:00Z",
        outcome=outcome,
        reason_code=reason_code,
    )
    submitted = broker(store).submit(manifest("job-third"), peer=PEER)
    assert submitted.status["state"]["name"] == "pending"
    assert submitted.status["lineage_24h"]["technical_failure_count"] == 0


def test_other_lineage_and_failures_outside_24h_do_not_trip_circuit() -> None:
    for mode in ("other_lineage", "outside_window"):
        store = LocalRootActionFixture()
        lineage = "other-lineage" if mode == "other_lineage" else "lineage-a"
        received = (
            "2026-07-27T10:00:00Z"
            if mode == "other_lineage"
            else "2026-07-26T10:00:00Z"
        )
        add_terminal(
            store,
            "job-old-one-" + mode,
            received_at=received,
            lineage_id=lineage,
        )
        add_terminal(
            store,
            "job-old-two-" + mode,
            received_at=received,
            lineage_id=lineage,
        )
        submitted = broker(store).submit(manifest("job-third"), peer=PEER)
        assert submitted.status["state"]["name"] == "pending"


def test_public_lineage_snapshot_is_immutable_without_state_transition() -> None:
    store = LocalRootActionFixture()
    add_terminal(store, "job-failure-one", received_at="2026-07-27T10:00:00Z")
    add_terminal(store, "job-failure-two", received_at="2026-07-27T11:00:00Z")
    sink = MemoryPublicSink()
    root_broker = TypedRootActionBroker(
        store,
        events=Events(
            [
                ("event-third-pending", "2026-07-27T12:00:00Z"),
                ("event-third-circuit", "2026-07-27T12:00:01Z"),
            ]
        ),
        public_sink=sink,
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({PEER.uid}),
            allowed_gids=frozenset({PEER.gid}),
        ),
    )
    submitted = root_broker.submit(manifest("job-third"), peer=PEER)
    before_record = store.read_record(submitted.job_id)
    before = root_broker.public_projection(submitted.job_id)
    before_lineage = json.loads(before.status_bytes)["lineage_24h"]
    assert before_lineage == {
        "approval_count": {
            "availability": "unavailable",
            "reason": "approval_design_not_ratified",
        },
        "availability": "measured",
        "lineage_id": "lineage-a",
        "measured_at": "2026-07-27T12:00:01Z",
        "measurement_semantics": "immutable_root_ledger_window_ending_at_measured_at",
        "snapshot_basis": "state_last_changed_at",
        "source": "root_owned_ledger",
        "submission_count": 3,
        "technical_failure_count": 2,
        "terminal_counts": {
            "canceled": 0,
            "expired": 0,
            "failed": 2,
            "prestart_failed": 1,
            "rejected": 0,
            "succeeded": 0,
        },
        "window_seconds": 86400,
    }

    root_broker.reconcile_public()
    after = sink.bundles[submitted.job_id]
    after_status = json.loads(after.status_bytes)
    assert after_status["lineage_24h"]["measured_at"] == before_record.last_changed_at
    assert after.projection_digest == before.projection_digest
    assert after.projection_bytes == before.projection_bytes
    assert store.read_record(submitted.job_id) == before_record
    assert sink.catalogs[-1]
