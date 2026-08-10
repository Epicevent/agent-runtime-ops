from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading

import pytest

from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.execution import (
    HandlerResult,
)
from agent_runtime_ops.root_actions.posix_store import PosixRootActionStore
from agent_runtime_ops.root_actions.receipts import (
    RECEIPT_SCHEMA,
    seal_raw_receipt,
    seal_receipt,
)
from agent_runtime_ops.root_actions.state import (
    JobState,
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from agent_runtime_ops.root_actions.worker import (
    RootActionExecutionWorker,
    RootActionWorkerError,
)
from agent_runtime_ops.root_actions.storage import StorageNotFound
from tests.test_root_action_admission import Events
from tests.test_root_action_contracts import encoded, valid_manifest
from tests.root_action_support import make_test_handler_registry


def audit_job():
    return seal_typed_manifest(encoded(valid_manifest()))


def claimed(store: PosixRootActionStore):
    job = audit_job()
    store.seal_pending(
        job,
        event_id="event-worker-pending",
        occurred_at="2026-07-28T02:00:00Z",
    )
    store.compare_and_append(
        TransitionEvent(
            event_id="event-worker-claim",
            job_id=job.job_id,
            job_digest=job.job_digest,
            expected_revision=0,
            kind=TransitionKind.CLAIM_EXECUTION,
            occurred_at="2026-07-28T02:00:01Z",
        )
    )
    return job


class SuccessfulHandler:
    operation_id = "audit.verify"
    operation_version = 1

    def run(self, _job):
        return HandlerResult(
            raw_bytes=b'{"private":"full result"}\n',
            public_status="pass",
            public_facts=(("writes", "0"),),
        )


class SecretFailureHandler:
    operation_id = "audit.verify"
    operation_version = 1

    def run(self, _job):
        raise RuntimeError("DO-NOT-EXPOSE root secret value")


def make_store(root: Path) -> PosixRootActionStore:
    return PosixRootActionStore(
        root,
        create=True,
        required_uid=None,
        required_gid=None,
        require_posix=False,
    )


def test_worker_persists_terminal_raw_public_and_history_before_projection() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        job = claimed(store)
        repaired = threading.Event()
        worker = RootActionExecutionWorker(
            store,
            handlers=make_test_handler_registry(SuccessfulHandler()),
            events=Events([("event-worker-complete", "2026-07-28T02:00:02Z")]),
            repair_public=lambda _job_id: repaired.set(),
        )
        worker.start()
        try:
            worker.enqueue(job.job_id, job.job_digest)
            assert repaired.wait(2)
        finally:
            worker.close()

        record = store.read_record(job.job_id)
        assert record.state is JobState.TERMINAL
        assert record.terminal_outcome.value == "succeeded"
        raw = store.read_raw_root_only(job.job_id)
        assert raw.raw_bytes == b'{"private":"full result"}\n'
        receipt = store.retrieve(job.job_id, job.job_digest).receipt_copy()
        assert receipt["terminal_outcome"] == "succeeded"
        assert receipt["result"]["facts"] == [{"name": "writes", "value": "0"}]
        assert [item.action for item in store.read_ledger(job.job_id)] == [
            "sealed_pending",
            "claim_execution",
            "complete_execution",
        ]


def test_handler_exception_becomes_unknown_without_exception_message_leak() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        job = claimed(store)
        repaired = threading.Event()
        worker = RootActionExecutionWorker(
            store,
            handlers=make_test_handler_registry(SecretFailureHandler()),
            events=Events([("event-worker-unknown", "2026-07-28T02:00:02Z")]),
            repair_public=lambda _job_id: repaired.set(),
        )
        worker.start()
        try:
            worker.enqueue(job.job_id, job.job_digest)
            assert repaired.wait(2)
        finally:
            worker.close()

        assert store.read_record(job.job_id).state is JobState.UNKNOWN
        raw_text = store.read_raw_root_only(job.job_id).raw_bytes.decode("utf-8")
        assert "RuntimeError" in raw_text
        assert "DO-NOT-EXPOSE" not in raw_text
        notice = store.retrieve(job.job_id, job.job_digest).receipt_copy()
        assert notice["reason_code"] == "worker_outcome_uncertain"


def test_startup_recovery_marks_running_claim_unknown_and_never_reruns() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        job = claimed(store)
        worker = RootActionExecutionWorker(
            store,
            handlers=make_test_handler_registry(SuccessfulHandler()),
            events=Events([("event-worker-restart", "2026-07-28T02:00:02Z")]),
        )
        assert worker.recover_orphaned_claims() == (job.job_id,)
        assert store.read_record(job.job_id).state is JobState.UNKNOWN
        assert (
            store.retrieve(job.job_id, job.job_digest).receipt_copy()["reason_code"]
            == "broker_restarted_with_running_job"
        )


def test_unstarted_worker_closes_claim_as_unknown_instead_of_stranding_it() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        job = claimed(store)
        worker = RootActionExecutionWorker(
            store,
            handlers=make_test_handler_registry(SuccessfulHandler()),
            events=Events([("event-worker-unavailable", "2026-07-28T02:00:02Z")]),
        )
        with pytest.raises(RootActionWorkerError, match="unavailable"):
            worker.enqueue(job.job_id, job.job_digest)
        assert store.read_record(job.job_id).state is JobState.UNKNOWN


def test_terminal_state_raw_and_public_receipt_roll_back_together() -> None:
    class FailingReceiptStore(PosixRootActionStore):
        def _insert_receipt(self, connection, artifact) -> None:
            raise RuntimeError("injected public receipt failure")

    with tempfile.TemporaryDirectory() as temporary:
        store = FailingReceiptStore(
            Path(temporary) / "root-actions",
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        job = claimed(store)
        raw = seal_raw_receipt(
            job_id=job.job_id,
            job_digest=job.job_digest,
            root_storage_id="raw-atomic-completion",
            raw_bytes=b"private result",
        )
        receipt = seal_receipt(
            json.dumps(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "public",
                    "job_id": job.job_id,
                    "job_digest": job.job_digest,
                    "operation_id": job.operation_id,
                    "request_id": job.request_id,
                    "reply_target": job.reply_target,
                    "terminal_outcome": "succeeded",
                    "raw_receipt_digest": raw.reference.raw_receipt_digest,
                    "started_at": "2026-07-28T02:00:01Z",
                    "ended_at": "2026-07-28T02:00:02Z",
                    "exit_code": 0,
                    "removed_lines": 0,
                    "result": {"status": "pass", "facts": []},
                }
            ).encode("utf-8")
        )
        with pytest.raises(RuntimeError, match="injected"):
            store.complete_claimed_execution(
                event=TransitionEvent(
                    event_id="event-atomic-completion",
                    job_id=job.job_id,
                    job_digest=job.job_digest,
                    expected_revision=1,
                    kind=TransitionKind.COMPLETE_EXECUTION,
                    occurred_at="2026-07-28T02:00:02Z",
                    outcome=TerminalOutcome.SUCCEEDED,
                    reason_code="handler_succeeded",
                ),
                raw=raw,
                receipt=receipt,
            )
        assert store.read_record(job.job_id).state is JobState.RUNNING
        assert len(store.read_ledger(job.job_id)) == 2
        with pytest.raises(StorageNotFound):
            store.read_raw_root_only(job.job_id)
        with pytest.raises(StorageNotFound):
            store.retrieve(job.job_id, job.job_digest)
