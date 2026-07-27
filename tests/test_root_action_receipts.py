from __future__ import annotations

import json
import hashlib
from dataclasses import replace
import unittest

from agent_runtime_ops.root_actions import seal_typed_manifest
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.projection import ProjectionError, status_projection
from agent_runtime_ops.root_actions.receipts import (
    QuarantineRecord,
    RawReceiptReference,
    RECEIPT_SCHEMA,
    ReceiptValidationError,
    seal_receipt,
    seal_raw_receipt,
)
from agent_runtime_ops.root_actions.state import (
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from agent_runtime_ops.root_actions.storage import StorageConflict, StorageNotFound
from tests.test_root_action_contracts import encoded, valid_manifest


RAW_BYTES = b'{"stdout":"bounded fixture","stderr":"","exit_code":0}\n'
RAW_DIGEST = "sha256:" + hashlib.sha256(RAW_BYTES).hexdigest()


def public_receipt(job) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "public",
        "job_id": job.job_id,
        "job_digest": job.job_digest,
        "operation_id": job.operation_id,
        "request_id": job.request_id,
        "reply_target": job.reply_target,
        "terminal_outcome": "succeeded",
        "raw_receipt_digest": RAW_DIGEST,
        "started_at": "2026-07-27T05:00:01Z",
        "ended_at": "2026-07-27T05:00:02Z",
        "exit_code": 0,
        "removed_lines": 0,
        "result": {
            "status": "pass",
            "facts": [
                {"name": "observed_schema", "value": "kwrag-receipt-v1"},
                {"name": "writes", "value": "0"},
            ],
        },
    }


def receipt_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class RootActionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.job = seal_typed_manifest(encoded(valid_manifest()))
        self.store = LocalRootActionFixture()
        self.record = self.store.seal_pending(
            self.job,
            event_id="event-sealed",
            occurred_at="2026-07-27T05:00:00Z",
        )

    def _terminal(self) -> None:
        self.store.compare_and_append(
            TransitionEvent(
                event_id="event-claim",
                job_id=self.job.job_id,
                job_digest=self.job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at="2026-07-27T05:00:01Z",
            )
        )
        self.store.compare_and_append(
            TransitionEvent(
                event_id="event-complete",
                job_id=self.job.job_id,
                job_digest=self.job.job_digest,
                expected_revision=1,
                kind=TransitionKind.COMPLETE_EXECUTION,
                occurred_at="2026-07-27T05:00:02Z",
                outcome=TerminalOutcome.SUCCEEDED,
                reason_code="exit-zero",
            )
        )

    def _put_raw(self) -> RawReceiptReference:
        artifact = seal_raw_receipt(
            job_id=self.job.job_id,
            job_digest=self.job.job_digest,
            root_storage_id="raw-receipt-001",
            raw_bytes=RAW_BYTES,
        )
        self.store.put_raw_if_absent(artifact)
        return artifact.reference

    def test_public_receipt_is_full_and_retrieved_by_exact_job_identity(self) -> None:
        self._terminal()
        self._put_raw()
        artifact = seal_receipt(receipt_bytes(public_receipt(self.job)))
        self.store.publish_if_absent(artifact)
        self.assertEqual(
            self.store.read_raw_root_only(self.job.job_id).raw_bytes,
            RAW_BYTES,
        )
        retrieved = self.store.retrieve(self.job.job_id, self.job.job_digest)
        self.assertEqual(retrieved.canonical_receipt, artifact.canonical_receipt)
        view = status_projection(
            self.job, self.store.read_record(self.job.job_id), retrieved
        )
        self.assertEqual(view["receipt"]["kind"], "public")
        self.assertEqual(view["state"]["execution_count"], 1)
        with self.assertRaises(StorageNotFound):
            self.store.retrieve(self.job.job_id, "sha256:" + "f" * 64)

    def test_partial_public_receipt_is_rejected_not_sanitized(self) -> None:
        value = public_receipt(self.job)
        value["removed_lines"] = 1
        with self.assertRaisesRegex(
            ReceiptValidationError, "cannot contain removed lines"
        ):
            seal_receipt(receipt_bytes(value))

    def test_receipt_time_interval_must_be_real_and_forward(self) -> None:
        value = public_receipt(self.job)
        value["ended_at"] = "2026-02-31T05:00:02Z"
        with self.assertRaisesRegex(ReceiptValidationError, "real RFC3339"):
            seal_receipt(receipt_bytes(value))
        value["ended_at"] = "2026-07-27T04:59:59Z"
        with self.assertRaisesRegex(ReceiptValidationError, "cannot precede"):
            seal_receipt(receipt_bytes(value))

    def test_quarantine_notice_has_no_partial_result_surface(self) -> None:
        self._terminal()
        raw = self._put_raw()
        value = {
            "schema": RECEIPT_SCHEMA,
            "kind": "quarantined",
            "job_id": self.job.job_id,
            "job_digest": self.job.job_digest,
            "operation_id": self.job.operation_id,
            "request_id": self.job.request_id,
            "reply_target": self.job.reply_target,
            "terminal_outcome": "succeeded",
            "raw_receipt_digest": RAW_DIGEST,
            "quarantine_id": "quarantine-001",
            "reason_code": "possible-secret-output",
        }
        artifact = seal_receipt(receipt_bytes(value))
        self.store.quarantine_if_absent(QuarantineRecord(raw, artifact))
        self.assertEqual(
            self.store.retrieve(self.job.job_id, self.job.job_digest).kind,
            "quarantined",
        )
        contaminated = dict(value, result={"status": "partial", "facts": []})
        with self.assertRaisesRegex(ReceiptValidationError, "field set mismatch"):
            seal_receipt(receipt_bytes(contaminated))

    def test_receipt_cannot_publish_while_pending_or_twice(self) -> None:
        artifact = seal_receipt(receipt_bytes(public_receipt(self.job)))
        self._put_raw()
        with self.assertRaisesRegex(StorageConflict, "before a final or unknown state"):
            self.store.publish_if_absent(artifact)
        self._terminal()
        self.store.publish_if_absent(artifact)
        with self.assertRaisesRegex(StorageConflict, "already exists"):
            self.store.publish_if_absent(artifact)

    def test_projection_rejects_receipt_for_another_digest(self) -> None:
        self._terminal()
        value = public_receipt(self.job)
        value["job_digest"] = "sha256:" + "f" * 64
        artifact = seal_receipt(receipt_bytes(value))
        with self.assertRaisesRegex(ProjectionError, "identity mismatch"):
            status_projection(
                self.job, self.store.read_record(self.job.job_id), artifact
            )

    def test_projection_rejects_receipt_with_a_different_terminal_outcome(self) -> None:
        self._terminal()
        value = public_receipt(self.job)
        value["terminal_outcome"] = "failed"
        artifact = seal_receipt(receipt_bytes(value))
        with self.assertRaisesRegex(ProjectionError, "terminal outcome mismatch"):
            status_projection(
                self.job, self.store.read_record(self.job.job_id), artifact
            )

    def test_pending_terminal_notice_is_retrievable_without_execution(self) -> None:
        terminal = self.store.compare_and_append(
            TransitionEvent(
                event_id="event-expired",
                job_id=self.job.job_id,
                job_digest=self.job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLOSE_PENDING,
                occurred_at="2026-07-27T05:00:01Z",
                outcome=TerminalOutcome.EXPIRED,
                reason_code="pending-ttl-expired",
            )
        )
        value = {
            "schema": RECEIPT_SCHEMA,
            "kind": "terminal_notice",
            "job_id": self.job.job_id,
            "job_digest": self.job.job_digest,
            "operation_id": self.job.operation_id,
            "request_id": self.job.request_id,
            "reply_target": self.job.reply_target,
            "terminal_outcome": "expired",
            "reason_code": "pending-ttl-expired",
        }
        artifact = seal_receipt(receipt_bytes(value))
        self.store.publish_if_absent(artifact)
        view = status_projection(self.job, terminal, artifact)
        self.assertEqual(view["state"]["execution_count"], 0)
        self.assertEqual(view["receipt"]["kind"], "terminal_notice")

        contaminated = dict(value, raw_receipt_digest=RAW_DIGEST)
        with self.assertRaisesRegex(ReceiptValidationError, "field set mismatch"):
            seal_receipt(receipt_bytes(contaminated))

    def test_unknown_state_requires_whole_unknown_notice(self) -> None:
        self.store.compare_and_append(
            TransitionEvent(
                event_id="event-claim",
                job_id=self.job.job_id,
                job_digest=self.job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at="2026-07-27T05:00:01Z",
            )
        )
        unknown = self.store.compare_and_append(
            TransitionEvent(
                event_id="event-unknown",
                job_id=self.job.job_id,
                job_digest=self.job.job_digest,
                expected_revision=1,
                kind=TransitionKind.MARK_UNKNOWN,
                occurred_at="2026-07-27T05:00:02Z",
                reason_code="host-outcome-uncertain",
            )
        )
        value = {
            "schema": RECEIPT_SCHEMA,
            "kind": "unknown",
            "job_id": self.job.job_id,
            "job_digest": self.job.job_digest,
            "operation_id": self.job.operation_id,
            "request_id": self.job.request_id,
            "reply_target": self.job.reply_target,
            "terminal_outcome": None,
            "raw_receipt_digest": RAW_DIGEST,
            "last_known_at": "2026-07-27T05:00:02Z",
            "reason_code": "host-outcome-uncertain",
        }
        artifact = seal_receipt(receipt_bytes(value))
        self._put_raw()
        self.store.publish_if_absent(artifact)
        self.assertEqual(
            status_projection(self.job, unknown, artifact)["receipt"]["kind"], "unknown"
        )

    def test_failed_quarantine_publish_does_not_leave_a_partial_index(self) -> None:
        value = {
            "schema": RECEIPT_SCHEMA,
            "kind": "quarantined",
            "job_id": self.job.job_id,
            "job_digest": self.job.job_digest,
            "operation_id": self.job.operation_id,
            "request_id": self.job.request_id,
            "reply_target": self.job.reply_target,
            "terminal_outcome": "succeeded",
            "raw_receipt_digest": RAW_DIGEST,
            "quarantine_id": "quarantine-atomic",
            "reason_code": "possible-secret-output",
        }
        artifact = seal_receipt(receipt_bytes(value))
        raw = self._put_raw()
        with self.assertRaises(StorageConflict):
            self.store.quarantine_if_absent(QuarantineRecord(raw, artifact))
        with self.assertRaises(StorageNotFound):
            self.store.read_quarantine_notice(self.job.job_id)
        self._terminal()
        self.store.quarantine_if_absent(QuarantineRecord(raw, artifact))
        self.assertEqual(
            self.store.read_quarantine_notice(self.job.job_id).receipt_digest,
            artifact.receipt_digest,
        )

    def test_forged_receipt_metadata_is_rejected(self) -> None:
        self._terminal()
        self._put_raw()
        artifact = seal_receipt(receipt_bytes(public_receipt(self.job)))
        forged = replace(artifact, receipt_digest="sha256:" + "f" * 64)
        with self.assertRaisesRegex(StorageConflict, "metadata does not match"):
            self.store.publish_if_absent(forged)


if __name__ == "__main__":
    unittest.main()
