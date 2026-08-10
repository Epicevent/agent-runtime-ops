from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest

from agent_runtime_ops.root_actions import (
    PosixRootActionStore,
    PosixStoreSecurityError,
    seal_typed_manifest,
)
from agent_runtime_ops.root_actions.receipts import (
    QuarantineRecord,
    RawReceiptReference,
    RECEIPT_SCHEMA,
    seal_receipt,
    seal_raw_receipt,
)
from agent_runtime_ops.root_actions.state import (
    ReplayBlocked,
    StaleRevision,
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from agent_runtime_ops.root_actions.storage import StorageConflict, StorageNotFound
from agent_runtime_ops.root_actions.storage import SubmissionMetadata
from tests.test_root_action_contracts import encoded, valid_manifest


RAW_BYTES = b'{"stdout":"posix fixture","stderr":"","exit_code":0}\n'
RAW_DIGEST = "sha256:" + hashlib.sha256(RAW_BYTES).hexdigest()


def transition(
    job,
    event_id: str,
    revision: int,
    kind: TransitionKind,
    *,
    second: int,
    outcome: TerminalOutcome | None = None,
    reason: str | None = None,
) -> TransitionEvent:
    return TransitionEvent(
        event_id=event_id,
        job_id=job.job_id,
        job_digest=job.job_digest,
        expected_revision=revision,
        kind=kind,
        occurred_at=f"2026-07-27T09:00:{second:02d}Z",
        outcome=outcome,
        reason_code=reason,
    )


def receipt_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


class PosixRootActionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root-actions"
        self.store = PosixRootActionStore(
            self.root,
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        self.job = seal_typed_manifest(encoded(valid_manifest()))
        self.pending = self.store.seal_pending(
            self.job,
            event_id="event-sealed",
            occurred_at="2026-07-27T09:00:00Z",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _terminal(self) -> None:
        self.store.compare_and_append(
            transition(
                self.job,
                "event-claim",
                0,
                TransitionKind.CLAIM_EXECUTION,
                second=1,
            )
        )
        self.store.compare_and_append(
            transition(
                self.job,
                "event-complete",
                1,
                TransitionKind.COMPLETE_EXECUTION,
                second=2,
                outcome=TerminalOutcome.SUCCEEDED,
                reason="exit-zero",
            )
        )

    def _put_raw(self) -> RawReceiptReference:
        artifact = seal_raw_receipt(
            job_id=self.job.job_id,
            job_digest=self.job.job_digest,
            root_storage_id="raw-receipt-posix-001",
            raw_bytes=RAW_BYTES,
        )
        self.store.put_raw_if_absent(artifact)
        return artifact.reference

    def _public_receipt(self):
        return seal_receipt(
            receipt_bytes(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "public",
                    "job_id": self.job.job_id,
                    "job_digest": self.job.job_digest,
                    "operation_id": self.job.operation_id,
                    "request_id": self.job.request_id,
                    "reply_target": self.job.reply_target,
                    "terminal_outcome": "succeeded",
                    "raw_receipt_digest": RAW_DIGEST,
                    "started_at": "2026-07-27T09:00:01Z",
                    "ended_at": "2026-07-27T09:00:02Z",
                    "exit_code": 0,
                    "removed_lines": 0,
                    "result": {
                        "status": "pass",
                        "facts": [{"name": "writes", "value": "0"}],
                    },
                }
            )
        )

    def test_reopen_preserves_canonical_job_record_and_ledger(self) -> None:
        reopened = PosixRootActionStore(
            self.root,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        self.assertEqual(reopened.read_sealed(self.job.job_id), self.job)
        self.assertEqual(reopened.read_record(self.job.job_id), self.pending)
        self.assertEqual(
            [entry.action for entry in reopened.read_ledger(self.job.job_id)],
            ["sealed_pending"],
        )

    def test_seal_pending_is_atomic_and_duplicate_safe(self) -> None:
        with self.assertRaisesRegex(StorageConflict, "already sealed"):
            self.store.seal_pending(
                self.job,
                event_id="event-duplicate",
                occurred_at="2026-07-27T09:00:01Z",
            )
        self.assertEqual(self.store.read_record(self.job.job_id), self.pending)
        self.assertEqual(len(self.store.read_ledger(self.job.job_id)), 1)

    def test_database_schema_version_and_exact_table_set_are_enforced(self) -> None:
        with self.store._connect() as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)

        extra_root = Path(self.temp.name) / "extra-table-store"
        extra = PosixRootActionStore(
            extra_root,
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        with extra._connect() as connection:
            connection.execute("CREATE TABLE root_action_unapproved(value TEXT)")
        with self.assertRaisesRegex(PosixStoreSecurityError, "table set"):
            PosixRootActionStore(
                extra_root,
                required_uid=None,
                required_gid=None,
                require_posix=False,
            )

    def test_disabled_rejection_and_notice_roll_back_as_one_transaction(self) -> None:
        class FailingReceiptStore(PosixRootActionStore):
            def _insert_receipt(self, connection, artifact) -> None:
                raise RuntimeError("injected receipt persistence failure")

        root = Path(self.temp.name) / "atomic-rejected-store"
        store = FailingReceiptStore(
            root,
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        value = valid_manifest()
        value["job_id"] = "job-atomic-disabled"
        job = seal_typed_manifest(encoded(value))
        close = transition(
            job,
            "event-disabled-close",
            0,
            TransitionKind.CLOSE_PENDING,
            second=1,
            outcome=TerminalOutcome.REJECTED,
            reason="disabled_unverified_authority",
        )
        notice = seal_receipt(
            receipt_bytes(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "terminal_notice",
                    "job_id": job.job_id,
                    "job_digest": job.job_digest,
                    "operation_id": job.operation_id,
                    "request_id": job.request_id,
                    "reply_target": job.reply_target,
                    "terminal_outcome": "rejected",
                    "reason_code": "disabled_unverified_authority",
                }
            )
        )
        with self.assertRaisesRegex(RuntimeError, "injected"):
            store.seal_rejected(
                job,
                pending_event_id="event-disabled-pending",
                pending_occurred_at="2026-07-27T09:00:00Z",
                close_event=close,
                notice=notice,
                submission=SubmissionMetadata(
                    peer_uid=1002,
                    peer_gid=1002,
                    peer_pid=4242,
                    broker_received_at="2026-07-27T09:00:00Z",
                ),
            )
        self.assertEqual(store.list_job_ids(), ())

    def test_parallel_claims_have_exactly_one_winner(self) -> None:
        events = [
            transition(
                self.job,
                f"event-claim-{index}",
                0,
                TransitionKind.CLAIM_EXECUTION,
                second=1,
            )
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
        self.assertEqual(len(self.store.read_ledger(self.job.job_id)), 2)

    def test_public_receipt_survives_reopen_and_is_identity_bound(self) -> None:
        self._terminal()
        self._put_raw()
        artifact = self._public_receipt()
        self.store.publish_if_absent(artifact)
        reopened = PosixRootActionStore(
            self.root,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        self.assertEqual(
            reopened.retrieve(self.job.job_id, self.job.job_digest),
            artifact,
        )
        self.assertEqual(
            reopened.read_raw_root_only(self.job.job_id).raw_bytes,
            RAW_BYTES,
        )
        with self.assertRaises(StorageNotFound):
            reopened.retrieve(self.job.job_id, "sha256:" + "f" * 64)

    def test_failed_quarantine_transaction_leaves_no_public_notice(self) -> None:
        raw = self._put_raw()
        notice = seal_receipt(
            receipt_bytes(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "quarantined",
                    "job_id": self.job.job_id,
                    "job_digest": self.job.job_digest,
                    "operation_id": self.job.operation_id,
                    "request_id": self.job.request_id,
                    "reply_target": self.job.reply_target,
                    "terminal_outcome": "succeeded",
                    "raw_receipt_digest": RAW_DIGEST,
                    "quarantine_id": "quarantine-posix-001",
                    "reason_code": "possible-secret-output",
                }
            )
        )
        with self.assertRaises(StorageConflict):
            self.store.quarantine_if_absent(QuarantineRecord(raw, notice))
        with self.assertRaises(StorageNotFound):
            self.store.retrieve(self.job.job_id, self.job.job_digest)
        with self.assertRaises(StorageNotFound):
            self.store.read_quarantine_notice(self.job.job_id)

        self._terminal()
        self.store.quarantine_if_absent(QuarantineRecord(raw, notice))
        self.assertEqual(
            self.store.read_quarantine_notice(self.job.job_id).receipt_digest,
            notice.receipt_digest,
        )

    @unittest.skipUnless(os.name == "posix", "POSIX inode policy requires POSIX")
    def test_database_hardlink_and_mode_drift_are_rejected(self) -> None:
        hardlink = self.root / "database-hardlink"
        os.link(self.store.database, hardlink)
        with self.assertRaisesRegex(PosixStoreSecurityError, "unsafe"):
            self.store.read_record(self.job.job_id)
        hardlink.unlink()

        os.chmod(self.store.database, 0o660)
        with self.assertRaisesRegex(PosixStoreSecurityError, "permissive"):
            self.store.read_record(self.job.job_id)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink policy requires POSIX")
    def test_database_symlink_replacement_is_rejected(self) -> None:
        original = self.root / "root-actions.original"
        self.store.database.rename(original)
        self.store.database.symlink_to(original)
        with self.assertRaisesRegex(PosixStoreSecurityError, "unsafe"):
            self.store.read_record(self.job.job_id)

    @unittest.skipUnless(
        os.name == "posix", "POSIX root identity policy requires POSIX"
    )
    def test_store_root_replacement_and_mode_drift_are_rejected(self) -> None:
        original = self.root.with_name("root-actions.original")
        self.root.rename(original)
        self.root.symlink_to(original, target_is_directory=True)
        try:
            with self.assertRaisesRegex(
                PosixStoreSecurityError, "root identity changed"
            ):
                self.store.read_record(self.job.job_id)
        finally:
            self.root.unlink()
            original.rename(self.root)

        os.chmod(self.root, 0o755)
        try:
            with self.assertRaisesRegex(
                PosixStoreSecurityError, "root mode is invalid"
            ):
                self.store.read_record(self.job.job_id)
        finally:
            os.chmod(self.root, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX mode policy requires POSIX")
    def test_database_is_single_link_regular_and_not_publicly_writable(self) -> None:
        self.assertEqual(stat.S_IMODE(self.root.lstat().st_mode), 0o700)
        info = self.store.database.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(info.st_mode) & 0o177, 0)


if __name__ == "__main__":
    unittest.main()
