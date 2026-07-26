from __future__ import annotations

import unittest

from agent_runtime_ops.domain.usage_ledger import RuntimeUsageStamp, UsageLedgerConflict, validate_export
from agent_runtime_ops.domain.usage_store import (
    UsageCollectionBusy,
    acquire_collection_lock,
    read_cursor,
    store_export_page,
)

from tests.test_usage_ledger import export_page, receipt


class FakeCursor:
    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.rows: list[dict] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *_args) -> None:
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.split())
        self.connection.trace.append(normalized.split(" ", 3)[0:3])
        self.rows = []
        if normalized.startswith("INSERT IGNORE INTO usage_collection_cursor"):
            instance_id = params[0]
            self.connection.cursors.setdefault(
                instance_id,
                {"last_ledger_seq": 0, "product_family": params[3], "last_status": "never"},
            )
        elif normalized.startswith("SELECT GET_LOCK"):
            self.rows = [{"acquired": self.connection.lock_acquired}]
        elif normalized.startswith("SELECT last_ledger_seq, product_family"):
            row = self.connection.cursors.get(params[0])
            self.rows = [] if row is None else [dict(row)]
        elif normalized.startswith("SELECT receipt_digest, product_ledger_seq FROM provider_usage_call"):
            row = self.connection.calls.get((params[0], params[1]))
            self.rows = (
                []
                if row is None
                else [{
                    "receipt_digest": row["receipt_digest"],
                    "product_ledger_seq": row["product_ledger_seq"],
                }]
            )
        elif normalized.startswith("SELECT receipt_digest, call_id FROM provider_usage_call"):
            row = self.connection.sequences.get((params[0], params[1], params[2]))
            self.rows = [] if row is None else [dict(row)]
        elif normalized.startswith("SELECT id, mb_id FROM slot_assignment_interval"):
            self.rows = list(self.connection.assignments)
        elif normalized.startswith("INSERT INTO provider_usage_call"):
            if len(params) != 51:
                raise AssertionError(f"provider_usage_call parameters={len(params)}")
            row = {
                "runtime_instance_id": params[0],
                "product_family": params[3],
                "product_ledger_seq": params[10],
                "receipt_digest": params[11],
                "call_id": params[12],
                "started_at": params[22],
                "assigned_mb_id": params[47],
                "assignment_status": params[48],
            }
            self.connection.calls[(params[0], params[12])] = row
            self.connection.sequences[(params[0], params[3], params[10])] = row
        elif normalized.startswith("UPDATE usage_collection_cursor SET linux_account"):
            row = self.connection.cursors[params[-1]]
            row.update(
                {
                    "last_ledger_seq": params[4],
                    "product_family": self.connection.family,
                    "last_status": "ok",
                }
            )
        elif normalized.startswith("INSERT INTO usage_collection_conflict"):
            self.connection.conflicts.append(
                {
                    "instance_id": params[0],
                    "call_id": params[2],
                    "kind": params[4],
                    "existing": params[5],
                    "observed": params[6],
                }
            )
        elif normalized.startswith("UPDATE usage_collection_cursor SET last_status='conflict'"):
            self.connection.cursors[params[-1]]["last_status"] = "conflict"
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self) -> None:
        self.family = "hermes"
        self.cursors: dict[str, dict] = {}
        self.calls: dict[tuple[str, str], dict] = {}
        self.sequences: dict[tuple[str, str, int], dict] = {}
        self.assignments: list[dict] = [{"id": 8, "mb_id": "jitech"}]
        self.conflicts: list[dict] = []
        self.transactions: list[str] = []
        self.trace: list[object] = []
        self.lock_acquired = 1

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def begin(self) -> None:
        self.transactions.append("BEGIN")

    def commit(self) -> None:
        self.transactions.append("COMMIT")

    def rollback(self) -> None:
        self.transactions.append("ROLLBACK")


STAMP = RuntimeUsageStamp(
    instance_id="e4526f41-9f61-4db8-90a5-b5eb53c29737",
    linux_account="oc20",
    public_host="oc20.ji-tech.co.kr",
    family="hermes",
    runtime_class="customer",
    binding_digest="sha256:" + "a" * 64,
    container_id="container-1",
    wrapper_image="ghcr.io/epicevent/agent-runtime-hermes@sha256:" + "b" * 64,
    product_image="ghcr.io/epicevent/hermes-runtime@sha256:" + "c" * 64,
    ops_repo_commit="d" * 40,
    collected_at="2026-07-26T01:00:00Z",
)


class UsageStoreTest(unittest.TestCase):
    def test_instance_collection_lock_is_connection_scoped_and_fail_closed(self) -> None:
        connection = FakeConnection()
        acquire_collection_lock(connection, STAMP.instance_id)
        connection.lock_acquired = 0
        with self.assertRaisesRegex(UsageCollectionBusy, "already running"):
            acquire_collection_lock(connection, STAMP.instance_id)

    def test_insert_once_stamps_assignment_and_advances_cursor(self) -> None:
        connection = FakeConnection()
        page = validate_export(export_page(), expected_after=0)
        result = store_export_page(connection, stamp=STAMP, page=page)
        self.assertEqual(result, {"inserted": 1, "idempotent": 0, "nextCursor": 1})
        stored = connection.calls[(STAMP.instance_id, receipt()["callId"])]
        self.assertEqual(stored["assigned_mb_id"], "jitech")
        self.assertEqual(stored["assignment_status"], "matched")
        self.assertEqual(connection.cursors[STAMP.instance_id]["last_ledger_seq"], 1)
        self.assertEqual(connection.transactions, ["BEGIN", "COMMIT"])

    def test_same_call_and_digest_is_idempotent(self) -> None:
        connection = FakeConnection()
        page = validate_export(export_page(), expected_after=0)
        store_export_page(connection, stamp=STAMP, page=page)
        connection.cursors[STAMP.instance_id]["last_ledger_seq"] = 0
        result = store_export_page(connection, stamp=STAMP, page=page)
        self.assertEqual(result["inserted"], 0)
        self.assertEqual(result["idempotent"], 1)
        self.assertEqual(len(connection.calls), 1)

    def test_same_call_different_digest_commits_conflict_without_cursor_advance(self) -> None:
        connection = FakeConnection()
        first = validate_export(export_page(), expected_after=0)
        store_export_page(connection, stamp=STAMP, page=first)
        connection.cursors[STAMP.instance_id]["last_ledger_seq"] = 0
        changed = receipt()
        changed["actual"]["responseId"] = "different"
        from agent_runtime_ops.domain.usage_ledger import receipt_digest

        changed["receiptDigest"] = receipt_digest(changed)
        second = validate_export(export_page(receipts=[changed]), expected_after=0)
        with self.assertRaises(UsageLedgerConflict):
            store_export_page(connection, stamp=STAMP, page=second)
        self.assertEqual(connection.cursors[STAMP.instance_id]["last_ledger_seq"], 0)
        self.assertEqual(connection.cursors[STAMP.instance_id]["last_status"], "conflict")

    def test_same_call_and_digest_at_different_sequence_is_not_idempotent(self) -> None:
        connection = FakeConnection()
        first = validate_export(export_page(), expected_after=0)
        store_export_page(connection, stamp=STAMP, page=first)
        connection.cursors[STAMP.instance_id]["last_ledger_seq"] = 0
        replay = receipt(seq=2)
        page = validate_export(export_page(receipts=[replay], high=2), expected_after=0)
        with self.assertRaises(UsageLedgerConflict):
            store_export_page(connection, stamp=STAMP, page=page)
        self.assertEqual(connection.conflicts[-1]["kind"], "call_id_sequence_mismatch")
        self.assertEqual(connection.cursors[STAMP.instance_id]["last_ledger_seq"], 0)
        self.assertEqual(len(connection.conflicts), 1)
        self.assertEqual(connection.transactions[-2:], ["BEGIN", "COMMIT"])
        with self.assertRaisesRegex(UsageLedgerConflict, "unresolved conflict"):
            read_cursor(connection, STAMP)
        self.assertEqual(connection.cursors[STAMP.instance_id]["last_status"], "conflict")

    def test_missing_assignment_is_not_attributed_to_current_person(self) -> None:
        connection = FakeConnection()
        connection.assignments = []
        page = validate_export(export_page(), expected_after=0)
        store_export_page(connection, stamp=STAMP, page=page)
        stored = connection.calls[(STAMP.instance_id, receipt()["callId"])]
        self.assertIsNone(stored["assigned_mb_id"])
        self.assertEqual(stored["assignment_status"], "unavailable")

    def test_offset_timestamp_is_normalized_to_utc_before_assignment_and_storage(self) -> None:
        connection = FakeConnection()
        row = receipt()
        row["startedAt"] = "2026-07-26T10:00:00+09:00"
        row["completedAt"] = "2026-07-26T10:00:01+09:00"
        from agent_runtime_ops.domain.usage_ledger import receipt_digest

        row["receiptDigest"] = receipt_digest(row)
        page = validate_export(export_page(receipts=[row]), expected_after=0)
        store_export_page(connection, stamp=STAMP, page=page)
        stored = connection.calls[(STAMP.instance_id, row["callId"])]
        self.assertEqual(stored["started_at"].isoformat(), "2026-07-26T01:00:00")


if __name__ == "__main__":
    unittest.main()
