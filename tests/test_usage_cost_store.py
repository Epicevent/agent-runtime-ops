from __future__ import annotations

import json
import unittest

from agent_runtime_ops.domain.usage_cost import (
    validate_fx_ledger,
    validate_pricing_catalog,
)
from agent_runtime_ops.domain.usage_cost_store import (
    COST_PROJECTION_LOCK_NAME,
    UsageCostProjectionBusy,
    project_costs,
)
from agent_runtime_ops.domain.usage_ledger import UsageContractError

from tests.test_usage_cost import fx, pricing
from tests.test_usage_ledger import receipt


class FakeNamedLocks:
    def __init__(self) -> None:
        self.owner: FakeConnection | None = None

    def acquire(self, connection: "FakeConnection") -> int:
        if self.owner is None or self.owner is connection:
            self.owner = connection
            return 1
        return 0

    def close(self, connection: "FakeConnection") -> None:
        if self.owner is connection:
            self.owner = None


class FakeCursor:
    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.rows: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str, params: tuple = ()) -> None:
        normalized = " ".join(sql.split())
        self.connection.trace.append((normalized, params))
        self.rows = []
        append_only_tables = {
            "usage_pricing_catalog_revision",
            "usage_reference_fx_ledger_revision",
            "provider_usage_cost_estimate",
        }
        referenced_append_only = next(
            (table for table in append_only_tables if table in normalized), None
        )
        if self.connection.enforce_select_insert_only and referenced_append_only:
            if " FOR UPDATE" in normalized:
                raise PermissionError(
                    1142,
                    f"SELECT with locking clause denied on {referenced_append_only}",
                )
            if normalized.startswith(("UPDATE ", "DELETE ")):
                raise PermissionError(
                    1142, f"mutation denied on {referenced_append_only}"
                )
        if normalized.startswith("SELECT GET_LOCK"):
            self.rows = [
                {"acquired": self.connection.named_locks.acquire(self.connection)}
            ]
        elif normalized.startswith(
            "SELECT TABLE_NAME AS table_name FROM information_schema.tables"
        ):
            self.rows = [
                {"table_name": "usage_pricing_catalog_revision"},
                {"table_name": "usage_reference_fx_ledger_revision"},
                {"table_name": "provider_usage_cost_estimate"},
            ]
        elif normalized.startswith(
            "SELECT table_name FROM information_schema.tables"
        ):
            # MySQL returns TABLE_NAME for an unaliased information_schema
            # field.  Keep this catch fixture so a regression cannot be hidden
            # by a lowercase-only fake cursor again.
            self.rows = [{"TABLE_NAME": "provider_usage_cost_estimate"}]
        elif normalized.startswith("SELECT artifact_json FROM usage_"):
            table = normalized.split(" FROM ", 1)[1].split(" ", 1)[0]
            row = self.connection.revisions.get((table, params[0]))
            self.rows = [] if row is None else [dict(row)]
        elif normalized.startswith("INSERT INTO usage_"):
            table = normalized.split("INSERT INTO ", 1)[1].split(" ", 1)[0]
            identity = (table, params[0])
            if identity in self.connection.revisions:
                raise AssertionError("duplicate revision identity reached INSERT")
            self.connection.revisions[identity] = {"artifact_json": params[4]}
        elif normalized.startswith("SELECT id, runtime_instance_id"):
            rows = list(self.connection.calls)
            if "WHERE c.linux_account=%s" in normalized:
                rows = [row for row in rows if row["linux_account"] == params[0]]
            self.rows = [dict(row) for row in rows]
        elif normalized.startswith("SELECT estimate_digest, estimate_json"):
            row = self.connection.estimates.get(tuple(params))
            self.rows = [] if row is None else [dict(row)]
        elif normalized.startswith("SELECT id FROM provider_usage_cost_estimate"):
            call_id, api_product, price_scenario = params
            found = any(
                identity[0] == call_id
                and identity[3] == api_product
                and identity[4] == price_scenario
                and row["estimate_status"] in {"complete", "partial"}
                for identity, row in self.connection.estimates.items()
            )
            self.rows = [{"id": 1}] if found else []
        elif normalized.startswith("INSERT INTO provider_usage_cost_estimate"):
            identity = (params[0], params[12], params[13], params[7], params[8])
            if identity in self.connection.estimates:
                raise AssertionError("duplicate estimate identity reached INSERT")
            self.connection.estimates[identity] = {
                "estimate_digest": params[5],
                "estimate_status": params[6],
                "estimate_json": params[20],
            }
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(
        self,
        *,
        named_locks: FakeNamedLocks | None = None,
        enforce_select_insert_only: bool = False,
    ) -> None:
        row = receipt()
        row["actual"].update(
            {
                "provider": "google",
                "model": "gemini-3.6-flash",
            }
        )
        row["usage"].update(
            {
                "serviceTier": "standard",
                "inputNonCached": 600_000,
                "cacheRead": 100_000,
                "outputCandidates": 40_000,
                "reasoningThinking": 10_000,
            }
        )
        row["usageCoverage"] = "complete"
        self.calls = [
            {
                "id": 7,
                "runtime_instance_id": "e4526f41-9f61-4db8-90a5-b5eb53c29737",
                "linux_account": "oc20",
                "receipt_digest": row["receiptDigest"],
                "receipt_json": json.dumps(row),
            }
        ]
        self.revisions: dict[tuple, dict] = {}
        self.estimates: dict[tuple, dict] = {}
        self.named_locks = named_locks or FakeNamedLocks()
        self.enforce_select_insert_only = enforce_select_insert_only
        self.trace: list[tuple] = []
        self.transactions: list[str] = []

    def cursor(self):
        return FakeCursor(self)

    def begin(self):
        self.transactions.append("BEGIN")

    def commit(self):
        self.transactions.append("COMMIT")

    def rollback(self):
        self.transactions.append("ROLLBACK")

    def close(self):
        self.named_locks.close(self)


class UsageCostStoreTest(unittest.TestCase):
    def test_select_insert_only_fixture_rejects_locking_read(self) -> None:
        connection = FakeConnection(enforce_select_insert_only=True)

        with self.assertRaisesRegex(PermissionError, "locking clause denied"):
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT artifact_json FROM usage_pricing_catalog_revision "
                    "WHERE artifact_digest=%s FOR UPDATE",
                    ("sha256:fixture",),
                )

    def test_select_insert_only_writer_projects_and_replays(self) -> None:
        connection = FakeConnection(enforce_select_insert_only=True)
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())

        first = project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        second = project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )

        self.assertEqual(
            first, {"inserted": 1, "idempotent": 0, "settledSkipped": 0}
        )
        self.assertEqual(
            second, {"inserted": 0, "idempotent": 1, "settledSkipped": 0}
        )
        self.assertTrue(all(" FOR UPDATE" not in sql for sql, _ in connection.trace))
        self.assertFalse(
            any(sql.startswith(("UPDATE ", "DELETE ")) for sql, _ in connection.trace)
        )

    def test_cost_lock_serializes_connections_and_preserves_duplicate(self) -> None:
        named_locks = FakeNamedLocks()
        first_connection = FakeConnection(named_locks=named_locks)
        second_connection = FakeConnection(named_locks=named_locks)
        second_connection.calls = first_connection.calls
        second_connection.revisions = first_connection.revisions
        second_connection.estimates = first_connection.estimates
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())

        first = project_costs(
            first_connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        with self.assertRaisesRegex(
            UsageCostProjectionBusy, "usage cost projection already running"
        ):
            project_costs(
                second_connection,
                catalog=catalog,
                fx=ledger,
                api_product="gemini_developer_api",
                price_scenario="paid_standard_list",
            )

        self.assertEqual(
            first, {"inserted": 1, "idempotent": 0, "settledSkipped": 0}
        )
        self.assertEqual(second_connection.transactions, [])
        self.assertEqual(len(first_connection.estimates), 1)
        first_connection.close()
        replay = project_costs(
            second_connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        self.assertEqual(
            replay, {"inserted": 0, "idempotent": 1, "settledSkipped": 0}
        )
        self.assertEqual(len(first_connection.estimates), 1)
        lock_reads = [
            params
            for sql, params in first_connection.trace + second_connection.trace
            if sql.startswith("SELECT GET_LOCK")
        ]
        self.assertTrue(lock_reads)
        self.assertTrue(
            all(params == (COST_PROJECTION_LOCK_NAME,) for params in lock_reads)
        )
        self.assertLessEqual(len(COST_PROJECTION_LOCK_NAME.encode("utf-8")), 64)

    def test_revision_digests_remain_bound_to_exact_bytes(self) -> None:
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())
        identities = (
            ("usage_pricing_catalog_revision", catalog.digest),
            ("usage_reference_fx_ledger_revision", ledger.digest),
        )
        for table, digest in identities:
            with self.subTest(table=table):
                connection = FakeConnection()
                project_costs(
                    connection,
                    catalog=catalog,
                    fx=ledger,
                    api_product="gemini_developer_api",
                    price_scenario="paid_standard_list",
                )
                connection.revisions[(table, digest)]["artifact_json"] = "{}"
                with self.assertRaisesRegex(UsageContractError, "different bytes"):
                    project_costs(
                        connection,
                        catalog=catalog,
                        fx=ledger,
                        api_product="gemini_developer_api",
                        price_scenario="paid_standard_list",
                    )
                self.assertEqual(connection.transactions[-2:], ["BEGIN", "ROLLBACK"])

    def test_insert_once_then_exact_replay_is_idempotent(self) -> None:
        connection = FakeConnection()
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())
        first = project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        second = project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        self.assertEqual(
            first, {"inserted": 1, "idempotent": 0, "settledSkipped": 0}
        )
        self.assertEqual(
            second, {"inserted": 0, "idempotent": 1, "settledSkipped": 0}
        )
        self.assertEqual(len(connection.estimates), 1)

    def test_price_scenario_is_part_of_projection_identity(self) -> None:
        connection = FakeConnection()
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())
        project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        result = project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="free_tier",
        )
        self.assertEqual(
            result, {"inserted": 1, "idempotent": 0, "settledSkipped": 0}
        )
        self.assertEqual(len(connection.estimates), 2)

    def test_new_daily_fx_artifact_does_not_revalue_a_settled_call(self) -> None:
        connection = FakeConnection()
        catalog = validate_pricing_catalog(pricing())
        first_ledger = validate_fx_ledger(fx())
        project_costs(
            connection,
            catalog=catalog,
            fx=first_ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        next_fx = fx()
        next_fx["revision"] = "fx-2026-07-27"
        next_fx["publishedAt"] = "2026-07-27T01:00:00+00:00"
        second_ledger = validate_fx_ledger(next_fx)
        result = project_costs(
            connection,
            catalog=catalog,
            fx=second_ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        self.assertEqual(
            result, {"inserted": 0, "idempotent": 0, "settledSkipped": 1}
        )
        self.assertEqual(len(connection.estimates), 1)

    def test_same_projection_identity_with_different_bytes_fails_closed(self) -> None:
        connection = FakeConnection()
        catalog = validate_pricing_catalog(pricing())
        ledger = validate_fx_ledger(fx())
        project_costs(
            connection,
            catalog=catalog,
            fx=ledger,
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        existing = next(iter(connection.estimates.values()))
        existing["estimate_json"] = "{}"
        with self.assertRaisesRegex(UsageContractError, "different bytes"):
            project_costs(
                connection,
                catalog=catalog,
                fx=ledger,
                api_product="gemini_developer_api",
                price_scenario="paid_standard_list",
            )
        self.assertEqual(connection.transactions[-2:], ["BEGIN", "ROLLBACK"])


if __name__ == "__main__":
    unittest.main()
