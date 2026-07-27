from __future__ import annotations

import copy
from datetime import datetime
from pathlib import Path
import unittest

from agent_runtime_ops.root_actions.catalog import build_public_catalog
from agent_runtime_ops.root_actions.inventory import (
    EXPECTED_FAMILY_COUNTS,
    EXPECTED_HISTORICAL_ACTION_COUNT,
    HISTORICAL_INVENTORY,
    INVENTORY_COVERAGE,
    InventoryValidationError,
    validate_inventory_coverage,
)


def inventory_names(value: dict[str, object]) -> set[str]:
    return {
        name
        for family in value["families"]  # type: ignore[index]
        for name in family["actions"]
    }


class RootActionHistoricalInventoryTests(unittest.TestCase):
    def test_frozen_inventory_has_exact_59_action_registry_coverage(self) -> None:
        self.assertEqual(
            INVENTORY_COVERAGE.actual_count, EXPECTED_HISTORICAL_ACTION_COUNT
        )
        self.assertEqual(dict(INVENTORY_COVERAGE.family_counts), EXPECTED_FAMILY_COUNTS)
        self.assertEqual(len(inventory_names(HISTORICAL_INVENTORY)), 59)
        self.assertEqual(
            set(INVENTORY_COVERAGE.operation_ids), set(EXPECTED_FAMILY_COUNTS)
        )
        self.assertNotIn(
            "artifact.probe_kwrag_product", INVENTORY_COVERAGE.operation_ids
        )

    def test_historical_inventory_never_seeds_operational_job_catalog(self) -> None:
        self.assertEqual(len(inventory_names(HISTORICAL_INVENTORY)), 59)
        catalog = build_public_catalog((), authority_job_count=0)
        self.assertEqual(catalog.pages, ())
        self.assertIn(b'"authority_job_count":0', catalog.catalog_bytes)
        self.assertIn(b'"listed_job_count":0', catalog.catalog_bytes)
        self.assertNotIn(b'"authority_job_count":59', catalog.catalog_bytes)

    def test_missing_and_duplicate_actions_are_caught(self) -> None:
        missing = copy.deepcopy(HISTORICAL_INVENTORY)
        missing["families"][0]["actions"].pop()
        with self.assertRaisesRegex(InventoryValidationError, "count mismatch"):
            validate_inventory_coverage(missing)

        duplicate = copy.deepcopy(HISTORICAL_INVENTORY)
        duplicate["families"][1]["actions"][0] = duplicate["families"][0]["actions"][0]
        with self.assertRaisesRegex(InventoryValidationError, "duplicate actions"):
            validate_inventory_coverage(duplicate)

    def test_local_frozen_evidence_matches_packaged_membership_when_available(
        self,
    ) -> None:
        evidence = (
            Path.home()
            / "Documents"
            / "reports"
            / "evidence"
            / "root-action-approval-2026-07-27"
            / "root-action-59-typed-family-inventory.txt"
        )
        if not evidence.is_file():
            self.skipTest("external frozen inventory evidence is not present")
        evidence_names = {
            line.strip()
            for line in evidence.read_text(encoding="utf-8").splitlines()
            if line.strip().endswith(".sh")
        }
        self.assertEqual(evidence_names, inventory_names(HISTORICAL_INVENTORY))

    def test_local_cutoff_universe_matches_packaged_membership_when_available(
        self,
    ) -> None:
        source_root = (
            Path.home() / "Documents" / "kakao rag" / ".artifacts" / "root-actions"
        )
        if not source_root.is_dir():
            self.skipTest("external historical action universe is not present")
        cutoff = datetime.fromisoformat(
            HISTORICAL_INVENTORY["source"]["cutoff"]  # type: ignore[index]
        ).timestamp()
        actual = {
            path.name
            for path in source_root.glob("*.sh")
            if path.is_file() and path.stat().st_mtime <= cutoff
        }
        self.assertEqual(actual, inventory_names(HISTORICAL_INVENTORY))


if __name__ == "__main__":
    unittest.main()
