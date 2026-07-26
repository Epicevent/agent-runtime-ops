from __future__ import annotations

import copy
from argparse import Namespace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.usage_cost import (
    project_call_cost,
    load_pricing_catalog,
    validate_fx_ledger,
    validate_pricing_catalog,
)
from agent_runtime_ops.domain.usage_ledger import UsageContractError
from agent_runtime_ops.commands.usage import _enforce_sudo_usage_artifact_defaults

from tests.test_usage_ledger import receipt


def pricing():
    return {
        "schema": "jitech-provider-pricing-catalog/v1",
        "revision": "2026-07-27.1",
        "publishedAt": "2026-07-27T00:00:00+09:00",
        "entries": [
            {
                "entryId": "google-gemini-api-gemini-3.6-flash-standard-2026-07-18",
                "provider": "google",
                "apiProduct": "gemini_developer_api",
                "actualModel": "gemini-3.6-flash",
                "serviceTier": "standard",
                "priceScenario": "paid_standard_list",
                "currency": "USD",
                "meteringProfile": "gemini-generate-content-v1",
                "effectiveFrom": "2026-07-18T00:00:00Z",
                "effectiveUntil": None,
                "ratesPerMillion": {
                    "inputNonCached": "1.50",
                    "cacheRead": "0.15",
                    "outputIncludingThinking": "7.50",
                },
                "unpricedComponents": ["cache_storage_token_hour", "search_grounding"],
                "source": {
                    "url": "https://ai.google.dev/gemini-api/docs/pricing",
                    "checkedAt": "2026-07-27T00:00:00+09:00",
                    "checkedBy": "operator",
                },
            }
        ],
    }


def fx():
    return {
        "schema": "jitech-daily-reference-fx/v1",
        "revision": "2026-07-24.ecb",
        "publishedAt": "2026-07-24T23:10:00+09:00",
        "baseCurrency": "USD",
        "quoteCurrency": "KRW",
        "maxCarryDays": 7,
        "rates": [
            {
                "rateDate": "2026-07-24",
                "usdPerEur": "1.1377",
                "krwPerEur": "1662.18",
                "krwPerUsd": "1461.000263689901",
                "source": {
                    "url": "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-hist-90d.xml",
                    "retrievedAt": "2026-07-24T23:10:00+09:00",
                    "documentSha256": "sha256:" + "a" * 64,
                    "derivation": "KRW_per_EUR / USD_per_EUR",
                },
            }
        ],
    }


class UsageCostTest(unittest.TestCase):
    def test_sudo_web_lane_cannot_override_root_owned_inputs(self) -> None:
        args = Namespace(
            pricing_file="/srv/openclaw-ops/usage-pricing/current.json",
            fx_file="/srv/openclaw-ops/usage-pricing/fx-daily.json",
            db_defaults_file="/etc/agent-runtime-ops/usage-writer.cnf",
            api_product="gemini_developer_api",
            price_scenario="paid_standard_list",
        )
        with patch.dict(os.environ, {"SUDO_USER": "svcops"}, clear=False):
            _enforce_sudo_usage_artifact_defaults(args)
            args.pricing_file = "/tmp/operator-chosen.json"
            with self.assertRaisesRegex(UsageContractError, "installed defaults"):
                _enforce_sudo_usage_artifact_defaults(args)

    def test_shipped_human_curated_catalog_is_valid_and_covers_current_stable_models(
        self,
    ) -> None:
        catalog_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "usage-pricing"
            / "google-gemini-paid-standard-2026-07-27.json"
        )
        catalog = load_pricing_catalog(catalog_path)
        self.assertEqual(
            [entry["actualModel"] for entry in catalog.payload["entries"]],
            ["gemini-3.5-flash", "gemini-3.6-flash"],
        )
        self.assertEqual(
            catalog.payload["entries"][1]["ratesPerMillion"]["outputIncludingThinking"],
            "7.50",
        )

    def test_human_readable_catalog_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "pricing.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(UsageContractError, "duplicate JSON key"):
                load_pricing_catalog(path)

    def test_known_components_are_only_a_daily_reference_estimate(self) -> None:
        row = receipt()
        row["actual"] = {
            "provider": "google",
            "model": "gemini-3.6-flash",
            "responseId": "response-1",
            "evidenceSource": "gemini_response.modelVersion",
        }
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
        projected = project_call_cost(
            row,
            validate_pricing_catalog(pricing()),
            validate_fx_ledger(fx()),
        )
        self.assertEqual(projected["estimateStatus"], "partial")
        self.assertEqual(projected["valuationKind"], "operational_estimate")
        self.assertEqual(projected["billingReconciliationStatus"], "not_applicable")
        self.assertEqual(projected["apiProduct"], "gemini_developer_api")
        self.assertEqual(projected["priceScenario"], "paid_standard_list")
        self.assertEqual(projected["referenceFxBasis"], "daily_reference_not_billing")
        self.assertEqual(projected["estimatedAmountUsd"], "1.290000000000")
        self.assertEqual(projected["estimatedAmountKrw"], "1884.6903")
        self.assertEqual(projected["referenceFxRateDate"], "2026-07-24")
        self.assertEqual(projected["referenceUsdPerEur"], "1.1377")
        self.assertEqual(projected["referenceKrwPerEur"], "1662.18")
        self.assertEqual(projected["referenceKrwPerUsd"], "1461.000263689901")
        for forbidden in (
            "amountUsd",
            "amountKrw",
            "billingAmountKrw",
            "paymentAmountKrw",
        ):
            self.assertNotIn(forbidden, projected)
        self.assertEqual(
            projected["missingComponents"],
            ["cache_storage_token_hour", "search_grounding"],
        )

    def test_weekend_uses_prior_daily_rate_but_pins_its_date(self) -> None:
        row = receipt()
        row["startedAt"] = "2026-07-26T03:00:00Z"
        row["actual"]["provider"] = "google"
        row["actual"]["model"] = "gemini-3.6-flash"
        row["usage"]["serviceTier"] = "standard"
        projected = project_call_cost(
            row,
            validate_pricing_catalog(pricing()),
            validate_fx_ledger(fx()),
        )
        self.assertEqual(projected["referenceFxRateDate"], "2026-07-24")
        self.assertIsNotNone(projected["estimatedAmountKrw"])

    def test_missing_price_or_stale_fx_is_not_zero(self) -> None:
        row = receipt()
        row["actual"]["provider"] = "google"
        row["actual"]["model"] = "gemini-new-model"
        row["usage"]["serviceTier"] = "standard"
        missing = project_call_cost(
            row,
            validate_pricing_catalog(pricing()),
            validate_fx_ledger(fx()),
        )
        self.assertEqual(missing["estimateStatus"], "unavailable")
        self.assertIsNone(missing["estimatedAmountKrw"])
        stale_fx = fx()
        stale_fx["maxCarryDays"] = 0
        row["actual"]["model"] = "gemini-3.6-flash"
        row["startedAt"] = "2026-07-26T03:00:00Z"
        stale = project_call_cost(
            row,
            validate_pricing_catalog(pricing()),
            validate_fx_ledger(stale_fx),
        )
        self.assertEqual(stale["missingComponents"], ["daily_fx_stale"])
        self.assertIsNone(stale["estimatedAmountKrw"])

    def test_price_scenario_is_explicit_and_never_inferred_from_service_tier(
        self,
    ) -> None:
        row = receipt()
        row["actual"]["provider"] = "google"
        row["actual"]["model"] = "gemini-3.6-flash"
        row["usage"]["serviceTier"] = "standard"
        projected = project_call_cost(
            row,
            validate_pricing_catalog(pricing()),
            validate_fx_ledger(fx()),
            price_scenario="free_tier",
        )
        self.assertEqual(projected["estimateStatus"], "unavailable")
        self.assertEqual(projected["priceScenario"], "free_tier")
        self.assertEqual(projected["missingComponents"], ["pricing_entry_missing"])
        self.assertIsNone(projected["estimatedAmountKrw"])

    def test_catalog_rejects_ambiguous_model_tier_and_noncanonical_order(self) -> None:
        duplicated = pricing()
        second = copy.deepcopy(duplicated["entries"][0])
        second["entryId"] = "z-duplicate"
        duplicated["entries"].append(second)
        with self.assertRaisesRegex(UsageContractError, "ambiguous"):
            validate_pricing_catalog(duplicated)
        unsorted = pricing()
        unsorted["entries"][0]["unpricedComponents"] = ["z", "a"]
        with self.assertRaisesRegex(UsageContractError, "sorted"):
            validate_pricing_catalog(unsorted)

    def test_fx_rejects_a_cross_rate_that_disagrees_with_raw_ecb_rates(self) -> None:
        tampered = fx()
        tampered["rates"][0]["krwPerUsd"] = "1460.993232000000"
        with self.assertRaisesRegex(UsageContractError, "krwPerEur / usdPerEur"):
            validate_fx_ledger(tampered)


if __name__ == "__main__":
    unittest.main()
