from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_runtime_ops.domain.usage_ledger import (
    CALL_SCHEMA,
    EXPORT_SCHEMA,
    UsageContractError,
    coverage_command,
    coverage_manifest_digest,
    export_command,
    parse_coverage_stdout,
    receipt_digest,
    redact_error,
    validate_call_receipt,
    validate_coverage,
    validate_export,
)


def receipt(
    *,
    seq: int = 1,
    call_id: str = "018f8512-7d1a-7a95-a53e-27f0cf9c7b82",
    family: str = "hermes",
) -> dict:
    coverage = coverage_payload(family)
    value = {
        "schema": CALL_SCHEMA,
        "ledgerSeq": seq,
        "receiptDigest": "",
        "producerCoverageDigest": coverage["manifestDigest"],
        "callId": call_id,
        "runId": "run-1",
        "turnId": "turn-1",
        "requestId": "request-1",
        "sessionId": "session-1",
        "trigger": "user",
        "attempt": 1,
        "retryOf": None,
        "fallbackParent": None,
        "fallbackIndex": 0,
        "startedAt": "2026-07-26T00:00:00.000Z",
        "completedAt": "2026-07-26T00:00:01.000Z",
        "status": "succeeded",
        "configured": {"provider": "google", "model": "gemini-3.6-flash"},
        "requested": {"provider": "google", "model": "gemini-3.6-flash"},
        "actual": {
            "provider": "google",
            "model": "gemini-3.6-flash",
            "responseId": "response-1",
            "evidenceSource": "gemini_response.modelVersion",
        },
        "usage": {
            "inputTotal": 100,
            "inputNonCached": 80,
            "cacheRead": 20,
            "cacheWrite": None,
            "outputCandidates": 12,
            "reasoningThinking": 3,
            "toolUsePrompt": 0,
            "providerReportedTotal": 115,
            "serviceTier": "standard",
            "rawProviderUsage": {
                "promptTokenCount": 100,
                "cachedContentTokenCount": 20,
                "candidatesTokenCount": 12,
                "thoughtsTokenCount": 3,
                "toolUsePromptTokenCount": 0,
                "totalTokenCount": 115,
                "serviceTier": "standard",
            },
        },
        "usageCoverage": "partial",
        "missingUsageFields": ["cacheWrite"],
        "receiptCoverage": "partial",
        "missingReceiptFields": ["usage.cacheWrite"],
        "finishReason": "STOP",
        "errorCategory": None,
    }
    value["receiptDigest"] = receipt_digest(value)
    return value


def coverage_payload(family: str = "hermes") -> dict:
    value = {
        "schema": "jitech-provider-usage-coverage/v1",
        "productFamily": family,
        "manifestDigest": "",
        "coverageStatus": "complete",
        "surfaces": [
            {
                "surfaceCode": "chat.main",
                "observationKind": "per_call",
                "meterFamily": "tokens",
                "modelEvidence": "provider_response",
                "retryObservation": "physical_attempt",
                "usageObservation": "provider_reported",
                "status": "implemented",
                "gapCode": None,
            }
        ],
    }
    value["manifestDigest"] = coverage_manifest_digest(value)
    return value


def export_page(
    *,
    after: int = 0,
    receipts: list[dict] | None = None,
    high: int | None = None,
    family: str = "hermes",
) -> dict:
    rows = receipts if receipts is not None else [receipt(seq=after + 1, family=family)]
    next_cursor = rows[-1]["ledgerSeq"] if rows else after
    high_watermark = next_cursor if high is None else high
    return {
        "schema": EXPORT_SCHEMA,
        "after": after,
        "nextCursor": next_cursor,
        "highWatermark": high_watermark,
        "count": len(rows),
        "hasMore": next_cursor < high_watermark,
        "receipts": rows,
        "coverageManifests": [coverage_payload(family)] if rows else [],
    }


class UsageReceiptContractTest(unittest.TestCase):
    def coverage_fixture(self) -> dict:
        path = (
            Path(__file__).parent
            / "fixtures"
            / "jitech-provider-usage-coverage-v1.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def test_exact_product_fixture_matches_common_contract(self) -> None:
        fixture_path = (
            Path(__file__).parent / "fixtures" / "jitech-provider-usage-export-v1.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        page = validate_export(fixture, expected_after=0, expected_family="openclaw")
        self.assertEqual(page.next_cursor, 1)
        self.assertEqual(page.high_watermark, 1)
        self.assertEqual(
            page.receipts[0]["receiptDigest"], receipt_digest(page.receipts[0])
        )

    def test_exact_common_receipt_and_export_pass(self) -> None:
        row = receipt()
        self.assertIs(validate_call_receipt(row), row)
        page = validate_export(
            export_page(receipts=[row]), expected_after=0, expected_family="hermes"
        )
        self.assertEqual(page.next_cursor, 1)
        self.assertEqual(len(page.receipts), 1)
        self.assertEqual(
            page.receipts[0]["producerCoverageDigest"],
            page.coverage_manifests[0].manifest_digest,
        )

    def test_export_requires_exact_historical_manifest_set(self) -> None:
        page = export_page()
        page["coverageManifests"] = []
        with self.assertRaisesRegex(UsageContractError, "must exactly match"):
            validate_export(page, expected_after=0, expected_family="hermes")

        page = export_page()
        extra = coverage_payload("hermes")
        extra["surfaces"][0]["surfaceCode"] = "chat.secondary"
        extra["manifestDigest"] = coverage_manifest_digest(extra)
        page["coverageManifests"].append(extra)
        page["coverageManifests"].sort(key=lambda item: item["manifestDigest"])
        with self.assertRaisesRegex(UsageContractError, "must exactly match"):
            validate_export(page, expected_after=0, expected_family="hermes")

    def test_empty_export_has_no_historical_manifests(self) -> None:
        page = validate_export(
            export_page(receipts=[]),
            expected_after=0,
            expected_family="hermes",
        )
        self.assertEqual(page.coverage_manifests, ())

    def test_unknown_field_fails_closed(self) -> None:
        row = receipt()
        row["providerText"] = "must never be accepted"
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "keys mismatch"):
            validate_call_receipt(row)

    def test_digest_tamper_fails_closed(self) -> None:
        row = receipt()
        row["usage"]["inputTotal"] = 101
        with self.assertRaisesRegex(UsageContractError, "does not match"):
            validate_call_receipt(row)

    def test_null_is_preserved_and_never_coerced_to_zero(self) -> None:
        row = receipt()
        row["usage"]["cacheRead"] = None
        row["missingUsageFields"] = ["cacheRead", "cacheWrite"]
        row["missingReceiptFields"] = ["usage.cacheRead", "usage.cacheWrite"]
        row["receiptDigest"] = receipt_digest(row)
        validated = validate_call_receipt(row)
        self.assertIsNone(validated["usage"]["cacheRead"])

    def test_complete_with_missing_fields_is_rejected(self) -> None:
        row = receipt()
        row["usageCoverage"] = "complete"
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "must be partial"):
            validate_call_receipt(row)

    def test_content_bearing_raw_usage_is_rejected(self) -> None:
        row = receipt()
        row["usage"]["rawProviderUsage"]["message"] = "customer text"
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "non-accounting"):
            validate_call_receipt(row)

    def test_raw_usage_modality_details_are_accounting_only(self) -> None:
        row = receipt()
        row["usage"]["rawProviderUsage"]["promptTokensDetails"] = [
            {"modality": "TEXT", "tokenCount": 100}
        ]
        row["receiptDigest"] = receipt_digest(row)
        self.assertIs(validate_call_receipt(row), row)

    def test_generic_provider_accounting_fields_are_allowed_without_content(self) -> None:
        row = receipt()
        row["usage"]["rawProviderUsage"] = {
            "prompt_tokens": 50,
            "completion_tokens": 7,
            "total_tokens": 57,
            "cache_read_input_tokens": 10,
            "prompt_tokens_details": {
                "cached_tokens": 10,
                "audio_tokens": 0,
            },
            "service_tier": "standard",
        }
        row["receiptDigest"] = receipt_digest(row)
        self.assertIs(validate_call_receipt(row), row)

    def test_generic_provider_detail_content_is_rejected(self) -> None:
        row = receipt()
        row["usage"]["rawProviderUsage"] = {
            "input_tokens": 50,
            "input_tokens_details": {"message": "must never be accepted"},
        }
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "non-accounting"):
            validate_call_receipt(row)

    def test_missing_usage_fields_must_exactly_match_null_dimensions(self) -> None:
        row = receipt()
        row["missingUsageFields"] = ["cacheRead"]
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "exactly name null"):
            validate_call_receipt(row)

    def test_receipt_missing_fields_cannot_invent_unknown_paths(self) -> None:
        row = receipt()
        row["missingReceiptFields"] = ["usage.cacheWrite", "bogus.path"]
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(
            UsageContractError, "inconsistent with applicable null evidence"
        ):
            validate_call_receipt(row)

    def test_unknown_trigger_and_non_success_error_are_exact_receipt_gaps(self) -> None:
        row = receipt()
        row["trigger"] = "unknown"
        row["status"] = "interrupted"
        row["finishReason"] = None
        row["errorCategory"] = None
        row["missingReceiptFields"] = ["trigger", "errorCategory", "usage.cacheWrite"]
        row["receiptDigest"] = receipt_digest(row)
        validate_call_receipt(row)
        row["missingReceiptFields"] = ["usage.cacheWrite"]
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(
            UsageContractError, "inconsistent with applicable null evidence"
        ):
            validate_call_receipt(row)

    def test_fallback_requires_positive_index(self) -> None:
        row = receipt()
        row["fallbackParent"] = "call-parent"
        row["receiptDigest"] = receipt_digest(row)
        with self.assertRaisesRegex(UsageContractError, "must be positive"):
            validate_call_receipt(row)

    def test_ledger_rollback_is_rejected(self) -> None:
        page = export_page(after=7, receipts=[], high=6)
        with self.assertRaisesRegex(UsageContractError, "moved backwards"):
            validate_export(page, expected_after=7, expected_family="hermes")

    def test_has_more_without_cursor_progress_is_rejected(self) -> None:
        page = export_page(after=7, receipts=[], high=8)
        with self.assertRaisesRegex(UsageContractError, "no cursor progress"):
            validate_export(page, expected_after=7, expected_family="hermes")

    def test_sequence_must_be_strictly_ascending(self) -> None:
        one = receipt(seq=2, call_id="call-two")
        two = receipt(seq=1, call_id="call-one")
        page = export_page(after=0, receipts=[one, two], high=2)
        with self.assertRaisesRegex(UsageContractError, "unique and ascending"):
            validate_export(page, expected_after=0, expected_family="hermes")

    def test_product_adapters_only_select_the_cli_entrypoint(self) -> None:
        self.assertEqual(
            export_command("hermes", after=9, limit=500),
            ["hermes", "usage-receipts", "export", "--after", "9", "--limit", "500"],
        )
        self.assertEqual(
            export_command("openclaw", after=9, limit=500),
            ["openclaw", "usage-receipts", "export", "--after", "9", "--limit", "500"],
        )
        self.assertEqual(
            coverage_command("hermes"),
            ["hermes", "usage-receipts", "coverage", "--json"],
        )

    def test_coverage_manifest_fixture_is_exact_and_partial(self) -> None:
        payload = self.coverage_fixture()
        result = validate_coverage(payload, expected_family="openclaw")
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.manifest_digest, coverage_manifest_digest(payload))
        self.assertEqual(
            [item["surfaceCode"] for item in result.surfaces],
            ["codex.app_server", "pi.embedded"],
        )
        parsed = parse_coverage_stdout(json.dumps(payload), expected_family="openclaw")
        self.assertEqual(parsed, result)

    def test_coverage_manifest_rejects_digest_order_and_false_complete(self) -> None:
        payload = self.coverage_fixture()
        payload["manifestDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(UsageContractError):
            validate_coverage(payload, expected_family="openclaw")

        payload = self.coverage_fixture()
        payload["surfaces"] = list(reversed(payload["surfaces"]))
        payload["manifestDigest"] = coverage_manifest_digest(payload)
        with self.assertRaises(UsageContractError):
            validate_coverage(payload, expected_family="openclaw")

        payload = self.coverage_fixture()
        payload["coverageStatus"] = "complete"
        payload["manifestDigest"] = coverage_manifest_digest(payload)
        with self.assertRaises(UsageContractError):
            validate_coverage(payload, expected_family="openclaw")

    def test_coverage_manifest_requires_gap_code_only_for_nonimplemented_surface(
        self,
    ) -> None:
        payload = self.coverage_fixture()
        payload["surfaces"][0]["gapCode"] = None
        payload["manifestDigest"] = coverage_manifest_digest(payload)
        with self.assertRaises(UsageContractError):
            validate_coverage(payload, expected_family="openclaw")

        payload = self.coverage_fixture()
        payload["surfaces"][1]["gapCode"] = "should_not_exist"
        payload["manifestDigest"] = coverage_manifest_digest(payload)
        with self.assertRaises(UsageContractError):
            validate_coverage(payload, expected_family="openclaw")

    def test_error_redaction_does_not_repeat_credentials(self) -> None:
        output = redact_error("Authorization: BearerValue password=hunter2 token=abc")
        self.assertNotIn("BearerValue", output)
        self.assertNotIn("hunter2", output)
        self.assertNotIn("token=abc", output)

    def test_writer_credential_loader_contract_is_single_fd_and_root_owned(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "opsctl"
            / "agent_runtime_ops"
            / "domain"
            / "usage_ledger.py"
        ).read_text(encoding="utf-8")
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("os.fstat(fd)", source)
        self.assertIn("info.st_uid != 0", source)
        self.assertIn("info.st_gid != 0", source)
        self.assertIn("info.st_nlink != 1", source)
        self.assertIn('os.fdopen(fd, "r", encoding="utf-8")', source)

    def test_install_contract_enables_three_minute_collector_and_scoped_sudoers(
        self,
    ) -> None:
        install_text = (Path(__file__).parents[1] / "install.sh").read_text(
            encoding="utf-8"
        )
        lock_text = (Path(__file__).parents[1] / "requirements.lock").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnUnitInactiveSec=3min", install_text)
        self.assertIn("ConditionPathExists=$USAGE_DB_DEFAULTS_FILE", install_text)
        self.assertIn("systemctl enable --now", install_text)
        self.assertIn("systemctl is-enabled --quiet", install_text)
        self.assertIn("systemctl is-active --quiet", install_text)
        self.assertIn('die "usage collector timer is not active"', install_text)
        usage_install = install_text.split("install_usage_collect_timer()", 1)[1].split(
            "install_ops_sudoers()", 1
        )[0]
        self.assertNotIn("|| true", usage_install)
        self.assertIn("usage collect --all --db-defaults-file", install_text)
        self.assertIn("NOPASSWD: %s usage collect *", install_text)
        self.assertNotIn("password=", install_text)
        self.assertIn("PyMySQL==1.1.2", lock_text)
        self.assertIn(
            "e6b1d89711dd51f8f74b1631fe08f039e7d76cf67a42a323d3178f0f25762ed9",
            lock_text,
        )


if __name__ == "__main__":
    unittest.main()
