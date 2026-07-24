from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.hermes_smoke import run_hermes_http_smoke


class HermesSmokeTests(unittest.TestCase):
    def test_hermes_smoke_checks_config_model_models_and_optional_chat(self) -> None:
        calls: list[list[str]] = []

        def fake_run_text(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            payload = [
                {"name": "hermes_smoke_config_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_model_info_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_claude_proxy_models_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_chat_ok", "ok": True, "detail": "status=200"},
            ]
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

        with patch("agent_runtime_ops.domain.hermes_smoke.run_text", side_effect=fake_run_text):
            checks = run_hermes_http_smoke("container123", chat_smoke=True)

        self.assertTrue(all(ok for ok, _, _ in checks))
        argv = calls[0]
        joined = " ".join(argv)
        self.assertIn("HERMES_CHAT_SMOKE=1", argv)
        self.assertIn("/api/hermes-config", joined)
        self.assertIn("/api/model/info", joined)
        self.assertIn("/api/claude-proxy/v1/models", joined)
        self.assertIn("/api/send-stream", joined)

    def test_hermes_smoke_marks_chat_not_required(self) -> None:
        def fake_run_text(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
            payload = [
                {"name": "hermes_smoke_config_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_model_info_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_claude_proxy_models_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_chat_not_required", "ok": True, "detail": "not_required"},
            ]
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

        with patch("agent_runtime_ops.domain.hermes_smoke.run_text", side_effect=fake_run_text):
            checks = run_hermes_http_smoke("container123", chat_smoke=False)

        self.assertIn((True, "hermes_smoke_chat_not_required", "not_required"), checks)

    def test_model_attestation_is_a_separate_required_result(self) -> None:
        calls: list[list[str]] = []

        def fake_run_text(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            payload = [
                {"name": "hermes_smoke_config_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_model_info_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_claude_proxy_models_ok", "ok": True, "detail": "status=200"},
                {"name": "hermes_smoke_chat_ok", "ok": True, "detail": "status=200"},
                {
                    "name": "hermes_smoke_model_attested",
                    "ok": True,
                    "detail": "configured_provider=gemini configured_model=gemini-3.6-flash done_events=1 complete_provider_receipts=1 evidence_requested_models=gemini-3.6-flash receipt_model_versions=gemini-3.6-flash receipt_response_ids=resp-hermes-123 actual_model_relation=exact receipt_fields=responseId,modelVersion,usageMetadata,finishReason source=done_event_providerModelEvidence+providerReceipt evidence_source=gemini_response.modelVersion",
                },
            ]
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

        with patch("agent_runtime_ops.domain.hermes_smoke.run_text", side_effect=fake_run_text):
            checks = run_hermes_http_smoke("container123", chat_smoke=False, model_attest=True)

        self.assertIn("HERMES_MODEL_ATTEST=1", calls[0])
        embedded_script = calls[0][-1]
        self.assertIn("payload.providerModelEvidence", embedded_script)
        self.assertIn("payload.providerReceipt", embedded_script)
        self.assertIn("gemini_response.modelVersion", embedded_script)
        self.assertIn("receipt.responseId === evidence.responseId", embedded_script)
        self.assertIn("receiptModel === actualModel", embedded_script)
        self.assertIn(
            (
                True,
                "hermes_smoke_model_attested",
                "configured_provider=gemini configured_model=gemini-3.6-flash done_events=1 complete_provider_receipts=1 evidence_requested_models=gemini-3.6-flash receipt_model_versions=gemini-3.6-flash receipt_response_ids=resp-hermes-123 actual_model_relation=exact receipt_fields=responseId,modelVersion,usageMetadata,finishReason source=done_event_providerModelEvidence+providerReceipt evidence_source=gemini_response.modelVersion",
            ),
            checks,
        )


if __name__ == "__main__":
    unittest.main()
