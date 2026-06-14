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


if __name__ == "__main__":
    unittest.main()
