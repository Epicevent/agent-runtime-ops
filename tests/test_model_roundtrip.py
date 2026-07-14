from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.domain.model_roundtrip import (
    MODEL_ROUNDTRIP_PROMPT,
    evaluate_roundtrip_reply,
    run_model_roundtrip_probe,
)


class EvaluateRoundtripReplyTest(unittest.TestCase):
    def test_ok_reply_passes(self) -> None:
        ok, detail = evaluate_roundtrip_reply("OK\n")
        self.assertTrue(ok)
        self.assertIn("ok_token=true", detail)

    def test_non_ok_but_real_reply_still_passes(self) -> None:
        # Any real completion proves the model answered — exact wording is not
        # the point; a 429/expired/blocked key is.
        ok, detail = evaluate_roundtrip_reply("Sure — OK it is.")
        self.assertTrue(ok)

    def test_reply_without_ok_token_still_passes_but_flags_it(self) -> None:
        ok, detail = evaluate_roundtrip_reply("네, 알겠습니다")
        self.assertTrue(ok)
        self.assertIn("ok_token=false", detail)

    def test_empty_output_fails(self) -> None:
        # oneshot writes nothing when the model produced no content.
        ok, detail = evaluate_roundtrip_reply("")
        self.assertFalse(ok)
        self.assertIn("no_reply", detail)

    def test_whitespace_only_fails(self) -> None:
        self.assertFalse(evaluate_roundtrip_reply("  \n  ")[0])

    def test_empty_sentinel_fails(self) -> None:
        ok, detail = evaluate_roundtrip_reply("(empty)")
        self.assertFalse(ok)
        self.assertIn("empty_sentinel", detail)

    def test_preview_is_single_line_and_bounded(self) -> None:
        ok, detail = evaluate_roundtrip_reply("line1\nline2 " + "x" * 200)
        self.assertTrue(ok)
        self.assertNotIn("\n", detail)
        self.assertLess(len(detail), 140)


def _proc(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class RunModelRoundtripProbeTest(unittest.TestCase):
    def test_uses_hermes_oneshot_in_container(self) -> None:
        seen = {}

        def fake_run_text(cmd, timeout=20):
            seen["cmd"] = cmd
            seen["timeout"] = timeout
            return _proc(0, "OK\n")

        with patch("agent_runtime_ops.domain.model_roundtrip.run_text", side_effect=fake_run_text):
            ok, _ = run_model_roundtrip_probe("cont-1", timeout=90)
        self.assertTrue(ok)
        self.assertEqual(seen["cmd"], ["docker", "exec", "cont-1", "hermes", "-z", MODEL_ROUNDTRIP_PROMPT])
        self.assertEqual(seen["timeout"], 90)

    def test_nonzero_exit_is_exec_failure(self) -> None:
        with patch(
            "agent_runtime_ops.domain.model_roundtrip.run_text",
            return_value=_proc(1, "", "no such container"),
        ):
            ok, detail = run_model_roundtrip_probe("cont-1")
        self.assertFalse(ok)
        self.assertIn("exec_failed", detail)
        self.assertIn("no such container", detail)

    def test_exit_zero_empty_output_still_fails(self) -> None:
        # The core trap: hermes -z returns 0 even when the model answered nothing.
        with patch("agent_runtime_ops.domain.model_roundtrip.run_text", return_value=_proc(0, "")):
            ok, detail = run_model_roundtrip_probe("cont-1")
        self.assertFalse(ok)
        self.assertIn("no_reply", detail)


if __name__ == "__main__":
    unittest.main()
