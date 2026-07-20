from __future__ import annotations

import unittest
from unittest import mock

from agent_runtime_ops.domain.secret_probe import (
    PROBE_VERIFIED,
    PROVIDER_CHECKS,
    build_probe_script,
    classify_probe_output,
    probe_key_in_container,
)

GEMINI = PROVIDER_CHECKS["GEMINI_API_KEY"]


class ScriptSafetyTest(unittest.TestCase):
    """값은 컨테이너 env 에서만 읽히고, 스크립트는 상태코드만 낸다."""

    def test_script_reads_env_not_literal_value(self) -> None:
        s = build_probe_script(GEMINI)
        # env 참조만 있고, 값 자체는 스크립트에 없다(opsctl 이 값을 모름).
        self.assertIn("$GEMINI_API_KEY", s)
        self.assertIn("x-goog-api-key: $GEMINI_API_KEY", s)

    def test_script_emits_status_code_only(self) -> None:
        # -o /dev/null: 본문 버림. -w %{http_code}: 상태코드만. 본문/URL 로깅 없음.
        s = build_probe_script(GEMINI)
        self.assertIn("-o /dev/null", s)
        self.assertIn("%{http_code}", s)

    def test_absent_key_short_circuits(self) -> None:
        s = build_probe_script(GEMINI)
        self.assertIn("echo absent", s)


class ClassifyTest(unittest.TestCase):
    def test_200_is_valid(self) -> None:
        self.assertEqual(classify_probe_output(GEMINI, "http=200\n", 0)[0], "valid")

    def test_403_is_invalid(self) -> None:
        # 잘못된 키 = provider 가 인증 거부. "dummy" 가 여기 걸린다.
        self.assertEqual(classify_probe_output(GEMINI, "http=403\n", 0)[0], "invalid")

    def test_400_is_invalid(self) -> None:
        self.assertEqual(classify_probe_output(GEMINI, "http=400\n", 0)[0], "invalid")

    def test_000_is_unreachable_not_invalid(self) -> None:
        # 네트워크/타임아웃 ≠ 무효 (nas probe 의 timeout≠EIO 와 같은 구분).
        self.assertEqual(classify_probe_output(GEMINI, "http=000\n", 0)[0], "unreachable")

    def test_5xx_is_unreachable_not_invalid(self) -> None:
        # provider 장애를 키 무효로 오판하지 않는다.
        self.assertEqual(classify_probe_output(GEMINI, "http=503\n", 0)[0], "unreachable")

    def test_absent(self) -> None:
        self.assertEqual(classify_probe_output(GEMINI, "absent\n", 0)[0], "absent")

    def test_notool_is_unreachable(self) -> None:
        self.assertEqual(classify_probe_output(GEMINI, "notool\n", 0)[0], "unreachable")

    def test_docker_exec_failure_is_error(self) -> None:
        self.assertEqual(classify_probe_output(GEMINI, "", 1)[0], "error")


class VerifiedSetTest(unittest.TestCase):
    def test_only_gemini_live_verified(self) -> None:
        # 추측을 확정으로 승격하지 않는다: 라이브로 닫은 건 지금 gemini 뿐.
        self.assertEqual(PROBE_VERIFIED, frozenset({"GEMINI_API_KEY"}))


class ProbeCallTest(unittest.TestCase):
    def test_probe_is_read_only_docker_exec(self) -> None:
        # probe 는 docker exec 로 스크립트만 돌린다 — 어떤 write/set 도 없다.
        captured = {}

        class R:
            returncode = 0
            stdout = "http=200\n"
            stderr = ""

        def fake_run(args):
            captured["args"] = args
            return R()

        with mock.patch("agent_runtime_ops.domain.secret_probe.run_text", fake_run):
            status, _ = probe_key_in_container("cabc123", GEMINI)
        self.assertEqual(status, "valid")
        self.assertEqual(captured["args"][:3], ["docker", "exec", "cabc123"])
        self.assertIn("sh", captured["args"])
        # 값이 argv 에 없다(env 참조뿐).
        self.assertNotIn("http=200", " ".join(a for a in captured["args"] if a != "http=200\n"))


if __name__ == "__main__":
    unittest.main()
