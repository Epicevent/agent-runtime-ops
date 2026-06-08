from __future__ import annotations

import unittest

from agent_runtime_ops.redaction import redact


class RedactionTests(unittest.TestCase):
    def test_preserves_secret_presence_status_values(self) -> None:
        text = "\n".join(
            [
                "gemini_api_key=present",
                "openai_api_key=absent",
                "runtime_secret_status=ok",
                "secret_value_printed=no",
            ]
        )
        self.assertEqual(redact(text), text)

    def test_redacts_actual_secret_assignments(self) -> None:
        secret = "AIza" + "A" * 32
        redacted = redact(f"gemini_api_key={secret}\npassword=super-secret\n")
        self.assertNotIn(secret, redacted)
        self.assertIn("gemini_api_key=<redacted>", redacted)
        self.assertIn("password=<redacted>", redacted)


if __name__ == "__main__":
    unittest.main()
