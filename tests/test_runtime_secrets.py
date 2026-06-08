from __future__ import annotations

import unittest

from agent_runtime_ops.profiles import load_profile
from agent_runtime_ops.runtime_secrets import (
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_provider_secret_values,
)


class RuntimeSecretTests(unittest.TestCase):
    def test_parse_secret_env_text_accepts_exports_and_quotes(self) -> None:
        values = parse_secret_env_text(
            """
            # comment
            export GEMINI_API_KEY='value with spaces'
            GOOGLE_API_KEY=plain
            """,
            source="test",
        )
        self.assertEqual(values["GEMINI_API_KEY"], "value with spaces")
        self.assertEqual(values["GOOGLE_API_KEY"], "plain")

    def test_validate_provider_secret_values_rejects_unknown_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported runtime secret"):
            validate_provider_secret_values({"DATABASE_URL": "postgres://example"})

    def test_render_upserted_secret_env_preserves_other_lines(self) -> None:
        rendered = render_upserted_secret_env(
            "OPENCLAW_RUNTIME_FAMILY=openclaw\nGEMINI_API_KEY='old'\n",
            {"GEMINI_API_KEY": "new'value", "GOOGLE_API_KEY": "also-new"},
        )
        self.assertIn("OPENCLAW_RUNTIME_FAMILY=openclaw", rendered)
        self.assertIn("GEMINI_API_KEY='new'\"'\"'value'", rendered)
        self.assertIn("GOOGLE_API_KEY='also-new'", rendered)

    def test_profile_secret_paths_follow_runtime_contracts(self) -> None:
        openclaw = primary_profile_secret_file(load_profile("openclaw-dev"), "dev-oc")
        hermes = primary_profile_secret_file(load_profile("hermes-dev"), "dev-hermess")
        self.assertEqual(openclaw.path.as_posix(), "/home/dev-oc/openclaw/.env")
        self.assertEqual(openclaw.owner_mode, "root")
        self.assertEqual(hermes.path.as_posix(), "/home/dev-hermess/.hermes/.env")
        self.assertEqual(hermes.owner_mode, "runtime")


if __name__ == "__main__":
    unittest.main()
