from __future__ import annotations

import unittest

from agent_runtime_ops.domain.hermes_config import (
    model_endpoint_drift,
    remove_version_note,
    upsert_version_note,
)


class ModelEndpointDriftTests(unittest.TestCase):
    def test_no_base_url_is_clean(self) -> None:
        result = model_endpoint_drift({"provider": "gemini", "model": {"default": "gemini-3.5-flash", "provider": "gemini"}})
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["routing_keys"], [])
        self.assertEqual(result["host"], "")

    def test_flat_string_model_is_clean(self) -> None:
        result = model_endpoint_drift({"provider": "gemini", "model": "gemini-3.5-flash"})
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["provider"], "gemini")
        self.assertEqual(result["routing_keys"], [])

    def test_matching_first_party_host_is_clean(self) -> None:
        result = model_endpoint_drift(
            {
                "model": {
                    "default": "gemini-3.5-flash",
                    "provider": "gemini",
                    "base_url": "https://generativelanguage.googleapis.com/v1beta",
                }
            }
        )
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["host"], "generativelanguage.googleapis.com")
        self.assertEqual(result["routing_keys"], ["base_url"])

    def test_openrouter_base_url_on_gemini_is_drift(self) -> None:
        # The exact misroute: a gemini/google provider left pointed at an
        # aggregator endpoint after a provider change — the Google key 401s there.
        result = model_endpoint_drift(
            {
                "model": {
                    "default": "gemini-3.5-flash",
                    "provider": "gemini",
                    "base_url": "https://openrouter.ai/api/v1",
                }
            }
        )
        self.assertEqual(result["verdict"], "drift")
        self.assertEqual(result["host"], "openrouter.ai")
        self.assertEqual(result["expected_host"], "googleapis.com")
        self.assertIn("does not match", result["reason"])

    def test_google_alias_normalizes_before_host_check(self) -> None:
        result = model_endpoint_drift(
            {
                "provider": "google",
                "model": {"default": "gemini-3.5-flash", "base_url": "https://openrouter.ai/api/v1"},
            }
        )
        self.assertEqual(result["provider"], "gemini")
        self.assertEqual(result["verdict"], "drift")

    def test_custom_provider_with_endpoint_is_unknown(self) -> None:
        # A deliberate gateway on a provider we have no canonical host for must
        # not be false-flagged as drift.
        result = model_endpoint_drift(
            {"model": {"default": "some-model", "provider": "myproxy", "base_url": "https://gw.internal/v1"}}
        )
        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["expected_host"], "")

    def test_intentional_openrouter_provider_is_clean(self) -> None:
        result = model_endpoint_drift(
            {"model": {"default": "auto", "provider": "openrouter", "base_url": "https://openrouter.ai/api/v1"}}
        )
        self.assertEqual(result["verdict"], "clean")

    def test_stale_api_key_surfaced_even_when_verdict_clean(self) -> None:
        result = model_endpoint_drift(
            {"model": {"default": "gemini-3.5-flash", "provider": "gemini", "api_key": "sk-stale", "api_mode": "responses"}}
        )
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["routing_keys"], ["api_key", "api_mode"])


class VersionNoteTests(unittest.TestCase):
    def test_upsert_inserts_newest_first(self) -> None:
        entries = upsert_version_note([], "2026.7.17", ["폴더 정리 지원"], date="2026-07-17")
        entries = upsert_version_note(entries, "2026.7.20", ["버전 기록 추가"])
        self.assertEqual([e["version"] for e in entries], ["2026.7.20", "2026.7.17"])
        self.assertEqual(entries[1], {"version": "2026.7.17", "notes": ["폴더 정리 지원"], "date": "2026-07-17"})

    def test_upsert_replaces_same_version(self) -> None:
        entries = upsert_version_note([], "2026.7.17", ["초안"])
        entries = upsert_version_note(entries, "2026.7.17", ["정정된 노트"])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["notes"], ["정정된 노트"])

    def test_upsert_strips_and_requires_nonempty(self) -> None:
        entries = upsert_version_note([], "2026.7.17", ["  공백 정리  ", ""])
        self.assertEqual(entries[0]["notes"], ["공백 정리"])
        with self.assertRaises(ValueError):
            upsert_version_note([], "2026.7.17", ["   ", ""])

    def test_upsert_validates_version_and_date(self) -> None:
        with self.assertRaises(ValueError):
            upsert_version_note([], "v1.2.3", ["note"])
        with self.assertRaises(ValueError):
            upsert_version_note([], "2026.7.17", ["note"], date="17-07-2026")
        # same-day follow-up suffix is valid
        entries = upsert_version_note([], "2026.7.17-1", ["note"])
        self.assertEqual(entries[0]["version"], "2026.7.17-1")

    def test_upsert_limits(self) -> None:
        with self.assertRaises(ValueError):
            upsert_version_note([], "2026.7.17", ["x"] * 11)
        with self.assertRaises(ValueError):
            upsert_version_note([], "2026.7.17", ["y" * 301])

    def test_remove(self) -> None:
        entries = upsert_version_note([], "2026.7.17", ["note"])
        remaining, removed = remove_version_note(entries, "2026.7.17")
        self.assertTrue(removed)
        self.assertEqual(remaining, [])
        remaining, removed = remove_version_note(remaining, "2026.7.17")
        self.assertFalse(removed)


if __name__ == "__main__":
    unittest.main()
