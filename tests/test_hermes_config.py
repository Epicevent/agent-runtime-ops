from __future__ import annotations

import unittest

from agent_runtime_ops.domain.hermes_config import model_endpoint_drift


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


if __name__ == "__main__":
    unittest.main()
