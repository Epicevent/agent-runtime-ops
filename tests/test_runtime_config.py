from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_runtime_ops.commands.runtime_config import (
    cmd_runtime_config_sanitize,
    cmd_runtime_config_status,
    cmd_runtime_set_model,
    runtime_provider_id,
)


class RuntimeConfigTests(unittest.TestCase):
    def test_runtime_provider_id_canonicalizes_google_aliases(self) -> None:
        for provider in ("google", "google-ai", "google_ai", "google-gemini", "google_gemini", "gemini"):
            self.assertEqual(runtime_provider_id(provider), "gemini")

    def test_runtime_set_model_stores_runtime_provider_id(self) -> None:
        written: dict[str, object] = {}
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config.read_hermes_config", return_value={}),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config", side_effect=lambda _slot, _path, config: written.update(config)),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_set_model(
                argparse.Namespace(
                    slot="oc16",
                    provider="google",
                    model="gemini-3.1-pro-preview",
                    state_root="/srv/openclaw-ops",
                )
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["provider"], "gemini")
        self.assertEqual(written["model"], "gemini-3.1-pro-preview")
        self.assertIn("provider_raw=google", text)
        self.assertIn("provider_runtime=gemini", text)

    def test_runtime_config_status_prints_raw_and_runtime_provider(self) -> None:
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_hermes_config",
                return_value={"provider": "google", "model": "gemini-3.1-pro-preview"},
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_status(argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops"))
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("provider=gemini", text)
        self.assertIn("provider_raw=google", text)
        self.assertIn("provider_runtime=gemini", text)

    def test_runtime_config_sanitize_dry_run_reports_paths_without_writing_values(self) -> None:
        secret_value = "do-not-print-this-secret"
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config.read_hermes_config",
                return_value={"providers": {"google": {"api_key": secret_value, "enabled": True}}},
            ),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config") as write_config,
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_sanitize(
                argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops", dry_run=True, apply=False)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        write_config.assert_not_called()
        self.assertIn("runtime_config_sanitize_mode=dry_run", text)
        self.assertIn("remove_path=providers.google.api_key value_present=yes secret_value_printed=no", text)
        self.assertIn("runtime_config_sanitize_status=dry_run", text)
        self.assertNotIn(secret_value, text)

    def test_runtime_config_sanitize_apply_removes_secret_override_paths(self) -> None:
        written: dict[str, object] = {}
        output = io.StringIO()
        config = {
            "providers": {
                "google": {"apiKey": "google-secret", "enabled": True},
                "gemini": {"key": "gemini-secret", "model": "gemini-3.1-pro-preview"},
            },
            "auth": {"gemini": {"api_key": "auth-secret", "other": "keep"}},
        }
        with (
            patch("agent_runtime_ops.commands.runtime_config.is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_config._load_hermes_target", return_value=SimpleNamespace(slot="oc16")),
            patch("agent_runtime_ops.commands.runtime_config.hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config.read_hermes_config", return_value=config),
            patch("agent_runtime_ops.commands.runtime_config.write_hermes_config", side_effect=lambda _slot, _path, value: written.update(value)),
            patch("agent_runtime_ops.commands.runtime_config.append_action_log"),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_config_sanitize(
                argparse.Namespace(slot="oc16", state_root="/srv/openclaw-ops", dry_run=False, apply=True)
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(written["providers"]["google"], {"enabled": True})
        self.assertEqual(written["providers"]["gemini"], {"model": "gemini-3.1-pro-preview"})
        self.assertEqual(written["auth"]["gemini"], {"other": "keep"})
        self.assertIn("remove_count=3", text)
        self.assertIn("runtime_config_sanitize_status=updated", text)
        self.assertNotIn("google-secret", text)
        self.assertNotIn("gemini-secret", text)
        self.assertNotIn("auth-secret", text)


if __name__ == "__main__":
    unittest.main()
