from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_runtime_ops.commands.runtime_config import cmd_runtime_config_status, cmd_runtime_set_model, runtime_provider_id


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
            patch("agent_runtime_ops.commands.runtime_config._hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch("agent_runtime_ops.commands.runtime_config._read_config", return_value={}),
            patch("agent_runtime_ops.commands.runtime_config._write_config", side_effect=lambda _slot, _path, config: written.update(config)),
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
            patch("agent_runtime_ops.commands.runtime_config._hermes_config_path", return_value=Path("/home/oc16/.hermes/config.yaml")),
            patch(
                "agent_runtime_ops.commands.runtime_config._read_config",
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


if __name__ == "__main__":
    unittest.main()
