from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.cli import cmd_heartbeat_disable, cmd_heartbeat_status
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings
from agent_runtime_ops.yamlio import dump_yaml


def binding(account: str, family: str, runtime_class: str, gateway: int, bridge: int) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family=family,
        runtime_class=runtime_class,
        gateway_port=gateway,
        bridge_port=bridge,
    )


def write_state(root: Path) -> None:
    digest = "sha256:" + "3" * 64
    (root / "runtime-bindings.json").write_text(
        dump_runtime_bindings([binding("dev-oc", "openclaw", "dev", 30789, 30790)]),
        encoding="utf-8",
    )
    manifest_dir = root / "runtime" / "dev-oc"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "manifest.yaml").write_text(
        dump_yaml(
            {
                "schema_version": 1,
                "target": "dev-oc",
                "linux_account": "dev-oc",
                "image_name": "direct-image",
                "family": "openclaw",
                "runtime_class": "dev",
                "runtime_profile": "openclaw-dev",
                "wrapper_image": f"ghcr.io/epicevent/agent-runtime-openclaw@{digest}",
                "product_image": f"ghcr.io/epicevent/openclaw-jitech@{digest}",
                "wrapper_image_digest": digest,
                "product_image_digest": digest,
            }
        ),
        encoding="utf-8",
    )


class CliHeartbeatTests(unittest.TestCase):
    def test_heartbeat_status_reports_config_without_file_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            home = root / "home" / "dev-oc"
            workspace = home / ".openclaw" / "workspace" / "agent"
            workspace.mkdir(parents=True)
            heartbeat_file = workspace / "HEARTBEAT.md"
            heartbeat_file.write_text("do not print this content\n", encoding="utf-8")
            config = home / ".openclaw" / "openclaw.json"
            config.write_text(
                json.dumps({"agents": {"defaults": {"heartbeat": {"every": "15m", "model": "gemini"}}}}),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._slot_home", return_value=home),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_heartbeat_status(argparse.Namespace(slot="dev-oc", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(f"heartbeat_file_1={heartbeat_file}", text)
        self.assertIn("heartbeat_config_every=15m", text)
        self.assertIn("heartbeat_config_enabled=yes", text)
        self.assertIn("heartbeat_status=ok", text)
        self.assertNotIn("do not print this content", text)

    def test_heartbeat_disable_sets_defaults_and_agent_overrides_to_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            home = root / "home" / "dev-oc"
            config = home / ".openclaw" / "openclaw.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                json.dumps(
                    {
                        "agents": {
                            "defaults": {"heartbeat": {"every": "15m", "model": "gemini"}},
                            "list": [{"id": "a", "heartbeat": {"every": "5m"}}],
                        }
                    }
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_home", return_value=home),
                patch("agent_runtime_ops.cli._runtime_ids", return_value=(1234, 1234, 1235)),
                patch("agent_runtime_ops.cli.os.chown", create=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_heartbeat_disable(argparse.Namespace(slot="dev-oc", state_root=str(root)))
            data = json.loads(config.read_text(encoding="utf-8"))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertEqual(data["agents"]["defaults"]["heartbeat"]["every"], "0m")
        self.assertEqual(data["agents"]["list"][0]["heartbeat"]["every"], "0m")
        self.assertIn("heartbeat_config_disabled=yes", text)
        self.assertIn("heartbeat_agent_overrides_disabled=1", text)
        self.assertIn("heartbeat_config_enabled=no", text)
        self.assertIn("heartbeat_disable_status=ok", text)


if __name__ == "__main__":
    unittest.main()
