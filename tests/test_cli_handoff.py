from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.cli import cmd_handoff_print, cmd_handoff_status, cmd_handoff_value_command
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings
from agent_runtime_ops.yamlio import dump_yaml


def binding(account: str, family: str, gateway: int, bridge: int) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family=family,
        runtime_class="dev",
        gateway_port=gateway,
        bridge_port=bridge,
    )


def write_state(root: Path) -> None:
    digest = "sha256:" + "2" * 64
    (root / "runtime-bindings.json").write_text(
        dump_runtime_bindings(
            [
                binding("dev-oc", "openclaw", 30789, 30790),
                binding("dev-hermess", "hermes", 30889, 30890),
            ]
        ),
        encoding="utf-8",
    )
    for target, family, profile in (
        ("dev-oc", "openclaw", "openclaw-dev"),
        ("dev-hermess", "hermes", "hermes-dev"),
    ):
        manifest_dir = root / "runtime" / target
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "manifest.yaml").write_text(
            dump_yaml(
                {
                    "schema_version": 1,
                    "target": target,
                    "linux_account": target,
                    "image_name": "direct-image",
                    "family": family,
                    "runtime_class": "dev",
                    "runtime_profile": profile,
                    "wrapper_image": f"ghcr.io/epicevent/agent-runtime-{family}@{digest}",
                    "product_image": f"ghcr.io/epicevent/{family}-jitech@{digest}",
                    "wrapper_image_digest": digest,
                    "product_image_digest": digest,
                }
            ),
            encoding="utf-8",
        )


class CliHandoffTests(unittest.TestCase):
    def test_openclaw_handoff_status_reports_token_structure_without_value(self) -> None:
        token = "secret-token-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            home = root / "home" / "dev-oc"
            config = home / ".openclaw" / "openclaw.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                '{"gateway":{"auth":{"mode":"token","token":"' + token + '"}}}\n',
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_home", return_value=home),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_handoff_status(argparse.Namespace(slot="dev-oc", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("handoff_kind=openclaw_gateway_token", text)
        self.assertIn(f"handoff_secret_file={config}", text)
        self.assertIn("handoff_secret_json_path=gateway.auth.token", text)
        self.assertIn("handoff_token=present", text)
        self.assertIn("handoff_value_printed=no", text)
        self.assertIn("handoff_value_retrieval=manual_cli", text)
        self.assertIn("handoff_value_command=sudo /usr/local/bin/opsctl handoff print dev-oc", text)
        self.assertIn("handoff_status=ok", text)
        self.assertNotIn("svcops-control.sh", text)
        self.assertNotIn(token, text)

    def test_hermes_handoff_status_reports_password_structure_without_value(self) -> None:
        password = "secret-password-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            handoff = root / "handoff" / "hermes-workspace-dev-hermess.env"
            handoff.parent.mkdir()
            handoff.write_text(f"password={password}\n", encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_handoff_status(argparse.Namespace(slot="dev-hermess", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("handoff_kind=hermes_workspace_password", text)
        self.assertIn(f"handoff_secret_file={handoff}", text)
        self.assertIn("handoff_secret_key=password", text)
        self.assertIn("handoff_password=present", text)
        self.assertIn("handoff_value_printed=no", text)
        self.assertIn("handoff_value_retrieval=manual_cli", text)
        self.assertIn("handoff_value_command=sudo /usr/local/bin/opsctl handoff print dev-hermess", text)
        self.assertIn("handoff_status=ok", text)
        self.assertNotIn("svcops-control.sh", text)
        self.assertNotIn(password, text)

    def test_handoff_value_command_reports_repo_native_manual_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_handoff_value_command(argparse.Namespace(slot="dev-oc", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("handoff_value_printed=no", text)
        self.assertIn("handoff_value_command=sudo /usr/local/bin/opsctl handoff print dev-oc", text)
        self.assertNotIn("svcops-control.sh", text)

    def test_handoff_print_openclaw_is_explicit_secret_output(self) -> None:
        token = "secret-token-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            home = root / "home" / "dev-oc"
            config = home / ".openclaw" / "openclaw.json"
            config.parent.mkdir(parents=True)
            config.write_text(
                '{"gateway":{"auth":{"mode":"token","token":"' + token + '"}}}\n',
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli._slot_home", return_value=home),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_handoff_print(argparse.Namespace(slot="dev-oc", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("handoff_value_printed=yes", text)
        self.assertIn(f"token={token}", text)
        self.assertIn("handoff_print_status=ok", text)

    def test_handoff_print_hermes_is_explicit_secret_output(self) -> None:
        password = "secret-password-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            handoff = root / "handoff" / "hermes-workspace-dev-hermess.env"
            handoff.parent.mkdir()
            handoff.write_text(f"password={password}\n", encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_handoff_print(argparse.Namespace(slot="dev-hermess", state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("handoff_value_printed=yes", text)
        self.assertIn(f"password={password}", text)
        self.assertIn("handoff_print_status=ok", text)


if __name__ == "__main__":
    unittest.main()
