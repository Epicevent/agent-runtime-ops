from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.commands.runtime_secret import _run_runtime_secret_container_checks, cmd_runtime_secret_status
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings
from agent_runtime_ops.runtime_secrets import RuntimeSecretFile
from agent_runtime_ops.yamlio import dump_yaml


def write_state(root: Path) -> None:
    account = "dev-hermess"
    digest = "sha256:" + "3" * 64
    binding = RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family="hermes",
        runtime_class="dev",
        gateway_port=30889,
        bridge_port=30890,
    )
    (root / "runtime-bindings.json").write_text(dump_runtime_bindings([binding]), encoding="utf-8")
    manifest_dir = root / "runtime" / account
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "manifest.yaml").write_text(
        dump_yaml(
            {
                "schema_version": 1,
                "target": account,
                "linux_account": account,
                "image_name": "direct-image",
                "family": "hermes",
                "runtime_class": "dev",
                "runtime_profile": "hermes-workspace-dev",
                "wrapper_image": f"ghcr.io/epicevent/agent-runtime-hermes@{digest}",
                "product_image": f"ghcr.io/epicevent/hermes-workspace@{digest}",
                "wrapper_image_digest": digest,
                "product_image_digest": digest,
            }
        ),
        encoding="utf-8",
    )


class CliRuntimeSecretTests(unittest.TestCase):
    def test_runtime_secret_status_reports_api_server_key_without_value(self) -> None:
        secret_value = "internal-api-token"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            secret_file = root / "secret.env"
            secret_file.write_text(
                f"API_SERVER_KEY='{secret_value}'\nGEMINI_API_KEY='gemini-token'\n",
                encoding="utf-8",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._assert_secret_path_safe"),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=secret_file, owner_mode="runtime"),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_status(argparse.Namespace(slot="dev-hermess", state_root=str(root)))

        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("api_server_key=present", text)
        self.assertIn("gemini_api_key=present", text)
        self.assertIn("secret_value_printed=no", text)
        self.assertNotIn(secret_value, text)

    def test_runtime_secret_container_checks_find_container_by_binding(self) -> None:
        binding = RuntimeBinding(
            instance_id="instance-oc16",
            linux_account="oc16",
            public_host="oc16.ji-tech.co.kr",
            family="hermes",
            runtime_class="customer",
            gateway_port=30289,
            bridge_port=30290,
        )
        desired = SimpleNamespace(slot="oc16", route=binding)
        profile = SimpleNamespace(name="hermes-workspace-customer")
        calls: list[list[str]] = []

        def fake_run(argv: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if argv[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(argv, 0, stdout="container123\n", stderr="")
            if argv[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    stdout='[{"State":{"Running":true,"Health":{"Status":"healthy"}}}]',
                    stderr="",
                )
            if argv[:2] == ["docker", "exec"]:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unexpected")

        with (
            patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
            patch("agent_runtime_ops.commands.runtime_secret.shutil.which", return_value="/usr/bin/docker"),
            patch("agent_runtime_ops.commands.runtime_secret._run_text", side_effect=fake_run),
        ):
            checks = _run_runtime_secret_container_checks(desired, profile, {"API_SERVER_KEY"})

        self.assertTrue(all(ok for ok, _, _ in checks))
        self.assertTrue(any("label=agent-runtime.instance-id=instance-oc16" in call for argv in calls for call in argv))
        self.assertIn(
            (True, "runtime_secret_hermes_api_token_matches_api_server_key", "secret_value_printed=no"),
            checks,
        )


if __name__ == "__main__":
    unittest.main()
