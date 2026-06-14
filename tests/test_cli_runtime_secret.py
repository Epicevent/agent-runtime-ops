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

from agent_runtime_ops.commands.runtime_secret import (
    _run_runtime_secret_container_checks,
    _secret_value_matches_container_env,
    _sync_runtime_compose_env_for_secret_values,
    cmd_runtime_secret_set,
    cmd_runtime_secret_status,
)
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
            patch("agent_runtime_ops.domain.runtime_truth.run_text", side_effect=fake_run),
            patch("agent_runtime_ops.commands.runtime_secret._run_text", side_effect=fake_run),
            patch(
                "agent_runtime_ops.commands.runtime_secret._secret_value_matches_container_env",
                side_effect=lambda _container, key, _value: (
                    True,
                    f"runtime_secret_{key.lower()}_matches_intended_value",
                    "secret_value_printed=no",
                ),
            ),
        ):
            checks = _run_runtime_secret_container_checks(desired, profile, {"API_SERVER_KEY": "secret"})

        self.assertTrue(all(ok for ok, _, _ in checks))
        self.assertTrue(any("label=agent-runtime.instance-id=instance-oc16" in call for argv in calls for call in argv))
        self.assertIn(
            (True, "runtime_secret_api_server_key_matches_intended_value", "secret_value_printed=no"),
            checks,
        )
        self.assertIn(
            (True, "runtime_secret_hermes_api_token_matches_api_server_key", "secret_value_printed=no"),
            checks,
        )

    def test_runtime_secret_value_match_passes_hash_over_stdin_only(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def fake_run(argv, **kwargs):
            calls.append((list(argv), kwargs.get("input")))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with patch("agent_runtime_ops.commands.runtime_secret.subprocess.run", side_effect=fake_run):
            ok, name, detail = _secret_value_matches_container_env("container123", "API_SERVER_KEY", "raw-secret-value")

        self.assertTrue(ok)
        self.assertEqual(name, "runtime_secret_api_server_key_matches_intended_value")
        self.assertEqual(detail, "secret_value_printed=no")
        argv, stdin_text = calls[0]
        joined = " ".join(argv)
        self.assertNotIn("raw-secret-value", joined)
        self.assertNotIn(stdin_text or "", joined)
        self.assertEqual(len(stdin_text or ""), 64)

    def test_sync_runtime_compose_env_uses_expanded_api_server_key(self) -> None:
        calls: list[tuple[Path, dict[str, str], int, int]] = []

        def fake_upsert(path: Path, updates: dict[str, str], uid: int, gid: int) -> None:
            calls.append((path, updates, uid, gid))

        with (
            patch("agent_runtime_ops.commands.runtime_secret.slot_uid_gid", return_value=(12000, 22000)),
            patch("agent_runtime_ops.commands.runtime_secret._upsert_runtime_env_file", side_effect=fake_upsert),
        ):
            synced = _sync_runtime_compose_env_for_secret_values(
                "oc16",
                Path("/home/oc16/openclaw"),
                {"HERMES_API_TOKEN": "token", "API_SERVER_KEY": "token"},
            )

        self.assertEqual(synced, ["API_SERVER_KEY"])
        self.assertEqual(calls, [(Path("/home/oc16/openclaw/.env"), {"API_SERVER_KEY": "token"}, 12000, 22000)])

    def test_runtime_secret_set_check_uses_full_apply_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"API_SERVER_KEY": "secret"}),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._upsert_runtime_secret_file",
                    return_value=Path("/home/dev-hermess/.config/hermes/runtime.env"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret._sync_runtime_compose_env_for_secret_values", return_value=["API_SERVER_KEY"]) as sync_env,
                patch("agent_runtime_ops.commands.runtime_secret._unsafe_service_recreate_after_runtime_secret_set") as restart,
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=Path("/home/dev-hermess/openclaw")),
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot", return_value=0) as apply,
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_runtime_secret_container_checks_with_wait",
                    return_value=[(True, "runtime_secret_api_server_key_matches_intended_value", "secret_value_printed=no")],
                ),
                patch("agent_runtime_ops.commands.runtime_secret._find_gateway_container", return_value=("container123", "lookup_ok")),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_hermes_http_smoke",
                    return_value=[(True, "hermes_smoke_chat_not_required", "not_required")],
                ) as smoke,
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_set(
                    argparse.Namespace(
                        slot="dev-hermess",
                        state_root=str(root),
                        env_file=None,
                        key="API_SERVER_KEY",
                        value_stdin=True,
                        no_restart=False,
                        check=True,
                        unsafe_service_recreate=False,
                    )
                )

        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        restart.assert_not_called()
        sync_env.assert_called_once()
        apply.assert_called_once()
        self.assertEqual(apply.call_args.kwargs["action_name"], "runtime_secret_recreate")
        self.assertFalse(apply.call_args.kwargs["allow_first_apply"])
        self.assertTrue(apply.call_args.kwargs["emit_progress"])
        smoke.assert_called_once_with("container123", chat_smoke=False)
        self.assertIn("phase=secret_write", text)
        self.assertIn("runtime_env_synced_keys=API_SERVER_KEY", text)
        self.assertIn("phase=full_recreate", text)
        self.assertIn("phase=secret_check", text)
        self.assertIn("phase=hermes_smoke", text)
        self.assertIn("runtime_secret_status=stored_checked", text)

    def test_runtime_secret_set_no_restart_still_syncs_runtime_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"API_SERVER_KEY": "secret"}),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._upsert_runtime_secret_file",
                    return_value=Path("/home/dev-hermess/.hermes/.env"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=Path("/home/dev-hermess/openclaw")),
                patch("agent_runtime_ops.commands.runtime_secret._sync_runtime_compose_env_for_secret_values", return_value=["API_SERVER_KEY"]) as sync_env,
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot") as apply,
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_set(
                    argparse.Namespace(
                        slot="dev-hermess",
                        state_root=str(root),
                        env_file=None,
                        key="API_SERVER_KEY",
                        value_stdin=True,
                        no_restart=True,
                        check=False,
                        unsafe_service_recreate=False,
                    )
                )

        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        sync_env.assert_called_once()
        apply.assert_not_called()
        self.assertIn("runtime_env_synced_keys=API_SERVER_KEY", text)
        self.assertIn("restart=skipped", text)


if __name__ == "__main__":
    unittest.main()
