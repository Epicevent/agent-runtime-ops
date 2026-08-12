from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.cli import build_parser
from agent_runtime_ops.commands.runtime_secret import (
    _SecretFingerprintRow,
    _runtime_secret_fingerprint_digest,
    _runtime_secret_fingerprint_row,
    _runtime_secret_fingerprint_targets,
    cmd_runtime_secret_fingerprint,
    _begin_secret_transaction,
    _run_runtime_secret_container_checks,
    _secret_value_matches_container_env,
    _sync_runtime_compose_env_for_secret_values,
    cmd_runtime_secret_set,
    cmd_runtime_secret_status,
    cmd_runtime_secret_recover,
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
    def test_manual_recover_restores_retained_transaction_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            secret_file = root / "secret.env"
            secret_file.write_text("GEMINI_API_KEY=old\n", encoding="utf-8")
            transaction = _begin_secret_transaction(root, "dev-hermess", [secret_file])
            secret_file.write_text("GEMINI_API_KEY=new\n", encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot", return_value=0) as apply,
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_recover(argparse.Namespace(slot="dev-hermess", state_root=str(root)))
            self.assertEqual(rc, 0)
            self.assertEqual(secret_file.read_text(encoding="utf-8"), "GEMINI_API_KEY=old\n")
            self.assertFalse(transaction.root.exists())
            apply.assert_called_once()
            self.assertIn("runtime_secret_recover_status=ok", output.getvalue())

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
        script = argv[-1]
        self.assertIn("command -v sha256sum", script)
        self.assertIn("command -v node", script)
        self.assertIn("command -v python3", script)
        self.assertIn("hash_tool_missing", script)

    def test_runtime_secret_value_match_fails_without_printing_secret_on_mismatch(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def fake_run(argv, **kwargs):
            calls.append((list(argv), kwargs.get("input")))
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")

        with patch("agent_runtime_ops.commands.runtime_secret.subprocess.run", side_effect=fake_run):
            ok, name, detail = _secret_value_matches_container_env("container123", "API_SERVER_KEY", "raw-secret-value")

        self.assertFalse(ok)
        self.assertEqual(name, "runtime_secret_api_server_key_matches_intended_value")
        self.assertEqual(detail, "secret_value_printed=no")
        argv, stdin_text = calls[0]
        joined = " ".join(argv)
        self.assertNotIn("raw-secret-value", joined)
        self.assertNotIn(stdin_text or "", joined)

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
                patch("agent_runtime_ops.commands.runtime_secret._probe_key_in_container", return_value=("valid", "http=200")),
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

    def test_runtime_secret_set_provider_key_enables_chat_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"GEMINI_API_KEY": "secret"}),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._upsert_runtime_secret_file",
                    return_value=Path("/home/dev-hermess/.config/hermes/runtime.env"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret._sync_runtime_compose_env_for_secret_values", return_value=[]),
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=Path("/home/dev-hermess/openclaw")),
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot", return_value=0),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_runtime_secret_container_checks_with_wait",
                    return_value=[(True, "runtime_secret_gemini_api_key_matches_intended_value", "secret_value_printed=no")],
                ),
                patch("agent_runtime_ops.commands.runtime_secret._find_gateway_container", return_value=("container123", "lookup_ok")),
                patch("agent_runtime_ops.commands.runtime_secret._probe_key_in_container", return_value=("valid", "http=200")),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_hermes_http_smoke",
                    return_value=[(True, "hermes_smoke_chat_ok", "status=200")],
                ) as smoke,
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = cmd_runtime_secret_set(
                    argparse.Namespace(
                        slot="dev-hermess",
                        state_root=str(root),
                        env_file=None,
                        key="GEMINI_API_KEY",
                        value_stdin=True,
                        no_restart=False,
                        check=True,
                        unsafe_service_recreate=False,
                    )
                )

        self.assertEqual(rc, 0)
        smoke.assert_called_once_with("container123", chat_smoke=True)

    def test_failed_live_check_restores_files_and_recreates_previous_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            secret_file = root / "secret.env"
            runtime_dir = root / "runtime-dir"
            runtime_dir.mkdir()
            runtime_env = runtime_dir / ".env"
            secret_file.write_text("GEMINI_API_KEY=old-secret\n", encoding="utf-8")
            runtime_env.write_text("API_SERVER_KEY=old-server\n", encoding="utf-8")
            old_secret = secret_file.read_bytes()
            old_runtime_env = runtime_env.read_bytes()

            def write_new_secret(*_args, **_kwargs):
                secret_file.write_text("GEMINI_API_KEY=new-secret\n", encoding="utf-8")
                return secret_file

            def write_new_runtime(*_args, **_kwargs):
                runtime_env.write_text("API_SERVER_KEY=new-server\n", encoding="utf-8")
                return ["API_SERVER_KEY"]

            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"API_SERVER_KEY": "new-server"}),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=secret_file, owner_mode="root"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=runtime_dir),
                patch("agent_runtime_ops.commands.runtime_secret._upsert_runtime_secret_file", side_effect=write_new_secret),
                patch("agent_runtime_ops.commands.runtime_secret._sync_runtime_compose_env_for_secret_values", side_effect=write_new_runtime),
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot", side_effect=[0, 0]) as apply,
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_runtime_secret_container_checks_with_wait",
                    return_value=[(False, "runtime_secret_api_server_key_matches_intended_value", "secret_value_printed=no")],
                ),
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_set(argparse.Namespace(
                    slot="dev-hermess", state_root=str(root), env_file=None,
                    key="API_SERVER_KEY", value_stdin=True, no_restart=False,
                    check=True, unsafe_service_recreate=False,
                ))

            self.assertEqual(rc, 1)
            self.assertEqual(secret_file.read_bytes(), old_secret)
            self.assertEqual(runtime_env.read_bytes(), old_runtime_env)
            self.assertEqual(apply.call_count, 2)
            self.assertIn("rollback_status=restored_verified", output.getvalue())
            self.assertEqual(list((root / "runtime-secret-transactions").glob("dev-hermess*")), [])

    def test_secret_transaction_refuses_concurrent_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            lock = root / "runtime-secret-transactions" / "dev-hermess.lock"
            lock.mkdir(parents=True)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"GEMINI_API_KEY": "new-key"}),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=root / "secret.env", owner_mode="root"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=root / "runtime-dir"),
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_set(argparse.Namespace(
                    slot="dev-hermess", state_root=str(root), env_file=None,
                    key="GEMINI_API_KEY", value_stdin=True, no_restart=False,
                    check=True, unsafe_service_recreate=False,
                ))
            self.assertEqual(rc, 1)
            self.assertIn("dev-hermess.lock", output.getvalue())

    def test_invalid_provider_probe_rolls_back_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._secret_values_from_args", return_value={"GEMINI_API_KEY": "new-key"}),
                patch("agent_runtime_ops.commands.runtime_secret._upsert_runtime_secret_file", return_value=Path("/home/dev-hermess/.hermes/.env")),
                patch("agent_runtime_ops.commands.runtime_secret._sync_runtime_compose_env_for_secret_values", return_value=[]),
                patch("agent_runtime_ops.commands.runtime_secret.slot_runtime_dir", return_value=Path("/home/dev-hermess/openclaw")),
                patch("agent_runtime_ops.commands.runtime_secret._apply_desired_slot", side_effect=[0, 0]) as apply,
                patch(
                    "agent_runtime_ops.commands.runtime_secret._run_runtime_secret_container_checks_with_wait",
                    return_value=[(True, "runtime_secret_gemini_api_key_matches_intended_value", "secret_value_printed=no")],
                ),
                patch("agent_runtime_ops.commands.runtime_secret._find_gateway_container", return_value=("container123", "lookup_ok")),
                patch("agent_runtime_ops.commands.runtime_secret._probe_key_in_container", return_value=("invalid", "http=401")),
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_set(argparse.Namespace(
                    slot="dev-hermess", state_root=str(root), env_file=None,
                    key="GEMINI_API_KEY", value_stdin=True, no_restart=False,
                    check=True, unsafe_service_recreate=False,
                ))

            self.assertEqual(rc, 1)
            self.assertEqual(apply.call_count, 2)
            self.assertIn("phase=provider_probe", output.getvalue())
            self.assertIn("rollback_status=restored_verified", output.getvalue())

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

    def test_runtime_secret_fingerprint_parser_defaults_to_sha256(self) -> None:
        args = build_parser().parse_args(
            ["runtime-secret", "fingerprint", "--key", "GEMINI_API_KEY", "--targets", "all"]
        )
        self.assertIs(args.func, cmd_runtime_secret_fingerprint)
        self.assertEqual(args.algorithm, "sha256")
        self.assertEqual(args.targets, "all")

    def test_runtime_secret_fingerprint_hashes_only_parsed_value_without_mutation(self) -> None:
        secret_value = "quoted secret value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            secret_file = root / "secret.env"
            secret_file.write_text(f"GEMINI_API_KEY='{secret_value}'\n", encoding="utf-8")
            before = secret_file.read_bytes()
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                patch("agent_runtime_ops.commands.runtime_secret._assert_secret_path_safe"),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=secret_file, owner_mode="runtime"),
                ),
                patch("agent_runtime_ops.commands.runtime_secret._append_action_log") as action_log,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_fingerprint(
                    argparse.Namespace(
                        key="GEMINI_API_KEY",
                        targets="dev-hermess",
                        algorithm="md5",
                        state_root=str(root),
                    )
                )

            text = output.getvalue()
            expected = hashlib.md5(
                secret_value.encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            self.assertEqual(rc, 0, text)
            self.assertIn(f"dev-hermess     PRESENT        md5        {expected}", text)
            self.assertIn("all_same=yes", text)
            self.assertIn("mutates=false", text)
            self.assertIn("secret_value_printed=no", text)
            self.assertNotIn(secret_value, text)
            self.assertNotIn(str(secret_file), text)
            self.assertEqual(secret_file.read_bytes(), before)
            action_log.assert_not_called()

    def test_runtime_secret_fingerprint_all_uses_enabled_bindings_natural_sort(self) -> None:
        expected = [
            "dev-hermes-img",
            "dev-hermess",
            "dev-oc",
            "dev-oc-img",
            *[f"oc{index}" for index in range(1, 21)],
        ]
        bindings = [
            *(
                SimpleNamespace(linux_account=target, enabled=True)
                for target in reversed(expected)
            ),
            SimpleNamespace(linux_account="oc-disabled", enabled=False),
        ]
        observed: list[str] = []

        def same(target: str, _key: str, algorithm: str, _root: Path):
            observed.append(target)
            return _SecretFingerprintRow(target, "PRESENT", algorithm, "a" * 64)

        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.runtime_secret.load_runtime_bindings",
                return_value=bindings,
            ),
            patch(
                "agent_runtime_ops.commands.runtime_secret._runtime_secret_fingerprint_row",
                side_effect=same,
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_secret_fingerprint(
                argparse.Namespace(
                    key="GEMINI_API_KEY",
                    targets="all",
                    algorithm="sha256",
                    state_root="/state",
                )
            )
        text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertEqual(observed, expected)
        self.assertIn("targets_checked=24", text)
        self.assertIn("present=24", text)
        self.assertIn("unique_fingerprints=1", text)
        self.assertIn("all_present=yes", text)
        self.assertIn("all_same=yes", text)

    def test_runtime_secret_fingerprint_difference_and_error_exit_contracts(self) -> None:
        def different(target: str, _key: str, algorithm: str, _root: Path):
            return _SecretFingerprintRow(
                target, "PRESENT", algorithm, "a" * 64 if target == "oc1" else "b" * 64
            )

        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.runtime_secret._runtime_secret_fingerprint_row",
                side_effect=different,
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_secret_fingerprint(
                argparse.Namespace(
                    key="GEMINI_API_KEY",
                    targets="oc2,oc1",
                    algorithm="sha256",
                    state_root="/state",
                )
            )
        text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("unique_fingerprints=2", text)
        self.assertIn("all_present=yes", text)
        self.assertIn("all_same=no", text)

        states = {
            "oc1": "MISSING",
            "oc2": "FILE_MISSING",
            "oc3": "FILE_UNSAFE",
            "oc4": "PARSE_FAILED",
            "oc5": "TARGET_ERROR",
        }
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.runtime_secret._runtime_secret_fingerprint_row",
                side_effect=lambda target, _key, algorithm, _root: _SecretFingerprintRow(
                    target, states[target], algorithm, "-"
                ),
            ),
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_runtime_secret_fingerprint(
                argparse.Namespace(
                    key="GEMINI_API_KEY",
                    targets="oc5,oc4,oc3,oc2,oc1",
                    algorithm="sha256",
                    state_root="/state",
                )
            )
        text = output.getvalue()
        self.assertEqual(rc, 2, text)
        self.assertIn("missing=1", text)
        self.assertIn("errors=4", text)
        self.assertIn("unique_fingerprints=0", text)
        self.assertNotIn(hashlib.md5(b"").hexdigest(), text)

    def test_runtime_secret_fingerprint_row_has_closed_failure_states(self) -> None:
        with patch(
            "agent_runtime_ops.commands.runtime_secret.load_runtime_target",
            side_effect=KeyError("secret-bearing target error"),
        ):
            row = _runtime_secret_fingerprint_row(
                "unknown", "GEMINI_API_KEY", "sha256", Path("/state")
            )
        self.assertEqual((row.state, row.fingerprint), ("TARGET_ERROR", "-"))

        desired = SimpleNamespace(slot="oc1", runtime_profile="openclaw-customer")
        profile = SimpleNamespace(name="openclaw-customer")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.env"
            invalid = root / "invalid.env"
            invalid.write_text("not env syntax\n", encoding="utf-8")
            absent_key = root / "absent.env"
            absent_key.write_text("OPENAI_API_KEY=value\n", encoding="utf-8")
            with (
                patch(
                    "agent_runtime_ops.commands.runtime_secret.load_runtime_target",
                    return_value=desired,
                ),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.load_profile",
                    return_value=profile,
                ),
                patch("agent_runtime_ops.commands.runtime_secret._assert_secret_path_safe"),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=missing, owner_mode="root"),
                ),
            ):
                row = _runtime_secret_fingerprint_row(
                    "oc1", "GEMINI_API_KEY", "sha256", root
                )
            self.assertEqual((row.state, row.fingerprint), ("FILE_MISSING", "-"))

            with (
                patch(
                    "agent_runtime_ops.commands.runtime_secret.load_runtime_target",
                    return_value=desired,
                ),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.load_profile",
                    return_value=profile,
                ),
                patch(
                    "agent_runtime_ops.commands.runtime_secret._assert_secret_path_safe",
                    side_effect=ValueError("unsafe secret path"),
                ),
                patch(
                    "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                    return_value=RuntimeSecretFile(path=invalid, owner_mode="root"),
                ),
            ):
                row = _runtime_secret_fingerprint_row(
                    "oc1", "GEMINI_API_KEY", "sha256", root
                )
            self.assertEqual((row.state, row.fingerprint), ("FILE_UNSAFE", "-"))

            for path, expected_state in (
                (invalid, "PARSE_FAILED"),
                (absent_key, "MISSING"),
            ):
                with (
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.load_runtime_target",
                        return_value=desired,
                    ),
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.load_profile",
                        return_value=profile,
                    ),
                    patch("agent_runtime_ops.commands.runtime_secret._assert_secret_path_safe"),
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                        return_value=RuntimeSecretFile(path=path, owner_mode="root"),
                    ),
                ):
                    row = _runtime_secret_fingerprint_row(
                        "oc1", "GEMINI_API_KEY", "sha256", root
                    )
                self.assertEqual((row.state, row.fingerprint), (expected_state, "-"))

    def test_runtime_secret_fingerprint_refuses_symlink_and_nonregular_files(self) -> None:
        desired = SimpleNamespace(slot="oc1", runtime_profile="openclaw-customer")
        profile = SimpleNamespace(name="openclaw-customer")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            regular = root / "regular.env"
            regular.write_text("GEMINI_API_KEY=value\n", encoding="utf-8")
            symlink = root / "symlink.env"
            symlink.symlink_to(regular)
            directory = root / "directory.env"
            directory.mkdir()
            for path in (symlink, directory):
                with (
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.load_runtime_target",
                        return_value=desired,
                    ),
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.load_profile",
                        return_value=profile,
                    ),
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.slot_home",
                        return_value=root,
                    ),
                    patch(
                        "agent_runtime_ops.commands.runtime_secret.primary_profile_secret_file",
                        return_value=RuntimeSecretFile(path=path, owner_mode="root"),
                    ),
                ):
                    row = _runtime_secret_fingerprint_row(
                        "oc1", "GEMINI_API_KEY", "sha256", root
                    )
                self.assertEqual((row.state, row.fingerprint), ("FILE_UNSAFE", "-"))

    def test_runtime_secret_fingerprint_rejects_authority_and_argument_errors(self) -> None:
        stderr = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=False),
            contextlib.redirect_stderr(stderr),
        ):
            rc = cmd_runtime_secret_fingerprint(
                argparse.Namespace(
                    key="GEMINI_API_KEY",
                    targets="all",
                    algorithm="sha256",
                    state_root="/state",
                )
            )
        self.assertEqual(rc, 2)
        self.assertIn("run as root/admin", stderr.getvalue())

        for key, algorithm, reason in (
            ("UNSUPPORTED_SECRET", "sha256", "unsupported_key"),
            ("GEMINI_API_KEY", "sha1", "unsupported_algorithm"),
        ):
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.runtime_secret._is_root", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_runtime_secret_fingerprint(
                    argparse.Namespace(
                        key=key,
                        targets="all",
                        algorithm=algorithm,
                        state_root="/state",
                    )
                )
            self.assertEqual(rc, 2)
            self.assertIn(f"reason={reason}", output.getvalue())
            self.assertIn("secret_value_printed=no", output.getvalue())
            self.assertNotIn(key, output.getvalue())

    def test_runtime_secret_fingerprint_digest_support_is_closed(self) -> None:
        self.assertEqual(
            _runtime_secret_fingerprint_digest("value", "md5"),
            hashlib.md5(b"value", usedforsecurity=False).hexdigest(),
        )
        self.assertEqual(
            _runtime_secret_fingerprint_digest("value", "sha256"),
            hashlib.sha256(b"value").hexdigest(),
        )
        with self.assertRaisesRegex(ValueError, "unsupported fingerprint algorithm"):
            _runtime_secret_fingerprint_digest("value", "sha1")

if __name__ == "__main__":
    unittest.main()
