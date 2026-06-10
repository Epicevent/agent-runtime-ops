from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.cli import (
    _approve_auto_once,
    _delete_official_credentials,
    _fstab_escape,
    _managed_fstab_marker,
    _official_credential_status,
    _remove_managed_fstab_entry,
    _write_managed_fstab_entry,
    cmd_nas_credential_status,
    cmd_nas_credential_set,
    cmd_nas_mount,
    cmd_nas_requests,
)
from agent_runtime_ops.nas import parse_smb_share
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
    digest = "sha256:" + "1" * 64
    (root / "runtime-bindings.json").write_text(
        dump_runtime_bindings(
            [
                binding("oc3", "openclaw", "customer", 28989, 28990),
                binding("dev-oc", "openclaw", "dev", 30789, 30790),
            ]
        ),
        encoding="utf-8",
    )
    for target, runtime_class, profile in (
        ("oc3", "customer", "openclaw-customer"),
        ("dev-oc", "dev", "openclaw-dev"),
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
                    "family": "openclaw",
                    "runtime_class": runtime_class,
                    "runtime_profile": profile,
                    "wrapper_image": f"ghcr.io/epicevent/agent-runtime-openclaw@{digest}",
                    "product_image": f"ghcr.io/epicevent/openclaw-jitech@{digest}",
                    "wrapper_image_digest": digest,
                    "product_image_digest": digest,
                }
            ),
            encoding="utf-8",
        )
    (root / "nas-policy.yaml").write_text(
        dump_yaml(
            {
                "defaults": {"auto_approve": False},
                "accounts": {
                    "oc3": {
                        "auto_approve": True,
                        "grants": [{"allow": "//192.168.0.222/*"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )


class CliNasTests(unittest.TestCase):
    def test_nas_requests_accepts_runtime_bindings_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_nas_requests(argparse.Namespace(state_root=str(root)))
        self.assertEqual(rc, 0)
        self.assertIn("pending_request_count=0", output.getvalue())
        self.assertIn("nas_requests_status=ok", output.getvalue())

    def test_approve_auto_accepts_runtime_bindings_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            result = _approve_auto_once(root)
        self.assertEqual(result, {"checked": 0, "approved": 0, "pending": 0, "rejected": 0, "failed": 0})

    def test_official_credential_status_ignores_legacy_paths(self) -> None:
        share = parse_smb_share("//192.168.0.222/hanpass")
        with tempfile.TemporaryDirectory() as tmp:
            root_path = Path(tmp) / "root.cred"
            customer_path = Path(tmp) / "customer.cred"
            legacy_path = Path(tmp) / ".openclaw-nas" / "legacy.cred"
            legacy_path.parent.mkdir()
            legacy_path.write_text("username=legacy\npassword=secret\n", encoding="utf-8")
            with (
                patch("agent_runtime_ops.cli.root_credential_path", return_value=root_path),
                patch("agent_runtime_ops.cli.customer_credential_path", return_value=customer_path),
            ):
                status = _official_credential_status("oc3", share)
        self.assertEqual(status["root_credential_present"], "no")
        self.assertEqual(status["customer_credential_present"], "no")
        self.assertEqual(status["official_credential_present"], "no")
        self.assertEqual(status["remount_possible"], "no")

    def test_delete_official_credentials_removes_root_and_customer_only(self) -> None:
        share = parse_smb_share("//192.168.0.222/hanpass")
        with tempfile.TemporaryDirectory() as tmp:
            root_path = Path(tmp) / "root.cred"
            customer_path = Path(tmp) / "customer.cred"
            legacy_path = Path(tmp) / "legacy.cred"
            root_path.write_text("username=root\npassword=secret\n", encoding="utf-8")
            customer_path.write_text("username=customer\npassword=secret\n", encoding="utf-8")
            legacy_path.write_text("username=legacy\npassword=secret\n", encoding="utf-8")
            with (
                patch("agent_runtime_ops.cli.root_credential_path", return_value=root_path),
                patch("agent_runtime_ops.cli.customer_credential_path", return_value=customer_path),
                patch("agent_runtime_ops.cli._credential_file_is_safe_for_slot"),
            ):
                removed = _delete_official_credentials("oc3", share)
            self.assertFalse(root_path.exists())
            self.assertFalse(customer_path.exists())
            self.assertTrue(legacy_path.exists())
        self.assertEqual(removed["root_credential_removed"], "yes")
        self.assertEqual(removed["customer_credential_removed"], "yes")

    def test_remove_managed_fstab_entry_removes_marker_and_entry(self) -> None:
        share = "//192.168.0.222/hanpass"
        marker = _managed_fstab_marker("oc3", share)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fstab = root / "fstab"
            lock = root / "lock"
            fstab.write_text(
                "\n".join(
                    [
                        "# keep me",
                        marker,
                        "//192.168.0.222/hanpass /home/oc3/nas_docs/host/hanpass cifs ro 0 0",
                        "//other/share /mnt/other cifs ro 0 0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            removed = _remove_managed_fstab_entry("oc3", share, fstab_path=fstab, lock_path=lock)
            text = fstab.read_text(encoding="utf-8")
        self.assertTrue(removed)
        self.assertNotIn(marker, text)
        self.assertIn("# keep me", text)
        self.assertIn("//other/share", text)

    def test_write_managed_fstab_entry_can_claim_same_source_legacy_entry(self) -> None:
        share = "//192.168.0.222/hanpass"
        mountpoint = Path("/tmp") / "oc3" / "nas_docs" / "host-f84f2e7ed9d1" / "hanpass"
        marker = _managed_fstab_marker("oc3", share)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fstab = root / "fstab"
            lock = root / "lock"
            fstab.write_text(
                "\n".join(
                    [
                        "# keep me",
                        f"{share} {_fstab_escape(str(mountpoint))} cifs credentials=/legacy.cred,ro 0 0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with (
                patch("agent_runtime_ops.cli._slot_uid_gid", return_value=(1009, 1009)),
                patch("agent_runtime_ops.cli._runtime_ids", return_value=(2009, 2009, 1030)),
            ):
                _write_managed_fstab_entry(
                    "oc3",
                    share,
                    mountpoint,
                    Path("/root/agent-runtime-ops/nas-credentials/oc3/host/hanpass.cred"),
                    claim_existing_same_source=True,
                    fstab_path=fstab,
                    lock_path=lock,
                )
            text = fstab.read_text(encoding="utf-8")
        self.assertIn("# disabled by agent-runtime-ops nas claim:", text)
        self.assertIn(marker, text)
        credential = Path("/root/agent-runtime-ops/nas-credentials/oc3/host/hanpass.cred")
        self.assertIn(f"credentials={_fstab_escape(str(credential))}", text)

    def test_nas_credential_status_outputs_presence_without_secret(self) -> None:
        share = parse_smb_share("//192.168.0.222/hanpass")
        with tempfile.TemporaryDirectory() as tmp:
            state_root = Path(tmp) / "state"
            state_root.mkdir()
            write_state(state_root)
            root_path = Path(tmp) / "root.cred"
            customer_path = Path(tmp) / "customer.cred"
            root_path.write_text("username=root\npassword=top-secret\n", encoding="utf-8")
            with (
                patch("agent_runtime_ops.cli.root_credential_path", return_value=root_path),
                patch("agent_runtime_ops.cli.customer_credential_path", return_value=customer_path),
            ):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    rc = cmd_nas_credential_status(
                        argparse.Namespace(state_root=str(state_root), slot="oc3", share=share.source)
                    )
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("credential_scope=official", text)
        self.assertIn("root_credential_present=yes", text)
        self.assertIn("customer_credential_present=no", text)
        self.assertIn("official_credential_present=yes", text)
        self.assertIn("secret_value_printed=no", text)
        self.assertNotIn("top-secret", text)

    def test_nas_credential_set_uses_state_root_without_printing_secret(self) -> None:
        share = "//192.168.0.222/hanpass"
        secret = "secret-password"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_root = root / "state"
            state_root.mkdir()
            write_state(state_root)
            credential = root / "cred"
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli.getpass.getuser", return_value="oc3"),
                patch("agent_runtime_ops.cli._ensure_customer_agent_dirs"),
                patch("agent_runtime_ops.cli._slot_uid_gid", return_value=(1003, 1003)),
                patch("agent_runtime_ops.cli.customer_credential_path", return_value=credential),
                patch("agent_runtime_ops.cli._write_credential_file") as write_credential,
                patch("sys.stdin", io.StringIO(secret)),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_credential_set(
                    argparse.Namespace(
                        state_root=str(state_root),
                        share=share,
                        username="nas-user",
                        password_stdin=True,
                        domain=None,
                    )
                )
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("target=oc3", text)
        self.assertIn("credential_status=stored", text)
        self.assertIn("secret_value_printed=no", text)
        self.assertNotIn(secret, text)
        write_credential.assert_called_once()
        self.assertEqual(write_credential.call_args.args[:4], (credential, "nas-user", secret, None))

    def test_nas_mount_canonicalizes_public_host_before_paths(self) -> None:
        share = parse_smb_share("//192.168.0.222/hanpass")
        decision = type(
            "Decision",
            (),
            {
                "slot": "oc3",
                "share": share,
                "allowed": True,
                "reason": "grant_matched",
                "matched_grant": share.source,
                "max_mounts": None,
                "mountpoint": Path("/home/oc3/nas_docs/host-f84f2e7ed9d1/hanpass"),
            },
        )()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential = root / "root.cred"
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.check_nas_policy", return_value=decision) as policy,
                patch("agent_runtime_ops.cli.root_credential_path", return_value=credential) as root_path,
                patch("agent_runtime_ops.cli._write_credential_file"),
                patch("agent_runtime_ops.cli._prepare_mount_entry", return_value=(decision, decision.mountpoint)) as prepare,
                patch("agent_runtime_ops.cli._findmnt_one", side_effect=[(1, "", []), (0, "", [])]),
                patch("agent_runtime_ops.cli._host_mount_prepared_share", return_value=(True, "ok")),
                patch("agent_runtime_ops.cli._append_action_log"),
                patch("sys.stdin", io.StringIO("secret-password")),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_mount(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="oc3.ji-tech.co.kr",
                        share=share.source,
                        username="nas-user",
                        password_stdin=True,
                        domain=None,
                        keep_fstab_on_failure=False,
                    )
                )
        self.assertEqual(rc, 0)
        policy.assert_called_once_with("oc3.ji-tech.co.kr", share.source, root)
        root_path.assert_called_once_with("oc3", share)
        self.assertEqual(prepare.call_args.args[:4], ("oc3", share.source, credential, root))
        self.assertIn("target=oc3", output.getvalue())

    def test_nas_mount_rolls_back_fstab_on_mount_failure_by_default(self) -> None:
        share = parse_smb_share("//192.168.0.222/hanpass")
        decision = type(
            "Decision",
            (),
            {
                "slot": "oc3",
                "share": share,
                "allowed": True,
                "reason": "grant_matched",
                "matched_grant": share.source,
                "max_mounts": None,
                "mountpoint": Path("/home/oc3/nas_docs/host-f84f2e7ed9d1/hanpass"),
            },
        )()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential = root / "root.cred"
            credential.write_text("username=nas\npassword=secret\n", encoding="utf-8")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.cli._is_root", return_value=True),
                patch("agent_runtime_ops.cli.check_nas_policy", return_value=decision),
                patch("agent_runtime_ops.cli.root_credential_path", return_value=credential),
                patch("agent_runtime_ops.cli._credential_file_is_safe_for_slot"),
                patch("agent_runtime_ops.cli._prepare_mount_entry", return_value=(decision, decision.mountpoint)),
                patch("agent_runtime_ops.cli._findmnt_one", return_value=(1, "", [])),
                patch("agent_runtime_ops.cli._host_mount_prepared_share", return_value=(False, "mount_failed")),
                patch("agent_runtime_ops.cli._remove_managed_fstab_entry", return_value=True) as remove_fstab,
                patch("agent_runtime_ops.cli._append_action_log"),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_nas_mount(
                    argparse.Namespace(
                        state_root=str(root),
                        slot="oc3",
                        share=share.source,
                        username=None,
                        password_stdin=False,
                        domain=None,
                        keep_fstab_on_failure=False,
                    )
                )
        text = output.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("mount_status=fail", text)
        self.assertIn("reason=mount_failed", text)
        self.assertIn("fstab_entry_rollback=removed", text)
        remove_fstab.assert_called_once_with("oc3", share.source)


if __name__ == "__main__":
    unittest.main()
