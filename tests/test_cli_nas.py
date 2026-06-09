from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.cli import (
    _approve_auto_once,
    _delete_official_credentials,
    _managed_fstab_marker,
    _official_credential_status,
    _remove_managed_fstab_entry,
    _slot_names_from_config,
    cmd_nas_credential_status,
    cmd_nas_requests,
    cmd_slot_list,
)
from agent_runtime_ops.nas import parse_smb_share
from agent_runtime_ops.routing import SlotRoute, dump_routing_registry


def write_state(root: Path) -> None:
    digest = "sha256:" + "1" * 64
    (root / "slots.yaml").write_text(
        """
slots:
  - slot: oc3
    lane: openclaw-customer-stable
  - slot: dev-oc
    lane: openclaw-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "lanes.yaml").write_text(
        """
lanes:
  openclaw-customer-stable:
    family: openclaw
    slot_class: customer
    release: openclaw-current
    runtime_profile: openclaw-customer
  openclaw-dev:
    family: openclaw
    slot_class: dev
    release: openclaw-current
    runtime_profile: openclaw-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "releases.yaml").write_text(
        f"""
releases:
  openclaw-current:
    family: openclaw
    wrapper_image: ghcr.io/epicevent/openclaw-nas-agent@{digest}
    product_image: ghcr.io/epicevent/openclaw-nas-agent@{digest}
    digest: {digest}
""".lstrip(),
        encoding="utf-8",
    )
    (root / "slot-registry.json").write_text(
        dump_routing_registry(
            [
                SlotRoute("oc3", "oc3.ji-tech.co.kr", 28989, 28990),
                SlotRoute("dev-oc", "dev-oc.ji-tech.co.kr", 30789, 30790),
            ]
        ),
        encoding="utf-8",
    )


class CliNasTests(unittest.TestCase):
    def test_slot_names_from_list_config(self) -> None:
        slots = [{"slot": "oc10"}, {"slot": "oc3"}, {"lane": "missing"}, "oc2"]
        self.assertEqual(_slot_names_from_config(slots), ["oc10", "oc2", "oc3"])

    def test_nas_requests_accepts_slots_yaml_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_nas_requests(argparse.Namespace(state_root=str(root)))
        self.assertEqual(rc, 0)
        self.assertIn("pending_request_count=0", output.getvalue())
        self.assertIn("nas_requests_status=ok", output.getvalue())

    def test_slot_list_reports_routing_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_slot_list(argparse.Namespace(state_root=str(root)))
        text = output.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("slot=dev-oc", text)
        self.assertIn("slot_class=dev", text)
        self.assertIn("gateway_port=30789", text)
        self.assertIn("public_host=dev-oc.ji-tech.co.kr", text)
        self.assertIn("slot_list_status=ok count=2", text)

    def test_approve_auto_accepts_slots_yaml_list(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
