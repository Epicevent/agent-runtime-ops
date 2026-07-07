from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.commands.nas_legacy import cmd_nas_legacy_adopt, cmd_nas_legacy_retire, cmd_nas_legacy_status
from agent_runtime_ops.domain.nas_legacy import legacy_fstab_entries, remove_fstab_lines

# Shapes lifted from the real 2026-07-07 fstab: a managed pair (excluded), a
# claim-disabled line (excluded), legacy noauto entries (the inventory), and
# oc3's dual hanpass entries sharing one share source.
FSTAB = """UUID=abcd / ext4 defaults 0 1
# agent-runtime-ops nas slot=oc17 source=//192.168.0.222/oc17
//192.168.0.222/oc17 /home/oc17/nas_docs/host-f84f2e7ed9d1/oc17 cifs credentials=/home/oc17/.agent-runtime-nas/credentials/host-f84f2e7ed9d1/oc17.cred,ro,nofail 0 0
# disabled by agent-runtime-ops nas claim: //192.168.0.222/OLD /home/oc17/nas_docs/host-f84f2e7ed9d1/OLD cifs credentials=/x,ro 0 0
//192.168.0.222/OC5 /home/oc5/nas_docs/host-f84f2e7ed9d1/OC5 cifs credentials=/home/oc5/.openclaw-nas/credentials/host-f84f2e7ed9d1/OC5.cred,ro,noauto 0 0
//192.168.0.222/hanpass /home/oc3/nas_docs/host-f84f2e7ed9d1/hanpass cifs credentials=/home/oc3/.openclaw-nas/credentials/host-f84f2e7ed9d1/hanpass.cred,ro,noauto 0 0
//192.168.0.222/hanpass /home/oc3/nas_docs/host-f84f2e7ed9d1/hanpass-8efec41653b4 cifs credentials=/home/oc3/.openclaw-nas/credentials/host-f84f2e7ed9d1/hanpass-8efec41653b4.cred,ro,noauto 0 0
//192.168.0.222/kakao-work /srv/kw-nas/slots/oc1/master cifs credentials=/root/x.cred,ro 0 0
"""


class LegacyFstabEntriesTest(unittest.TestCase):
    def test_inventory_excludes_managed_disabled_and_non_slot(self) -> None:
        entries = legacy_fstab_entries(FSTAB)
        self.assertEqual(
            [(e.slot, e.share, e.noauto) for e in entries],
            [
                ("oc5", "//192.168.0.222/OC5", True),
                ("oc3", "//192.168.0.222/hanpass", True),
                ("oc3", "//192.168.0.222/hanpass", True),
            ],
        )
        self.assertEqual(entries[0].credential_path, "/home/oc5/.openclaw-nas/credentials/host-f84f2e7ed9d1/OC5.cred")

    def test_remove_fstab_lines(self) -> None:
        entries = legacy_fstab_entries(FSTAB)
        oc3_lines = {e.line_number for e in entries if e.slot == "oc3"}
        remaining = remove_fstab_lines(FSTAB, oc3_lines)
        self.assertNotIn("/home/oc3/", remaining)
        self.assertIn("/home/oc5/", remaining)
        self.assertIn("slot=oc17", remaining)


class AdoptTest(unittest.TestCase):
    def _adopt(self, tmp: Path, *, with_source: bool = True, dest_exists: bool = False):
        fstab = tmp / "fstab"
        source = tmp / "legacy" / "OC5.cred"
        dest = tmp / "official" / "OC5.cred"
        text = FSTAB.replace("/home/oc5/.openclaw-nas/credentials/host-f84f2e7ed9d1/OC5.cred", str(source).replace("\\", "/").replace(" ", "\\040"))
        fstab.write_text(text, encoding="utf-8")
        if with_source:
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("username=u\npassword=p\n", encoding="utf-8")
        if dest_exists:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("username=u\npassword=p\n", encoding="utf-8")
        stdout = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_legacy.FSTAB_PATH", fstab),
            patch("agent_runtime_ops.commands.nas_legacy._is_root", return_value=True),
            patch("agent_runtime_ops.commands.nas_legacy.root_credential_path", return_value=dest),
            patch("agent_runtime_ops.commands.nas_legacy._append_action_log"),
            contextlib.redirect_stdout(stdout),
        ):
            rc = cmd_nas_legacy_adopt(SimpleNamespace(state_root=str(tmp), slot="oc5", share="//192.168.0.222/OC5"))
        return rc, stdout.getvalue(), dest

    def test_promotes_declared_credential(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, dest = self._adopt(Path(raw))
            self.assertEqual(rc, 0, out)
            self.assertIn("credential_promotion=promoted", out)
            self.assertIn("secret_value_printed=no", out)
            self.assertTrue(dest.exists())
            self.assertNotIn("password", out)

    def test_already_official_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, _ = self._adopt(Path(raw), dest_exists=True)
            self.assertEqual(rc, 0, out)
            self.assertIn("credential_promotion=already_official", out)

    def test_missing_declared_credential_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, _ = self._adopt(Path(raw), with_source=False)
            self.assertEqual(rc, 1)
            self.assertIn("declared_credential_missing", out)

    def test_unknown_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            (tmp / "fstab").write_text("UUID=abcd / ext4 defaults 0 1\n", encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_legacy.FSTAB_PATH", tmp / "fstab"),
                patch("agent_runtime_ops.commands.nas_legacy._is_root", return_value=True),
                patch("agent_runtime_ops.commands.nas_legacy._append_action_log"),
                contextlib.redirect_stdout(stdout),
            ):
                rc = cmd_nas_legacy_adopt(SimpleNamespace(state_root=raw, slot="oc5", share="//192.168.0.222/OC5"))
            self.assertEqual(rc, 1)
            self.assertIn("legacy_entry_not_found", stdout.getvalue())


class RetireTest(unittest.TestCase):
    def _retire(self, tmp: Path, *, mounted: bool = False, delete_credential: bool = False):
        fstab = tmp / "fstab"
        cred_a = tmp / "creds" / "hanpass.cred"
        cred_b = tmp / "creds" / "hanpass-8efec41653b4.cred"
        text = FSTAB.replace("/home/oc3/.openclaw-nas/credentials/host-f84f2e7ed9d1/hanpass.cred", str(cred_a).replace("\\", "/"))
        text = text.replace("/home/oc3/.openclaw-nas/credentials/host-f84f2e7ed9d1/hanpass-8efec41653b4.cred", str(cred_b).replace("\\", "/"))
        fstab.write_text(text, encoding="utf-8")
        cred_a.parent.mkdir(parents=True, exist_ok=True)
        cred_a.write_text("username=u\npassword=p\n", encoding="utf-8")
        cred_b.write_text("username=u\npassword=p\n", encoding="utf-8")

        def findmnt(path):
            if mounted:
                return 0, "", [{"target": str(path), "source": "//192.168.0.222/hanpass", "fstype": "cifs", "options": "ro"}]
            return 1, "not mounted", []

        stdout = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_legacy.FSTAB_PATH", fstab),
            patch("agent_runtime_ops.commands.nas_legacy.FSTAB_LOCK_PATH", tmp / "fstab.lock"),
            patch("agent_runtime_ops.commands.nas_legacy._is_root", return_value=True),
            patch("agent_runtime_ops.commands.nas_legacy._findmnt_one", side_effect=findmnt),
            patch("agent_runtime_ops.commands.nas_legacy._append_action_log"),
            contextlib.redirect_stdout(stdout),
        ):
            rc = cmd_nas_legacy_retire(
                SimpleNamespace(state_root=str(tmp), slot="oc3", share="//192.168.0.222/hanpass", delete_credential=delete_credential)
            )
        return rc, stdout.getvalue(), fstab, (cred_a, cred_b)

    def test_removes_all_matching_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, fstab, creds = self._retire(Path(raw))
            self.assertEqual(rc, 0, out)
            self.assertIn("fstab_entries_removed=2", out)
            remaining = fstab.read_text(encoding="utf-8")
            self.assertNotIn("/home/oc3/", remaining)
            self.assertIn("/home/oc5/", remaining)
            self.assertIn("slot=oc17", remaining)
            self.assertTrue(creds[0].exists())

    def test_refuses_when_mounted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, fstab, _ = self._retire(Path(raw), mounted=True)
            self.assertEqual(rc, 1)
            self.assertIn("still_mounted", out)
            self.assertIn("/home/oc3/", fstab.read_text(encoding="utf-8"))

    def test_delete_credential_removes_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            rc, out, _, creds = self._retire(Path(raw), delete_credential=True)
            self.assertEqual(rc, 0, out)
            self.assertIn("legacy_credentials_deleted=2", out)
            self.assertFalse(creds[0].exists())
            self.assertFalse(creds[1].exists())


class StatusTest(unittest.TestCase):
    def test_status_reports_inventory_presence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            fstab = tmp / "fstab"
            fstab.write_text(FSTAB, encoding="utf-8")
            stdout = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.nas_legacy.FSTAB_PATH", fstab),
                patch("agent_runtime_ops.commands.nas_legacy._is_root", return_value=False),
                patch("agent_runtime_ops.commands.nas_legacy._findmnt_one", return_value=(1, "", [])),
                contextlib.redirect_stdout(stdout),
            ):
                rc = cmd_nas_legacy_status(SimpleNamespace(state_root=raw))
            out = stdout.getvalue()
            self.assertEqual(rc, 0, out)
            self.assertIn("legacy_entry_count=3", out)
            self.assertIn("legacy_1_target_slot=oc3", out)
            self.assertIn("legacy_1_mounted=no", out)
            self.assertIn("declared_credential_present=unknown_requires_root", out)


if __name__ == "__main__":
    unittest.main()
