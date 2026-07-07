from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.commands.nas_view import cmd_nas_view_status
from agent_runtime_ops.domain.nas_views import crontab_has_reboot_restore, fstab_boot_entry_present

SHARE = "//192.168.0.222/kakao-work"
MARKER = f"# agent-runtime-ops nas slot=oc1 source={SHARE}"
ENTRY = f"{SHARE} /srv/kw-nas/slots/oc1/master cifs credentials=/root/x.cred,ro,nosuid,nodev,vers=3.1.1,nofail,_netdev 0 0"
FSTAB_OK = f"UUID=abcd / ext4 defaults 0 1\n\n{MARKER}\n{ENTRY}\n"
CRON_OK = "MAILTO=''\n@reboot /usr/local/bin/opsctl nas view restore >> /var/log/nas-view-restore.log 2>&1\n"


class FstabBootEntryTest(unittest.TestCase):
    def test_marker_plus_entry_is_present(self) -> None:
        self.assertTrue(fstab_boot_entry_present("oc1", SHARE, FSTAB_OK))

    def test_missing_marker(self) -> None:
        self.assertFalse(fstab_boot_entry_present("oc1", SHARE, "UUID=abcd / ext4 defaults 0 1\n"))

    def test_marker_without_entry_line(self) -> None:
        self.assertFalse(fstab_boot_entry_present("oc1", SHARE, f"{MARKER}\n# something else\n"))
        self.assertFalse(fstab_boot_entry_present("oc1", SHARE, f"{MARKER}\n"))

    def test_other_slot_marker_does_not_match(self) -> None:
        self.assertFalse(fstab_boot_entry_present("oc2", SHARE, FSTAB_OK))


class CrontabRebootRestoreTest(unittest.TestCase):
    def test_active_line_matches(self) -> None:
        self.assertTrue(crontab_has_reboot_restore(CRON_OK))

    def test_commented_line_does_not_match(self) -> None:
        self.assertFalse(crontab_has_reboot_restore("# @reboot /usr/local/bin/opsctl nas view restore\n"))

    def test_unrelated_reboot_line_does_not_match(self) -> None:
        self.assertFalse(crontab_has_reboot_restore("@reboot /usr/local/bin/other-tool\n"))

    def test_empty(self) -> None:
        self.assertFalse(crontab_has_reboot_restore(""))


def _mounted_ro(path):
    return 0, "", [{"target": str(path), "source": SHARE, "fstype": "cifs", "options": "ro,relatime"}]


def _status_output(*, fstab_text: str, is_root: bool, cron_rc: int = 0, cron_out: str = CRON_OK, failed_units=([], None)):
    records = {"views": {"oc1": {"user_id": "7362168", "share": SHARE, "package": "p"}}}
    stdout = io.StringIO()
    with (
        patch("agent_runtime_ops.commands.nas_view.load_views_state", return_value=records),
        patch("agent_runtime_ops.commands.nas_view._findmnt_one", side_effect=_mounted_ro),
        patch("agent_runtime_ops.commands.nas_view._read_fstab", return_value=fstab_text),
        patch("agent_runtime_ops.commands.nas_view._is_root", return_value=is_root),
        patch("agent_runtime_ops.commands.nas_view.failed_cifs_mount_units", return_value=failed_units),
        patch(
            "agent_runtime_ops.commands.nas_view._run_text",
            return_value=SimpleNamespace(returncode=cron_rc, stdout=cron_out, stderr=""),
        ),
        contextlib.redirect_stdout(stdout),
    ):
        code = cmd_nas_view_status(SimpleNamespace(state_root="/unused"))
    return code, stdout.getvalue()


class StatusBootSectionTest(unittest.TestCase):
    def test_all_persistent_passes(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True)
        self.assertEqual(code, 0, out)
        self.assertIn("boot_fstab_entries=1/1", out)
        self.assertIn("boot_restore_cron=yes", out)

    def test_missing_fstab_entry_fails(self) -> None:
        code, out = _status_output(fstab_text="", is_root=True)
        self.assertEqual(code, 1)
        self.assertIn("boot_fstab_entries=0/1", out)
        self.assertIn("boot_fstab_missing=oc1", out)

    def test_missing_cron_fails(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True, cron_rc=1, cron_out="")
        self.assertEqual(code, 1)
        self.assertIn("boot_restore_cron=no", out)

    def test_non_root_reports_unknown_without_failing(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=False)
        self.assertEqual(code, 0, out)
        self.assertIn("boot_restore_cron=unknown_requires_root", out)

    def test_no_failed_units_reports_zero(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True)
        self.assertEqual(code, 0, out)
        self.assertIn("failed_cifs_mount_units=0", out)

    def test_failed_cifs_units_are_loud(self) -> None:
        code, out = _status_output(
            fstab_text=FSTAB_OK, is_root=True, failed_units=(["mnt-nas-kakao\\x2dwork.mount"], None)
        )
        self.assertEqual(code, 1)
        self.assertIn("failed_cifs_mount_units=1", out)
        self.assertIn("failed_cifs_mount_unit_names=mnt-nas-kakao\\x2dwork.mount", out)

    def test_systemctl_unavailable_reports_unknown_without_failing(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True, failed_units=([], "systemctl missing"))
        self.assertEqual(code, 0, out)
        self.assertIn("failed_cifs_mount_units=unknown", out)


if __name__ == "__main__":
    unittest.main()
