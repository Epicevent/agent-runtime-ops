from __future__ import annotations

import contextlib
import io
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.commands.nas_view import cmd_nas_view_status
from agent_runtime_ops.domain.nas_views import (
    crontab_has_reboot_restore,
    fstab_boot_entry_present,
    managed_fstab_mount_targets,
)

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


class ManagedFstabMountTargetsTest(unittest.TestCase):
    def test_extracts_slot_share_target(self) -> None:
        self.assertEqual(
            managed_fstab_mount_targets(FSTAB_OK),
            [("oc1", SHARE, "/srv/kw-nas/slots/oc1/master")],
        )

    def test_unescapes_octal_target(self) -> None:
        text = f"{MARKER}\n{SHARE} /srv/kw\\040nas/x cifs ro 0 0\n"
        self.assertEqual(managed_fstab_mount_targets(text)[0][2], "/srv/kw nas/x")

    def test_marker_without_entry_skipped(self) -> None:
        self.assertEqual(managed_fstab_mount_targets(f"{MARKER}\n# junk\n"), [])


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
    def test_degraded_contract_fixture_matches_exact_producer_output(self) -> None:
        code, out = _status_output(fstab_text="", is_root=True)
        fixture = (
            Path(__file__).parent / "fixtures" / "nas-view-status-v1-degraded.txt"
        ).read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        grant_prefixes = (
            "view_1_grant_evidence_applicable=",
            "view_1_grant_evidence_count=",
            "view_1_grant_evidence_json=",
            "view_1_grant_evidence_complete=",
        )
        legacy_projection = "\n".join(
            line for line in out.splitlines() if not line.startswith(grant_prefixes)
        ) + "\n"
        self.assertEqual(legacy_projection, fixture)
        self.assertIn("view_1_grant_evidence_applicable=no", out)
        self.assertIn("view_1_grant_evidence_count=0", out)
        self.assertIn("view_1_grant_evidence_json=[]", out)
        self.assertIn("view_1_grant_evidence_complete=yes", out)

    def test_all_persistent_passes(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True)
        self.assertEqual(code, 0, out)
        self.assertIn("view_status_schema=agent-runtime-nas-view-status/v1", out)
        self.assertIn("boot_fstab_entries=1/1", out)
        self.assertIn("boot_restore_cron=yes", out)
        self.assertIn("view_status=ok", out)
        self.assertIn("view_exit_code=0", out)
        self.assertIn("view_status_issues_json=[]", out)
        self.assertIn("view_observation_gaps_json=[]", out)
        self.assertTrue(out.rstrip().endswith("view_snapshot_complete=yes"), out)

    def test_missing_fstab_entry_fails(self) -> None:
        code, out = _status_output(fstab_text="", is_root=True)
        self.assertEqual(code, 1)
        self.assertIn("boot_fstab_entries=0/1", out)
        self.assertIn("boot_fstab_missing=oc1", out)
        self.assertIn("view_status=degraded", out)
        self.assertIn("view_exit_code=1", out)
        self.assertIn('view_status_issues_json=["boot_fstab_missing"]', out)
        self.assertTrue(out.rstrip().endswith("view_snapshot_complete=yes"), out)

    def test_missing_cron_fails(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True, cron_rc=1, cron_out="")
        self.assertEqual(code, 1)
        self.assertIn("boot_restore_cron=no", out)

    def test_non_root_reports_unknown_without_failing(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=False)
        self.assertEqual(code, 0, out)
        self.assertIn("boot_restore_cron=unknown_requires_root", out)
        self.assertIn('view_observation_gaps_json=["boot_restore_requires_root"]', out)

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
        self.assertIn('view_observation_gaps_json=["failed_cifs_mount_units_unavailable"]', out)

    def test_all_managed_entries_mounted(self) -> None:
        code, out = _status_output(fstab_text=FSTAB_OK, is_root=True)
        self.assertEqual(code, 0, out)
        self.assertIn("managed_fstab_mounted=1/1", out)

    def test_declared_but_unmounted_entry_is_loud(self) -> None:
        # A second managed pair (oc9) exists in fstab but its target is not
        # mounted — the 2026-07-07 shape: registration green, mount absent.
        oc9 = (
            "# agent-runtime-ops nas slot=oc9 source=//192.168.0.222/OC9\n"
            "//192.168.0.222/OC9 /srv/kw-nas/slots/oc9/master cifs ro,nofail 0 0\n"
        )

        def findmnt(path):
            if "oc9" in str(path):
                return 1, "not mounted", []
            return _mounted_ro(path)

        records = {"views": {"oc1": {"user_id": "7362168", "share": SHARE, "package": "p"}}}
        stdout = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.nas_view.load_views_state", return_value=records),
            patch("agent_runtime_ops.commands.nas_view._findmnt_one", side_effect=findmnt),
            patch("agent_runtime_ops.commands.nas_view._read_fstab", return_value=FSTAB_OK + oc9),
            patch("agent_runtime_ops.commands.nas_view._is_root", return_value=False),
            patch("agent_runtime_ops.commands.nas_view.failed_cifs_mount_units", return_value=([], None)),
            contextlib.redirect_stdout(stdout),
        ):
            code = cmd_nas_view_status(SimpleNamespace(state_root="/unused"))
        out = stdout.getvalue()
        self.assertEqual(code, 1, out)
        self.assertIn("view_1_healthy=yes", out)
        self.assertIn("managed_fstab_mounted=1/2", out)
        self.assertIn("managed_fstab_unmounted=/srv/kw-nas/slots/oc9/master", out)
        self.assertIn("view_status=degraded", out)
        self.assertIn('view_status_issues_json=["managed_fstab_unmounted"]', out)
        self.assertTrue(out.rstrip().endswith("view_snapshot_complete=yes"), out)


if __name__ == "__main__":
    unittest.main()
