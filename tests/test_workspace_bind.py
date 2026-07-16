from __future__ import annotations

from pathlib import Path, PurePosixPath
import tempfile
import unittest

from agent_runtime_ops.domain.runtime_checks import _workspace_bind_stamp_ok
from agent_runtime_ops.domain.workspace_bind import choose_workspace_assignment
from agent_runtime_ops.host.fstab import (
    read_managed_workspace_binds,
    remove_managed_workspace_bind_entry,
    write_managed_workspace_bind_entry,
)


def _rw_row(target: str) -> dict[str, str]:
    return {"target": target, "source": "//10.10.10.2/OC5", "fstype": "cifs", "options": "rw,relatime"}


class ChooseWorkspaceAssignmentTest(unittest.TestCase):
    """One writable mount: nothing to decide, bind it. None: clear. Several:
    the tool does not guess — explicit workspace-assign (the slot-assignment
    web's entry point) decides."""

    def test_single_mount_auto_assigns(self) -> None:
        action, mountpoint = choose_workspace_assignment([_rw_row("/home/oc5/nas_rw/host-a/OC5")])
        self.assertEqual(action, "assign")
        self.assertEqual(mountpoint, "/home/oc5/nas_rw/host-a/OC5")

    def test_no_mount_clears(self) -> None:
        action, mountpoint = choose_workspace_assignment([])
        self.assertEqual(action, "clear")
        self.assertIsNone(mountpoint)

    def test_two_mounts_require_explicit_choice(self) -> None:
        # The migration shape: old NAS and new NAS OC5 mounted side by side.
        action, mountpoint = choose_workspace_assignment(
            [_rw_row("/home/oc5/nas_rw/host-a/OC5"), _rw_row("/home/oc5/nas_rw/host-b/OC5")]
        )
        self.assertEqual(action, "manual")
        self.assertIsNone(mountpoint)


class WorkspaceBindFstabTest(unittest.TestCase):
    def test_write_read_replace_remove_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fstab = Path(d) / "fstab"
            fstab.write_text("# base\n", encoding="utf-8")
            write_managed_workspace_bind_entry(
                "oc5",
                PurePosixPath("/home/oc5/nas_rw/host-a/OC5"),
                PurePosixPath("/home/oc5/workspace"),
                fstab_path=fstab,
                lock_path=Path(d) / "lock",
            )
            binds = read_managed_workspace_binds(fstab)
            self.assertEqual(len(binds), 1)
            self.assertEqual(binds[0]["slot"], "oc5")
            self.assertEqual(binds[0]["source"], "/home/oc5/nas_rw/host-a/OC5")
            self.assertEqual(binds[0]["target"], "/home/oc5/workspace")
            # Rewrite replaces (slot-keyed) — reassignment leaves ONE bind.
            write_managed_workspace_bind_entry(
                "oc5",
                PurePosixPath("/home/oc5/nas_rw/host-b/OC5"),
                PurePosixPath("/home/oc5/workspace"),
                fstab_path=fstab,
                lock_path=Path(d) / "lock",
            )
            binds = read_managed_workspace_binds(fstab)
            self.assertEqual(len(binds), 1)
            self.assertEqual(binds[0]["source"], "/home/oc5/nas_rw/host-b/OC5")
            self.assertTrue(remove_managed_workspace_bind_entry("oc5", fstab_path=fstab, lock_path=Path(d) / "lock"))
            self.assertEqual(read_managed_workspace_binds(fstab), [])


class WorkspaceBindStampTest(unittest.TestCase):
    def test_good_bind_passes(self) -> None:
        ok, detail = _workspace_bind_stamp_ok(
            [{"slot": "oc5", "source": "/home/oc5/nas_rw/host-a/OC5", "target": "/home/oc5/workspace"}], "oc5"
        )
        self.assertTrue(ok, detail)

    def test_wrong_target_is_drift(self) -> None:
        ok, detail = _workspace_bind_stamp_ok(
            [{"slot": "oc5", "source": "/home/oc5/nas_rw/host-a/OC5", "target": "/home/oc5/elsewhere"}], "oc5"
        )
        self.assertFalse(ok)
        self.assertIn("bind_target=", detail)

    def test_source_outside_nas_rw_is_drift(self) -> None:
        ok, detail = _workspace_bind_stamp_ok(
            [{"slot": "oc5", "source": "/home/oc5/nas_docs/host-a/OC5", "target": "/home/oc5/workspace"}], "oc5"
        )
        self.assertFalse(ok)
        self.assertIn("bind_source_outside_nas_rw=", detail)

    def test_other_slots_binds_ignored(self) -> None:
        ok, detail = _workspace_bind_stamp_ok(
            [{"slot": "oc9", "source": "/home/oc9/nas_rw/host-a/OC9", "target": "/home/oc9/workspace"}], "oc5"
        )
        self.assertTrue(ok)
        self.assertEqual(detail, "binds=0")


if __name__ == "__main__":
    unittest.main()
