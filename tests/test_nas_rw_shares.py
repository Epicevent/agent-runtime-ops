from __future__ import annotations

import unittest
from pathlib import Path

from agent_runtime_ops.host.fstab import write_managed_fstab_entry
from agent_runtime_ops.nas import (
    host_component,
    mountpoint_for_share,
    nas_root,
    nas_rw_root,
    parse_smb_share,
    share_is_writable,
    workspace_root,
)


class ShareIsWritableTest(unittest.TestCase):
    def test_ocn_shares_are_writable(self) -> None:
        for name in ["OC1", "OC5", "OC17", "OC20", "oc3"]:
            self.assertTrue(share_is_writable(parse_smb_share(f"//10.10.10.2/{name}")), name)

    def test_customer_shares_are_readonly(self) -> None:
        for name in ["kakao-work", "hanpass_groupware", "OCEAN", "OC", "OC1x", "xOC1"]:
            self.assertFalse(share_is_writable(parse_smb_share(f"//10.10.10.2/{name}")), name)


class MountpointPlacementTest(unittest.TestCase):
    """One tree per intent, one spot per source: writable OCn mounts nested
    under {home}/nas_rw (outside the read-only nas_docs tree, so recursive
    read_only can never stamp it ro), keyed by host so the same share name on
    two NAS hosts never collides (the old-NAS/new-NAS remove refusal). The
    workspace is a bind onto ONE of these, never a direct mount target."""

    def test_ocn_mounts_per_source_under_nas_rw(self) -> None:
        mountpoint = mountpoint_for_share("oc1", parse_smb_share("//10.10.10.2/OC1"))
        self.assertEqual(
            mountpoint,
            nas_rw_root("oc1") / host_component("10.10.10.2") / "OC1",
        )

    def test_same_share_name_on_two_hosts_gets_two_spots(self) -> None:
        new_nas = mountpoint_for_share("oc5", parse_smb_share("//10.10.10.2/OC5"))
        old_nas = mountpoint_for_share("oc5", parse_smb_share("//192.168.0.222/OC5"))
        self.assertNotEqual(new_nas, old_nas)

    def test_ocn_is_not_under_nas_docs_and_not_the_workspace(self) -> None:
        mountpoint = mountpoint_for_share("oc1", parse_smb_share("//10.10.10.2/OC1"))
        self.assertNotIn(nas_root("oc1"), mountpoint.parents)
        self.assertNotEqual(mountpoint, workspace_root("oc1"))
        self.assertNotIn(workspace_root("oc1"), mountpoint.parents)

    def test_corpus_stays_nested_under_nas_docs(self) -> None:
        share = parse_smb_share("//10.10.10.2/kakao-work")
        mountpoint = mountpoint_for_share("oc1", share)
        self.assertEqual(
            mountpoint,
            nas_root("oc1") / host_component("10.10.10.2") / "kakao-work",
        )
        self.assertIn(nas_root("oc1"), mountpoint.parents)


class FstabModeTest(unittest.TestCase):
    def _write(self, tmp: Path, share: str, read_write: bool) -> str:
        fstab = tmp / "fstab"
        fstab.write_text("# base\n", encoding="utf-8")
        write_managed_fstab_entry(
            "oc1",
            share,
            tmp / "mnt",
            tmp / "cred",
            slot_uid_gid=lambda _slot: (1006, 1006),
            runtime_ids=lambda _slot: (1006, 1006, 1028),
            read_write=read_write,
            fstab_path=fstab,
            lock_path=tmp / "lock",
        )
        return fstab.read_text(encoding="utf-8")

    def test_ocn_entry_is_rw(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            text = self._write(Path(d), "//10.10.10.2/OC1", read_write=True)
        self.assertIn(",rw,", text)
        # group (slot_data) must be able to write: the container runtime user
        # writes OCn via group membership, not as the owner uid.
        self.assertIn("file_mode=0660", text)
        self.assertIn("dir_mode=0770", text)
        self.assertNotIn(",ro,", text)

    def test_customer_entry_is_ro(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            text = self._write(Path(d), "//10.10.10.2/kakao-work", read_write=False)
        self.assertIn(",ro,", text)
        self.assertIn("file_mode=0440", text)
        self.assertIn("dir_mode=0550", text)
        self.assertNotIn(",rw,", text)


if __name__ == "__main__":
    unittest.main()
