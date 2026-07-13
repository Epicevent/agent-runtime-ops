from __future__ import annotations

import unittest
from pathlib import Path

from agent_runtime_ops.host.fstab import write_managed_fstab_entry
from agent_runtime_ops.nas import parse_smb_share, share_is_writable


class ShareIsWritableTest(unittest.TestCase):
    def test_ocn_shares_are_writable(self) -> None:
        for name in ["OC1", "OC5", "OC17", "OC20", "oc3"]:
            self.assertTrue(share_is_writable(parse_smb_share(f"//10.10.10.2/{name}")), name)

    def test_customer_shares_are_readonly(self) -> None:
        for name in ["kakao-work", "hanpass_groupware", "OCEAN", "OC", "OC1x", "xOC1"]:
            self.assertFalse(share_is_writable(parse_smb_share(f"//10.10.10.2/{name}")), name)


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
        self.assertIn("file_mode=0640", text)
        self.assertIn("dir_mode=0750", text)
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
