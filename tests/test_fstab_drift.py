from __future__ import annotations

from pathlib import Path, PurePosixPath
import tempfile
import unittest

from agent_runtime_ops.host.fstab import (
    fstab_escape,
    fstab_unescape,
    read_managed_fstab_entries,
    write_managed_fstab_entry,
)
from agent_runtime_ops.domain.runtime_checks import _fstab_stamp_drift_ok


def _entry(slot: str, source: str, mountpoint: str, access: str, credentials: str = "/root/agent-runtime-ops/nas-credentials/x.cred") -> dict[str, str]:
    return {"slot": slot, "source": source, "mountpoint": mountpoint, "access": access, "credentials": credentials}


class FstabRoundTripTest(unittest.TestCase):
    def test_escape_round_trip(self) -> None:
        for value in ["/home/oc1/workspace", "/mnt/nas docs/한패스", "a\tb", "back\\slash"]:
            self.assertEqual(fstab_unescape(fstab_escape(value)), value)

    def test_writer_output_is_readable(self) -> None:
        # The reader must parse exactly what the writer stamps — same file,
        # both directions, including the marker key.
        with tempfile.TemporaryDirectory() as d:
            fstab = Path(d) / "fstab"
            fstab.write_text("# base\n//other/x /mnt/x cifs ro 0 0\n", encoding="utf-8")
            write_managed_fstab_entry(
                "oc2",
                "//10.10.10.2/OC2",
                PurePosixPath("/home/oc2/workspace"),
                Path(d) / "cred",
                slot_uid_gid=lambda _s: (1006, 1006),
                runtime_ids=lambda _s: (1006, 1006, 1028),
                read_write=True,
                fstab_path=fstab,
                lock_path=Path(d) / "lock",
            )
            entries = read_managed_fstab_entries(fstab)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["slot"], "oc2")
        self.assertEqual(entry["source"], "//10.10.10.2/OC2")
        self.assertEqual(entry["mountpoint"], "/home/oc2/workspace")
        self.assertEqual(entry["access"], "rw")
        # Non-managed lines are not entries.
        self.assertNotIn("//other/x", [e["source"] for e in entries])


class FstabStampDriftTest(unittest.TestCase):
    """The Q4 invariant mechanized: stamps that today's derivation would
    write differently must turn red on their own (the reboot zombie class)."""

    def test_no_entries_is_vacuous_pass(self) -> None:
        ok, detail = _fstab_stamp_drift_ok([], "oc2")
        self.assertTrue(ok)
        self.assertEqual(detail, "entries=0")

    def test_current_ocn_stamp_passes(self) -> None:
        from agent_runtime_ops.nas import host_component

        current = f"/home/oc2/nas_rw/{host_component('10.10.10.2')}/OC2"
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc2", "//10.10.10.2/OC2", current, "rw")], "oc2"
        )
        self.assertTrue(ok, detail)

    def test_pre_split_ocn_stamp_is_drift(self) -> None:
        # The original incident shape: OCn stamped under nas_docs — boot would
        # recreate it inside the read-only tree.
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc2", "//10.10.10.2/OC2", "/home/oc2/nas_docs/host-b29e08d7b4bf/OC2", "rw")], "oc2"
        )
        self.assertFalse(ok)
        self.assertIn("mountpoint=/home/oc2/nas_docs/host-b29e08d7b4bf/OC2", detail)

    def test_flat_workspace_stamp_is_drift(self) -> None:
        # The interim flat placement: one hardcoded spot, two NAS hosts with
        # the same share name collide. Stamps from that era must turn red —
        # they are the fleet's migration todo list.
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc2", "//10.10.10.2/OC2", "/home/oc2/workspace", "rw")], "oc2"
        )
        self.assertFalse(ok)
        self.assertIn("mountpoint=/home/oc2/workspace", detail)

    def test_ocn_stamped_ro_is_drift(self) -> None:
        from agent_runtime_ops.nas import host_component

        current = f"/home/oc2/nas_rw/{host_component('10.10.10.2')}/OC2"
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc2", "//10.10.10.2/OC2", current, "ro")], "oc2"
        )
        self.assertFalse(ok)
        self.assertIn("access=ro!=rw", detail)

    def test_corpus_stamped_rw_is_drift(self) -> None:
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc3", "//10.10.10.2/kakao-work", "/home/oc3/nas_docs/host-x/kakao-work", "rw")], "oc3"
        )
        self.assertFalse(ok)
        self.assertIn("access=rw!=ro", detail)

    def test_corpus_credential_under_home_is_drift(self) -> None:
        # The #32 vault invariant: a corpus credential a customer can read.
        ok, detail = _fstab_stamp_drift_ok(
            [
                _entry(
                    "oc3",
                    "//10.10.10.2/kakao-work",
                    "/home/oc3/nas_docs/host-x/kakao-work",
                    "ro",
                    credentials="/home/oc3/.agent-runtime-nas/credentials/host-x/kakao-work.cred",
                )
            ],
            "oc3",
        )
        self.assertFalse(ok)
        self.assertIn("credentials_under_home", detail)

    def test_corpus_placement_mismatch_is_note_not_failure(self) -> None:
        # ro stamps from other lanes may legitimately live elsewhere; unmeasured
        # placement is a named note, not a red.
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc1", "//10.10.10.2/kakao-work", "/srv/kw-nas/slots/oc1/master", "ro", credentials="/etc/samba/credentials/ro_kakao.cred")],
            "oc1",
        )
        self.assertTrue(ok, detail)
        self.assertIn("placement_notes=", detail)

    def test_other_slots_entries_are_ignored(self) -> None:
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc9", "//10.10.10.2/OC9", "/home/oc9/nas_docs/host-x/OC9", "rw")], "oc2"
        )
        self.assertTrue(ok)
        self.assertEqual(detail, "entries=0")

    def test_unparseable_source_is_drift(self) -> None:
        ok, detail = _fstab_stamp_drift_ok(
            [_entry("oc2", "garbage", "/home/oc2/workspace", "rw")], "oc2"
        )
        self.assertFalse(ok)
        self.assertIn("unparseable_source", detail)


if __name__ == "__main__":
    unittest.main()
