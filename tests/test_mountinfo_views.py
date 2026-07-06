from __future__ import annotations

import unittest

from agent_runtime_ops.host.mounts import parse_mountinfo_lines

# Lines modeled on the real oc1 container mountinfo: two plain CIFS mounts,
# the kw entry (ext4 subtree bind), and per-view CIFS subtree binds whose
# mountinfo root field carries the share subpath.
MOUNTINFO = [
    "900 850 0:58 / /home/node/nas_docs/host-f84f2e7ed9d1/OC1 ro,relatime master:401 - cifs //192.168.0.222/OC1 ro,vers=3.1.1",
    "901 850 0:60 / /home/node/nas_docs/host-f84f2e7ed9d1/hanpass_groupware ro,relatime master:405 - cifs //192.168.0.222/hanpass_groupware ro,vers=3.1.1",
    "903 850 259:2 /srv/kw-nas/slots/oc1/view /home/node/nas_docs/kw ro,relatime master:1 - ext4 /dev/nvme0n1p2 rw",
    "905 903 0:59 /users/함석헌_대표이사_7362168 /home/node/nas_docs/kw/package ro,relatime master:432 - cifs //192.168.0.222/kakao-work ro,vers=3.1.1",
    "906 903 0:59 /media/10727974 /home/node/nas_docs/kw/media/10727974 ro,relatime master:433 - cifs //192.168.0.222/kakao-work ro,vers=3.1.1",
    "800 700 259:2 / /etc/hosts rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw",
]

# What the host side (findmnt -P, bracket notation) reports for the same mounts.
HOST_FINDMNT_SOURCES = {
    "//192.168.0.222/OC1",
    "//192.168.0.222/hanpass_groupware",
    "//192.168.0.222/kakao-work[/users/함석헌_대표이사_7362168]",
    "//192.168.0.222/kakao-work[/media/10727974]",
}


class ParseMountinfoLinesTest(unittest.TestCase):
    def test_rows_outside_root_are_filtered(self) -> None:
        rows = parse_mountinfo_lines(MOUNTINFO, "/home/node/nas_docs")
        self.assertEqual(len(rows), 5)
        self.assertNotIn("/etc/hosts", {row["target"] for row in rows})

    def test_plain_share_source_has_no_bracket(self) -> None:
        rows = parse_mountinfo_lines(MOUNTINFO, "/home/node/nas_docs")
        by_target = {row["target"]: row for row in rows}
        self.assertEqual(
            by_target["/home/node/nas_docs/host-f84f2e7ed9d1/OC1"]["source"],
            "//192.168.0.222/OC1",
        )

    def test_subtree_bind_source_serializes_like_findmnt(self) -> None:
        rows = parse_mountinfo_lines(MOUNTINFO, "/home/node/nas_docs")
        by_target = {row["target"]: row for row in rows}
        self.assertEqual(
            by_target["/home/node/nas_docs/kw/package"]["source"],
            "//192.168.0.222/kakao-work[/users/함석헌_대표이사_7362168]",
        )
        self.assertEqual(
            by_target["/home/node/nas_docs/kw"]["source"],
            "/dev/nvme0n1p2[/srv/kw-nas/slots/oc1/view]",
        )

    def test_host_findmnt_sources_are_subset_of_container_sources(self) -> None:
        # The exact comparison live_container_sees_host_cifs_sources performs.
        rows = parse_mountinfo_lines(MOUNTINFO, "/home/node/nas_docs")
        container_cifs = {row["source"] for row in rows if row["fstype"] == "cifs"}
        self.assertTrue(HOST_FINDMNT_SOURCES.issubset(container_cifs))

    def test_octal_escapes_decode_in_root_field(self) -> None:
        line = (
            "910 903 0:59 /media/with\\040space /home/node/nas_docs/kw/media/x "
            "ro,relatime master:440 - cifs //192.168.0.222/kakao-work ro"
        )
        rows = parse_mountinfo_lines([line], "/home/node/nas_docs")
        self.assertEqual(rows[0]["source"], "//192.168.0.222/kakao-work[/media/with space]")

    def test_propagation_still_reported(self) -> None:
        rows = parse_mountinfo_lines(MOUNTINFO, "/home/node/nas_docs")
        self.assertEqual({row["propagation"] for row in rows}, {"slave"})


if __name__ == "__main__":
    unittest.main()
