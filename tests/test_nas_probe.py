from __future__ import annotations

import unittest

from agent_runtime_ops.domain.nas_probe import classify_probe, probe_mounts, smb_host_of


class SmbHostTest(unittest.TestCase):
    def test_plain_share(self) -> None:
        self.assertEqual(smb_host_of("//10.10.10.2/OC5"), "10.10.10.2")

    def test_subpath_source(self) -> None:
        # findmnt 는 서브패스 마운트를 //host/share/sub 로 보고한다 (kw 뷰 등).
        self.assertEqual(smb_host_of("//10.10.10.2/kakao-work/users/x_7362168"), "10.10.10.2")

    def test_non_smb_source(self) -> None:
        self.assertEqual(smb_host_of("/dev/sda1"), "")


class ClassifyTest(unittest.TestCase):
    def test_rc0_alive(self) -> None:
        self.assertEqual(classify_probe(0, ""), (True, ""))

    def test_timeout_is_dead_hang(self) -> None:
        # timeout(1) 규약: 124 = 제한시간 초과 = 죽은 cifs 가 매달린 것.
        alive, reason = classify_probe(124, "")
        self.assertFalse(alive)
        self.assertEqual(reason, "timeout")

    def test_io_error_carries_reason(self) -> None:
        alive, reason = classify_probe(1, "stat: cannot read file system information: Host is down")
        self.assertFalse(alive)
        self.assertIn("Host is down", reason)


class ProbeMountsTest(unittest.TestCase):
    def test_parallel_probe_maps_rows(self) -> None:
        rows = [
            {"target": "/a", "source": "//10.10.10.2/A"},
            {"target": "/b", "source": "//10.10.10.2/B"},
        ]
        fake = lambda target: (target == "/a", "" if target == "/a" else "timeout")  # noqa: E731
        out = probe_mounts(rows, probe=fake)
        self.assertEqual([r["alive"] for r in out], ["yes", "no"])
        self.assertEqual(out[1]["reason"], "timeout")
        self.assertEqual(out[0]["source"], "//10.10.10.2/A")

    def test_empty_list(self) -> None:
        self.assertEqual(probe_mounts([]), [])


if __name__ == "__main__":
    unittest.main()
