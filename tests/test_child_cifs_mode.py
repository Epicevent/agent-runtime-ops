from __future__ import annotations

import unittest

from agent_runtime_ops.domain.runtime_checks import _child_cifs_mode_ok


def _row(source: str, ro: bool) -> dict[str, str]:
    return {
        "source": source,
        "fstype": "cifs",
        "options": "ro,relatime" if ro else "rw,relatime",
    }


# Exact strings from the oc14 canary incident (new NAS 10.10.10.2).
OC14_RW = _row("//10.10.10.2/OC14", ro=False)
OC14_RO = _row("//10.10.10.2/OC14", ro=True)
KAKAO_RO = _row("//192.168.0.222/kakao-work", ro=True)
KAKAO_RW = _row("//192.168.0.222/kakao-work", ro=False)
KAKAO_VIEW_RO = _row("//10.10.10.2/kakao-work[/users/함석헌_대표이사_7362168]", ro=True)


class ChildCifsModeTest(unittest.TestCase):
    def test_ocn_rw_passes(self) -> None:
        # The incident: a single grant-matched OCn share mounted rw must pass.
        ok, detail = _child_cifs_mode_ok([OC14_RW])
        self.assertTrue(ok, detail)
        self.assertIn("rw=1", detail)

    def test_ocn_mounted_ro_is_mismatch(self) -> None:
        # OCn should be writable; ro contradicts its class.
        ok, detail = _child_cifs_mode_ok([OC14_RO])
        self.assertFalse(ok)
        self.assertIn("//10.10.10.2/OC14:ro!=rw", detail)

    def test_customer_share_ro_passes(self) -> None:
        ok, detail = _child_cifs_mode_ok([KAKAO_RO])
        self.assertTrue(ok, detail)

    def test_customer_share_rw_is_rejected(self) -> None:
        # Non-OCn CIFS mounted rw must still fail — no blanket rw allow.
        ok, detail = _child_cifs_mode_ok([KAKAO_RW])
        self.assertFalse(ok)
        self.assertIn("//192.168.0.222/kakao-work:rw!=ro", detail)

    def test_kakao_view_stays_ro(self) -> None:
        # A view's base share (kakao-work) is not writable, so ro is expected.
        ok, _ = _child_cifs_mode_ok([KAKAO_VIEW_RO])
        self.assertTrue(ok)

    def test_mixed_fleet_ocn_rw_customer_ro(self) -> None:
        ok, detail = _child_cifs_mode_ok([OC14_RW, KAKAO_RO, KAKAO_VIEW_RO])
        self.assertTrue(ok, detail)
        self.assertIn("count=3", detail)
        self.assertIn("rw=1", detail)
        self.assertIn("ro=2", detail)

    def test_one_bad_mount_fails_the_set(self) -> None:
        ok, detail = _child_cifs_mode_ok([OC14_RW, KAKAO_RW])
        self.assertFalse(ok)
        self.assertIn("kakao-work:rw!=ro", detail)

    def test_unparseable_source_requires_ro(self) -> None:
        self.assertTrue(_child_cifs_mode_ok([_row("garbage", ro=True)])[0])
        self.assertFalse(_child_cifs_mode_ok([_row("garbage", ro=False)])[0])


class ContainerCeilingModeTest(unittest.TestCase):
    """Container side (#28): ro is always acceptable — the container's
    nas_docs bind is deliberately read-only — but rw is allowed only for
    writable-class (OCn) shares."""

    def test_ocn_seen_ro_in_container_passes(self) -> None:
        # The #28 incident line: host=rw, container=ro must be a normal combo.
        ok, detail = _child_cifs_mode_ok([OC14_RO], ro_always_ok=True)
        self.assertTrue(ok, detail)
        self.assertIn("ro=1", detail)

    def test_ocn_seen_rw_in_container_also_passes(self) -> None:
        ok, _ = _child_cifs_mode_ok([OC14_RW], ro_always_ok=True)
        self.assertTrue(ok)

    def test_customer_share_rw_in_container_is_still_a_violation(self) -> None:
        # The ceiling: the container must never see more writability than
        # the share class grants.
        ok, detail = _child_cifs_mode_ok([KAKAO_RW], ro_always_ok=True)
        self.assertFalse(ok)
        self.assertIn("//192.168.0.222/kakao-work:rw!=ro", detail)

    def test_customer_share_ro_passes(self) -> None:
        self.assertTrue(_child_cifs_mode_ok([KAKAO_RO, KAKAO_VIEW_RO], ro_always_ok=True)[0])

    def test_mixed_incident_shape(self) -> None:
        # oc14 during migration: OCn ro (host rw not propagated), views ro.
        ok, detail = _child_cifs_mode_ok([OC14_RO, KAKAO_VIEW_RO], ro_always_ok=True)
        self.assertTrue(ok, detail)

    def test_unparseable_rw_source_is_still_rejected(self) -> None:
        self.assertFalse(_child_cifs_mode_ok([_row("garbage", ro=False)], ro_always_ok=True)[0])


if __name__ == "__main__":
    unittest.main()
