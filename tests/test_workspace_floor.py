from __future__ import annotations

import unittest

from agent_runtime_ops.domain.runtime_checks import _workspace_cifs_floor_ok


def _row(target: str, ro: bool) -> dict[str, str]:
    return {
        "target": target,
        "source": "//10.10.10.2/OC2",
        "fstype": "cifs",
        "options": "ro,relatime" if ro else "rw,relatime",
    }


# Exact shapes from the 2026-07-15 oc2 canary: host workspace mount rw,
# container /home/node/workspace seen rw only after recreate.
HOST_RW = _row("/home/oc2/workspace", ro=False)
HOST_RO = _row("/home/oc2/workspace", ro=True)
CONT_RW = _row("/home/node/workspace", ro=False)
CONT_RO = _row("/home/node/workspace", ro=True)


class WorkspaceFloorTest(unittest.TestCase):
    """The floor the ceiling check structurally cannot provide: 17 slots sat
    frozen (host rw / container ro or absent) behind green checks in 2026-07."""

    def test_no_ocn_is_vacuous_pass(self) -> None:
        # oc1 and dev slots: no OCn mounted on the host -> nothing to gate.
        ok, detail = _workspace_cifs_floor_ok([], None)
        self.assertTrue(ok)
        self.assertEqual(detail, "host=absent")

    def test_host_rw_container_rw_passes(self) -> None:
        ok, detail = _workspace_cifs_floor_ok([HOST_RW], [CONT_RW])
        self.assertTrue(ok, detail)
        self.assertIn("container=rw", detail)

    def test_frozen_container_fails(self) -> None:
        # The freeze class: recursive-ro stamped the clone (pre-split shape).
        ok, detail = _workspace_cifs_floor_ok([HOST_RW], [CONT_RO])
        self.assertFalse(ok)
        self.assertIn("container_ro=/home/node/workspace", detail)

    def test_container_missing_bind_fails(self) -> None:
        # The oc2 mid-migration state: host migrated, old container has no
        # workspace bind -> the agent has NO access, which must read as red.
        ok, detail = _workspace_cifs_floor_ok([HOST_RW], [])
        self.assertFalse(ok)
        self.assertEqual(detail, "host=rw container=absent")

    def test_container_unreadable_fails(self) -> None:
        # If the floor cannot be proven, it is not green.
        ok, detail = _workspace_cifs_floor_ok([HOST_RW], None)
        self.assertFalse(ok)
        self.assertEqual(detail, "host=rw container=unreadable")

    def test_host_ro_fails(self) -> None:
        # A read-only OCn mount on the HOST contradicts the writable class.
        ok, detail = _workspace_cifs_floor_ok([HOST_RO], [CONT_RO])
        self.assertFalse(ok)
        self.assertIn("host_ro=/home/oc2/workspace", detail)


if __name__ == "__main__":
    unittest.main()
