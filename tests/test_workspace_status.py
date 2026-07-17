from __future__ import annotations

import unittest
from unittest import mock

from agent_runtime_ops.domain.workspace_bind import (
    workspace_bound_source,
    workspace_status_has_signal,
    workspace_status_row,
)


def _rw_row(source: str, target: str) -> dict[str, str]:
    return {"target": target, "source": source, "fstype": "cifs", "options": "rw,relatime"}


class WorkspaceStatusRowTest(unittest.TestCase):
    def test_row_carries_share_identities(self) -> None:
        row = workspace_status_row(
            "oc5",
            [_rw_row("//10.10.10.2/OC5", "/home/oc5/nas_rw/host-a/OC5")],
            "//10.10.10.2/OC5",
            True,
        )
        self.assertEqual(row["slot"], "oc5")
        self.assertEqual(row["bound_to"], "//10.10.10.2/OC5")
        self.assertEqual(row["rw_sources"], ["//10.10.10.2/OC5"])
        self.assertTrue(row["stamp_bind"])

    def test_empty_bound_source_normalizes_to_none(self) -> None:
        row = workspace_status_row("oc7", [], "", False)
        self.assertEqual(row["bound_to"], "none")


class WorkspaceStatusSignalTest(unittest.TestCase):
    """Unstamped /home candidates earn a line only with a live signal —
    ordinary service accounts must stay out of the fleet report."""

    def test_no_signal(self) -> None:
        self.assertFalse(workspace_status_has_signal(workspace_status_row("svcops", [], "none", False)))

    def test_bound_is_signal(self) -> None:
        self.assertTrue(workspace_status_has_signal(workspace_status_row("oc5", [], "//10.10.10.2/OC5", False)))

    def test_rw_mount_is_signal(self) -> None:
        row = workspace_status_row("oc5", [_rw_row("//10.10.10.2/OC5", "/home/oc5/nas_rw/host-a/OC5")], "none", False)
        self.assertTrue(workspace_status_has_signal(row))

    def test_stamp_is_signal(self) -> None:
        self.assertTrue(workspace_status_has_signal(workspace_status_row("oc5", [], "none", True)))


class WorkspaceBoundSourceTest(unittest.TestCase):
    def test_unbound_returns_none(self) -> None:
        with mock.patch("agent_runtime_ops.domain.workspace_bind.findmnt_one", return_value=(1, "not mounted", [])):
            self.assertEqual(workspace_bound_source("oc5"), "none")

    def test_bound_returns_share_source(self) -> None:
        rows = [{"target": "/home/oc5/workspace", "source": "//10.10.10.2/OC5", "fstype": "cifs"}]
        with mock.patch("agent_runtime_ops.domain.workspace_bind.findmnt_one", return_value=(0, "", rows)):
            self.assertEqual(workspace_bound_source("oc5"), "//10.10.10.2/OC5")


if __name__ == "__main__":
    unittest.main()
