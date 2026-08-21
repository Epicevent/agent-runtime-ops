from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.workspace_probe import probe_workspace_write, workspace_local_entry_count


class WorkspaceLocalEntryCountTest(unittest.TestCase):
    def test_empty_directory_has_zero_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(workspace_local_entry_count(Path(directory)), 0)

    def test_counts_hidden_and_normal_names_without_reading_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".hidden").write_text("contents are irrelevant", encoding="utf-8")
            (root / "subdir").mkdir()
            self.assertEqual(workspace_local_entry_count(root), 2)


class WorkspaceWriteProbePreconditionTest(unittest.TestCase):
    @patch("agent_runtime_ops.domain.workspace_probe.os.geteuid", return_value=1000)
    def test_refuses_non_root(self, _geteuid) -> None:
        self.assertEqual(probe_workspace_write(Path("/tmp"), "oc1_rt"), (False, "root_required"))

    @patch("agent_runtime_ops.domain.workspace_probe.pwd.getpwnam", side_effect=KeyError)
    @patch("agent_runtime_ops.domain.workspace_probe.os.geteuid", return_value=0)
    def test_refuses_missing_runtime_user(self, _geteuid, _getpwnam) -> None:
        self.assertEqual(probe_workspace_write(Path("/tmp"), "missing_rt"), (False, "runtime_user_missing"))


if __name__ == "__main__":
    unittest.main()
