from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.workspace_guidance import ensure_runtime_workspace_guidance


class WorkspaceGuidanceTests(unittest.TestCase):
    def test_hermes_workspace_is_data_group_readable_and_setgid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home" / "oc17"
            app_home = home / ".hermes"
            workspace = app_home / "workspace"
            source = root / "hermes-workspace-guidance.md"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("managed guidance\n", encoding="utf-8")
            chmod_calls: list[tuple[Path, int]] = []

            def fake_chmod(path: str | Path, mode: int) -> None:
                chmod_calls.append((Path(path), mode))

            with (
                patch(
                    "agent_runtime_ops.domain.workspace_guidance.workspace_guidance_paths",
                    return_value=(
                        app_home,
                        workspace,
                        [workspace / "AGENTS.md"],
                        source,
                        "<!-- BEGIN -->",
                        "<!-- END -->",
                    ),
                ),
                patch("agent_runtime_ops.domain.workspace_guidance.slot_home", return_value=home),
                patch("agent_runtime_ops.domain.workspace_guidance.runtime_ids", return_value=(12017, 13017, 14017)),
                patch("agent_runtime_ops.domain.workspace_guidance.ensure_group_member", return_value="added") as ensure_member,
                patch("agent_runtime_ops.domain.workspace_guidance.os.chown", create=True),
                patch("agent_runtime_ops.domain.workspace_guidance.os.chmod", side_effect=fake_chmod),
            ):
                result = ensure_runtime_workspace_guidance(
                    "oc17",
                    SimpleNamespace(metadata={"family": "hermes"}),
                )

            ensure_member.assert_called_once_with("oc17", "oc17_data")
            self.assertIn((app_home, 0o750), chmod_calls)
            self.assertIn((workspace, 0o2750), chmod_calls)
            self.assertEqual(result["workspace_data_group_member"], "added")
            self.assertTrue((workspace / "AGENTS.md").is_file())

