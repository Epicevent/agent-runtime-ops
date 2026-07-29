from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_runtime_ops.domain.dev_recipe_runtime import (
    dist_halves,
    ensure_dev_runtime_dir,
    merge_preserved_control_ui,
    preflight_dev_dist,
)


def _make_dist(root: Path, *, runtime: bool, control_ui: bool) -> Path:
    dist = root / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    if runtime:
        (dist / "index.js").write_text("// entry", encoding="utf-8")
        (dist / "gateway.abc123.js").write_text("// chunk", encoding="utf-8")
    if control_ui:
        ui = dist / "control-ui"
        (ui / "assets").mkdir(parents=True)
        (ui / "index.html").write_text("<!doctype html>", encoding="utf-8")
        (ui / "assets" / "app.js").write_text("// ui", encoding="utf-8")
    return dist


class DistHalvesTest(unittest.TestCase):
    def test_full_dist_reports_both_halves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=True)
            self.assertEqual(dist_halves(dist), (True, True))

    def test_runtime_only_dist(self) -> None:
        # The pnpm build:docker output shape from the incident.
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=False)
            self.assertEqual(dist_halves(dist), (True, False))

    def test_control_ui_dir_without_index_does_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=False)
            (dist / "control-ui").mkdir()
            self.assertEqual(dist_halves(dist), (True, False))


class PreflightTest(unittest.TestCase):
    def test_full_dist_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=True)
            self.assertTrue(preflight_dev_dist(dist, runtime_only=False))

    def test_half_dist_refused_with_guidance(self) -> None:
        # Verification scenario 1 from issue #26: control-ui 빠진 dist → 거부.
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=False)
            with self.assertRaises(ValueError) as ctx:
                preflight_dev_dist(dist, runtime_only=False)
            message = str(ctx.exception)
            self.assertIn("control-ui", message)
            self.assertIn("pnpm -C ui build", message)
            self.assertIn("--runtime-only", message)

    def test_half_dist_allowed_with_runtime_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = _make_dist(Path(tmp), runtime=True, control_ui=False)
            self.assertFalse(preflight_dev_dist(dist, runtime_only=True))

    def test_non_dist_directory_always_refused(self) -> None:
        # Missing runtime entry is not a dist at all — even with --runtime-only.
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "dist"
            empty.mkdir()
            for runtime_only in (False, True):
                with self.assertRaises(ValueError) as ctx:
                    preflight_dev_dist(empty, runtime_only=runtime_only)
                self.assertIn("index.js", str(ctx.exception))


class RuntimeDirectoryPreflightTest(unittest.TestCase):
    def test_read_only_preflight_requires_directory_and_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home_root = root / "home"
            slot_home = home_root / "oc20"
            slot_home.mkdir(parents=True)
            runtime_dir = slot_home / "openclaw"
            state_root = root / "state"

            def mapped_path(value: object) -> Path:
                return home_root if str(value) == "/home" else Path(value)

            with (
                patch(
                    "agent_runtime_ops.domain.dev_recipe_runtime.Path",
                    side_effect=mapped_path,
                ),
                patch(
                    "agent_runtime_ops.domain.dev_recipe_runtime.slot_uid_gid",
                    return_value=(1000, 1000),
                ),
            ):
                with self.assertRaises(FileNotFoundError):
                    ensure_dev_runtime_dir("oc20", create=False)

                runtime_dir.write_text("not a directory", encoding="utf-8")
                with self.assertRaises(FileNotFoundError):
                    ensure_dev_runtime_dir("oc20", create=False)

                runtime_dir.unlink()
                runtime_dir.mkdir()
                with self.assertRaisesRegex(
                    ValueError,
                    "missing an existing runtime manifest",
                ):
                    ensure_dev_runtime_dir(
                        "oc20",
                        create=False,
                        state_root=state_root,
                        require_existing_manifest=True,
                    )

                (runtime_dir / ".agent-runtime-manifest").write_text(
                    "slot=oc20\n",
                    encoding="utf-8",
                )
                self.assertEqual(
                    ensure_dev_runtime_dir(
                        "oc20",
                        create=False,
                        state_root=state_root,
                        require_existing_manifest=True,
                    ),
                    runtime_dir,
                )


class MergePreservedControlUiTest(unittest.TestCase):
    def test_preserves_slot_control_ui_into_staged_tree(self) -> None:
        # Verification scenario 3: --runtime-only keeps the current dashboard.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = _make_dist(root / "incoming", runtime=True, control_ui=False)
            dest = _make_dist(root / "slot", runtime=True, control_ui=True)
            self.assertTrue(merge_preserved_control_ui(staged, dest))
            self.assertTrue((staged / "control-ui" / "index.html").is_file())
            self.assertTrue((staged / "control-ui" / "assets" / "app.js").is_file())

    def test_dist_with_own_control_ui_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = _make_dist(root / "incoming", runtime=True, control_ui=True)
            marker = staged / "control-ui" / "from-incoming.txt"
            marker.write_text("incoming", encoding="utf-8")
            dest = _make_dist(root / "slot", runtime=True, control_ui=True)
            self.assertFalse(merge_preserved_control_ui(staged, dest))
            self.assertTrue(marker.is_file())

    def test_nothing_to_preserve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = _make_dist(root / "incoming", runtime=True, control_ui=False)
            dest = _make_dist(root / "slot", runtime=True, control_ui=False)
            self.assertFalse(merge_preserved_control_ui(staged, dest))
            self.assertFalse((staged / "control-ui").exists())


if __name__ == "__main__":
    unittest.main()
