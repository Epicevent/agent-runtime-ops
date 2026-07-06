from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.domain.update_signal import (
    UPDATE_SIGNAL_FILENAME,
    probe_image_version,
    write_update_signals,
)

IMAGE = "ghcr.io/epicevent/openclaw-jitech@sha256:abc"


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class ProbeImageVersionTest(unittest.TestCase):
    def test_parses_runtime_version_output(self) -> None:
        def runner(argv, **_kwargs):
            self.assertIn("--version", argv)
            self.assertIn(IMAGE, argv)
            return _completed(stdout="OpenClaw 2026.7.6\n")

        with patch("agent_runtime_ops.domain.update_signal.shutil.which", return_value="/usr/bin/docker"):
            self.assertEqual(probe_image_version(IMAGE, runner=runner), "2026.7.6")

    def test_accepts_prerelease_tokens(self) -> None:
        with patch("agent_runtime_ops.domain.update_signal.shutil.which", return_value="/usr/bin/docker"):
            version = probe_image_version(
                IMAGE, runner=lambda *a, **k: _completed(stdout="OpenClaw 2026.8.0-beta.1\n")
            )
        self.assertEqual(version, "2026.8.0-beta.1")

    def test_raises_on_nonzero_exit(self) -> None:
        with patch("agent_runtime_ops.domain.update_signal.shutil.which", return_value="/usr/bin/docker"):
            with self.assertRaises(ValueError):
                probe_image_version(IMAGE, runner=lambda *a, **k: _completed(returncode=1, stderr="boom"))

    def test_raises_when_output_has_no_version(self) -> None:
        with patch("agent_runtime_ops.domain.update_signal.shutil.which", return_value="/usr/bin/docker"):
            with self.assertRaises(ValueError):
                probe_image_version(IMAGE, runner=lambda *a, **k: _completed(stdout="no numbers here"))


def _binding(account: str, family: str = "openclaw", enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(linux_account=account, family=family, enabled=enabled)


class WriteUpdateSignalsTest(unittest.TestCase):
    def test_writes_contract_payload_per_family_slot(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for slot in ("oc1", "oc2"):
                (root / slot / ".openclaw").mkdir(parents=True)
            bindings = [
                _binding("oc1"),
                _binding("oc2"),
                _binding("hermes1", family="hermes"),
                _binding("oc9", enabled=False),
            ]
            results = write_update_signals(
                root,
                "openclaw",
                IMAGE,
                available_version="2026.7.6",
                bindings=bindings,
                home_resolver=lambda slot: root / slot,
            )
            payload = json.loads(Path(results[0][2]).read_text(encoding="utf-8"))
        self.assertEqual([(slot, ok) for slot, ok, _ in results], [("oc1", True), ("oc2", True)])
        # Product contract: envelope version 1 + availableVersion required.
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["availableVersion"], "2026.7.6")
        self.assertEqual(payload["imageTag"], IMAGE)
        self.assertIn("approvedAt", payload)

    def test_missing_state_dir_reports_failure_without_raising(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "oc1" / ".openclaw").mkdir(parents=True)
            results = write_update_signals(
                root,
                "openclaw",
                IMAGE,
                available_version="2026.7.6",
                bindings=[_binding("oc1"), _binding("oc2")],
                home_resolver=lambda slot: root / slot,
            )
        by_slot = {slot: (ok, detail) for slot, ok, detail in results}
        self.assertTrue(by_slot["oc1"][0])
        self.assertFalse(by_slot["oc2"][0])
        self.assertIn("state dir missing", by_slot["oc2"][1])

    def test_overwrites_previous_signal_atomically(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "oc1" / ".openclaw"
            state_dir.mkdir(parents=True)
            (state_dir / UPDATE_SIGNAL_FILENAME).write_text('{"version":1,"availableVersion":"2026.5.19"}')
            write_update_signals(
                root,
                "openclaw",
                IMAGE,
                available_version="2026.7.6",
                bindings=[_binding("oc1")],
                home_resolver=lambda slot: root / slot,
            )
            payload = json.loads((state_dir / UPDATE_SIGNAL_FILENAME).read_text(encoding="utf-8"))
            leftovers = [p.name for p in state_dir.iterdir() if p.name != UPDATE_SIGNAL_FILENAME]
        self.assertEqual(payload["availableVersion"], "2026.7.6")
        self.assertEqual(leftovers, [])


LABELS = {
    "org.opencontainers.image.revision": "a" * 40,
    "org.opencontainers.image.source": "https://github.com/Epicevent/openclaw-jitech",
}


class ApproveAnnounceTest(unittest.TestCase):
    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            family="openclaw",
            role="product",
            image=IMAGE,
            source_commit="a" * 40,
            state_root="/tmp/unused",
        )

    def test_product_approval_announces_and_never_blocks(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        with (
            patch.object(image_cmd, "_is_root", return_value=True),
            patch.object(image_cmd, "image_recipe_labels_from_wrapper", return_value=dict(LABELS)),
            patch.object(image_cmd, "verify_commit_on_default_branch", return_value="main"),
            patch.object(image_cmd, "verify_source_commit"),
            patch.object(image_cmd, "write_image_approval", return_value=Path("/tmp/policy.yaml")),
            patch.object(image_cmd, "probe_image_version", return_value="2026.7.6"),
            patch.object(
                image_cmd,
                "write_update_signals",
                return_value=[("oc1", True, "/home/oc1/.openclaw/update-signal.json"), ("oc2", False, "nope")],
            ),
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = image_cmd.cmd_image_approve(self._args())
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("update_signal slot=oc1 ok", text)
        self.assertIn("update_signal slot=oc2 FAIL", text)
        self.assertIn("update_signal_status=written count=1/2 availableVersion=2026.7.6", text)

    def test_wrapper_approval_does_not_announce(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        args = self._args()
        args.role = "wrapper"
        with (
            patch.object(image_cmd, "_is_root", return_value=True),
            patch.object(image_cmd, "image_recipe_labels_from_wrapper", return_value=dict(LABELS)),
            patch.object(image_cmd, "verify_commit_on_default_branch", return_value="main"),
            patch.object(image_cmd, "verify_source_commit"),
            patch.object(image_cmd, "write_image_approval", return_value=Path("/tmp/policy.yaml")),
            patch.object(image_cmd, "probe_image_version") as probe,
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = image_cmd.cmd_image_approve(args)
        self.assertEqual(rc, 0)
        probe.assert_not_called()
        self.assertNotIn("update_signal", out.getvalue())

    def test_probe_failure_prints_skip_and_approval_stands(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        with (
            patch.object(image_cmd, "_is_root", return_value=True),
            patch.object(image_cmd, "image_recipe_labels_from_wrapper", return_value=dict(LABELS)),
            patch.object(image_cmd, "verify_commit_on_default_branch", return_value="main"),
            patch.object(image_cmd, "verify_source_commit"),
            patch.object(image_cmd, "write_image_approval", return_value=Path("/tmp/policy.yaml")),
            patch.object(image_cmd, "probe_image_version", side_effect=ValueError("no docker")),
            patch.object(image_cmd, "write_update_signals") as writer,
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = image_cmd.cmd_image_approve(self._args())
        self.assertEqual(rc, 0)
        writer.assert_not_called()
        self.assertIn("update_signal_status=skipped reason=version_probe_failed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
