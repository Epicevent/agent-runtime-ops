from __future__ import annotations

import argparse
import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agent_runtime_ops.domain.source_provenance import verify_commit_on_default_branch

GIT_ENV = {
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def _git(repo: Path, *args: str) -> str:
    import os

    env = dict(os.environ)
    env.update(GIT_ENV)
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=True
    )
    return proc.stdout.strip()


class VerifyCommitOnDefaultBranchTest(unittest.TestCase):
    """Real-git integration: a throwaway origin with a merged and an unmerged commit."""

    def _make_origin(self, tmp: str) -> tuple[str, str, str]:
        origin = Path(tmp) / "origin"
        origin.mkdir()
        subprocess.run(
            ["git", "init", "-b", "main", str(origin)], capture_output=True, text=True, check=True
        )
        (origin / "a.txt").write_text("a\n")
        _git(origin, "add", "a.txt")
        _git(origin, "commit", "-m", "on main")
        merged = _git(origin, "rev-parse", "HEAD")
        _git(origin, "checkout", "-q", "-b", "feature")
        (origin / "b.txt").write_text("b\n")
        _git(origin, "add", "b.txt")
        _git(origin, "commit", "-m", "unmerged feature work")
        unmerged = _git(origin, "rev-parse", "HEAD")
        _git(origin, "checkout", "-q", "main")
        return str(origin), merged, unmerged

    def test_merged_commit_passes_and_reports_branch(self) -> None:
        with TemporaryDirectory() as tmp:
            url, merged, _unmerged = self._make_origin(tmp)
            self.assertEqual(verify_commit_on_default_branch(url, merged), "main")

    def test_unmerged_commit_is_refused_with_merge_hint(self) -> None:
        with TemporaryDirectory() as tmp:
            url, _merged, unmerged = self._make_origin(tmp)
            with self.assertRaises(ValueError) as caught:
                verify_commit_on_default_branch(url, unmerged)
        self.assertIn("not merged", str(caught.exception))

    def test_unknown_commit_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            url, _merged, _unmerged = self._make_origin(tmp)
            with self.assertRaises(ValueError):
                verify_commit_on_default_branch(url, "f" * 40)

    def test_unclonable_repo_reports_infra_error(self) -> None:
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as caught:
                verify_commit_on_default_branch(str(Path(tmp) / "missing"), "f" * 40)
        self.assertIn("could not clone", str(caught.exception))


LABELS = {
    "org.opencontainers.image.revision": "a" * 40,
    "org.opencontainers.image.source": "https://github.com/Epicevent/openclaw-jitech",
}


class ApproveAncestryGateTest(unittest.TestCase):
    def _args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "family": "openclaw",
            "role": "product",
            "image": "ghcr.io/epicevent/openclaw-jitech@sha256:abc",
            "source_commit": "a" * 40,
            "state_root": "/tmp/unused",
            "allow_unmerged_source": False,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _base_patches(self, image_cmd, labels: dict[str, str]):
        return (
            patch.object(image_cmd, "_is_root", return_value=True),
            patch.object(image_cmd, "image_recipe_labels_from_wrapper", return_value=dict(labels)),
            patch.object(image_cmd, "verify_source_commit"),
            patch.object(image_cmd, "write_image_approval", return_value=Path("/tmp/policy.yaml")),
            patch.object(image_cmd, "probe_image_version", return_value="2026.7.6"),
            patch.object(image_cmd, "write_update_signals", return_value=[]),
        )

    def test_unmerged_source_commit_blocks_approval(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        with contextlib.ExitStack() as stack:
            for cm in self._base_patches(image_cmd, LABELS):
                stack.enter_context(cm)
            stack.enter_context(
                patch.object(
                    image_cmd,
                    "verify_commit_on_default_branch",
                    side_effect=ValueError("source commit aaa is not merged"),
                )
            )
            write_approval = stack.enter_context(patch.object(image_cmd, "write_image_approval"))
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = image_cmd.cmd_image_approve(self._args())
        self.assertEqual(rc, 2)
        write_approval.assert_not_called()
        self.assertIn("not merged", err.getvalue())

    def test_allow_unmerged_source_flag_skips_gate_with_audit_line(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        with contextlib.ExitStack() as stack:
            for cm in self._base_patches(image_cmd, LABELS):
                stack.enter_context(cm)
            ancestry = stack.enter_context(patch.object(image_cmd, "verify_commit_on_default_branch"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = image_cmd.cmd_image_approve(self._args(allow_unmerged_source=True))
        self.assertEqual(rc, 0)
        ancestry.assert_not_called()
        self.assertIn("source_ancestry=skipped reason=allow-unmerged-source", out.getvalue())

    def test_missing_source_label_blocks_when_commit_claimed(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        labels = {"org.opencontainers.image.revision": "a" * 40}
        with contextlib.ExitStack() as stack:
            for cm in self._base_patches(image_cmd, labels):
                stack.enter_context(cm)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = image_cmd.cmd_image_approve(self._args())
        self.assertEqual(rc, 2)
        self.assertIn("org.opencontainers.image.source", err.getvalue())

    def test_no_source_commit_claim_skips_ancestry(self) -> None:
        from agent_runtime_ops.commands import image as image_cmd

        with contextlib.ExitStack() as stack:
            for cm in self._base_patches(image_cmd, LABELS):
                stack.enter_context(cm)
            ancestry = stack.enter_context(patch.object(image_cmd, "verify_commit_on_default_branch"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = image_cmd.cmd_image_approve(self._args(source_commit="", role="wrapper"))
        self.assertEqual(rc, 0)
        ancestry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
