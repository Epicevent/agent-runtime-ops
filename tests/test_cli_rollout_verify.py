from __future__ import annotations

import argparse
import contextlib
import io
import unittest
from unittest.mock import patch

from agent_runtime_ops.commands.rollout_verify import cmd_rollout_verify

MODULE = "agent_runtime_ops.commands.rollout_verify"

TRUTH = {
    "truth_status": "ok",
    "family": "openclaw",
    "product_image": "ghcr.io/epicevent/openclaw-jitech@sha256:aaa",
    "wrapper_image": "ghcr.io/epicevent/agent-runtime-openclaw@sha256:bbb",
}
TRUTH_CHECKS = [(True, "truth_container_lookup", "instance_label")]


def _args(slot: str, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "slot": slot,
        "pack": None,
        "gemini_chat_smoke": False,
        "state_root": "/tmp/does-not-matter",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _run(args: argparse.Namespace) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cmd_rollout_verify(args)
    return rc, out.getvalue()


class RolloutVerifyTest(unittest.TestCase):
    def test_pass_when_truth_approvals_and_pack_all_green(self) -> None:
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(f"{MODULE}.live_runtime_truth", return_value=(dict(TRUTH), list(TRUTH_CHECKS))),
            patch(f"{MODULE}.is_image_ref_approved", return_value=True) as approved,
            patch(f"{MODULE}.cmd_checklist_pack", return_value=0) as pack,
        ):
            rc, out = _run(_args("oc14"))
        self.assertEqual(rc, 0)
        self.assertIn("rollout_verify_status=pass", out)
        self.assertIn("verify_product_digest_approved", out)
        self.assertEqual(approved.call_count, 2)
        pack_args = pack.call_args.args[0]
        self.assertEqual(pack_args.pack, "openclaw-runtime")
        self.assertEqual(pack_args.slot, "oc14")

    def test_fail_when_wrapper_digest_not_approved(self) -> None:
        def approval(_state_root, _family, role, _ref) -> bool:
            return role != "wrapper"

        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(f"{MODULE}.live_runtime_truth", return_value=(dict(TRUTH), list(TRUTH_CHECKS))),
            patch(f"{MODULE}.is_image_ref_approved", side_effect=approval),
            patch(f"{MODULE}.cmd_checklist_pack", return_value=0),
        ):
            rc, out = _run(_args("oc14"))
        self.assertEqual(rc, 1)
        self.assertIn("rollout_verify_status=fail", out)
        self.assertIn("FAIL verify_wrapper_digest_approved", out)

    def test_dev_slot_skips_approval_gate(self) -> None:
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(f"{MODULE}.live_runtime_truth", return_value=(dict(TRUTH), list(TRUTH_CHECKS))),
            patch(f"{MODULE}.is_image_ref_approved") as approved,
            patch(f"{MODULE}.cmd_checklist_pack", return_value=0),
        ):
            rc, out = _run(_args("dev-oc"))
        self.assertEqual(rc, 0)
        self.assertIn("verify_approval_gate", out)
        self.assertIn("dev-target-exempt", out)
        approved.assert_not_called()

    def test_partial_retrieval_labels_never_report_capability_absent(self) -> None:
        partial_truth = {
            **TRUTH,
            "retrieval_labels_present": "true",
            "retrieval_schema": "",
        }
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(
                f"{MODULE}.live_runtime_truth",
                return_value=(partial_truth, list(TRUTH_CHECKS)),
            ),
            patch(f"{MODULE}.is_image_ref_approved", return_value=True),
            patch(
                f"{MODULE}.desired_from_live_image_truth",
                side_effect=ValueError("retrieval labels are incomplete"),
            ) as desired,
            patch(f"{MODULE}.cmd_checklist_pack") as pack,
        ):
            rc, out = _run(_args("oc14"))

        self.assertEqual(rc, 1)
        self.assertIn("retrieval labels are incomplete", out)
        self.assertNotIn("capability-absent", out)
        desired.assert_called_once()
        pack.assert_not_called()

    def test_partial_runtime_projection_never_reports_capability_absent(self) -> None:
        partial_truth = {
            **TRUTH,
            "retrieval_labels_present": "false",
            "retrieval_projection_labels_present": "true",
            "retrieval_projection_complete": "false",
            "retrieval_projection_consistent": "false",
        }
        projection_check = (
            False,
            "truth_retrieval_projection_complete_and_consistent",
            "invalid",
        )
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(
                f"{MODULE}.live_runtime_truth",
                return_value=(partial_truth, [*TRUTH_CHECKS, projection_check]),
            ),
            patch(f"{MODULE}.is_image_ref_approved", return_value=True),
            patch(f"{MODULE}.desired_from_live_image_truth") as desired,
            patch(f"{MODULE}.cmd_checklist_pack", return_value=0),
        ):
            rc, out = _run(_args("oc14"))

        self.assertEqual(rc, 1)
        self.assertIn("invalid-runtime-projection", out)
        self.assertNotIn("capability-absent", out)
        desired.assert_not_called()

    def test_fail_when_checklist_pack_fails(self) -> None:
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(f"{MODULE}._authorize_deploy_target", return_value=None),
            patch(f"{MODULE}.live_runtime_truth", return_value=(dict(TRUTH), list(TRUTH_CHECKS))),
            patch(f"{MODULE}.is_image_ref_approved", return_value=True),
            patch(f"{MODULE}.cmd_checklist_pack", return_value=1),
        ):
            rc, out = _run(_args("oc14"))
        self.assertEqual(rc, 1)
        self.assertIn("rollout_verify_status=fail", out)

    def test_dev_account_refused_for_customer_target(self) -> None:
        with (
            patch(f"{MODULE}._is_root", return_value=True),
            patch(
                f"{MODULE}._authorize_deploy_target",
                return_value="rollout verify: account openclawdev may only deploy dev-* slots, not oc1",
            ),
            patch(f"{MODULE}.live_runtime_truth") as truth,
        ):
            rc, out = _run(_args("oc1"))
        self.assertEqual(rc, 2)
        self.assertIn("rollout_verify_status=fail", out)
        truth.assert_not_called()


if __name__ == "__main__":
    unittest.main()
