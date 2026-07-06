from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.nas import check_nas_policy, parse_cifs_mount_source

# Real strings from the oc1 live mount inventory (kw-NAS per-view binds).
VIEW_USERS = "//192.168.0.222/kakao-work[/users/함석헌_대표이사_7362168]"
VIEW_MEDIA = "//192.168.0.222/kakao-work[/media/10727974]"
PLAIN = "//192.168.0.222/hanpass_groupware"


class ParseCifsMountSourceTest(unittest.TestCase):
    def test_plain_share_has_no_subpath(self) -> None:
        share, subpath = parse_cifs_mount_source(PLAIN)
        self.assertEqual(share.source, PLAIN)
        self.assertIsNone(subpath)

    def test_view_parses_base_share_and_subpath(self) -> None:
        share, subpath = parse_cifs_mount_source(VIEW_USERS)
        self.assertEqual(share.source, "//192.168.0.222/kakao-work")
        self.assertEqual(subpath, "/users/함석헌_대표이사_7362168")

    def test_view_media_form(self) -> None:
        share, subpath = parse_cifs_mount_source(VIEW_MEDIA)
        self.assertEqual(share.share, "kakao-work")
        self.assertEqual(subpath, "/media/10727974")

    def test_traversal_subpaths_are_rejected(self) -> None:
        for bad in (
            "//192.168.0.222/kakao-work[/..]",
            "//192.168.0.222/kakao-work[/users/../../etc]",
            "//192.168.0.222/kakao-work[/users//x]",
            "//192.168.0.222/kakao-work[/]",
            "//192.168.0.222/kakao-work[/.]",
        ):
            with self.assertRaises(ValueError, msg=bad):
                parse_cifs_mount_source(bad)

    def test_garbage_still_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_cifs_mount_source("not-a-share")


def _binding(slot: str = "oc1", runtime_class: str = "customer") -> SimpleNamespace:
    return SimpleNamespace(linux_account=slot, runtime_class=runtime_class)


def _policy(grants: list[str]) -> dict:
    return {"accounts": {"oc1": {"auto_approve": True, "grants": grants}}}


class ViewPolicyDecisionTest(unittest.TestCase):
    def _decide(self, source: str, grants: list[str]):
        with (
            patch("agent_runtime_ops.nas.get_runtime_binding", return_value=_binding()),
            patch("agent_runtime_ops.nas.load_yaml", return_value=_policy(grants)),
            patch(
                "agent_runtime_ops.nas._grant_patterns",
                return_value=(True, grants, None),
            ),
        ):
            return check_nas_policy("oc1", source, Path("/unused"))

    def test_view_allowed_by_base_share_grant(self) -> None:
        decision = self._decide(VIEW_USERS, ["//192.168.0.222/kakao-work"])
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "grant_matched_view")
        self.assertEqual(decision.share.source, "//192.168.0.222/kakao-work")

    def test_view_refused_without_grant(self) -> None:
        decision = self._decide(VIEW_MEDIA, ["//192.168.0.222/hanpass_groupware"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "grant_not_matched_view")

    def test_plain_share_reason_unchanged(self) -> None:
        decision = self._decide(PLAIN, ["//192.168.0.222/hanpass_groupware"])
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "grant_matched")

    def test_traversal_view_raises_for_loud_check_failure(self) -> None:
        with self.assertRaises(ValueError):
            self._decide("//192.168.0.222/kakao-work[/users/../../etc]", ["*"])


if __name__ == "__main__":
    unittest.main()
