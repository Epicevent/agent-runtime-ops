from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from agent_runtime_ops.cli import _approve_auto_once, _slot_names_from_config, cmd_nas_requests


def write_state(root: Path) -> None:
    digest = "sha256:" + "1" * 64
    (root / "slots.yaml").write_text(
        """
slots:
  - slot: oc3
    lane: openclaw-customer-stable
  - slot: dev-oc
    lane: openclaw-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "lanes.yaml").write_text(
        """
lanes:
  openclaw-customer-stable:
    family: openclaw
    slot_class: customer
    release: openclaw-current
    runtime_profile: openclaw-customer
  openclaw-dev:
    family: openclaw
    slot_class: dev
    release: openclaw-current
    runtime_profile: openclaw-dev
""".lstrip(),
        encoding="utf-8",
    )
    (root / "releases.yaml").write_text(
        f"""
releases:
  openclaw-current:
    family: openclaw
    wrapper_image: ghcr.io/epicevent/openclaw-nas-agent@{digest}
    product_image: ghcr.io/epicevent/openclaw-nas-agent@{digest}
    digest: {digest}
""".lstrip(),
        encoding="utf-8",
    )


class CliNasTests(unittest.TestCase):
    def test_slot_names_from_list_config(self) -> None:
        slots = [{"slot": "oc10"}, {"slot": "oc3"}, {"lane": "missing"}, "oc2"]
        self.assertEqual(_slot_names_from_config(slots), ["oc10", "oc2", "oc3"])

    def test_nas_requests_accepts_slots_yaml_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cmd_nas_requests(argparse.Namespace(state_root=str(root)))
        self.assertEqual(rc, 0)
        self.assertIn("pending_request_count=0", output.getvalue())
        self.assertIn("nas_requests_status=ok", output.getvalue())

    def test_approve_auto_accepts_slots_yaml_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_state(root)
            result = _approve_auto_once(root)
        self.assertEqual(result, {"checked": 0, "approved": 0, "pending": 0, "rejected": 0, "failed": 0})


if __name__ == "__main__":
    unittest.main()
