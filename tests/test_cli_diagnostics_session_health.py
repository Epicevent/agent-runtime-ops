from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_runtime_ops.commands.diagnostics import cmd_diagnostics_session_health
from agent_runtime_ops.routing import RuntimeBinding, dump_runtime_bindings


def _binding(account: str) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, account)),
        linux_account=account,
        public_host=f"{account}.ji-tech.co.kr",
        family="openclaw",
        runtime_class="customer",
        gateway_port=28789,
        bridge_port=28790,
    )


def _write_bindings(root: Path, account: str) -> None:
    (root / "runtime-bindings.json").write_text(
        dump_runtime_bindings([_binding(account)]), encoding="utf-8"
    )


def _dispatch(find_out: str, find_rc: int, logs_out: str):
    """Return a run_text side_effect that answers exec-find vs logs by argv."""

    def _side_effect(command, timeout=20):
        if command[1] == "exec":
            return subprocess.CompletedProcess(command, find_rc, find_out, "")
        if command[1] == "logs":
            return subprocess.CompletedProcess(command, 0, logs_out, "")
        raise AssertionError(f"unexpected docker command: {command!r}")

    return _side_effect


class CliSessionHealthTests(unittest.TestCase):
    def test_degraded_on_tombstone_and_log_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            find_out = (
                "65309\t/home/node/.openclaw/agents/main/sessions/0d330d6f.jsonl\n"
                "0\t/home/node/.openclaw/agents/main/sessions/39cb0c55.jsonl\n"
            )
            logs_out = (
                "EmbeddedAttemptSessionTakeoverError: session file changed\n"
                "Embedded agent failed before reply: EEXIST: file already exists\n"
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=("abc123def456", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text",
                    side_effect=_dispatch(find_out, 0, logs_out),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_session_health(
                    argparse.Namespace(slot="oc1", since="6h", state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("session_health_status=degraded", text)
        self.assertIn("session_total=2", text)
        self.assertIn("zero_byte_tombstones=1", text)
        self.assertIn("tombstone=39cb0c55.jsonl", text)
        self.assertIn("log_signature[EmbeddedAttemptSessionTakeoverError]=1", text)
        self.assertIn("log_signature[EEXIST]=1", text)

    def test_ok_when_no_tombstone_and_clean_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            find_out = (
                "65309\t/home/node/.openclaw/agents/main/sessions/aaa.jsonl\n"
                "1024\t/home/node/.openclaw/agents/main/sessions/bbb.jsonl\n"
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=("abc123def456", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text",
                    side_effect=_dispatch(find_out, 0, "ready\nlistening\n"),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_session_health(
                    argparse.Namespace(slot="oc1", since="6h", state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("session_health_status=ok", text)
        self.assertIn("zero_byte_tombstones=0", text)
        self.assertIn("log_signature_total=0", text)

    def test_exec_failure_reports_scan_not_ok_but_still_scans_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=("abc123def456", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text",
                    side_effect=_dispatch("", 1, "failed to persist prompt error entry\n"),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_session_health(
                    argparse.Namespace(slot="oc1", since="6h", state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("session_scan_ok=no", text)
        self.assertIn("session_total=0", text)
        # log signature still counted even when the filesystem scan failed
        self.assertIn("session_health_status=degraded", text)
        self.assertIn("log_signature[failed to persist prompt error entry]=1", text)

    def test_bad_since_fails_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch("agent_runtime_ops.commands.diagnostics.run_text") as run_mock,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_session_health(
                    argparse.Namespace(slot="oc1", since="; rm -rf /", state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("session_health_status=fail", text)
        run_mock.assert_not_called()

    def test_container_not_found_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=(None, "not_found"),
                ),
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_session_health(
                    argparse.Namespace(slot="oc1", since="6h", state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("reason=container_not_found lookup=not_found", text)

    def test_requires_root(self) -> None:
        with patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=False):
            rc = cmd_diagnostics_session_health(
                argparse.Namespace(slot="oc1", since="6h", state_root="/nonexistent")
            )
        self.assertEqual(rc, 2)

    def test_developer_customer_target_is_rejected_before_container_lookup(self) -> None:
        output = io.StringIO()
        with (
            patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.diagnostics._sudo_user",
                return_value="atelier",
            ),
            patch(
                "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding"
            ) as lookup,
            patch("agent_runtime_ops.commands.diagnostics.run_text") as run_mock,
            contextlib.redirect_stdout(output),
        ):
            rc = cmd_diagnostics_session_health(
                argparse.Namespace(slot="oc20", since="6h", state_root="/nonexistent")
            )
        self.assertEqual(rc, 1)
        self.assertIn("may inspect only dev-* targets", output.getvalue())
        lookup.assert_not_called()
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
