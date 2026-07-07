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

from agent_runtime_ops.commands.diagnostics import cmd_diagnostics_logs
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


class CliDiagnosticsLogsTests(unittest.TestCase):
    def test_live_logs_tail_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            secret = "AIzaSyRedactMeReallyLongGoogleKey0123456789"
            proc = subprocess.CompletedProcess(
                ["docker"],
                0,
                f"provider call failed url=...key={secret}\nGEMINI_API_KEY={secret}\nHTTP 429 rate limited\n",
                "",
            )
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=("abc123def456", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text", return_value=proc
                ) as run_mock,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_logs(
                    argparse.Namespace(slot="oc1", tail=50, since=None, state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 0, text)
        self.assertIn("diagnostics_logs_status=ok", text)
        self.assertIn("container=abc123def456", text)
        self.assertIn("logs_tail_begin", text)
        self.assertIn("HTTP 429 rate limited", text)
        self.assertNotIn(secret, text)
        self.assertIn("GEMINI_API_KEY=<redacted>", text)
        docker_cmd = run_mock.call_args.args[0]
        self.assertEqual(docker_cmd[:4], ["docker", "logs", "--tail", "50"])
        self.assertEqual(docker_cmd[-1], "abc123def456")

    def test_since_is_passed_through_when_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            proc = subprocess.CompletedProcess(["docker"], 0, "ready\n", "")
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.find_gateway_container_by_binding",
                    return_value=("abc123def456", "instance_label"),
                ),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text", return_value=proc
                ) as run_mock,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                rc = cmd_diagnostics_logs(
                    argparse.Namespace(slot="oc1", tail=200, since="15m", state_root=str(root))
                )
            self.assertEqual(rc, 0)
            docker_cmd = run_mock.call_args.args[0]
            self.assertIn("--since", docker_cmd)
            self.assertEqual(docker_cmd[docker_cmd.index("--since") + 1], "15m")

    def test_bad_since_fails_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_bindings(root, "oc1")
            output = io.StringIO()
            with (
                patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=True),
                patch(
                    "agent_runtime_ops.commands.diagnostics.run_text"
                ) as run_mock,
                contextlib.redirect_stdout(output),
            ):
                rc = cmd_diagnostics_logs(
                    argparse.Namespace(
                        slot="oc1", tail=200, since="; rm -rf /", state_root=str(root)
                    )
                )
            text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("diagnostics_logs_status=fail", text)
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
                rc = cmd_diagnostics_logs(
                    argparse.Namespace(slot="oc1", tail=50, since=None, state_root=str(root))
                )
            text = output.getvalue()
        self.assertEqual(rc, 1, text)
        self.assertIn("reason=container_not_found lookup=not_found", text)

    def test_requires_root(self) -> None:
        with patch("agent_runtime_ops.commands.diagnostics._is_root", return_value=False):
            rc = cmd_diagnostics_logs(
                argparse.Namespace(slot="oc1", tail=50, since=None, state_root="/nonexistent")
            )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
