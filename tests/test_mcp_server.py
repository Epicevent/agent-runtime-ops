from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from agent_runtime_ops.mcp_server import CommandResult, McpServer


class FakeRunner:
    def __init__(self, responses: list[tuple[int, str, str]] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, object]] = []

    def run(self, argv: list[str], *, input_text: str | None = None, timeout: int = 60) -> CommandResult:
        self.calls.append({"argv": argv, "input_text": input_text, "timeout": timeout})
        if self.responses:
            returncode, stdout, stderr = self.responses.pop(0)
            return CommandResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr)
        return CommandResult(argv=argv, returncode=0, stdout="", stderr="")


def call_tool(server: McpServer, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    return response["result"]["structuredContent"]


class McpServerTests(unittest.TestCase):
    def test_initialize_and_tools_list(self) -> None:
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        response = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            }
        )
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")

        tools = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {item["name"] for item in tools["result"]["tools"]}
        self.assertIn("ops_orientation", names)
        self.assertIn("slot_list", names)
        self.assertIn("runtime_secret_set_from_file", names)
        self.assertIn("deploy_update", names)
        self.assertIn("nas_remove", names)
        self.assertIn("nas_credential_status", names)
        secret_tool = next(item for item in tools["result"]["tools"] if item["name"] == "runtime_secret_set_from_file")
        key_schema = secret_tool["inputSchema"]["properties"]["key"]
        self.assertIn("GEMINI_API_KEY", key_schema["enum"])
        self.assertNotIn("API_KEY", key_schema["enum"])

    def test_unknown_tool_and_malformed_json(self) -> None:
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        unknown = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "missing_tool", "arguments": {}},
            }
        )
        self.assertEqual(unknown["error"]["code"], -32602)
        self.assertIn("unknown tool", unknown["error"]["message"])

        malformed = server.handle_line("{")
        self.assertEqual(malformed["error"]["code"], -32700)

    def test_ops_orientation_includes_slot_list(self) -> None:
        runner = FakeRunner(
            [
                (0, "update_status=current\n", ""),
                (0, "slot=dev-oc slot_class=dev runtime_profile=openclaw-dev\n", ""),
                (0, "openclaw-dev sha256:abc\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "ops_orientation")
        self.assertTrue(payload["ok"])
        self.assertIn("slot=dev-oc", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "update", "status"])
        self.assertEqual(runner.calls[1]["argv"], ["opsctl", "slot", "list"])
        self.assertEqual(runner.calls[2]["argv"], ["opsctl", "profile", "list"])

    def test_slot_list_uses_argv_list(self) -> None:
        runner = FakeRunner([(0, "slot=dev-oc slot_class=dev runtime_profile=openclaw-dev\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "slot_list")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "slot", "list"])

    def test_slot_check_uses_argv_lists(self) -> None:
        runner = FakeRunner(
            [
                (0, "status=ok\n", ""),
                (0, '{"mutates": false}\n', ""),
                (0, "PASS contract\n", ""),
                (0, "PASS live\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "slot_check", {"slot": "oc1", "live": True})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "status", "oc1"])
        self.assertEqual(runner.calls[1]["argv"], ["opsctl", "plan", "oc1"])
        self.assertEqual(runner.calls[2]["argv"], ["opsctl", "check", "oc1"])
        self.assertEqual(runner.calls[3]["argv"], ["sudo", "opsctl", "check", "--live", "oc1"])
        self.assertTrue(all(isinstance(call["argv"], list) for call in runner.calls))

    def test_secret_raw_argument_is_rejected_and_redacted(self) -> None:
        secret = "AIza" + "A" * 32
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "runtime_secret_set_from_file",
            {"slot": "dev-oc", "key": "GEMINI_API_KEY", "value": secret},
        )
        self.assertFalse(payload["ok"])
        self.assertNotIn(secret, str(payload))
        self.assertIn("raw secret argument rejected", payload["next_action"])

        runner = FakeRunner([(0, f"api_key={secret}\n", ""), (0, "openclaw-dev sha256:abc\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        redacted = call_tool(server, "ops_orientation")
        self.assertNotIn(secret, redacted["stdout"])
        self.assertIn("api_key=<redacted>", redacted["stdout"])

    def test_runtime_secret_set_from_file_passes_secret_via_stdin(self) -> None:
        secret = "AIza" + "B" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gemini.txt"
            path.write_text(secret + "\n", encoding="utf-8")
            runner = FakeRunner([(0, "secret_value_printed=no\nruntime_secret_status=stored\n", "")])
            server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo", secret_roots=[Path(tmp)])
            payload = call_tool(
                server,
                "runtime_secret_set_from_file",
                {"slot": "dev-oc", "key": "GEMINI_API_KEY", "secret_file": str(path)},
            )
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(runner.calls[0]["input_text"], secret)
        self.assertEqual(
            runner.calls[0]["argv"],
            [
                "sudo",
                "opsctl",
                "runtime-secret",
                "set",
                "dev-oc",
                "--key",
                "GEMINI_API_KEY",
                "--value-stdin",
                "--check",
            ],
        )
        self.assertNotIn(secret, str(payload))

    def test_deploy_update_without_approval_returns_exact_root_command(self) -> None:
        target = "a" * 40
        runner = FakeRunner([(1, "update_status=not_ready\ninstalled_ref=" + "b" * 40 + "\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "deploy_update", {"target_ref": target})
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(payload["next_action"], f"sudo opsctl update approve {target}")

    def test_nas_credential_status_uses_sudo_and_is_non_mutating(self) -> None:
        runner = FakeRunner([(0, "official_credential_present=yes\nsecret_value_printed=no\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "nas_credential_status",
            {"slot": "oc3", "share": "//192.168.0.222/hanpass"},
        )
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["sudo", "opsctl", "nas", "credential", "status", "oc3", "//192.168.0.222/hanpass"],
        )

    def test_nas_remove_uses_argv_lists_and_reports_mutation(self) -> None:
        runner = FakeRunner(
            [
                (0, "official_credential_present=yes\n", ""),
                (0, "remove_status=ok\nofficial_credential_present=no\n", ""),
                (0, "official_credential_present=no\n", ""),
                (0, "mounted_child_cifs_count=0\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "nas_remove",
            {"slot": "oc3", "share": "//192.168.0.222/hanpass", "delete_empty_dir": True},
        )
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(
            runner.calls[1]["argv"],
            ["sudo", "opsctl", "nas", "remove", "oc3", "//192.168.0.222/hanpass", "--delete-empty-dir"],
        )
        self.assertTrue(all(isinstance(call["argv"], list) for call in runner.calls))


if __name__ == "__main__":
    unittest.main()
