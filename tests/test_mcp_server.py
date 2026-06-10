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


def call_tool_result(server: McpServer, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    return response["result"]


def call_tool(server: McpServer, name: str, arguments: dict[str, object] | None = None) -> dict[str, object]:
    return call_tool_result(server, name, arguments)["structuredContent"]


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
        self.assertIn("one MCP tool at a time", response["result"]["instructions"])
        self.assertIn("runtime binding", response["result"]["instructions"])
        self.assertIn("live image truth", response["result"]["instructions"])
        self.assertIn("runtime_class", response["result"]["instructions"])

        tools = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {item["name"] for item in tools["result"]["tools"]}
        self.assertIn("ops_orientation", names)
        self.assertNotIn("slot_list", names)
        self.assertIn("binding_list", names)
        self.assertIn("binding_status", names)
        self.assertIn("binding_set_public_host", names)
        self.assertNotIn("routing_status", names)
        self.assertIn("apache_status", names)
        self.assertIn("apache_set_host", names)
        self.assertIn("runtime_truth", names)
        self.assertIn("document_tools_status", names)
        self.assertIn("runtime_secret_set_from_file", names)
        self.assertIn("deploy_update", names)
        self.assertIn("canonical_recipe_validate", names)
        self.assertIn("dev_recipe_status", names)
        self.assertIn("dev_recipe_apply", names)
        self.assertIn("rollout_image_plan", names)
        self.assertIn("rollout_image_dev_apply", names)
        self.assertIn("rollout_image_canary", names)
        self.assertIn("rollout_image_promote", names)
        self.assertNotIn("release_import", names)
        self.assertNotIn("rollout_status", names)
        self.assertNotIn("rollout_plan", names)
        self.assertNotIn("rollout_dev_plan", names)
        self.assertNotIn("rollout_dev_apply", names)
        self.assertNotIn("rollout_canary", names)
        self.assertNotIn("rollout_promote", names)
        self.assertNotIn("rollout_rollback_canary", names)
        self.assertNotIn("slot_apply", names)
        self.assertIn("handoff_status", names)
        self.assertIn("handoff_value_command", names)
        self.assertIn("heartbeat_status", names)
        self.assertIn("heartbeat_disable", names)
        self.assertIn("nas_remove", names)
        self.assertIn("nas_credential_status", names)
        target_check_tool = next(item for item in tools["result"]["tools"] if item["name"] == "target_check")
        self.assertIn("runtime_class", target_check_tool["description"])
        target_check_schema = target_check_tool["inputSchema"]["properties"]
        self.assertEqual(target_check_schema["runtime_class"]["enum"], ["customer", "dev"])
        self.assertNotIn("live", target_check_schema)
        status_tool = next(item for item in tools["result"]["tools"] if item["name"] == "runtime_secret_status")
        self.assertIn("runtime_class", status_tool["description"])
        status_schema = status_tool["inputSchema"]["properties"]
        self.assertEqual(status_schema["runtime_class"]["enum"], ["customer", "dev"])
        self.assertEqual(status_schema["family"]["enum"], ["hermes", "openclaw"])
        handoff_tool = next(item for item in tools["result"]["tools"] if item["name"] == "handoff_status")
        self.assertIn("gateway tokens", handoff_tool["description"])
        handoff_schema = handoff_tool["inputSchema"]["properties"]
        self.assertEqual(handoff_schema["runtime_class"]["enum"], ["customer", "dev"])
        heartbeat_tool = next(item for item in tools["result"]["tools"] if item["name"] == "heartbeat_status")
        heartbeat_schema = heartbeat_tool["inputSchema"]["properties"]
        self.assertEqual(heartbeat_schema["family"]["enum"], ["openclaw"])
        secret_tool = next(item for item in tools["result"]["tools"] if item["name"] == "runtime_secret_set_from_file")
        key_schema = secret_tool["inputSchema"]["properties"]["key"]
        self.assertIn("API_SERVER_KEY", key_schema["enum"])
        self.assertIn("GEMINI_API_KEY", key_schema["enum"])
        self.assertNotIn("API_KEY", key_schema["enum"])
        image_plan_tool = next(item for item in tools["result"]["tools"] if item["name"] == "rollout_image_plan")
        self.assertIn("wrapper_image", image_plan_tool["inputSchema"]["properties"])
        document_tools_tool = next(item for item in tools["result"]["tools"] if item["name"] == "document_tools_status")
        self.assertIn("HWP/HWPX", document_tools_tool["description"])

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

    def test_canonical_recipe_validate_uses_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "canonical_recipe_status=ok\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "canonical_recipe_validate", {"name": "hermes-workspace"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["opsctl", "recipe", "validate-canonical", "hermes-workspace"],
        )

    def test_runtime_truth_uses_sudo_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "truth_status=ok\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "runtime_truth", {"target": "oc3"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "runtime", "truth", "oc3"])

    def test_document_tools_status_uses_sudo_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "document_tools_status=ok count=1 failed=0\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "document_tools_status", {"target": "OC15.JI-TECH.CO.KR."})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "document-tools", "status", "oc15.ji-tech.co.kr"])

    def test_document_tools_status_all_uses_sudo_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "document_tools_status=ok count=22 failed=0\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "document_tools_status", {"all": True})
        self.assertTrue(payload["ok"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "document-tools", "status", "--all"])

    def test_rollout_image_plan_uses_digest_images_without_release_name(self) -> None:
        wrapper = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "a" * 64
        product = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "b" * 64
        runner = FakeRunner([(0, '{"rollout_image_plan_status":"ok"}\n', "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "rollout_image_plan",
            {"wrapper_image": wrapper, "product_image": product, "target": "oc3"},
        )
        self.assertTrue(payload["ok"])
        self.assertEqual(
            runner.calls[0]["argv"],
            [
                "sudo",
                "opsctl",
                "rollout",
                "image-plan",
                "--wrapper-image",
                wrapper,
                "--product-image",
                product,
                "--target",
                "oc3",
            ],
        )

    def test_ops_orientation_includes_binding_list(self) -> None:
        runner = FakeRunner(
            [
                (0, "update_status=current\n", ""),
                (0, "linux_account=dev-oc runtime_class=dev family=openclaw\n", ""),
                (0, "openclaw-dev sha256:abc\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "ops_orientation")
        self.assertTrue(payload["ok"])
        self.assertIn("linux_account=dev-oc", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "update", "status"])
        self.assertEqual(runner.calls[1]["argv"], ["opsctl", "binding", "list"])
        self.assertEqual(runner.calls[2]["argv"], ["opsctl", "profile", "list"])

    def test_binding_list_uses_argv_list(self) -> None:
        runner = FakeRunner([(0, "linux_account=dev-oc runtime_class=dev family=openclaw\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "binding_list")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "list"])

    def test_binding_set_public_host_uses_sudo_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "binding_set_public_host_status=ok\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "binding_set_public_host", {"target": "oc3", "host": "Demo.JI-TECH.CO.KR."})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["sudo", "opsctl", "binding", "set-public-host", "oc3", "demo.ji-tech.co.kr"],
        )

    def test_apache_set_host_uses_sudo_opsctl_argv(self) -> None:
        runner = FakeRunner([(0, "apache_set_host_status=ok\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "apache_set_host", {"linux_account": "oc3", "host": "Demo.JI-TECH.CO.KR."})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "apache", "set-host", "oc3", "demo.ji-tech.co.kr"])

    def test_target_check_uses_argv_lists(self) -> None:
        runner = FakeRunner(
            [
                (0, "binding_status=ok\n", ""),
                (0, "apache_status=ok\n", ""),
                (0, "truth_status=ok\n", ""),
                (0, "PASS live\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "target_check", {"target": "oc1"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "status", "oc1"])
        self.assertEqual(runner.calls[1]["argv"], ["opsctl", "apache", "status", "oc1"])
        self.assertEqual(runner.calls[2]["argv"], ["sudo", "opsctl", "runtime", "truth", "oc1"])
        self.assertEqual(runner.calls[3]["argv"], ["sudo", "opsctl", "check", "--live", "oc1"])
        self.assertTrue(all(isinstance(call["argv"], list) for call in runner.calls))

    def test_target_check_failure_is_structured_result_not_mcp_error(self) -> None:
        runner = FakeRunner(
            [
                (0, "binding_status=ok\n", ""),
                (0, "apache_status=ok\n", ""),
                (0, "truth_status=ok\n", ""),
                (1, "FAIL live_container_nas_root_propagation\ncheck_status=fail failed=1\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        result = call_tool_result(server, "target_check", {"target": "oc1"})
        payload = result["structuredContent"]
        self.assertFalse(payload["ok"])
        self.assertFalse(result["isError"])
        self.assertEqual(payload["returncode"], 1)
        self.assertIn("check_status=fail", payload["stdout"])

    def test_target_check_accepts_runtime_class_selector(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "\n".join(
                        [
                            "linux_account=dev-hermess runtime_class=dev family=hermes",
                            "linux_account=dev-oc runtime_class=dev family=openclaw",
                            "linux_account=oc1 runtime_class=customer family=openclaw",
                        ]
                    )
                    + "\n",
                    "",
                ),
                (0, "binding_status=ok linux_account=dev-hermess\n", ""),
                (0, "apache_status=ok target=dev-hermess\n", ""),
                (0, "target=dev-hermess truth_status=ok\n", ""),
                (0, "PASS dev-hermess\n", ""),
                (0, "binding_status=ok linux_account=dev-oc\n", ""),
                (0, "apache_status=ok target=dev-oc\n", ""),
                (0, "target=dev-oc truth_status=ok\n", ""),
                (1, "FAIL dev-oc\ncheck_status=fail failed=1\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        result = call_tool_result(server, "target_check", {"runtime_class": "dev"})
        payload = result["structuredContent"]
        self.assertFalse(payload["ok"])
        self.assertFalse(result["isError"])
        self.assertIn("PASS dev-hermess", payload["stdout"])
        self.assertIn("check_status=fail", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "list"])
        self.assertEqual(runner.calls[1]["argv"], ["opsctl", "binding", "status", "dev-hermess"])
        self.assertEqual(runner.calls[5]["argv"], ["opsctl", "binding", "status", "dev-oc"])

    def test_secret_raw_argument_is_rejected_and_redacted(self) -> None:
        secret = "AIza" + "A" * 32
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        result = call_tool_result(
            server,
            "runtime_secret_set_from_file",
            {"target": "dev-oc", "key": "GEMINI_API_KEY", "value": secret},
        )
        payload = result["structuredContent"]
        self.assertFalse(payload["ok"])
        self.assertTrue(result["isError"])
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
                {"target": "dev-oc", "key": "GEMINI_API_KEY", "secret_file": str(path)},
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

    def test_runtime_secret_status_accepts_multiple_targets(self) -> None:
        runner = FakeRunner(
            [
                (0, "target=dev-oc\ngemini_api_key=present\nruntime_secret_status=ok\n", ""),
                (0, "target=dev-hermess\ngemini_api_key=present\nruntime_secret_status=ok\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "runtime_secret_status", {"targets": ["dev-oc", "dev-hermess"]})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertIn("gemini_api_key=present", payload["stdout"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["sudo", "opsctl", "runtime-secret", "status", "dev-oc"],
        )
        self.assertEqual(
            runner.calls[1]["argv"],
            ["sudo", "opsctl", "runtime-secret", "status", "dev-hermess"],
        )

    def test_runtime_secret_status_accepts_runtime_class_selector(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "\n".join(
                        [
                            "linux_account=dev-hermess family=hermes runtime_class=dev",
                            "linux_account=dev-oc family=openclaw runtime_class=dev",
                            "linux_account=oc1 family=openclaw runtime_class=customer",
                        ]
                    )
                    + "\n",
                    "",
                ),
                (0, "target=dev-hermess\ngemini_api_key=present\nruntime_secret_status=ok\n", ""),
                (0, "target=dev-oc\ngemini_api_key=present\nruntime_secret_status=ok\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "runtime_secret_status", {"runtime_class": "dev"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertIn("target=dev-hermess", payload["stdout"])
        self.assertIn("target=dev-oc", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "list"])
        self.assertEqual(
            runner.calls[1]["argv"],
            ["sudo", "opsctl", "runtime-secret", "status", "dev-hermess"],
        )
        self.assertEqual(
            runner.calls[2]["argv"],
            ["sudo", "opsctl", "runtime-secret", "status", "dev-oc"],
        )

    def test_runtime_secret_status_runtime_class_can_filter_family(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "\n".join(
                        [
                            "linux_account=dev-hermess runtime_class=dev family=hermes",
                            "linux_account=dev-oc runtime_class=dev family=openclaw",
                        ]
                    )
                    + "\n",
                    "",
                ),
                (0, "target=dev-oc\ngemini_api_key=present\nruntime_secret_status=ok\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "runtime_secret_status", {"runtime_class": "dev", "family": "openclaw"})
        self.assertTrue(payload["ok"])
        self.assertIn("target=dev-oc", payload["stdout"])
        self.assertEqual(runner.calls[-1]["argv"], ["sudo", "opsctl", "runtime-secret", "status", "dev-oc"])

    def test_runtime_secret_status_requires_one_target_shape(self) -> None:
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "runtime_secret_status", {"target": "dev-oc", "targets": ["dev-hermess"]})
        self.assertFalse(payload["ok"])
        self.assertIn("provide exactly one of target, targets, or runtime_class", payload["next_action"])

    def test_handoff_status_accepts_runtime_class_selector(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "\n".join(
                        [
                            "linux_account=dev-hermess family=hermes runtime_class=dev",
                            "linux_account=dev-oc family=openclaw runtime_class=dev",
                        ]
                    )
                    + "\n",
                    "",
                ),
                (0, "target=dev-hermess\nhandoff_password=present\nhandoff_value_printed=no\nhandoff_status=ok\n", ""),
                (0, "target=dev-oc\nhandoff_token=present\nhandoff_value_printed=no\nhandoff_status=ok\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "handoff_status", {"runtime_class": "dev"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertIn("handoff_token=present", payload["stdout"])
        self.assertIn("handoff_password=present", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "list"])
        self.assertEqual(runner.calls[1]["argv"], ["sudo", "opsctl", "handoff", "status", "dev-hermess"])
        self.assertEqual(runner.calls[2]["argv"], ["sudo", "opsctl", "handoff", "status", "dev-oc"])

    def test_handoff_value_command_returns_repo_native_command_without_secret(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "target=dev-oc\nhandoff_value_printed=no\n"
                    "handoff_value_command=sudo /usr/local/bin/opsctl handoff print dev-oc\n"
                    "handoff_value_command_status=ok\n",
                    "",
                )
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "handoff_value_command", {"target": "dev-oc"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertIn("handoff_value_printed=no", payload["stdout"])
        self.assertIn("handoff_value_command=sudo /usr/local/bin/opsctl handoff print dev-oc", payload["stdout"])
        self.assertNotIn("svcops-control.sh", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "handoff", "value-command", "dev-oc"])

    def test_heartbeat_status_accepts_runtime_class_selector(self) -> None:
        runner = FakeRunner(
            [
                (
                    0,
                    "\n".join(
                        [
                            "linux_account=dev-hermess family=hermes runtime_class=dev",
                            "linux_account=dev-oc family=openclaw runtime_class=dev",
                        ]
                    )
                    + "\n",
                    "",
                ),
                (0, "target=dev-oc\nheartbeat_config_enabled=no\nheartbeat_status=ok\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "heartbeat_status", {"runtime_class": "dev", "family": "openclaw"})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertIn("heartbeat_status=ok", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "binding", "list"])
        self.assertEqual(runner.calls[1]["argv"], ["sudo", "opsctl", "heartbeat", "status", "dev-oc"])

    def test_heartbeat_disable_runs_status_then_disable(self) -> None:
        runner = FakeRunner(
            [
                (0, "target=dev-oc\nheartbeat_config_enabled=yes\nheartbeat_status=ok\n", ""),
                (
                    0,
                    "target=dev-oc\nheartbeat_config_disabled=yes\nheartbeat_config_enabled=no\n"
                    "heartbeat_disable_status=ok\n",
                    "",
                ),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "heartbeat_disable", {"target": "dev-oc"})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertIn("heartbeat_disable_status=ok", payload["stdout"])
        self.assertEqual(runner.calls[0]["argv"], ["sudo", "opsctl", "heartbeat", "status", "dev-oc"])
        self.assertEqual(runner.calls[1]["argv"], ["sudo", "opsctl", "heartbeat", "disable", "dev-oc"])

    def test_deploy_update_without_approval_returns_exact_root_command(self) -> None:
        target = "a" * 40
        runner = FakeRunner([(1, "update_status=not_ready\ninstalled_ref=" + "b" * 40 + "\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(server, "deploy_update", {"target_ref": target})
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(payload["next_action"], f"sudo opsctl update approve {target}")

    def test_legacy_release_state_tools_are_not_public_mcp_tools(self) -> None:
        server = McpServer(runner=FakeRunner(), opsctl="opsctl", sudo="sudo")
        for name in (
            "release_import",
            "rollout_status",
            "rollout_plan",
            "rollout_dev_plan",
            "rollout_dev_apply",
            "rollout_canary",
            "rollout_promote",
            "rollout_rollback_canary",
            "slot_apply",
        ):
            response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": {}},
                }
            )
            self.assertEqual(response["error"]["code"], -32602)
            self.assertIn("unknown tool", response["error"]["message"])

    def test_dev_recipe_apply_runs_status_then_apply_dev(self) -> None:
        runner = FakeRunner(
            [
                (0, "target=dev-oc\nrecipe_status=missing\n", ""),
                (0, "recipe_apply_dev_status=prepared\napply=skipped\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "dev_recipe_apply",
            {
                "target": "dev-oc",
                "recipe_name": "openclaw-ui",
                "sync_from": "/home/openclawdev/openclaw/dist/control-ui",
                "build_command": "npm run build",
                "no_apply": True,
            },
        )
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(runner.calls[0]["argv"], ["opsctl", "recipe", "status", "dev-oc"])
        self.assertEqual(
            runner.calls[1]["argv"],
            [
                "sudo",
                "opsctl",
                "recipe",
                "apply-dev",
                "dev-oc",
                "--recipe-name",
                "openclaw-ui",
                "--sync-from",
                "/home/openclawdev/openclaw/dist/control-ui",
                "--build-command",
                "npm run build",
                "--no-apply",
            ],
        )

    def test_nas_credential_status_uses_sudo_and_is_non_mutating(self) -> None:
        runner = FakeRunner([(0, "official_credential_present=yes\nsecret_value_printed=no\n", "")])
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "nas_credential_status",
            {"target": "oc3", "share": "//192.168.0.222/hanpass"},
        )
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["mutated"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["sudo", "opsctl", "nas", "credential", "status", "oc3", "//192.168.0.222/hanpass"],
        )

    def test_nas_mount_accepts_public_host_target(self) -> None:
        runner = FakeRunner(
            [
                (0, "policy_check_status=pass\n", ""),
                (0, "target=oc3\nmount_status=ok\n", ""),
                (0, "target=oc3\nmounted_child_cifs_count=1\n", ""),
            ]
        )
        server = McpServer(runner=runner, opsctl="opsctl", sudo="sudo")
        payload = call_tool(
            server,
            "nas_mount",
            {"target": "oc3.ji-tech.co.kr", "share": "//192.168.0.222/hanpass"},
        )
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["mutated"])
        self.assertEqual(
            runner.calls[0]["argv"],
            ["opsctl", "nas", "policy-check", "oc3.ji-tech.co.kr", "//192.168.0.222/hanpass"],
        )
        self.assertEqual(
            runner.calls[1]["argv"],
            ["sudo", "opsctl", "nas", "mount", "oc3.ji-tech.co.kr", "//192.168.0.222/hanpass"],
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
            {"target": "oc3", "share": "//192.168.0.222/hanpass", "delete_empty_dir": True},
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
