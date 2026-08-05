from __future__ import annotations

from agent_runtime_ops.mcp.runner import CommandResult
from agent_runtime_ops.mcp_server import McpServer


class FakeRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: int = 60,
    ) -> CommandResult:
        self.calls.append(argv)
        return CommandResult(
            argv=argv,
            returncode=self.returncode,
            stdout='{"schema":"agent-runtime-svcops-readonly-observation/v1"}\n',
            stderr="",
        )


def call(
    server: McpServer, name: str, arguments: dict[str, object]
) -> dict[str, object]:
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]["structuredContent"]


def test_runtime_observation_is_read_only_and_accepts_degraded_receipt() -> None:
    runner = FakeRunner(returncode=1)
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    result = call(server, "runtime_observation", {"target": "oc20"})
    assert result["ok"] is True
    assert result["mutated"] is False
    assert runner.calls == [["/sudo", "/opsctl", "observation", "status", "oc20"]]


def test_dev_logs_reject_customer_target_before_runner() -> None:
    runner = FakeRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    result = call(server, "dev_runtime_logs", {"target": "oc20"})
    assert result["ok"] is False
    assert result["mutated"] is False
    assert "dev-*" in result["reason"]
    assert runner.calls == []


def test_dev_logs_use_fixed_typed_argv() -> None:
    runner = FakeRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    result = call(
        server,
        "dev_runtime_logs",
        {"target": "dev-hermes-img", "tail": 40, "since": "15m"},
    )
    assert result["ok"] is True
    assert result["mutated"] is False
    assert runner.calls == [
        [
            "/sudo",
            "/opsctl",
            "diagnostics",
            "logs",
            "dev-hermes-img",
            "--tail",
            "40",
            "--since",
            "15m",
        ]
    ]


def test_dev_session_health_uses_fixed_typed_argv() -> None:
    runner = FakeRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    result = call(
        server,
        "dev_session_health",
        {"target": "dev-oc-img", "since": "2h"},
    )
    assert result["ok"] is True
    assert result["mutated"] is False
    assert runner.calls == [
        [
            "/sudo",
            "/opsctl",
            "diagnostics",
            "session-health",
            "dev-oc-img",
            "--since",
            "2h",
        ]
    ]


def test_dev_session_health_rejects_customer_target_before_runner() -> None:
    runner = FakeRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    result = call(server, "dev_session_health", {"target": "oc20"})
    assert result["ok"] is False
    assert result["mutated"] is False
    assert "dev-*" in result["reason"]
    assert runner.calls == []
