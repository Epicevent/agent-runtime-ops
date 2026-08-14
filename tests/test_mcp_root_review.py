from __future__ import annotations

import hashlib
import os
from pathlib import Path

from agent_runtime_ops.mcp.runner import CommandResult
from agent_runtime_ops.mcp_server import McpServer
from agent_runtime_ops.root_review import RootReviewStore


class NoRunRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: int = 60,
    ) -> CommandResult:
        self.calls.append(argv)
        raise AssertionError("root-review tools must not execute a subprocess")


def call(
    server: McpServer, name: str, arguments: dict[str, object]
) -> tuple[dict[str, object], bool]:
    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]["structuredContent"], response["result"]["isError"]


def make_store(tmp_path: Path) -> tuple[RootReviewStore, Path, Path]:
    assignments = tmp_path / "assignments"
    requests = tmp_path / "requests"
    output = tmp_path / "output"
    for directory in (assignments, requests, output):
        directory.mkdir()
    request = requests / "agent-one.txt"
    transcript = output / "agent-one.log"
    request.write_text("STATUS=NO_PENDING_ROOT_COMMAND\n", encoding="utf-8")
    transcript.write_text("existing\n", encoding="utf-8")
    (assignments / "agent-one.env").write_text(
        "\n".join(
            (
                "assignment_schema=root-review-assignment/v3",
                "agent_tmux_session=agent-one",
                "agent_pane=%42",
                "agent_pane_pid=4242",
                "agent_codex_executable=/usr/local/bin/codex",
                "root_session=agent-one-root",
                "root_session_id=$1",
                "root_pane=%43",
                "viewer_pane=%44",
                f"transcript={transcript}",
                f"request={request}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    uid = os.getuid() if hasattr(os, "getuid") else 0
    gid = os.getgid() if hasattr(os, "getgid") else 0
    return (
        RootReviewStore(
            assignment_dir=assignments,
            request_dir=requests,
            transcript_dir=output,
            pane_id="%42",
            agent_uid=uid,
            agent_gid=gid,
            root_uid=uid,
            enforce_posix_metadata=False,
        ),
        request,
        transcript,
    )


def test_mcp_publish_is_visible_wait_resolve_are_content_free_and_do_not_run(
    tmp_path: Path,
) -> None:
    store, request, transcript = make_store(tmp_path)
    runner = NoRunRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    server.root_review_store_factory = lambda: store
    command = "/usr/bin/id -u"

    published, is_error = call(
        server,
        "root_review_publish",
        {"purpose": "Read identity", "command": command},
    )
    assert is_error is False
    assert published["ok"] is True
    assert published["mutated"] is True
    assert published["root_review"]["command"] == command
    assert published["root_review"]["command_sha256"] == (
        "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()
    )
    assert published["root_review"]["command_bytes"] == len(command.encode("utf-8"))
    handle = published["root_review"]["handle"]

    pending, is_error = call(
        server,
        "root_review_wait",
        {"handle": handle, "wait_timeout_seconds": 0.001},
    )
    assert is_error is False
    assert pending["mutated"] is False
    assert pending["root_review"]["state"] == "pending"

    with transcript.open("ab") as stream:
        stream.write(b"complete\n")
    observed, is_error = call(server, "root_review_wait", {"handle": handle})
    assert is_error is False
    assert observed["root_review"]["state"] == "transcript_appended"
    assert "complete" not in str(observed)
    assert command not in str(observed)

    resolved, is_error = call(server, "root_review_resolve", {"handle": handle})
    assert is_error is False
    assert resolved["root_review"]["state"] == "no_pending"
    assert command not in str(resolved)
    assert request.read_text(encoding="utf-8").startswith(
        "STATUS=NO_PENDING_ROOT_COMMAND\n"
    )
    assert runner.calls == []


def test_mcp_rejects_unknown_fields_and_stale_handle(tmp_path: Path) -> None:
    store, request, _transcript = make_store(tmp_path)
    runner = NoRunRunner()
    server = McpServer(runner=runner, opsctl="/opsctl", sudo="/sudo")
    server.root_review_store_factory = lambda: store

    rejected, is_error = call(
        server,
        "root_review_publish",
        {"purpose": "Read", "command": "/usr/bin/true", "path": "/tmp/card"},
    )
    assert is_error is True
    assert rejected["ok"] is False
    assert rejected["reason"] == "unsupported argument(s): path"

    published, is_error = call(
        server,
        "root_review_publish",
        {"purpose": "Read", "command": "/usr/bin/true"},
    )
    assert is_error is False
    handle = published["root_review"]["handle"]
    request.write_text("STATUS=NO_PENDING_ROOT_COMMAND\n", encoding="utf-8")
    stale, is_error = call(server, "root_review_wait", {"handle": handle})
    assert is_error is True
    assert stale["reason"] == "root_review_handle_stale_or_mismatched"
    assert runner.calls == []


def test_mcp_publish_returns_exact_multiline_command(tmp_path: Path) -> None:
    store, request, _transcript = make_store(tmp_path)
    server = McpServer(runner=NoRunRunner(), opsctl="/opsctl", sudo="/sudo")
    server.root_review_store_factory = lambda: store
    command = "set -eu\nprintf '%s\\n' visible\n/usr/bin/id -u"

    published, is_error = call(
        server,
        "root_review_publish",
        {"purpose": "Show every operation", "command": command},
    )

    assert is_error is False
    assert published["root_review"]["command"] == command
    assert f"COMMAND_BEGIN\n{command}\nCOMMAND_END\n" in request.read_text(
        encoding="utf-8"
    )


def test_mcp_tool_specs_do_not_accept_paths_or_status_fields() -> None:
    server = McpServer(runner=NoRunRunner(), opsctl="/opsctl", sudo="/sudo")
    response = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    tools = {item["name"]: item for item in response["result"]["tools"]}
    assert set(tools) >= {
        "root_review_publish",
        "root_review_wait",
        "root_review_resolve",
    }
    for name in ("root_review_publish", "root_review_wait", "root_review_resolve"):
        properties = tools[name]["inputSchema"]["properties"]
        assert not ({"path", "status", "request_sha256"} & set(properties))
