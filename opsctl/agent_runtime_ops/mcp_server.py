from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any, TextIO

from .mcp.registry import get_handler
from .mcp.runner import CommandRunner
from .mcp.specs import list_tool_specs
from .mcp import validation
from .redaction import redact


PROTOCOL_VERSION = "2025-06-18"


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ToolError(Exception):
    pass


def _json_error(message_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message_id, "error": error}


def _json_result(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _default_secret_roots() -> list[Path]:
    return validation.default_secret_roots()


class McpServer:
    tool_error = ToolError

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        opsctl: str | None = None,
        sudo: str | None = None,
        secret_roots: list[Path] | None = None,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.opsctl = opsctl or os.environ.get("AGENT_RUNTIME_OPS_OPSCTL") or "/usr/local/bin/opsctl"
        self.sudo = sudo or os.environ.get("AGENT_RUNTIME_OPS_SUDO") or "sudo"
        self.secret_roots = secret_roots or _default_secret_roots()

    def handle_line(self, line: str) -> dict[str, Any] | None:
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            return _json_error(None, -32700, "parse error", {"reason": str(exc)})
        return self.handle_message(message)

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(message, dict):
            return _json_error(None, -32600, "invalid request")
        message_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return _json_error(message_id, -32600, "missing method")
        try:
            if method == "initialize":
                return _json_result(message_id, self._initialize(message.get("params") or {}))
            if method == "notifications/initialized":
                return None
            if method == "tools/list":
                return _json_result(message_id, {"tools": self._tool_specs()})
            if method == "tools/call":
                return _json_result(message_id, self._tools_call(message.get("params") or {}))
            if method == "ping":
                return _json_result(message_id, {})
            raise ProtocolError(-32601, f"method not found: {method}")
        except ProtocolError as exc:
            return _json_error(message_id, exc.code, exc.message, exc.data)

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or PROTOCOL_VERSION)
        protocol = requested if requested in {PROTOCOL_VERSION, "2025-03-26"} else PROTOCOL_VERSION
        return {
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "agent-runtime-ops",
                "title": "Agent Runtime Ops",
                "version": "0.1.0",
            },
            "instructions": (
                "Use these tools to inspect and operate the svcops runtime through opsctl. "
                "Separate intended runtime binding, actual Apache route state, live image truth, canonical recipe, runtime profile, and applied manifest before changing a target. "
                "Call one MCP tool at a time and wait for its response before calling another tool. "
                "Use selector arguments such as runtime_class for group queries instead of parallel per-target calls. "
                "Do not pass raw secret values as tool arguments."
            ),
        }

    def _tool_specs(self) -> list[dict[str, Any]]:
        return list_tool_specs()

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise ProtocolError(-32602, "tools/call params must be an object")
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str):
            raise ProtocolError(-32602, "tools/call requires a tool name")
        if not isinstance(args, dict):
            raise ProtocolError(-32602, "tool arguments must be an object")
        handler = get_handler(name)
        if handler is None:
            raise ProtocolError(-32602, f"unknown tool: {name}")
        is_error = False
        try:
            payload = handler(self, args)
        except ToolError as exc:
            is_error = True
            payload = self._common_response(
                ok=False,
                mutated=False,
                runs=[],
                next_action=str(exc),
                extra={"reason": str(exc)},
            )
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": is_error,
        }

    def _run(self, argv: list[str], *, input_text: str | None = None, timeout: int = 60) -> dict[str, Any]:
        result = self.runner.run(argv, input_text=input_text, timeout=timeout)
        return {
            "command": {
                "argv": result.argv,
                "display": shlex.join(result.argv),
                "stdin": "provided" if input_text is not None else "none",
            },
            "returncode": result.returncode,
            "stdout": redact(result.stdout or ""),
            "stderr": redact(result.stderr or ""),
        }

    def _common_response(
        self,
        *,
        ok: bool,
        mutated: bool,
        runs: list[dict[str, Any]],
        next_action: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stdout = "\n".join(item["stdout"].rstrip() for item in runs if item["stdout"]).strip()
        stderr = "\n".join(item["stderr"].rstrip() for item in runs if item["stderr"]).strip()
        payload: dict[str, Any] = {
            "ok": ok,
            "mutated": mutated,
            "commands": [item["command"]["display"] for item in runs],
            "returncode": runs[-1]["returncode"] if runs else 0,
            "stdout": stdout,
            "stderr": stderr,
            "results": runs,
        }
        if next_action:
            payload["next_action"] = next_action
        if extra:
            payload.update(extra)
        return payload

def serve(input_stream: TextIO = sys.stdin, output_stream: TextIO = sys.stdout) -> None:
    server = McpServer()
    for line in input_stream:
        response = server.handle_line(line)
        if response is None:
            continue
        output_stream.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
        output_stream.flush()


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
