from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import sys
from typing import Any, TextIO

from .mcp.registry import get_handler
from .mcp.runner import CommandRunner
from .mcp.specs import list_tool_specs
from .redaction import redact


PROTOCOL_VERSION = "2025-06-18"
LINUX_ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TARGET_RE = re.compile(
    r"^(?:[a-z][a-z0-9-]{0,31}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$"
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SENSITIVE_ARGUMENTS = {
    "api_key",
    "apikey",
    "key_value",
    "password",
    "passwd",
    "raw_secret",
    "secret",
    "secret_value",
    "token",
    "value",
}


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


def _parse_key_value_tokens(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for token in shlex.split(text):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _default_secret_roots() -> list[Path]:
    raw = os.environ.get(
        "AGENT_RUNTIME_OPS_SECRET_ROOTS",
        "/home/svcops/.codex-secrets:/home/svcops/.secrets:/srv/openclaw-ops/secrets",
    )
    return [Path(item).expanduser() for item in raw.split(os.pathsep) if item]


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

    def _reject_unknown(self, args: dict[str, Any], allowed: set[str]) -> None:
        unknown = sorted(set(args) - allowed)
        if unknown:
            lowered = {item.lower().replace("-", "_") for item in unknown}
            if lowered & SENSITIVE_ARGUMENTS:
                raise ToolError("raw secret argument rejected; pass an allowed secret_file path or a manual stdin flow")
            raise ToolError("unsupported argument(s): " + ",".join(unknown))

    def _reject_sensitive_raw_args(self, args: dict[str, Any], *, allowed: set[str] | None = None) -> None:
        allowed = allowed or set()
        for key in args:
            normalized = key.lower().replace("-", "_")
            if key not in allowed and normalized in SENSITIVE_ARGUMENTS:
                raise ToolError("raw secret argument rejected; pass an allowed secret_file path or a manual stdin flow")

    def _slot(self, value: Any) -> str:
        return self._linux_account(value)

    def _linux_account(self, value: Any) -> str:
        account = str(value or "").strip()
        if not LINUX_ACCOUNT_RE.match(account):
            raise ToolError("linux_account must be a safe Unix account name")
        return account

    def _target(self, value: Any) -> str:
        target = str(value or "").strip().lower().rstrip(".")
        if not TARGET_RE.match(target):
            raise ToolError("target must be a linux account, public host, or instance UUID")
        return target

    def _family(self, value: Any) -> str:
        family = str(value or "")
        if family not in {"hermes", "openclaw"}:
            raise ToolError("family must be hermes or openclaw")
        return family

    def _safe_name(self, value: Any) -> str:
        name = str(value or "")
        if not SAFE_NAME_RE.match(name):
            raise ToolError("name must contain only letters, numbers, '.', '_', or '-'")
        return name

    def _image_ref(self, value: Any) -> str:
        image_ref = str(value or "")
        if not IMAGE_REF_RE.match(image_ref):
            raise ToolError("image reference must be digest-pinned as REGISTRY/IMAGE@sha256:<64 hex>")
        return image_ref

    def _host(self, value: Any) -> str:
        host = str(value or "").strip().lower().rstrip(".")
        if not HOST_RE.match(host):
            raise ToolError("host must be a DNS name without scheme, port, path, or whitespace")
        return host

    def _safe_text(self, value: Any, name: str) -> str:
        text = str(value or "").strip()
        if text and not SAFE_TEXT_RE.match(text):
            raise ToolError(f"{name} must not contain control characters")
        return text

    def _path_text(self, value: Any, name: str) -> str:
        text = self._safe_text(value, name)
        if not text.startswith("/"):
            raise ToolError(f"{name} must be an absolute path")
        return text

    def _slots(self, args: dict[str, Any]) -> list[str]:
        has_slot = args.get("target") is not None
        has_slots = args.get("targets") is not None
        has_runtime_class = args.get("runtime_class") is not None
        if sum([has_slot, has_slots, has_runtime_class]) != 1:
            raise ToolError("provide exactly one of target, targets, or runtime_class")
        if has_slot:
            return [self._slot(args.get("target"))]
        if has_runtime_class:
            raise ToolError("runtime_class requires current target resolution")
        raw_slots = args.get("targets")
        if not isinstance(raw_slots, list) or not raw_slots:
            raise ToolError("targets must be a non-empty array")
        return [self._slot(item) for item in raw_slots]

    def _resolve_slots(self, args: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
        if args.get("runtime_class") is None:
            return self._slots(args), []
        runtime_class = str(args.get("runtime_class") or "")
        if runtime_class not in {"customer", "dev"}:
            raise ToolError("runtime_class must be customer or dev")
        family = args.get("family")
        if family is not None:
            family = str(family)
            if family not in {"hermes", "openclaw"}:
                raise ToolError("family must be hermes or openclaw")
        binding_list = self._run([self.opsctl, "binding", "list"], timeout=60)
        if binding_list["returncode"] != 0:
            return [], [binding_list]
        runs = [binding_list]
        slots: list[str] = []
        for raw_line in binding_list["stdout"].splitlines():
            row = _parse_key_value_tokens(raw_line)
            if (row.get("runtime_class") or row.get("runtime_class")) != runtime_class:
                continue
            slot = row.get("linux_account") or row.get("target")
            if family and row.get("family") != family:
                continue
            if slot:
                slots.append(self._linux_account(slot))
        if not slots:
            raise ToolError("no targets matched runtime_class/family")
        return slots, runs

    def _share(self, value: Any) -> str:
        share = str(value or "")
        if not share.startswith("//") or any(ch in share for ch in "\r\n\t"):
            raise ToolError("share must be an SMB path like //HOST/SHARE")
        return share

    def _read_allowed_secret_file(self, value: Any) -> str:
        if not value:
            raise ToolError("secret_file is required")
        path = Path(str(value)).expanduser()
        try:
            if path.is_symlink():
                raise ToolError("secret_file must not be a symlink")
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ToolError(f"secret_file is not readable: {exc}") from exc
        allowed_roots = [root.expanduser().resolve(strict=False) for root in self.secret_roots]
        if not any(resolved == root or root in resolved.parents for root in allowed_roots):
            raise ToolError("secret_file must be under an allowed secret root")
        if not resolved.is_file():
            raise ToolError("secret_file must be a regular file")
        value_text = resolved.read_text(encoding="utf-8", errors="replace").strip()
        if not value_text:
            raise ToolError("secret_file is empty")
        return value_text


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
