from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any, TextIO

from .paths import REPO_ROOT
from .redaction import redact
from .runtime_secrets import PROVIDER_SECRET_KEYS


PROTOCOL_VERSION = "2025-06-18"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
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


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    def run(self, argv: list[str], *, input_text: str | None = None, timeout: int = 60) -> CommandResult:
        proc = subprocess.run(
            argv,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(argv=argv, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


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


def _parse_key_values(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


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
        return [
            {
                "name": "ops_orientation",
                "title": "Orient Agent Runtime Ops",
                "description": "Check installed update status, runtime bindings, repository root, and runtime profiles.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "binding_list",
                "title": "List Runtime Bindings",
                "description": "List intended runtime bindings: instance id, linux account, public host, family, runtime class, and ports.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "binding_status",
                "title": "Runtime Binding Status",
                "description": "Compare intended binding truth with actual Apache route state for one target or all targets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "binding_set_public_host",
                "title": "Set Binding Public Host",
                "description": "Change intended public host and Apache ServerName together for one runtime binding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}, "host": {"type": "string"}},
                    "required": ["target", "host"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "apache_status",
                "title": "Apache Route Status",
                "description": "Inspect actual Apache route state and compare it to binding truth.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "apache_set_host",
                "title": "Set Apache Public Host",
                "description": "Low-level Apache-only repair command. Prefer binding_set_public_host for normal changes.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"linux_account": {"type": "string"}, "host": {"type": "string"}},
                    "required": ["linux_account", "host"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "runtime_truth",
                "title": "Runtime Image Truth",
                "description": "Inspect running container image labels directly; this is the authoritative runtime truth path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "all": {"type": "boolean", "default": False},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "target_check",
                "title": "Check Target",
                "description": (
                    "Run binding status, Apache route status, live image truth, and live contract check. "
                    "For dev or customer groups, prefer runtime_class over repeated per-target calls."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                        "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                    },
                    "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                    "additionalProperties": False,
                },
            },
            {
                "name": "deploy_update",
                "title": "Deploy Approved Update",
                "description": "Run self-update when the server has an approved full SHA that is not installed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target_ref": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "rollout_image_plan",
                "title": "Plan Image Rollout",
                "description": "Validate wrapper/product image labels directly against runtime bindings without using release state.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "wrapper_image": {"type": "string"},
                        "product_image": {"type": "string"},
                        "target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["wrapper_image", "product_image"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "rollout_image_dev_apply",
                "title": "Apply Dev Image",
                "description": "Apply a digest-pinned wrapper/product image directly to a dev runtime binding.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "wrapper_image": {"type": "string"},
                        "product_image": {"type": "string"},
                        "allow_first_apply": {"type": "boolean", "default": False},
                    },
                    "required": ["target", "wrapper_image", "product_image"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "rollout_image_canary",
                "title": "Apply Canary Image",
                "description": "Apply a digest-pinned wrapper/product image directly to one customer canary target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "wrapper_image": {"type": "string"},
                        "product_image": {"type": "string"},
                        "allow_first_apply": {"type": "boolean", "default": False},
                    },
                    "required": ["target", "wrapper_image", "product_image"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "rollout_image_promote",
                "title": "Promote Live Image",
                "description": "Read image truth from a canary target and apply that exact image to explicit customer targets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    },
                    "required": ["from_target", "targets"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "canonical_recipe_validate",
                "title": "Validate Canonical Recipe",
                "description": "Validate the repo-owned canonical runtime recipe that generates dev/customer projections and wrapper labels.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "dev_recipe_status",
                "title": "Dev Recipe Status",
                "description": "Inspect the source-mode recipe currently recorded for a dev target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "dev_recipe_apply",
                "title": "Apply Dev Recipe",
                "description": (
                    "Connect a source-mode dev target to external dev output, optionally syncing it into the target stage, "
                    "then apply and live-check the target."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "recipe_name": {"type": "string"},
                        "source_output": {"type": "string"},
                        "sync_from": {"type": "string"},
                        "build_command": {"type": "string"},
                        "allow_first_apply": {"type": "boolean", "default": False},
                        "no_apply": {"type": "boolean", "default": False},
                    },
                    "required": ["target"],
                    "oneOf": [{"required": ["source_output"]}, {"required": ["sync_from"]}],
                    "additionalProperties": False,
                },
            },
            {
                "name": "runtime_secret_status",
                "title": "Runtime Secret Status",
                "description": (
                    "Check whether supported provider secret keys exist without printing values. "
                    "For dev or customer groups, prefer runtime_class over parallel per-target calls."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                        "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                    },
                    "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                    "additionalProperties": False,
                },
            },
            {
                "name": "runtime_secret_set_from_file",
                "title": "Set Runtime Secret From File",
                "description": "Inject one provider secret from an allowed local file through opsctl stdin.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "key": {"type": "string", "enum": sorted(PROVIDER_SECRET_KEYS)},
                        "secret_file": {"type": "string"},
                        "check": {"type": "boolean", "default": True},
                        "no_restart": {"type": "boolean", "default": False},
                    },
                    "required": ["target", "key", "secret_file"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "handoff_status",
                "title": "Handoff Credential Status",
                "description": (
                    "Report handoff credential structure and presence without printing values. "
                    "Use this for gateway tokens or workspace passwords instead of runtime_secret_status."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                        "family": {"type": "string", "enum": ["hermes", "openclaw"]},
                    },
                    "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                    "additionalProperties": False,
                },
            },
            {
                "name": "handoff_value_command",
                "title": "Handoff Value Command",
                "description": (
                    "Return the exact repo-native CLI command an authorized operator can run in their own terminal "
                    "to print a handoff credential value. This MCP tool does not print the value."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "heartbeat_status",
                "title": "OpenClaw Heartbeat Status",
                "description": (
                    "Inspect OpenClaw heartbeat config and optional HEARTBEAT.md metadata without printing file contents. "
                    "For dev or customer groups, prefer runtime_class over parallel per-target calls."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "targets": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "runtime_class": {"type": "string", "enum": ["customer", "dev"]},
                        "family": {"type": "string", "enum": ["openclaw"]},
                    },
                    "oneOf": [{"required": ["target"]}, {"required": ["targets"]}, {"required": ["runtime_class"]}],
                    "additionalProperties": False,
                },
            },
            {
                "name": "heartbeat_disable",
                "title": "Disable OpenClaw Heartbeat",
                "description": "Set OpenClaw heartbeat cadence to 0m for one target and verify the resulting status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "target_rollback",
                "title": "Rollback Target",
                "description": "Rollback one target and run a live check.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_status",
                "title": "NAS Status",
                "description": "List pending NAS requests and optionally mounted child CIFS shares for a target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_mount",
                "title": "Mount NAS Share",
                "description": "Policy-check and mount an already-credentialed NAS share for a target.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}, "share": {"type": "string"}},
                    "required": ["target", "share"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_unmount",
                "title": "Unmount NAS Share",
                "description": "Temporarily unmount a managed NAS child CIFS share while keeping official credentials.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "share": {"type": "string"},
                        "lazy": {"type": "boolean", "default": False},
                        "delete_empty_dir": {"type": "boolean", "default": False},
                    },
                    "required": ["target", "share"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_remove",
                "title": "Remove NAS Share",
                "description": "Unmount a NAS share and remove official credentials plus the managed fstab entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "share": {"type": "string"},
                        "lazy": {"type": "boolean", "default": False},
                        "delete_empty_dir": {"type": "boolean", "default": False},
                    },
                    "required": ["target", "share"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_credential_status",
                "title": "NAS Credential Status",
                "description": "Report official root/customer credential presence for a NAS share without printing secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}, "share": {"type": "string"}},
                    "required": ["target", "share"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_approve_auto_once",
                "title": "Approve NAS Requests Once",
                "description": "Run one non-watch nas approve-auto pass.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise ProtocolError(-32602, "tools/call params must be an object")
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str):
            raise ProtocolError(-32602, "tools/call requires a tool name")
        if not isinstance(args, dict):
            raise ProtocolError(-32602, "tool arguments must be an object")
        handlers = {
            "ops_orientation": self._tool_ops_orientation,
            "binding_list": self._tool_binding_list,
            "binding_status": self._tool_binding_status,
            "binding_set_public_host": self._tool_binding_set_public_host,
            "apache_status": self._tool_apache_status,
            "apache_set_host": self._tool_apache_set_host,
            "runtime_truth": self._tool_runtime_truth,
            "target_check": self._tool_target_check,
            "deploy_update": self._tool_deploy_update,
            "rollout_image_plan": self._tool_rollout_image_plan,
            "rollout_image_dev_apply": self._tool_rollout_image_dev_apply,
            "rollout_image_canary": self._tool_rollout_image_canary,
            "rollout_image_promote": self._tool_rollout_image_promote,
            "canonical_recipe_validate": self._tool_canonical_recipe_validate,
            "dev_recipe_status": self._tool_dev_recipe_status,
            "dev_recipe_apply": self._tool_dev_recipe_apply,
            "runtime_secret_status": self._tool_runtime_secret_status,
            "runtime_secret_set_from_file": self._tool_runtime_secret_set_from_file,
            "handoff_status": self._tool_handoff_status,
            "handoff_value_command": self._tool_handoff_value_command,
            "heartbeat_status": self._tool_heartbeat_status,
            "heartbeat_disable": self._tool_heartbeat_disable,
            "target_rollback": self._tool_target_rollback,
            "nas_status": self._tool_nas_status,
            "nas_mount": self._tool_nas_mount,
            "nas_unmount": self._tool_nas_unmount,
            "nas_remove": self._tool_nas_remove,
            "nas_credential_status": self._tool_nas_credential_status,
            "nas_approve_auto_once": self._tool_nas_approve_auto_once,
        }
        if name not in handlers:
            raise ProtocolError(-32602, f"unknown tool: {name}")
        is_error = False
        try:
            payload = handlers[name](args)
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

    def _tool_ops_orientation(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, set())
        runs = [
            self._run([self.opsctl, "update", "status"]),
            self._run([self.opsctl, "binding", "list"]),
            self._run([self.opsctl, "profile", "list"]),
        ]
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=False, runs=runs, extra={"repo_root": str(REPO_ROOT)})

    def _tool_binding_list(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, set())
        runs = [self._run([self.opsctl, "binding", "list"], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_binding_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        argv = [self.opsctl, "binding", "status"]
        if args.get("target"):
            argv.append(self._target(args.get("target")))
        runs = [self._run(argv, timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_binding_set_public_host(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "host"})
        target = self._target(args.get("target"))
        host = self._host(args.get("host"))
        runs = [self._run([self.sudo, self.opsctl, "binding", "set-public-host", target, host], timeout=120)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

    def _tool_apache_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        argv = [self.opsctl, "apache", "status"]
        if args.get("target"):
            argv.append(self._target(args.get("target")))
        runs = [self._run(argv, timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_apache_set_host(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"linux_account", "host"})
        linux_account = self._linux_account(args.get("linux_account"))
        host = self._host(args.get("host"))
        runs = [self._run([self.sudo, self.opsctl, "apache", "set-host", linux_account, host], timeout=120)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

    def _tool_runtime_truth(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "all"})
        argv = [self.sudo, self.opsctl, "runtime", "truth"]
        if bool(args.get("all", False)):
            if args.get("target") is not None:
                raise ToolError("provide either target or all, not both")
            argv.append("--all")
        else:
            argv.append(self._slot(args.get("target")))
        runs = [self._run(argv, timeout=120)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_target_check(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
        slots, runs = self._resolve_slots(args)
        for slot in slots:
            runs.append(self._run([self.opsctl, "binding", "status", slot]))
            runs.append(self._run([self.opsctl, "apache", "status", slot]))
            runs.append(self._run([self.sudo, self.opsctl, "runtime", "truth", slot], timeout=120))
            runs.append(self._run([self.sudo, self.opsctl, "check", "--live", slot], timeout=120))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=False, runs=runs)

    def _tool_deploy_update(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target_ref"})
        target_ref = args.get("target_ref")
        if target_ref is not None:
            target_ref = str(target_ref)
            if not FULL_SHA_RE.match(target_ref):
                raise ToolError("target_ref must be a full 40-character commit sha")
        status = self._run([self.opsctl, "update", "status"])
        runs = [status]
        data = _parse_key_values(status["stdout"])
        approved_ref = data.get("approved_ref", "")
        installed_ref = data.get("installed_ref", "")
        if status["returncode"] != 0 or not approved_ref:
            ref_for_command = target_ref or "FULL_40_CHARACTER_COMMIT_SHA"
            command = shlex.join([self.sudo, self.opsctl, "update", "approve", ref_for_command])
            return self._common_response(
                ok=False,
                mutated=False,
                runs=runs,
                next_action=command,
                extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
            )
        if target_ref and approved_ref != target_ref:
            command = shlex.join([self.sudo, self.opsctl, "update", "approve", target_ref])
            return self._common_response(
                ok=False,
                mutated=False,
                runs=runs,
                next_action=command,
                extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
            )
        if data.get("approved_matches_installed") == "yes":
            return self._common_response(
                ok=True,
                mutated=False,
                runs=runs,
                extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
            )
        runs.append(self._run([self.sudo, self.opsctl, "self-update"], timeout=300))
        runs.append(self._run([self.opsctl, "update", "status"]))
        runs.append(self._run([self.opsctl, "profile", "list"]))
        post_data = _parse_key_values(runs[-2]["stdout"])
        ok = all(item["returncode"] == 0 for item in runs) and post_data.get("approved_matches_installed") == "yes"
        return self._common_response(
            ok=ok,
            mutated=True,
            runs=runs,
            extra={
                "approved_ref": post_data.get("approved_ref", approved_ref),
                "installed_ref": post_data.get("installed_ref", installed_ref),
            },
        )

    def _tool_rollout_image_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"wrapper_image", "product_image", "target", "targets"})
        argv = [
            self.sudo,
            self.opsctl,
            "rollout",
            "image-plan",
            "--wrapper-image",
            self._image_ref(args.get("wrapper_image")),
            "--product-image",
            self._image_ref(args.get("product_image")),
        ]
        if args.get("target"):
            argv.extend(["--target", self._slot(args.get("target"))])
        slots = args.get("targets")
        if slots is not None:
            if not isinstance(slots, list) or not slots:
                raise ToolError("targets must be a non-empty array")
            argv.append("--targets")
            argv.extend(self._slot(item) for item in slots)
        runs = [self._run(argv, timeout=180)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_rollout_image_dev_apply(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._tool_rollout_image_apply(args, command="image-dev-apply")

    def _tool_rollout_image_canary(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._tool_rollout_image_apply(args, command="image-canary")

    def _tool_rollout_image_apply(self, args: dict[str, Any], *, command: str) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "wrapper_image", "product_image", "allow_first_apply"})
        argv = [
            self.sudo,
            self.opsctl,
            "rollout",
            command,
            "--target",
            self._slot(args.get("target")),
            "--wrapper-image",
            self._image_ref(args.get("wrapper_image")),
            "--product-image",
            self._image_ref(args.get("product_image")),
        ]
        if bool(args.get("allow_first_apply", False)):
            argv.append("--allow-first-apply")
        runs = [self._run(argv, timeout=900)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

    def _tool_rollout_image_promote(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"from_target", "targets"})
        slots = args.get("targets")
        if not isinstance(slots, list) or not slots:
            raise ToolError("targets must be a non-empty array")
        slot_values = [self._slot(item) for item in slots]
        argv = [
            self.sudo,
            self.opsctl,
            "rollout",
            "image-promote",
            "--from-target",
            self._slot(args.get("from_target")),
            "--targets",
            ",".join(slot_values),
        ]
        runs = [self._run(argv, timeout=1800)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

    def _tool_canonical_recipe_validate(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"name"})
        name = self._safe_name(args.get("name"))
        runs = [self._run([self.opsctl, "recipe", "validate-canonical", name], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_dev_recipe_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        slot = self._slot(args.get("target"))
        if not slot.startswith("dev-"):
            raise ToolError("dev recipe tools require a dev target")
        runs = [self._run([self.opsctl, "recipe", "status", slot], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_dev_recipe_apply(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(
            args,
            {
                "target",
                "recipe_name",
                "source_output",
                "sync_from",
                "build_command",
                "allow_first_apply",
                "no_apply",
            },
        )
        slot = self._slot(args.get("target"))
        if not slot.startswith("dev-"):
            raise ToolError("dev recipe tools require a dev target")
        has_source_output = args.get("source_output") is not None
        has_sync_from = args.get("sync_from") is not None
        if has_source_output == has_sync_from:
            raise ToolError("provide exactly one of source_output or sync_from")
        runs = [self._run([self.opsctl, "recipe", "status", slot], timeout=60)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix dev recipe status before apply")
        argv = [self.sudo, self.opsctl, "recipe", "apply-dev", slot]
        recipe_name = args.get("recipe_name")
        if recipe_name:
            argv.extend(["--recipe-name", self._safe_name(recipe_name)])
        if has_source_output:
            argv.extend(["--source-output", self._path_text(args.get("source_output"), "source_output")])
        else:
            argv.extend(["--sync-from", self._path_text(args.get("sync_from"), "sync_from")])
        build_command = self._safe_text(args.get("build_command"), "build_command")
        if build_command:
            argv.extend(["--build-command", build_command])
        if bool(args.get("allow_first_apply", False)):
            argv.append("--allow-first-apply")
        if bool(args.get("no_apply", False)):
            argv.append("--no-apply")
        runs.append(self._run(argv, timeout=900))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_runtime_secret_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
        slots, runs = self._resolve_slots(args)
        runs.extend(
            self._run([self.sudo, self.opsctl, "runtime-secret", "status", slot], timeout=60)
            for slot in slots
        )
        return self._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)

    def _tool_runtime_secret_set_from_file(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "key", "secret_file", "check", "no_restart"})
        self._reject_sensitive_raw_args(args, allowed={"secret_file"})
        slot = self._slot(args.get("target"))
        key = str(args.get("key") or "")
        if key not in PROVIDER_SECRET_KEYS:
            raise ToolError(f"unsupported runtime secret key: {key}")
        value = self._read_allowed_secret_file(args.get("secret_file"))
        argv = [self.sudo, self.opsctl, "runtime-secret", "set", slot, "--key", key, "--value-stdin"]
        if bool(args.get("no_restart", False)):
            argv.append("--no-restart")
        if bool(args.get("check", True)):
            argv.append("--check")
        runs = [self._run(argv, input_text=value, timeout=240)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

    def _tool_handoff_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
        slots, runs = self._resolve_slots(args)
        runs.extend(
            self._run([self.sudo, self.opsctl, "handoff", "status", slot], timeout=60)
            for slot in slots
        )
        return self._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)

    def _tool_handoff_value_command(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        slot = self._slot(args.get("target"))
        runs = [self._run([self.sudo, self.opsctl, "handoff", "value-command", slot], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_heartbeat_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
        if args.get("family") is not None and str(args.get("family")) != "openclaw":
            raise ToolError("heartbeat tools support only openclaw targets")
        slots, runs = self._resolve_slots(args)
        runs.extend(
            self._run([self.sudo, self.opsctl, "heartbeat", "status", slot], timeout=60)
            for slot in slots
        )
        return self._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)

    def _tool_heartbeat_disable(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        slot = self._slot(args.get("target"))
        runs = [
            self._run([self.sudo, self.opsctl, "heartbeat", "status", slot], timeout=60),
            self._run([self.sudo, self.opsctl, "heartbeat", "disable", slot], timeout=120),
        ]
        return self._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=True, runs=runs)

    def _tool_target_rollback(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        slot = self._slot(args.get("target"))
        runs = [self._run([self.opsctl, "status", slot], timeout=60)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix target status before rollback")
        runs.append(self._run([self.sudo, self.opsctl, "rollback", slot], timeout=240))
        runs.append(self._run([self.sudo, self.opsctl, "check", "--live", slot], timeout=180))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target"})
        runs = [self._run([self.opsctl, "nas", "requests"], timeout=60)]
        slot_value = args.get("target")
        if slot_value:
            runs.append(self._run([self.opsctl, "nas", "mounted", self._slot(slot_value)], timeout=60))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=False, runs=runs)

    def _tool_nas_mount(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "share"})
        self._reject_sensitive_raw_args(args)
        slot = self._slot(args.get("target"))
        share = self._share(args.get("share"))
        runs = [self._run([self.opsctl, "nas", "policy-check", slot, share], timeout=60)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix NAS policy or grant before mount")
        runs.append(self._run([self.sudo, self.opsctl, "nas", "mount", slot, share], timeout=180))
        runs.append(self._run([self.opsctl, "nas", "mounted", slot], timeout=60))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_unmount(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"})
        slot = self._slot(args.get("target"))
        share = self._share(args.get("share"))
        argv = [self.sudo, self.opsctl, "nas", "unmount", slot, share]
        if bool(args.get("lazy", False)):
            argv.append("--lazy")
        if bool(args.get("delete_empty_dir", False)):
            argv.append("--delete-empty-dir")
        runs = [
            self._run([self.opsctl, "nas", "mounted", slot], timeout=60),
            self._run(argv, timeout=180),
            self._run([self.opsctl, "nas", "mounted", slot], timeout=60),
        ]
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_remove(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"})
        slot = self._slot(args.get("target"))
        share = self._share(args.get("share"))
        argv = [self.sudo, self.opsctl, "nas", "remove", slot, share]
        if bool(args.get("lazy", False)):
            argv.append("--lazy")
        if bool(args.get("delete_empty_dir", False)):
            argv.append("--delete-empty-dir")
        runs = [
            self._run([self.sudo, self.opsctl, "nas", "credential", "status", slot, share], timeout=60),
            self._run(argv, timeout=180),
            self._run([self.sudo, self.opsctl, "nas", "credential", "status", slot, share], timeout=60),
            self._run([self.opsctl, "nas", "mounted", slot], timeout=60),
        ]
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_credential_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"target", "share"})
        slot = self._slot(args.get("target"))
        share = self._share(args.get("share"))
        runs = [self._run([self.sudo, self.opsctl, "nas", "credential", "status", slot, share], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_nas_approve_auto_once(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, set())
        runs = [self._run([self.sudo, self.opsctl, "nas", "approve-auto"], timeout=180)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)

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
