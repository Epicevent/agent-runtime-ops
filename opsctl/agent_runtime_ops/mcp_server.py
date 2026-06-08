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
SLOT_RE = re.compile(r"^(?:oc[0-9]+|dev-[a-z0-9-]+)$")
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
                "Do not pass raw secret values as tool arguments."
            ),
        }

    def _tool_specs(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "ops_orientation",
                "title": "Orient Agent Runtime Ops",
                "description": "Check installed update status, slots, repository root, and runtime profiles.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "slot_list",
                "title": "List Slots",
                "description": "List current slots with lane, family, slot class, runtime profile, release, and mode.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "slot_check",
                "title": "Check Slot",
                "description": "Run status, plan, contract check, and optionally live check for a slot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slot": {"type": "string"},
                        "live": {"type": "boolean", "default": False},
                    },
                    "required": ["slot"],
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
                "name": "runtime_secret_status",
                "title": "Runtime Secret Status",
                "description": "Check whether supported provider secret keys exist for a slot without printing values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot": {"type": "string"}},
                    "required": ["slot"],
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
                        "slot": {"type": "string"},
                        "key": {"type": "string", "enum": sorted(PROVIDER_SECRET_KEYS)},
                        "secret_file": {"type": "string"},
                        "check": {"type": "boolean", "default": True},
                        "no_restart": {"type": "boolean", "default": False},
                    },
                    "required": ["slot", "key", "secret_file"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "slot_apply",
                "title": "Apply Slot",
                "description": "Pre-check, apply one slot, and run a live check.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slot": {"type": "string"},
                        "allow_first_apply": {"type": "boolean", "default": False},
                    },
                    "required": ["slot"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "slot_rollback",
                "title": "Rollback Slot",
                "description": "Rollback one slot and run a live check.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot": {"type": "string"}},
                    "required": ["slot"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_status",
                "title": "NAS Status",
                "description": "List pending NAS requests and optionally mounted child CIFS shares for a slot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot": {"type": "string"}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_mount",
                "title": "Mount NAS Share",
                "description": "Policy-check and mount an already-credentialed NAS share for a slot.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot": {"type": "string"}, "share": {"type": "string"}},
                    "required": ["slot", "share"],
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
                        "slot": {"type": "string"},
                        "share": {"type": "string"},
                        "lazy": {"type": "boolean", "default": False},
                        "delete_empty_dir": {"type": "boolean", "default": False},
                    },
                    "required": ["slot", "share"],
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
                        "slot": {"type": "string"},
                        "share": {"type": "string"},
                        "lazy": {"type": "boolean", "default": False},
                        "delete_empty_dir": {"type": "boolean", "default": False},
                    },
                    "required": ["slot", "share"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "nas_credential_status",
                "title": "NAS Credential Status",
                "description": "Report official root/customer credential presence for a NAS share without printing secrets.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"slot": {"type": "string"}, "share": {"type": "string"}},
                    "required": ["slot", "share"],
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
            "slot_list": self._tool_slot_list,
            "slot_check": self._tool_slot_check,
            "deploy_update": self._tool_deploy_update,
            "runtime_secret_status": self._tool_runtime_secret_status,
            "runtime_secret_set_from_file": self._tool_runtime_secret_set_from_file,
            "slot_apply": self._tool_slot_apply,
            "slot_rollback": self._tool_slot_rollback,
            "nas_status": self._tool_nas_status,
            "nas_mount": self._tool_nas_mount,
            "nas_unmount": self._tool_nas_unmount,
            "nas_remove": self._tool_nas_remove,
            "nas_credential_status": self._tool_nas_credential_status,
            "nas_approve_auto_once": self._tool_nas_approve_auto_once,
        }
        if name not in handlers:
            raise ProtocolError(-32602, f"unknown tool: {name}")
        try:
            payload = handlers[name](args)
        except ToolError as exc:
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
            "isError": not bool(payload.get("ok")),
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
            self._run([self.opsctl, "slot", "list"]),
            self._run([self.opsctl, "profile", "list"]),
        ]
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=False, runs=runs, extra={"repo_root": str(REPO_ROOT)})

    def _tool_slot_list(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, set())
        runs = [self._run([self.opsctl, "slot", "list"], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_slot_check(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot", "live"})
        slot = self._slot(args.get("slot"))
        live = bool(args.get("live", False))
        runs = [
            self._run([self.opsctl, "status", slot]),
            self._run([self.opsctl, "plan", slot]),
            self._run([self.opsctl, "check", slot]),
        ]
        if live:
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

    def _tool_runtime_secret_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot"})
        slot = self._slot(args.get("slot"))
        runs = [self._run([self.sudo, self.opsctl, "runtime-secret", "status", slot], timeout=60)]
        return self._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)

    def _tool_runtime_secret_set_from_file(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot", "key", "secret_file", "check", "no_restart"})
        self._reject_sensitive_raw_args(args, allowed={"secret_file"})
        slot = self._slot(args.get("slot"))
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

    def _tool_slot_apply(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot", "allow_first_apply"})
        slot = self._slot(args.get("slot"))
        runs = [self._run([self.opsctl, "check", slot], timeout=90)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix slot check failures before apply")
        argv = [self.sudo, self.opsctl, "apply", slot]
        if bool(args.get("allow_first_apply", False)):
            argv.append("--allow-first-apply")
        runs.append(self._run(argv, timeout=240))
        runs.append(self._run([self.sudo, self.opsctl, "check", "--live", slot], timeout=180))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_slot_rollback(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot"})
        slot = self._slot(args.get("slot"))
        runs = [self._run([self.opsctl, "status", slot], timeout=60)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix slot status before rollback")
        runs.append(self._run([self.sudo, self.opsctl, "rollback", slot], timeout=240))
        runs.append(self._run([self.sudo, self.opsctl, "check", "--live", slot], timeout=180))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_status(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot"})
        runs = [self._run([self.opsctl, "nas", "requests"], timeout=60)]
        slot_value = args.get("slot")
        if slot_value:
            runs.append(self._run([self.opsctl, "nas", "mounted", self._slot(slot_value)], timeout=60))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=False, runs=runs)

    def _tool_nas_mount(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot", "share"})
        self._reject_sensitive_raw_args(args)
        slot = self._slot(args.get("slot"))
        share = self._share(args.get("share"))
        runs = [self._run([self.opsctl, "nas", "policy-check", slot, share], timeout=60)]
        if runs[0]["returncode"] != 0:
            return self._common_response(ok=False, mutated=False, runs=runs, next_action="fix NAS policy or grant before mount")
        runs.append(self._run([self.sudo, self.opsctl, "nas", "mount", slot, share], timeout=180))
        runs.append(self._run([self.opsctl, "nas", "mounted", slot], timeout=60))
        ok = all(item["returncode"] == 0 for item in runs)
        return self._common_response(ok=ok, mutated=True, runs=runs)

    def _tool_nas_unmount(self, args: dict[str, Any]) -> dict[str, Any]:
        self._reject_unknown(args, {"slot", "share", "lazy", "delete_empty_dir"})
        slot = self._slot(args.get("slot"))
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
        self._reject_unknown(args, {"slot", "share", "lazy", "delete_empty_dir"})
        slot = self._slot(args.get("slot"))
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
        self._reject_unknown(args, {"slot", "share"})
        slot = self._slot(args.get("slot"))
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
                raise ToolError("raw secret argument rejected; pass an allowed secret_file path or use stdin runbooks")
            raise ToolError("unsupported argument(s): " + ",".join(unknown))

    def _reject_sensitive_raw_args(self, args: dict[str, Any], *, allowed: set[str] | None = None) -> None:
        allowed = allowed or set()
        for key in args:
            normalized = key.lower().replace("-", "_")
            if key not in allowed and normalized in SENSITIVE_ARGUMENTS:
                raise ToolError("raw secret argument rejected; pass an allowed secret_file path or use stdin runbooks")

    def _slot(self, value: Any) -> str:
        slot = str(value or "")
        if not SLOT_RE.match(slot):
            raise ToolError("slot must look like ocN or dev-name")
        return slot

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
