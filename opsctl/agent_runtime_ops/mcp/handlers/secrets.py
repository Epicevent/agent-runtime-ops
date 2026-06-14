from __future__ import annotations

from typing import Any

from ...runtime_secrets import RUNTIME_SECRET_KEYS
from .. import validation as v

MUTATING_RUNTIME_TIMEOUT = 900


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "targets", "runtime_class", "family"}, error_type=server.tool_error)
    slots, runs = v.resolve_slots(server, args, error_type=server.tool_error)
    runs.extend(
        server._run([server.sudo, server.opsctl, "runtime-secret", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def set_from_file(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "key", "secret_file", "check", "no_restart"}, error_type=server.tool_error)
    v.reject_sensitive_raw_args(args, allowed={"secret_file"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    key = str(args.get("key") or "")
    if key not in RUNTIME_SECRET_KEYS:
        raise server.tool_error(f"unsupported runtime secret key: {key}")
    value = v.read_allowed_secret_file(args.get("secret_file"), server.secret_roots, error_type=server.tool_error)
    argv = [server.sudo, server.opsctl, "runtime-secret", "set", slot, "--key", key, "--value-stdin"]
    if v.boolean_arg(args, "no_restart", default=False, error_type=server.tool_error):
        argv.append("--no-restart")
    if v.boolean_arg(args, "check", default=True, error_type=server.tool_error):
        argv.append("--check")
    runs = [server._run(argv, input_text=value, timeout=MUTATING_RUNTIME_TIMEOUT)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
