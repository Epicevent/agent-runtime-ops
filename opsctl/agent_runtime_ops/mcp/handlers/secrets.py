from __future__ import annotations

from typing import Any

from ...runtime_secrets import RUNTIME_SECRET_KEYS


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
    slots, runs = server._resolve_slots(args)
    runs.extend(
        server._run([server.sudo, server.opsctl, "runtime-secret", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def set_from_file(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "key", "secret_file", "check", "no_restart"})
    server._reject_sensitive_raw_args(args, allowed={"secret_file"})
    slot = server._slot(args.get("target"))
    key = str(args.get("key") or "")
    if key not in RUNTIME_SECRET_KEYS:
        raise server.tool_error(f"unsupported runtime secret key: {key}")
    value = server._read_allowed_secret_file(args.get("secret_file"))
    argv = [server.sudo, server.opsctl, "runtime-secret", "set", slot, "--key", key, "--value-stdin"]
    if bool(args.get("no_restart", False)):
        argv.append("--no-restart")
    if bool(args.get("check", True)):
        argv.append("--check")
    runs = [server._run(argv, input_text=value, timeout=240)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
