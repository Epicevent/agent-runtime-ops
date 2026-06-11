from __future__ import annotations

from typing import Any

from .. import validation as v


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "targets", "runtime_class", "family"}, error_type=server.tool_error)
    if args.get("family") is not None and str(args.get("family")) != "openclaw":
        raise server.tool_error("heartbeat tools support only openclaw targets")
    slots, runs = v.resolve_slots(server, args, error_type=server.tool_error)
    runs.extend(
        server._run([server.sudo, server.opsctl, "heartbeat", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def disable(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    runs = [
        server._run([server.sudo, server.opsctl, "heartbeat", "status", slot], timeout=60),
        server._run([server.sudo, server.opsctl, "heartbeat", "disable", slot], timeout=120),
    ]
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=True, runs=runs)
