from __future__ import annotations

from typing import Any

from .. import validation as v


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "targets", "runtime_class", "family"}, error_type=server.tool_error)
    slots, runs = v.resolve_slots(server, args, error_type=server.tool_error)
    runs.extend(
        server._run([server.sudo, server.opsctl, "handoff", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def value_command(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    runs = [server._run([server.sudo, server.opsctl, "handoff", "value-command", slot], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)
