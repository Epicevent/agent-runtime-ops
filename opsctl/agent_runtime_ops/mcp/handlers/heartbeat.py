from __future__ import annotations

from typing import Any


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
    if args.get("family") is not None and str(args.get("family")) != "openclaw":
        raise server.tool_error("heartbeat tools support only openclaw targets")
    slots, runs = server._resolve_slots(args)
    runs.extend(
        server._run([server.sudo, server.opsctl, "heartbeat", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def disable(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    slot = server._slot(args.get("target"))
    runs = [
        server._run([server.sudo, server.opsctl, "heartbeat", "status", slot], timeout=60),
        server._run([server.sudo, server.opsctl, "heartbeat", "disable", slot], timeout=120),
    ]
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=True, runs=runs)
