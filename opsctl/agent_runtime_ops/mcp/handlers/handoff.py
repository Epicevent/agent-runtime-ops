from __future__ import annotations

from typing import Any


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
    slots, runs = server._resolve_slots(args)
    runs.extend(
        server._run([server.sudo, server.opsctl, "handoff", "status", slot], timeout=60)
        for slot in slots
    )
    return server._common_response(ok=all(item["returncode"] == 0 for item in runs), mutated=False, runs=runs)


def value_command(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    slot = server._slot(args.get("target"))
    runs = [server._run([server.sudo, server.opsctl, "handoff", "value-command", slot], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)
