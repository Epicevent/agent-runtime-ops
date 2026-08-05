from __future__ import annotations

from typing import Any

from .. import validation as v


def runtime_status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    argv = [
        server.sudo,
        server.opsctl,
        "observation",
        "status",
        v.linux_account(args.get("target"), error_type=server.tool_error),
    ]
    runs = [server._run(argv, timeout=90)]
    return server._common_response(
        ok=runs[0]["returncode"] in {0, 1},
        mutated=False,
        runs=runs,
    )


def dev_logs(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "tail", "since"}, error_type=server.tool_error)
    target = v.linux_account(args.get("target"), error_type=server.tool_error)
    if not target.startswith("dev-"):
        raise server.tool_error("developer live logs require a dev-* target")
    tail = args.get("tail", 200)
    if isinstance(tail, bool) or not isinstance(tail, int) or not 1 <= tail <= 2000:
        raise server.tool_error("tail must be an integer from 1 to 2000")
    argv = [
        server.sudo,
        server.opsctl,
        "diagnostics",
        "logs",
        target,
        "--tail",
        str(tail),
    ]
    since = args.get("since")
    if since is not None:
        if not isinstance(since, str):
            raise server.tool_error("since must be a relative age string")
        argv.extend(["--since", since])
    runs = [server._run(argv, timeout=60)]
    return server._common_response(
        ok=runs[0]["returncode"] == 0,
        mutated=False,
        runs=runs,
    )


def dev_session_health(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "since"}, error_type=server.tool_error)
    target = v.linux_account(args.get("target"), error_type=server.tool_error)
    if not target.startswith("dev-"):
        raise server.tool_error("developer session health requires a dev-* target")
    argv = [server.sudo, server.opsctl, "diagnostics", "session-health", target]
    since = args.get("since")
    if since is not None:
        if not isinstance(since, str):
            raise server.tool_error("since must be a relative age string")
        argv.extend(["--since", since])
    runs = [server._run(argv, timeout=90)]
    return server._common_response(
        ok=runs[0]["returncode"] == 0,
        mutated=False,
        runs=runs,
    )
