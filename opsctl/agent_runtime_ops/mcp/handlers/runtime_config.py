from __future__ import annotations

from typing import Any

from .. import validation as v


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    runs = [server._run([server.sudo, server.opsctl, "runtime", "config-status", slot], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def sanitize(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "apply"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    apply_changes = v.boolean_arg(args, "apply", default=False, error_type=server.tool_error)
    argv = [
        server.sudo,
        server.opsctl,
        "runtime",
        "config-sanitize",
        slot,
        "--apply" if apply_changes else "--dry-run",
    ]
    runs = [server._run(argv, timeout=120)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=apply_changes, runs=runs)


def set_model(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "provider", "model"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    provider = v.safe_text(args.get("provider"), "provider", error_type=server.tool_error)
    model = v.safe_text(args.get("model"), "model", error_type=server.tool_error)
    if not provider:
        raise server.tool_error("provider is required")
    if not model:
        raise server.tool_error("model is required")
    runs = [
        server._run(
            [
                server.sudo,
                server.opsctl,
                "runtime",
                "set-model",
                slot,
                "--provider",
                provider,
                "--model",
                model,
            ],
            timeout=120,
        )
    ]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
