from __future__ import annotations

from typing import Any

from .. import validation as v


def canonical_validate(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"name"}, error_type=server.tool_error)
    name = v.safe_name(args.get("name"), error_type=server.tool_error)
    runs = [server._run([server.opsctl, "recipe", "validate-canonical", name], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def dev_status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    if not slot.startswith("dev-"):
        raise server.tool_error("dev recipe tools require a dev target")
    runs = [server._run([server.opsctl, "recipe", "status", slot], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def dev_apply(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(
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
        error_type=server.tool_error,
    )
    slot = v.linux_account(args.get("target"), error_type=server.tool_error)
    if not slot.startswith("dev-"):
        raise server.tool_error("dev recipe tools require a dev target")
    has_source_output = args.get("source_output") is not None
    has_sync_from = args.get("sync_from") is not None
    if has_source_output == has_sync_from:
        raise server.tool_error("provide exactly one of source_output or sync_from")
    runs = [server._run([server.opsctl, "recipe", "status", slot], timeout=60)]
    if runs[0]["returncode"] != 0:
        return server._common_response(ok=False, mutated=False, runs=runs, next_action="fix dev recipe status before apply")
    argv = [server.sudo, server.opsctl, "recipe", "apply-dev", slot]
    recipe_name = args.get("recipe_name")
    if recipe_name:
        argv.extend(["--recipe-name", v.safe_name(recipe_name, error_type=server.tool_error)])
    if has_source_output:
        argv.extend(["--source-output", v.path_text(args.get("source_output"), "source_output", error_type=server.tool_error)])
    else:
        argv.extend(["--sync-from", v.path_text(args.get("sync_from"), "sync_from", error_type=server.tool_error)])
    build_command = v.safe_text(args.get("build_command"), "build_command", error_type=server.tool_error)
    if build_command:
        argv.extend(["--build-command", build_command])
    if bool(args.get("allow_first_apply", False)):
        argv.append("--allow-first-apply")
    if bool(args.get("no_apply", False)):
        argv.append("--no-apply")
    runs.append(server._run(argv, timeout=900))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=True, runs=runs)
