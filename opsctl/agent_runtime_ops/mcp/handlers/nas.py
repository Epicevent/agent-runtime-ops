from __future__ import annotations

from typing import Any

from .. import validation as v


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target"}, error_type=server.tool_error)
    runs = [server._run([server.opsctl, "nas", "requests"], timeout=60)]
    slot_value = args.get("target")
    if slot_value:
        runs.append(server._run([server.opsctl, "nas", "mounted", v.target(slot_value, error_type=server.tool_error)], timeout=60))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=False, runs=runs)


def mount(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "share", "keep_fstab_on_failure"}, error_type=server.tool_error)
    v.reject_sensitive_raw_args(args, error_type=server.tool_error)
    target = v.target(args.get("target"), error_type=server.tool_error)
    share = v.share(args.get("share"), error_type=server.tool_error)
    runs = [server._run([server.opsctl, "nas", "policy-check", target, share], timeout=60)]
    if runs[0]["returncode"] != 0:
        return server._common_response(ok=False, mutated=False, runs=runs, next_action="fix NAS policy or grant before mount")
    argv = [server.sudo, server.opsctl, "nas", "mount", target, share]
    if bool(args.get("keep_fstab_on_failure", False)):
        argv.append("--keep-fstab-on-failure")
    runs.append(server._run(argv, timeout=180))
    runs.append(server._run([server.opsctl, "nas", "mounted", target], timeout=60))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=True, runs=runs)


def unmount(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"}, error_type=server.tool_error)
    target = v.target(args.get("target"), error_type=server.tool_error)
    share = v.share(args.get("share"), error_type=server.tool_error)
    argv = [server.sudo, server.opsctl, "nas", "unmount", target, share]
    if bool(args.get("lazy", False)):
        argv.append("--lazy")
    if bool(args.get("delete_empty_dir", False)):
        argv.append("--delete-empty-dir")
    runs = [
        server._run([server.opsctl, "nas", "mounted", target], timeout=60),
        server._run(argv, timeout=180),
        server._run([server.opsctl, "nas", "mounted", target], timeout=60),
    ]
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=True, runs=runs)


def remove(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"}, error_type=server.tool_error)
    target = v.target(args.get("target"), error_type=server.tool_error)
    share = v.share(args.get("share"), error_type=server.tool_error)
    argv = [server.sudo, server.opsctl, "nas", "remove", target, share]
    if bool(args.get("lazy", False)):
        argv.append("--lazy")
    if bool(args.get("delete_empty_dir", False)):
        argv.append("--delete-empty-dir")
    runs = [
        server._run([server.sudo, server.opsctl, "nas", "credential", "status", target, share], timeout=60),
        server._run(argv, timeout=180),
        server._run([server.sudo, server.opsctl, "nas", "credential", "status", target, share], timeout=60),
        server._run([server.opsctl, "nas", "mounted", target], timeout=60),
    ]
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=True, runs=runs)


def credential_status(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "share"}, error_type=server.tool_error)
    target = v.target(args.get("target"), error_type=server.tool_error)
    share = v.share(args.get("share"), error_type=server.tool_error)
    runs = [server._run([server.sudo, server.opsctl, "nas", "credential", "status", target, share], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def approve_auto_once(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, set(), error_type=server.tool_error)
    runs = [server._run([server.sudo, server.opsctl, "nas", "approve-auto"], timeout=180)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
