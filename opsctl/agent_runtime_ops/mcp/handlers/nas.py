from __future__ import annotations

from typing import Any


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    runs = [server._run([server.opsctl, "nas", "requests"], timeout=60)]
    slot_value = args.get("target")
    if slot_value:
        runs.append(server._run([server.opsctl, "nas", "mounted", server._target(slot_value)], timeout=60))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=False, runs=runs)


def mount(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "share", "keep_fstab_on_failure"})
    server._reject_sensitive_raw_args(args)
    target = server._target(args.get("target"))
    share = server._share(args.get("share"))
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
    server._reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"})
    target = server._target(args.get("target"))
    share = server._share(args.get("share"))
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
    server._reject_unknown(args, {"target", "share", "lazy", "delete_empty_dir"})
    target = server._target(args.get("target"))
    share = server._share(args.get("share"))
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
    server._reject_unknown(args, {"target", "share"})
    target = server._target(args.get("target"))
    share = server._share(args.get("share"))
    runs = [server._run([server.sudo, server.opsctl, "nas", "credential", "status", target, share], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def approve_auto_once(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, set())
    runs = [server._run([server.sudo, server.opsctl, "nas", "approve-auto"], timeout=180)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
