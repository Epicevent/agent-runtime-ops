from __future__ import annotations

from typing import Any

from ...paths import REPO_ROOT


def ops_orientation(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, set())
    runs = [
        server._run([server.opsctl, "update", "status"]),
        server._run([server.opsctl, "binding", "list"]),
        server._run([server.opsctl, "profile", "list"]),
    ]
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=False, runs=runs, extra={"repo_root": str(REPO_ROOT)})


def binding_list(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, set())
    runs = [server._run([server.opsctl, "binding", "list"], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def binding_status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    argv = [server.opsctl, "binding", "status"]
    if args.get("target"):
        argv.append(server._target(args.get("target")))
    runs = [server._run(argv, timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def binding_set_public_host(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "host"})
    target = server._target(args.get("target"))
    host = server._host(args.get("host"))
    runs = [server._run([server.sudo, server.opsctl, "binding", "set-public-host", target, host], timeout=120)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)


def apache_status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    argv = [server.opsctl, "apache", "status"]
    if args.get("target"):
        argv.append(server._target(args.get("target")))
    runs = [server._run(argv, timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def apache_set_host(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"linux_account", "host"})
    linux_account = server._linux_account(args.get("linux_account"))
    host = server._host(args.get("host"))
    runs = [server._run([server.sudo, server.opsctl, "apache", "set-host", linux_account, host], timeout=120)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)


def runtime_truth(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "all"})
    argv = [server.sudo, server.opsctl, "runtime", "truth"]
    if bool(args.get("all", False)):
        if args.get("target") is not None:
            raise server.tool_error("provide either target or all, not both")
        argv.append("--all")
    else:
        argv.append(server._target(args.get("target")))
    runs = [server._run(argv, timeout=120)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def document_tools_status(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "all"})
    argv = [server.sudo, server.opsctl, "document-tools", "status"]
    if bool(args.get("all", False)):
        if args.get("target") is not None:
            raise server.tool_error("provide either target or all, not both")
        argv.append("--all")
    else:
        argv.append(server._target(args.get("target")))
    runs = [server._run(argv, timeout=180)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def target_check(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "targets", "runtime_class", "family"})
    slots, runs = server._resolve_slots(args)
    for slot in slots:
        runs.append(server._run([server.opsctl, "binding", "status", slot]))
        runs.append(server._run([server.opsctl, "apache", "status", slot]))
        runs.append(server._run([server.sudo, server.opsctl, "runtime", "truth", slot], timeout=120))
        runs.append(server._run([server.sudo, server.opsctl, "check", "--live", slot], timeout=120))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=False, runs=runs)


def target_rollback(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"target"})
    slot = server._slot(args.get("target"))
    runs = [server._run([server.opsctl, "status", slot], timeout=60)]
    if runs[0]["returncode"] != 0:
        return server._common_response(ok=False, mutated=False, runs=runs, next_action="fix target status before rollback")
    runs.append(server._run([server.sudo, server.opsctl, "rollback", slot], timeout=240))
    runs.append(server._run([server.sudo, server.opsctl, "check", "--live", slot], timeout=180))
    ok = all(item["returncode"] == 0 for item in runs)
    return server._common_response(ok=ok, mutated=True, runs=runs)
