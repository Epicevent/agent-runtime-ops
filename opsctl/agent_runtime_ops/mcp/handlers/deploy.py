from __future__ import annotations

import re
import shlex
from typing import Any

from .. import validation as v


FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _parse_key_values(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def deploy_update(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target_ref"}, error_type=server.tool_error)
    target_ref = args.get("target_ref")
    if target_ref is not None:
        target_ref = str(target_ref)
        if not FULL_SHA_RE.match(target_ref):
            raise server.tool_error("target_ref must be a full 40-character commit sha")
    status = server._run([server.opsctl, "update", "status"])
    runs = [status]
    data = _parse_key_values(status["stdout"])
    approved_ref = data.get("approved_ref", "")
    installed_ref = data.get("installed_ref", "")
    if status["returncode"] != 0 or not approved_ref:
        ref_for_command = target_ref or "FULL_40_CHARACTER_COMMIT_SHA"
        command = shlex.join([server.sudo, server.opsctl, "update", "approve", ref_for_command])
        return server._common_response(
            ok=False,
            mutated=False,
            runs=runs,
            next_action=command,
            extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
        )
    if target_ref and approved_ref != target_ref:
        command = shlex.join([server.sudo, server.opsctl, "update", "approve", target_ref])
        return server._common_response(
            ok=False,
            mutated=False,
            runs=runs,
            next_action=command,
            extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
        )
    if data.get("approved_matches_installed") == "yes":
        return server._common_response(
            ok=True,
            mutated=False,
            runs=runs,
            extra={"approved_ref": approved_ref, "installed_ref": installed_ref},
        )
    runs.append(server._run([server.sudo, server.opsctl, "self-update"], timeout=300))
    runs.append(server._run([server.opsctl, "update", "status"]))
    runs.append(server._run([server.opsctl, "profile", "list"]))
    post_data = _parse_key_values(runs[-2]["stdout"])
    ok = all(item["returncode"] == 0 for item in runs) and post_data.get("approved_matches_installed") == "yes"
    return server._common_response(
        ok=ok,
        mutated=True,
        runs=runs,
        extra={
            "approved_ref": post_data.get("approved_ref", approved_ref),
            "installed_ref": post_data.get("installed_ref", installed_ref),
        },
    )
