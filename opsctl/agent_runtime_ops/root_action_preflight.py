"""Bounded host observations outside the decision-independent typed core."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import stat
from typing import Any, Mapping


ROOT_ACTION_PREFLIGHT_SCHEMA = "agent-runtime-root-action-preflight/v1"
TRUSTED_READER_ACCOUNT_ENV = "AGENT_RUNTIME_OPS_TRUSTED_ACCOUNT"
TRUSTED_READER_ACCOUNT_FALLBACK = "svcops"
TRUSTED_READER_ACCOUNT = os.environ.get(
    TRUSTED_READER_ACCOUNT_ENV, TRUSTED_READER_ACCOUNT_FALLBACK
)
STATE_ROOT = Path("/var/lib/agent-runtime-ops/root-actions")
PRIVATE_ROOT = STATE_ROOT / "private"
PUBLIC_ROOT = STATE_ROOT / "public"
RUNTIME_ROOT = Path("/run/agent-runtime-ops")
BROKER_SOCKET = RUNTIME_ROOT / "root-action-broker.sock"
PUBLIC_CATALOG = PUBLIC_ROOT / "catalog.json"
BROKER_UNIT = Path("/etc/systemd/system/agent-runtime-root-action-broker.service")
MAX_UNIT_BYTES = 64 * 1024

_INSTALL_CHECKS = (
    "platform.linux_peercred",
    "identity.svcops",
    "unit.broker",
    "path.state_root",
    "path.private_root",
    "path.public_root",
    "path.runtime_root",
)


def _mode(value: int) -> str:
    return f"{stat.S_IMODE(value):04o}"


def _file_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular_file"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _path_snapshot(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {
            "path": str(path),
            "exists": False,
            "kind": "unavailable",
            "uid": "unavailable",
            "gid": "unavailable",
            "mode": "unavailable",
            "nlink": "unavailable",
        }
    except PermissionError:
        return {
            "path": str(path),
            "exists": "unavailable",
            "kind": "unavailable",
            "uid": "unavailable",
            "gid": "unavailable",
            "mode": "unavailable",
            "nlink": "unavailable",
            "observation_error": "permission_denied",
        }
    except OSError:
        return {
            "path": str(path),
            "exists": "unavailable",
            "kind": "unavailable",
            "uid": "unavailable",
            "gid": "unavailable",
            "mode": "unavailable",
            "nlink": "unavailable",
            "observation_error": "io_error",
        }
    return {
        "path": str(path),
        "exists": True,
        "kind": _file_kind(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": _mode(info.st_mode),
        "nlink": info.st_nlink,
    }


def _identity_snapshot() -> dict[str, Any]:
    if os.name != "posix":
        return {
            "account": TRUSTED_READER_ACCOUNT,
            "present": "unavailable",
            "uid": "unavailable",
            "primary_gid": "unavailable",
            "group_gid": "unavailable",
            "observation_error": "unsupported_platform",
        }
    try:
        import grp
        import pwd

        account = pwd.getpwnam(TRUSTED_READER_ACCOUNT)
        group = grp.getgrnam(TRUSTED_READER_ACCOUNT)
    except KeyError:
        return {
            "account": TRUSTED_READER_ACCOUNT,
            "present": False,
            "uid": "unavailable",
            "primary_gid": "unavailable",
            "group_gid": "unavailable",
        }
    except OSError:
        return {
            "account": TRUSTED_READER_ACCOUNT,
            "present": "unavailable",
            "uid": "unavailable",
            "primary_gid": "unavailable",
            "group_gid": "unavailable",
            "observation_error": "identity_lookup_failed",
        }
    return {
        "account": TRUSTED_READER_ACCOUNT,
        "present": True,
        "uid": account.pw_uid,
        "primary_gid": account.pw_gid,
        "group_gid": group.gr_gid,
    }


def _platform_snapshot() -> dict[str, Any]:
    geteuid = getattr(os, "geteuid", None)
    return {
        "os_name": os.name,
        "so_peercred": hasattr(socket, "SO_PEERCRED"),
        "effective_uid": geteuid() if geteuid is not None else "unavailable",
    }


def _read_unit_directives(path: Path, path_value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        path_value.get("exists") is not True
        or path_value.get("kind") != "regular_file"
        or path_value.get("nlink") != 1
    ):
        return {"read_status": "not_read", "directives": {}}
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        return {
            "read_status": "unsupported_no_nofollow",
            "directives": {},
        }
    flags |= nofollow
    try:
        fd = os.open(path, flags)
    except PermissionError:
        return {"read_status": "permission_denied", "directives": {}}
    except OSError:
        return {"read_status": "io_error", "directives": {}}
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return {"read_status": "unsafe_file", "directives": {}}
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(8192, MAX_UNIT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_UNIT_BYTES:
                break
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > MAX_UNIT_BYTES:
        return {"read_status": "too_large", "directives": {}}
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {"read_status": "invalid_utf8", "directives": {}}
    allowlist = {
        "User",
        "Group",
        "ExecStart",
        "ReadWritePaths",
        "RestrictAddressFamilies",
    }
    directives: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in allowlist:
            directives.setdefault(key, []).append(value)
    return {
        "read_status": "read",
        "placeholder_count": text.count("@@CURRENT_LINK@@"),
        "directives": directives,
    }


def capture_root_action_preflight() -> dict[str, Any]:
    paths = {
        "unit": _path_snapshot(BROKER_UNIT),
        "state_root": _path_snapshot(STATE_ROOT),
        "private_root": _path_snapshot(PRIVATE_ROOT),
        "public_root": _path_snapshot(PUBLIC_ROOT),
        "runtime_root": _path_snapshot(RUNTIME_ROOT),
        "broker_socket": _path_snapshot(BROKER_SOCKET),
        "public_catalog": _path_snapshot(PUBLIC_CATALOG),
    }
    return {
        "platform": _platform_snapshot(),
        "identity": _identity_snapshot(),
        "paths": paths,
        "unit": _read_unit_directives(BROKER_UNIT, paths["unit"]),
    }


def _status_for_path(
    observed: Mapping[str, Any],
    *,
    expected_kind: str,
    expected_uid: int | str,
    expected_gid: int | str,
    expected_mode: str,
    absence: str,
) -> str:
    if observed.get("exists") is False:
        return absence
    if observed.get("exists") is not True:
        return "not_observed"
    expected = {
        "kind": expected_kind,
        "uid": expected_uid,
        "gid": expected_gid,
        "mode": expected_mode,
    }
    if expected_uid == "unavailable" or expected_gid == "unavailable":
        return "not_observed"
    matches = all(observed.get(key) == value for key, value in expected.items())
    return "match" if matches else "mismatch"


def _path_check(
    check_id: str,
    observed: Mapping[str, Any],
    *,
    kind: str,
    uid: int | str,
    gid: int | str,
    mode: str,
    absence: str = "mismatch",
    classification: str = "safety_invariant",
) -> dict[str, Any]:
    return {
        "id": check_id,
        "classification": classification,
        "status": _status_for_path(
            observed,
            expected_kind=kind,
            expected_uid=uid,
            expected_gid=gid,
            expected_mode=mode,
            absence=absence,
        ),
        "expected": {
            "exists": True,
            "kind": kind,
            "uid": uid,
            "gid": gid,
            "mode": mode,
        },
        "observed": dict(observed),
    }


def _unit_status(path_status: str, unit: Mapping[str, Any]) -> str:
    if path_status != "match":
        return path_status
    if unit.get("read_status") != "read":
        return "not_observed"
    directives = unit.get("directives")
    if not isinstance(directives, Mapping):
        return "mismatch"
    exec_start = directives.get("ExecStart")
    valid_exec = (
        isinstance(exec_start, list)
        and len(exec_start) == 1
        and isinstance(exec_start[0], str)
        and exec_start[0].startswith("/")
        and exec_start[0].endswith(
            "/.venv/bin/python -m agent_runtime_ops.root_actions.service"
        )
    )
    exact = {
        "User": ["root"],
        "Group": ["root"],
        "ReadWritePaths": [
            "/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops"
        ],
        "RestrictAddressFamilies": ["AF_UNIX"],
    }
    return (
        "match"
        if unit.get("placeholder_count") == 0
        and valid_exec
        and all(directives.get(key) == value for key, value in exact.items())
        else "mismatch"
    )


def _gate(checks: list[dict[str, Any]], selected: tuple[str, ...]) -> str:
    statuses = {
        check["status"] for check in checks if check.get("id") in selected
    }
    if "mismatch" in statuses or "unsupported" in statuses:
        return "mismatch"
    if statuses != {"match"}:
        return "not_observed"
    return "match"


def evaluate_root_action_preflight(
    snapshot: Mapping[str, Any],
    *,
    observed_at: str | None = None,
) -> dict[str, Any]:
    platform = snapshot.get("platform", {})
    identity = snapshot.get("identity", {})
    paths = snapshot.get("paths", {})
    unit = snapshot.get("unit", {})
    if not all(isinstance(value, Mapping) for value in (platform, identity, paths, unit)):
        raise ValueError("root action preflight snapshot is invalid")

    platform_status = (
        "match"
        if platform.get("os_name") == "posix" and platform.get("so_peercred") is True
        else "unsupported"
    )
    identity_status = (
        "match"
        if identity.get("present") is True
        and isinstance(identity.get("uid"), int)
        and identity.get("primary_gid") == identity.get("group_gid")
        else (
            "mismatch"
            if identity.get("present") is False
            or (
                identity.get("present") is True
                and identity.get("primary_gid") != identity.get("group_gid")
            )
            else "not_observed"
        )
    )
    trusted_gid: int | str = (
        identity["group_gid"]
        if identity_status == "match" and isinstance(identity.get("group_gid"), int)
        else "unavailable"
    )
    checks: list[dict[str, Any]] = [
        {
            "id": "platform.linux_peercred",
            "classification": "safety_invariant",
            "status": platform_status,
            "expected": {"os_name": "posix", "so_peercred": True},
            "observed": dict(platform),
        },
        {
            "id": "identity.svcops",
            "classification": "safety_invariant",
            "status": identity_status,
            "expected": {
                "account": TRUSTED_READER_ACCOUNT,
                "present": True,
                "primary_group_matches_named_group": True,
            },
            "observed": dict(identity),
        },
    ]
    unit_path_check = _path_check(
        "unit.broker",
        paths.get("unit", {}),
        kind="regular_file",
        uid=0,
        gid=0,
        mode="0644",
    )
    unit_path_check["status"] = _unit_status(unit_path_check["status"], unit)
    unit_path_check["observed"] = {
        "path": dict(paths.get("unit", {})),
        "content": dict(unit),
    }
    unit_path_check["expected"]["directives"] = {
        "User": ["root"],
        "Group": ["root"],
        "ExecStart": "absolute installed current/.venv Python root-action service",
        "ReadWritePaths": [
            "/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops"
        ],
        "RestrictAddressFamilies": ["AF_UNIX"],
        "placeholder_count": 0,
    }
    checks.append(unit_path_check)
    checks.extend(
        [
            _path_check(
                "path.state_root",
                paths.get("state_root", {}),
                kind="directory",
                uid=0,
                gid=trusted_gid,
                mode="0750",
            ),
            _path_check(
                "path.private_root",
                paths.get("private_root", {}),
                kind="directory",
                uid=0,
                gid=0,
                mode="0700",
            ),
            _path_check(
                "path.public_root",
                paths.get("public_root", {}),
                kind="directory",
                uid=0,
                gid=trusted_gid,
                mode="0750",
            ),
            _path_check(
                "path.runtime_root",
                paths.get("runtime_root", {}),
                kind="directory",
                uid=0,
                gid=trusted_gid,
                mode="0750",
            ),
            _path_check(
                "endpoint.broker_socket",
                paths.get("broker_socket", {}),
                kind="socket",
                uid=0,
                gid=trusted_gid,
                mode="0660",
                absence="not_observed",
                classification="activation_evidence",
            ),
            _path_check(
                "publication.catalog",
                paths.get("public_catalog", {}),
                kind="regular_file",
                uid=0,
                gid=trusted_gid,
                mode="0640",
                absence="not_observed",
                classification="publication_evidence",
            ),
        ]
    )
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    return {
        "schema": ROOT_ACTION_PREFLIGHT_SCHEMA,
        "probe_status": "complete",
        "observed_at": timestamp,
        "read_only": True,
        "mutations_performed": False,
        "network_calls_performed": False,
        "secrets_included": False,
        "checks": checks,
        "gates": {
            "install_contract": _gate(checks, _INSTALL_CHECKS),
            "activation_surface": _gate(checks, ("endpoint.broker_socket",)),
            "publication_surface": _gate(checks, ("publication.catalog",)),
        },
        "proof_boundary": {
            "does_not_prove": [
                "service_process_liveness",
                "strong_reauthentication",
                "approval_assertion",
                "typed_dispatch",
                "handler_execution",
                "ops_web_deployment",
                "requester_terminal_receipt_round_trip",
            ]
        },
    }


def root_action_preflight() -> dict[str, Any]:
    return evaluate_root_action_preflight(capture_root_action_preflight())
