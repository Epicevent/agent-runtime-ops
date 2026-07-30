#!/usr/bin/env python3
"""Durable, fail-closed publication of the installed OPS activation identity.

The installer owns five independently addressed filesystem entries.  Linux does
not provide a group rename across their two parent directories, so this helper
records the exact baseline and intended candidate before the first visible
replacement.  An interrupted publication is recovered to the baseline by a
fresh installer process; it is never inferred as a new baseline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


SCHEMA = "agent-runtime-ops-activation-transaction/v2"
ENTRY_NAMES = ("opsctl", "mcp", "gemini", "manifest", "current")
BROKER_NAME = "broker"
ALL_IDENTITY_NAMES = (*ENTRY_NAMES, BROKER_NAME)
REGULAR_NAMES = ("opsctl", "mcp", "gemini")
SYMLINK_NAMES = ("manifest", "current")
MAX_WRAPPER_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
TRANSACTION_KEYS = {
    "schema",
    "phase",
    "candidate_commit",
    "candidate_release",
    "previous_release",
    "ops_gid",
    "paths",
    "entries",
    "broker",
}
ENTRY_KEYS = {"baseline", "candidate"}
ABSENT_KEYS = {"kind"}
REGULAR_KEYS = {"kind", "sha256", "bytes", "mode", "uid", "gid", "nlink"}
SYMLINK_KEYS = {"kind", "target", "mode", "uid", "gid", "nlink"}
BROKER_KEYS = {
    "unit_path",
    "service_name",
    "baseline_state",
    "baseline_unit_file_state",
    "carried_baseline_state",
    "carried_baseline_unit_file_state",
    "desired_state",
    "desired_unit_file_state",
    "reactivation_origin",
    "baseline",
    "candidate",
}
BROKER_STATES = {"active", "inactive", "absent", "unavailable"}
BROKER_UNIT_FILE_STATES = {"enabled", "disabled", "absent", "unavailable"}
REACTIVATION_ORIGIN_KEYS = {
    "schema",
    "source_manifest_sha256",
    "failed_candidate_commit",
    "previous_release",
    "service_name",
    "baseline_unit_sha256",
    "desired_state",
    "desired_unit_file_state",
}
REACTIVATION_ORIGIN_SCHEMA = "agent-runtime-ops-broker-reactivation-origin/v1"
RECOVERED_INTENT_MARKER = "recovered-active-intent"
ADOPTION_CLAIMED_MARKER = "broker-reactivation-adoption-claimed"
REVOKED_INTENT_MARKER = "broker-reactivation-revoked"
START_DISPATCH_MARKER = "broker-start-dispatch-committed"
ACTIVE_ATTESTED_MARKER = "broker-active-attested"
RECOVERED_MARKER_BYTES = b"recovered\n"
MAX_DURABILITY_ENTRIES = 250_000


class TransactionError(RuntimeError):
    pass


def _fail(message: str) -> None:
    raise TransactionError(message)


def _exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{where}: key mismatch missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _safe_absolute(value: str, where: str) -> Path:
    if not value or not os.path.isabs(value):
        _fail(f"{where}: absolute path required")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(f"{where}: control characters are forbidden")
    normalized = os.path.abspath(value)
    if value != normalized:
        _fail(f"{where}: canonical absolute path required")
    return Path(value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(path: Path, limit: int = MAX_WRAPPER_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail(f"{path}: regular single-link file required")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                _fail(f"{path}: file exceeds {limit} bytes")
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail(f"{path}: file changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def _kind(path: Path) -> str:
    try:
        meta = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(meta.st_mode):
        return "symlink"
    if stat.S_ISREG(meta.st_mode):
        return "regular"
    return "other"


def _absent_meta() -> dict[str, Any]:
    return {"kind": "absent"}


def _regular_meta(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> tuple[dict[str, Any], bytes]:
    meta = os.lstat(path)
    if not stat.S_ISREG(meta.st_mode):
        _fail(f"{path}: regular file required")
    if (
        meta.st_uid != expected_uid
        or meta.st_gid != expected_gid
        or stat.S_IMODE(meta.st_mode) != expected_mode
        or meta.st_nlink != 1
    ):
        _fail(f"{path}: unsafe owner/mode/link count")
    data = _read_bounded(path)
    return (
        {
            "kind": "regular",
            "sha256": _sha256(data),
            "bytes": len(data),
            "mode": expected_mode,
            "uid": expected_uid,
            "gid": expected_gid,
            "nlink": 1,
        },
        data,
    )


def _symlink_meta(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_target: str | None = None,
) -> dict[str, Any]:
    meta = os.lstat(path)
    if not stat.S_ISLNK(meta.st_mode):
        _fail(f"{path}: symlink required")
    if meta.st_uid != expected_uid or meta.st_gid != expected_gid or meta.st_nlink != 1:
        _fail(f"{path}: unsafe symlink owner/link count")
    target = os.readlink(path)
    if expected_target is not None and target != expected_target:
        _fail(f"{path}: unexpected symlink target")
    if not target or any(ord(char) < 32 or ord(char) == 127 for char in target):
        _fail(f"{path}: unsafe symlink target")
    return {
        "kind": "symlink",
        "target": target,
        "mode": stat.S_IMODE(meta.st_mode),
        "uid": expected_uid,
        "gid": expected_gid,
        "nlink": 1,
    }


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            _fail(f"{path}: directory required for fsync")
        os.fsync(fd)
    finally:
        os.close(fd)


def _validate_root_controlled_directory(path: Path, where: str) -> None:
    meta = os.lstat(path)
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != 0
        or stat.S_IMODE(meta.st_mode) & 0o022
    ):
        _fail(f"{where}: root-owned nonwritable directory required")


def _validate_root_controlled_parent_chain(path: Path, where: str) -> None:
    current = path.parent
    immediate = True
    while True:
        meta = os.lstat(current)
        mode = stat.S_IMODE(meta.st_mode)
        if (
            not stat.S_ISDIR(meta.st_mode)
            or stat.S_ISLNK(meta.st_mode)
            or meta.st_uid != 0
            or (immediate and mode & 0o022)
            or (not immediate and mode & 0o022 and not mode & stat.S_ISVTX)
        ):
            _fail(f"{where}: unsafe activation endpoint parent: {current}")
        parent = current.parent
        if parent == current:
            return
        current = parent
        immediate = False


def _write_file(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _phase_marker_temp(tx_dir: Path, marker_name: str) -> Path:
    return tx_dir / f".{marker_name}.next"


def _recover_phase_marker_staging(
    tx_dir: Path, marker_name: str, expected: bytes
) -> None:
    marker = tx_dir / marker_name
    temp = _phase_marker_temp(tx_dir, marker_name)
    if not _lexists(temp):
        return
    if _lexists(marker):
        _fail(f"transaction phase marker and staging both exist: {marker_name}")
    meta = os.lstat(temp)
    if (
        not stat.S_ISREG(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != 0
        or meta.st_gid != 0
        or stat.S_IMODE(meta.st_mode) != 0o600
        or meta.st_nlink != 1
    ):
        _fail(f"unsafe transaction phase staging: {marker_name}")
    partial = _read_bounded(temp, len(expected))
    if not expected.startswith(partial):
        _fail(f"transaction phase staging content mismatch: {marker_name}")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags)
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_nlink,
        ) != (
            meta.st_dev,
            meta.st_ino,
            meta.st_mode,
            meta.st_uid,
            meta.st_gid,
            meta.st_nlink,
        ):
            _fail(f"transaction phase staging changed: {marker_name}")
        os.lseek(fd, len(partial), os.SEEK_SET)
        offset = len(partial)
        while offset < len(expected):
            offset += os.write(fd, expected[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, marker)
    _fsync_directory(tx_dir)


def _write_phase_marker(tx_dir: Path, marker_name: str, data: bytes) -> bool:
    marker = tx_dir / marker_name
    if _lexists(marker):
        if _read_bounded(marker, len(data)) != data:
            _fail(f"transaction phase marker mismatch: {marker_name}")
        return False
    _recover_phase_marker_staging(tx_dir, marker_name, data)
    if _lexists(marker):
        if _read_bounded(marker, len(data)) != data:
            _fail(f"transaction phase marker mismatch: {marker_name}")
        return False
    temp = _phase_marker_temp(tx_dir, marker_name)
    _write_file(temp, data)
    _fsync_directory(tx_dir)
    os.replace(temp, marker)
    _fsync_directory(tx_dir)
    return True


def _manifest_bytes(value: dict[str, Any]) -> bytes:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    if len(data) > MAX_MANIFEST_BYTES:
        _fail("transaction manifest exceeds size bound")
    return data


def _config_from_args(args: argparse.Namespace) -> dict[str, str]:
    paths = {
        "opsctl": str(_safe_absolute(args.opsctl_link, "opsctl_link")),
        "mcp": str(_safe_absolute(args.mcp_link, "mcp_link")),
        "gemini": str(_safe_absolute(args.gemini_link, "gemini_link")),
        "manifest": str(_safe_absolute(args.manifest_link, "manifest_link")),
        "current": str(_safe_absolute(args.current_link, "current_link")),
    }
    if len(set(paths.values())) != len(paths):
        _fail("managed activation paths must be pairwise distinct")
    return paths


def _validate_endpoint_isolation(
    paths: dict[str, str], broker_unit: Path, pending_dir: Path
) -> None:
    endpoints = [*(Path(value) for value in paths.values()), broker_unit]
    staging_endpoints = [_temp_path(path) for path in endpoints]
    visible_paths = [*endpoints, *staging_endpoints]
    if len({str(path) for path in visible_paths}) != len(visible_paths):
        _fail(
            "broker, managed activation paths, and derived staging paths "
            "must be pairwise distinct"
        )
    reserved = {
        pending_dir,
        Path(f"{pending_dir}.new"),
        Path(f"{pending_dir}.complete"),
        Path(f"{pending_dir}.recovered.complete"),
        Path(f"{pending_dir}.recovered.acknowledged"),
        Path(f"{pending_dir}.recovered.retired"),
        pending_dir.parent / ".activation-candidate.prepare",
    }
    for endpoint in visible_paths:
        _validate_root_controlled_parent_chain(endpoint, f"activation endpoint {endpoint}")
        if any(
            endpoint == root or root in endpoint.parents or endpoint in root.parents
            for root in reserved
        ):
            _fail("managed activation endpoint overlaps transaction storage")
    install_root = pending_dir.parent
    if Path(paths["manifest"]) != install_root / ".agent-runtime-ops-manifest":
        _fail("manifest activation endpoint is not the fixed install-root child")
    if Path(paths["current"]) != install_root / "current":
        _fail("current activation endpoint is not the fixed install-root child")


def _validate_candidate_release(candidate_release: Path, releases_dir: Path) -> None:
    meta = os.lstat(candidate_release)
    if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
        _fail("candidate release must be a fixed directory")
    releases_real = os.path.realpath(releases_dir)
    candidate_real = os.path.realpath(candidate_release)
    if os.path.dirname(candidate_real) != releases_real:
        _fail("candidate release is outside releases directory")


def _candidate_payloads(
    candidate_dir: Path,
) -> tuple[dict[str, bytes], dict[str, str], bytes]:
    meta = os.lstat(candidate_dir)
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != 0
        or meta.st_gid != 0
        or stat.S_IMODE(meta.st_mode) != 0o700
    ):
        _fail("candidate identity directory must be root:root 0700")
    expected = {*REGULAR_NAMES, "manifest-target", "current-target", "broker-unit"}
    actual = {entry.name for entry in os.scandir(candidate_dir)}
    if actual != expected:
        _fail("candidate identity directory has unexpected entries")
    regular: dict[str, bytes] = {}
    for name in REGULAR_NAMES:
        path = candidate_dir / name
        file_meta = os.lstat(path)
        if (
            not stat.S_ISREG(file_meta.st_mode)
            or stat.S_ISLNK(file_meta.st_mode)
            or file_meta.st_uid != 0
            or file_meta.st_gid != 0
            or stat.S_IMODE(file_meta.st_mode) != 0o600
            or file_meta.st_nlink != 1
        ):
            _fail(f"candidate {name}: root:root 0600 single-link file required")
        regular[name] = _read_bounded(path)
    targets: dict[str, str] = {}
    for name in ("manifest", "current"):
        raw = _read_bounded(candidate_dir / f"{name}-target", 4096)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TransactionError(f"candidate {name} target is not UTF-8") from exc
        if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
            _fail(f"candidate {name} target must be exactly one line")
        target = text[:-1]
        if not target or any(ord(char) < 32 or ord(char) == 127 for char in target):
            _fail(f"candidate {name} target is unsafe")
        targets[name] = target
    broker_unit = _read_bounded(candidate_dir / "broker-unit")
    broker_meta = os.lstat(candidate_dir / "broker-unit")
    if (
        not stat.S_ISREG(broker_meta.st_mode)
        or stat.S_ISLNK(broker_meta.st_mode)
        or broker_meta.st_uid != 0
        or broker_meta.st_gid != 0
        or stat.S_IMODE(broker_meta.st_mode) != 0o600
        or broker_meta.st_nlink != 1
    ):
        _fail("candidate broker unit: root:root 0600 single-link file required")
    return regular, targets, broker_unit


def begin(args: argparse.Namespace) -> None:
    if os.geteuid() != 0:
        _fail("activation transaction requires root")
    tx_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    stage_dir = Path(f"{tx_dir}.new")
    install_root = _safe_absolute(args.install_root, "install_root")
    releases_dir = _safe_absolute(args.releases_dir, "releases_dir")
    candidate_release = _safe_absolute(args.candidate_release, "candidate_release")
    candidate_dir = _safe_absolute(args.candidate_dir, "candidate_dir")
    paths = _config_from_args(args)
    ops_gid = int(args.ops_gid)
    if ops_gid < 0:
        _fail("ops_gid must be a nonnegative platform gid")
    completion_dirs = (
        Path(f"{tx_dir}.complete"),
        Path(f"{tx_dir}.recovered.complete"),
        Path(f"{tx_dir}.recovered.retired"),
    )
    if _lexists(tx_dir) or _lexists(stage_dir) or any(
        _lexists(path) for path in completion_dirs
    ):
        _fail("activation transaction or staging path already exists")
    if tx_dir != install_root / ".activation-transaction.pending":
        _fail("transaction path must be the fixed install-root child")
    if releases_dir != install_root / "releases":
        _fail("releases path must be the fixed install-root child")
    if candidate_dir != install_root / ".activation-candidate.prepare":
        _fail("candidate identity path must be the fixed install-root child")
    _validate_root_controlled_directory(install_root, "install_root")
    _validate_root_controlled_directory(releases_dir, "releases_dir")
    if not args.candidate_commit or len(args.candidate_commit) != 40 or any(
        char not in "0123456789abcdef" for char in args.candidate_commit
    ):
        _fail("candidate commit must be an exact lowercase full SHA")
    _validate_candidate_release(candidate_release, releases_dir)
    candidate_regular, candidate_targets, candidate_broker = _candidate_payloads(
        candidate_dir
    )
    if candidate_targets["manifest"] != "current/.agent-runtime-ops-manifest":
        _fail("candidate manifest target is not canonical")
    expected_current_target = f"releases/{candidate_release.name}"
    if candidate_targets["current"] != expected_current_target:
        _fail("candidate current target is not exact")
    if not candidate_release.name.startswith(f"{args.candidate_commit}."):
        _fail("candidate release name is not bound to the candidate commit")
    broker_unit = _safe_absolute(args.broker_unit, "broker_unit")
    broker_service_name = args.broker_service_name
    broker_state = args.broker_state
    broker_unit_file_state = args.broker_unit_file_state
    if (
        broker_state not in BROKER_STATES
        or broker_unit_file_state not in BROKER_UNIT_FILE_STATES
        or not broker_service_name
        or "/" in broker_service_name
        or "\\" in broker_service_name
        or any(ord(char) < 33 or ord(char) == 127 for char in broker_service_name)
    ):
        _fail("broker state, unit-file state, or service name is invalid")
    if broker_unit.name != broker_service_name:
        _fail("broker service name must equal the fixed unit basename")
    _validate_endpoint_isolation(paths, broker_unit, tx_dir)

    previous_release = args.previous_release
    # An absent first-install baseline still publishes the broker unit, but it
    # must remain inactive and disabled until a separately authorized
    # activation.  Baseline absence and candidate target state are therefore
    # deliberately distinct.
    desired_broker_state = "inactive" if broker_state == "absent" else broker_state
    desired_unit_file_state = (
        "disabled" if broker_unit_file_state == "absent" else broker_unit_file_state
    )
    carried_baseline_state = broker_state
    carried_baseline_unit_file_state = broker_unit_file_state
    if broker_state == "active" and broker_unit_file_state == "enabled":
        carried_baseline_state = "inactive"
        carried_baseline_unit_file_state = "disabled"
    reactivation_origin: dict[str, Any] | None = None
    carrier_dir = Path(f"{tx_dir}.recovered.acknowledged")
    if _lexists(carrier_dir):
        carrier_tx, carrier_manifest = _load_transaction(
            args, recovered_state="acknowledged"
        )
        carrier_broker = carrier_manifest["broker"]
        if (
            carrier_manifest["phase"]
            not in {"recovered_active_intent", "recovered_intent_claimed"}
            or carrier_manifest["candidate_commit"] != args.candidate_commit
            or carrier_manifest["previous_release"] != (previous_release or None)
            or carrier_broker["service_name"] != broker_service_name
            or broker_state != "inactive"
            or broker_unit_file_state != "disabled"
        ):
            _fail("recovered broker intent does not match the new activation")
        _require_live_variant(
            carrier_tx, carrier_manifest, "baseline", "recovered broker intent baseline"
        )
        _claim_reactivation_carrier(carrier_tx, carrier_manifest)
        _require_live_variant(
            carrier_tx,
            carrier_manifest,
            "baseline",
            "claimed recovered broker intent baseline",
        )
        reactivation_origin = _reactivation_origin(carrier_tx, carrier_manifest)
        desired_broker_state = reactivation_origin["desired_state"]
        desired_unit_file_state = reactivation_origin["desired_unit_file_state"]
    entries: dict[str, dict[str, dict[str, Any]]] = {}
    baseline_payloads: dict[str, bytes] = {}
    if not previous_release:
        for name, raw_path in paths.items():
            if _lexists(Path(raw_path)):
                _fail(f"first install requires exact absence: {name}")
            entries[name] = {"baseline": _absent_meta(), "candidate": {}}
    else:
        previous = _safe_absolute(previous_release, "previous_release")
        previous_meta = os.lstat(previous)
        if not stat.S_ISDIR(previous_meta.st_mode) or stat.S_ISLNK(previous_meta.st_mode):
            _fail("previous release must be a fixed directory")
        if os.path.dirname(os.path.realpath(previous)) != os.path.realpath(releases_dir):
            _fail("previous release is not an exact child of releases directory")
        current_path = Path(paths["current"])
        current_meta = _symlink_meta(
            current_path,
            expected_uid=0,
            expected_gid=ops_gid,
            expected_target=f"releases/{previous.name}",
        )
        if os.path.realpath(current_path) != str(previous):
            _fail("current does not resolve to exact previous release")
        entries["current"] = {"baseline": current_meta, "candidate": {}}
        manifest_meta = _symlink_meta(
            Path(paths["manifest"]),
            expected_uid=0,
            expected_gid=ops_gid,
            expected_target="current/.agent-runtime-ops-manifest",
        )
        entries["manifest"] = {"baseline": manifest_meta, "candidate": {}}
        for name in REGULAR_NAMES:
            baseline_meta, data = _regular_meta(
                Path(paths[name]),
                expected_uid=0,
                expected_gid=ops_gid,
                expected_mode=0o755,
            )
            entries[name] = {"baseline": baseline_meta, "candidate": {}}
            baseline_payloads[name] = data

    for name in REGULAR_NAMES:
        data = candidate_regular[name]
        entries[name]["candidate"] = {
            "kind": "regular",
            "sha256": _sha256(data),
            "bytes": len(data),
            "mode": 0o755,
            "uid": 0,
            "gid": ops_gid,
            "nlink": 1,
        }
    for name in SYMLINK_NAMES:
        entries[name]["candidate"] = {
            "kind": "symlink",
            "target": candidate_targets[name],
            "mode": 0o777,
            "uid": 0,
            "gid": ops_gid,
            "nlink": 1,
        }

    broker_baseline_payload: bytes | None = None
    if _lexists(broker_unit):
        broker_baseline, broker_baseline_payload = _regular_meta(
            broker_unit,
            expected_uid=0,
            expected_gid=0,
            expected_mode=0o644,
        )
    else:
        broker_baseline = _absent_meta()
    if broker_state == "absent" and (
        broker_unit_file_state != "absent" or broker_baseline["kind"] != "absent"
    ):
        _fail("absent broker state requires an absent unit")
    if broker_state in {"active", "inactive"} and (
        broker_unit_file_state not in {"enabled", "disabled"}
        or broker_baseline["kind"] != "regular"
    ):
        _fail("active or inactive broker state requires a regular unit")
    if broker_state == "unavailable" and broker_unit_file_state != "unavailable":
        _fail("unavailable broker state requires unavailable unit-file state")
    if broker_state == "active" and not previous_release:
        _fail("an active broker requires an exact previous release")
    if reactivation_origin is not None and (
        broker_baseline["kind"] != "regular"
        or broker_baseline["sha256"]
        != reactivation_origin["baseline_unit_sha256"]
    ):
        _fail("recovered broker intent baseline unit changed")
    broker_candidate = {
        "kind": "regular",
        "sha256": _sha256(candidate_broker),
        "bytes": len(candidate_broker),
        "mode": 0o644,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
    }

    manifest = {
        "schema": SCHEMA,
        "phase": "publishing",
        "candidate_commit": args.candidate_commit,
        "candidate_release": str(candidate_release),
        "previous_release": previous_release or None,
        "ops_gid": ops_gid,
        "paths": paths,
        "entries": entries,
        "broker": {
            "unit_path": str(broker_unit),
            "service_name": broker_service_name,
            "baseline_state": broker_state,
            "baseline_unit_file_state": broker_unit_file_state,
            "carried_baseline_state": carried_baseline_state,
            "carried_baseline_unit_file_state": carried_baseline_unit_file_state,
            "desired_state": desired_broker_state,
            "desired_unit_file_state": desired_unit_file_state,
            "reactivation_origin": reactivation_origin,
            "baseline": broker_baseline,
            "candidate": broker_candidate,
        },
    }
    for name, raw_path in {**paths, BROKER_NAME: str(broker_unit)}.items():
        if _lexists(_temp_path(Path(raw_path))):
            _fail(f"reserved activation staging path already exists: {name}")
    os.mkdir(stage_dir, 0o700)
    os.chown(stage_dir, 0, 0)
    os.chmod(stage_dir, 0o700)
    for name, data in baseline_payloads.items():
        _write_file(stage_dir / f"baseline-{name}", data)
    for name, data in candidate_regular.items():
        _write_file(stage_dir / f"candidate-{name}", data)
    if broker_baseline_payload is not None:
        _write_file(stage_dir / "baseline-broker", broker_baseline_payload)
    _write_file(stage_dir / "candidate-broker", candidate_broker)
    _write_file(stage_dir / "manifest.json", _manifest_bytes(manifest))
    _fsync_directory(stage_dir)
    os.rename(stage_dir, tx_dir)
    _fsync_directory(install_root)
    _retire_adopted_carrier(args, manifest)


def _validate_meta(
    value: Any,
    where: str,
    *,
    allowed_kinds: set[str],
    expected_gid: int,
    expected_regular_mode: int,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{where}: object required")
    kind = value.get("kind")
    if kind not in allowed_kinds:
        _fail(f"{where}: unsupported identity kind")
    if kind == "absent":
        _exact_keys(value, ABSENT_KEYS, where)
    elif kind == "regular":
        _exact_keys(value, REGULAR_KEYS, where)
        if (
            not isinstance(value.get("sha256"), str)
            or len(value["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in value["sha256"])
            or not isinstance(value.get("bytes"), int)
            or not 0 <= value["bytes"] <= MAX_WRAPPER_BYTES
            or value.get("mode") != expected_regular_mode
            or value.get("uid") != 0
            or value.get("gid") != expected_gid
            or value.get("nlink") != 1
        ):
            _fail(f"{where}: invalid regular identity")
    elif kind == "symlink":
        _exact_keys(value, SYMLINK_KEYS, where)
        target = value.get("target")
        if (
            not isinstance(target, str)
            or not target
            or any(ord(char) < 32 or ord(char) == 127 for char in target)
            or value.get("mode") != 0o777
            or value.get("uid") != 0
            or value.get("gid") != expected_gid
            or value.get("nlink") != 1
        ):
            _fail(f"{where}: invalid symlink identity")
    else:
        _fail(f"{where}: unsupported kind")
    return value


def _load_transaction(
    args: argparse.Namespace, *, recovered_state: str | None = None
) -> tuple[Path, dict[str, Any]]:
    pending_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    if pending_dir.name != ".activation-transaction.pending":
        _fail("transaction path is not the fixed pending identity")
    recovered_suffixes = {
        "complete": ".recovered.complete",
        "acknowledged": ".recovered.acknowledged",
        "retired": ".recovered.retired",
    }
    if recovered_state is not None and recovered_state not in recovered_suffixes:
        _fail("unsupported recovered transaction identity")
    tx_dir = (
        Path(f"{pending_dir}{recovered_suffixes[recovered_state]}")
        if recovered_state is not None
        else pending_dir
    )
    _validate_root_controlled_directory(tx_dir.parent, "transaction parent")
    meta = os.lstat(tx_dir)
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != 0
        or meta.st_gid != 0
        or stat.S_IMODE(meta.st_mode) != 0o700
        or meta.st_nlink != 2
    ):
        _fail("transaction directory must be root:root 0700 with no subdirectories")
    manifest_path = tx_dir / "manifest.json"
    raw = _read_bounded(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransactionError("invalid transaction manifest") from exc
    if not isinstance(manifest, dict):
        _fail("transaction manifest must be an object")
    _exact_keys(manifest, TRANSACTION_KEYS, "manifest")
    if manifest.get("schema") != SCHEMA:
        _fail("transaction schema mismatch")
    if manifest.get("phase") != "publishing":
        _fail("transaction phase is invalid")
    paths = _config_from_args(args)
    if manifest.get("paths") != paths:
        _fail("transaction paths do not match installer configuration")
    ops_gid = manifest.get("ops_gid")
    if not isinstance(ops_gid, int) or ops_gid < 0 or ops_gid != int(args.ops_gid):
        _fail("transaction group does not match installer configuration")
    candidate_commit = manifest.get("candidate_commit")
    if (
        not isinstance(candidate_commit, str)
        or len(candidate_commit) != 40
        or any(char not in "0123456789abcdef" for char in candidate_commit)
    ):
        _fail("transaction candidate commit is invalid")
    candidate_release = _safe_absolute(
        manifest.get("candidate_release", ""), "candidate_release"
    )
    if candidate_release.parent != pending_dir.parent / "releases":
        _fail("transaction candidate release is outside the fixed install root")
    if not candidate_release.name.startswith(f"{candidate_commit}."):
        _fail("candidate release name is not bound to the candidate commit")
    previous_release = manifest.get("previous_release")
    if previous_release is not None:
        if not isinstance(previous_release, str):
            _fail("previous release must be a string or null")
        previous = _safe_absolute(previous_release, "previous_release")
        if previous.parent != candidate_release.parent or previous == candidate_release:
            _fail("previous release is not an exact sibling of candidate release")
    entries = manifest.get("entries")
    if not isinstance(entries, dict) or set(entries) != set(ENTRY_NAMES):
        _fail("transaction entries mismatch")
    expected_files = {
        "manifest.json",
        *(f"candidate-{name}" for name in REGULAR_NAMES),
        "candidate-broker",
    }
    for marker_name, marker_bytes in (
        ("recovered", RECOVERED_MARKER_BYTES),
        (START_DISPATCH_MARKER, b"start_dispatch_committed\n"),
        (ACTIVE_ATTESTED_MARKER, b"active_attested\n"),
    ):
        _recover_phase_marker_staging(tx_dir, marker_name, marker_bytes)
    recovered_marker = tx_dir / "recovered"
    recovered_intent_marker = tx_dir / RECOVERED_INTENT_MARKER
    adoption_claimed_marker = tx_dir / ADOPTION_CLAIMED_MARKER
    revoked_intent_marker = tx_dir / REVOKED_INTENT_MARKER
    dispatch_marker = tx_dir / START_DISPATCH_MARKER
    active_marker = tx_dir / ACTIVE_ATTESTED_MARKER
    if sum(
        int(_lexists(path))
        for path in (
            recovered_marker,
            recovered_intent_marker,
            adoption_claimed_marker,
            revoked_intent_marker,
        )
    ) > 1:
        _fail("transaction has conflicting recovery phase markers")
    if _lexists(recovered_marker):
        expected_files.add("recovered")
        manifest["phase"] = "recovered"
    if _lexists(recovered_intent_marker):
        expected_files.add(RECOVERED_INTENT_MARKER)
        manifest["phase"] = "recovered_active_intent"
    if _lexists(adoption_claimed_marker):
        expected_files.add(ADOPTION_CLAIMED_MARKER)
        manifest["phase"] = "recovered_intent_claimed"
    if _lexists(revoked_intent_marker):
        expected_files.add(REVOKED_INTENT_MARKER)
        manifest["phase"] = "recovered_intent_revoked"
    if _lexists(dispatch_marker):
        expected_files.add(START_DISPATCH_MARKER)
    if _lexists(active_marker):
        expected_files.add(ACTIVE_ATTESTED_MARKER)
    if _lexists(active_marker) and not _lexists(dispatch_marker):
        _fail("active attestation marker lacks dispatch commitment")
    if manifest["phase"] != "publishing" and (
        _lexists(dispatch_marker) or _lexists(active_marker)
    ):
        _fail("recovered transaction cannot carry broker dispatch markers")
    if recovered_state is not None and manifest["phase"] not in {
        "recovered",
        "recovered_active_intent",
        "recovered_intent_claimed",
        "recovered_intent_revoked",
    }:
        _fail("recovered completion identity lacks its recovery marker")
    for name in ENTRY_NAMES:
        entry = entries[name]
        if not isinstance(entry, dict):
            _fail(f"entries.{name}: object required")
        _exact_keys(entry, ENTRY_KEYS, f"entries.{name}")
        allowed_baseline = {"absent", "regular"} if name in REGULAR_NAMES else {"absent", "symlink"}
        allowed_candidate = {"regular"} if name in REGULAR_NAMES else {"symlink"}
        baseline = _validate_meta(
            entry["baseline"],
            f"entries.{name}.baseline",
            allowed_kinds=allowed_baseline,
            expected_gid=ops_gid,
            expected_regular_mode=0o755,
        )
        _validate_meta(
            entry["candidate"],
            f"entries.{name}.candidate",
            allowed_kinds=allowed_candidate,
            expected_gid=ops_gid,
            expected_regular_mode=0o755,
        )
        if baseline["kind"] == "regular":
            expected_files.add(f"baseline-{name}")
    baseline_kinds = {entries[name]["baseline"]["kind"] for name in ENTRY_NAMES}
    if previous_release is None:
        if baseline_kinds != {"absent"}:
            _fail("first-install baseline must be exactly all absent")
    else:
        if any(entries[name]["baseline"]["kind"] != "regular" for name in REGULAR_NAMES):
            _fail("previous-install wrapper baseline is incomplete")
        if any(entries[name]["baseline"]["kind"] != "symlink" for name in SYMLINK_NAMES):
            _fail("previous-install symlink baseline is incomplete")
        if entries["manifest"]["baseline"]["target"] != "current/.agent-runtime-ops-manifest":
            _fail("baseline manifest target is not canonical")
        expected_previous_target = f"releases/{Path(previous_release).name}"
        if entries["current"]["baseline"]["target"] != expected_previous_target:
            _fail("baseline current target is not exact")
    if entries["manifest"]["candidate"]["target"] != "current/.agent-runtime-ops-manifest":
        _fail("candidate manifest target is not canonical")
    if entries["current"]["candidate"]["target"] != f"releases/{candidate_release.name}":
        _fail("candidate current target is not exact")

    broker = manifest.get("broker")
    if not isinstance(broker, dict):
        _fail("broker transaction object is required")
    _exact_keys(broker, BROKER_KEYS, "broker")
    broker_unit_path = _safe_absolute(broker.get("unit_path", ""), "broker.unit_path")
    if broker_unit_path != _safe_absolute(args.broker_unit, "broker_unit"):
        _fail("broker unit path does not match installer configuration")
    _validate_endpoint_isolation(paths, broker_unit_path, pending_dir)
    service_name = broker.get("service_name")
    if (
        not isinstance(service_name, str)
        or not service_name
        or "/" in service_name
        or "\\" in service_name
        or any(ord(char) < 33 or ord(char) == 127 for char in service_name)
    ):
        _fail("broker service name is invalid")
    if broker_unit_path.name != service_name:
        _fail("broker service name does not match the unit basename")
    baseline_state = broker.get("baseline_state")
    baseline_unit_file_state = broker.get("baseline_unit_file_state")
    carried_baseline_state = broker.get("carried_baseline_state")
    carried_baseline_unit_file_state = broker.get(
        "carried_baseline_unit_file_state"
    )
    desired_state = broker.get("desired_state")
    desired_unit_file_state = broker.get("desired_unit_file_state")
    if (
        baseline_state not in BROKER_STATES
        or carried_baseline_state not in BROKER_STATES
        or desired_state not in BROKER_STATES
        or baseline_unit_file_state not in BROKER_UNIT_FILE_STATES
        or carried_baseline_unit_file_state not in BROKER_UNIT_FILE_STATES
        or desired_unit_file_state not in BROKER_UNIT_FILE_STATES
    ):
        _fail("broker runtime or unit-file state is invalid")
    broker_baseline = _validate_meta(
        broker["baseline"],
        "broker.baseline",
        allowed_kinds={"absent", "regular"},
        expected_gid=0,
        expected_regular_mode=0o644,
    )
    broker_candidate = _validate_meta(
        broker["candidate"],
        "broker.candidate",
        allowed_kinds={"regular"},
        expected_gid=0,
        expected_regular_mode=0o644,
    )
    if baseline_state == "absent" and (
        baseline_unit_file_state != "absent" or broker_baseline["kind"] != "absent"
    ):
        _fail("absent broker state requires an absent baseline unit")
    if baseline_state in {"active", "inactive"} and (
        baseline_unit_file_state not in {"enabled", "disabled"}
        or broker_baseline["kind"] != "regular"
    ):
        _fail("active or inactive broker state requires a regular baseline unit")
    if baseline_state == "unavailable" and baseline_unit_file_state != "unavailable":
        _fail("unavailable broker state requires unavailable unit-file state")
    if desired_state == "absent" and desired_unit_file_state != "absent":
        _fail("absent desired broker state requires absent unit-file state")
    if desired_state in {"active", "inactive"} and desired_unit_file_state not in {
        "enabled",
        "disabled",
    }:
        _fail("loaded desired broker state requires enabled or disabled unit-file state")
    if desired_state == "unavailable" and desired_unit_file_state != "unavailable":
        _fail("unavailable desired state requires unavailable unit-file state")
    if baseline_state == "active" and previous_release is None:
        _fail("an active broker requires a previous release")
    origin = broker.get("reactivation_origin")
    if origin is not None:
        if not isinstance(origin, dict):
            _fail("broker reactivation origin must be an object or null")
        _exact_keys(origin, REACTIVATION_ORIGIN_KEYS, "broker reactivation origin")
        if (
            origin.get("schema") != REACTIVATION_ORIGIN_SCHEMA
            or not isinstance(origin.get("source_manifest_sha256"), str)
            or len(origin["source_manifest_sha256"]) != 64
            or any(
                char not in "0123456789abcdef"
                for char in origin["source_manifest_sha256"]
            )
            or origin.get("failed_candidate_commit") != candidate_commit
            or origin.get("previous_release") != previous_release
            or origin.get("service_name") != service_name
            or not isinstance(origin.get("baseline_unit_sha256"), str)
            or len(origin["baseline_unit_sha256"]) != 64
            or any(
                char not in "0123456789abcdef"
                for char in origin["baseline_unit_sha256"]
            )
            or origin.get("desired_state") != "active"
            or origin.get("desired_unit_file_state") != "enabled"
            or broker_baseline["kind"] != "regular"
            or origin.get("baseline_unit_sha256") != broker_baseline["sha256"]
            or baseline_state != "inactive"
            or baseline_unit_file_state != "disabled"
            or carried_baseline_state != "inactive"
            or carried_baseline_unit_file_state != "disabled"
            or desired_state != "active"
            or desired_unit_file_state != "enabled"
        ):
            _fail("broker reactivation origin binding is invalid")
    elif baseline_state == "absent":
        if desired_state != "inactive" or desired_unit_file_state != "disabled":
            _fail("absent baseline requires an inactive disabled candidate target")
    elif (
        desired_state != baseline_state
        or desired_unit_file_state != baseline_unit_file_state
    ):
        _fail("ordinary broker desired state must equal its baseline state")
    if baseline_state == "active" and baseline_unit_file_state == "enabled":
        if (
            carried_baseline_state != "inactive"
            or carried_baseline_unit_file_state != "disabled"
        ):
            _fail("active enabled broker requires an inactive disabled carry baseline")
    elif (
        carried_baseline_state != baseline_state
        or carried_baseline_unit_file_state != baseline_unit_file_state
    ):
        _fail("ordinary carried baseline must equal the recorded baseline")
    if (_lexists(dispatch_marker) or _lexists(active_marker)) and origin is None:
        _fail("broker dispatch markers require a carried reactivation origin")
    if manifest["phase"] == "recovered_active_intent" and (
        desired_state != "active"
        or desired_unit_file_state != "enabled"
        or carried_baseline_state != "inactive"
        or carried_baseline_unit_file_state != "disabled"
    ):
        _fail("recovered active intent has no exact active+enabled target")
    if broker_baseline["kind"] == "regular":
        expected_files.add("baseline-broker")
    actual_files = {entry.name for entry in os.scandir(tx_dir)}
    if actual_files != expected_files:
        _fail("transaction directory has unexpected or missing files")
    for filename in expected_files:
        file_meta = os.lstat(tx_dir / filename)
        if (
            not stat.S_ISREG(file_meta.st_mode)
            or stat.S_ISLNK(file_meta.st_mode)
            or file_meta.st_uid != 0
            or file_meta.st_gid != 0
            or stat.S_IMODE(file_meta.st_mode) != 0o600
            or file_meta.st_nlink != 1
        ):
            _fail(f"transaction file is unsafe: {filename}")
    for marker_name, marker_bytes in (
        # Recovery intent and revocation are atomic renames of the same exact
        # root-owned marker.  The filename is the monotonic phase authority;
        # preserving the bytes makes every rename immediately self-validating.
        (RECOVERED_INTENT_MARKER, RECOVERED_MARKER_BYTES),
        (ADOPTION_CLAIMED_MARKER, RECOVERED_MARKER_BYTES),
        (REVOKED_INTENT_MARKER, RECOVERED_MARKER_BYTES),
        (START_DISPATCH_MARKER, b"start_dispatch_committed\n"),
        (ACTIVE_ATTESTED_MARKER, b"active_attested\n"),
    ):
        if _lexists(tx_dir / marker_name) and _read_bounded(
            tx_dir / marker_name, 128
        ) != marker_bytes:
            _fail(f"transaction phase marker mismatch: {marker_name}")
    for name in REGULAR_NAMES:
        for variant in ("baseline", "candidate"):
            identity = entries[name][variant]
            if identity["kind"] != "regular":
                continue
            data = _read_bounded(tx_dir / f"{variant}-{name}")
            if len(data) != identity["bytes"] or _sha256(data) != identity["sha256"]:
                _fail(f"transaction payload digest mismatch: {variant}-{name}")
    for variant, identity in (
        ("baseline", broker_baseline),
        ("candidate", broker_candidate),
    ):
        if identity["kind"] != "regular":
            continue
        data = _read_bounded(tx_dir / f"{variant}-broker")
        if len(data) != identity["bytes"] or _sha256(data) != identity["sha256"]:
            _fail(f"transaction payload digest mismatch: {variant}-broker")
    return tx_dir, manifest


def _matches(path: Path, identity: dict[str, Any], data: bytes | None) -> bool:
    kind = _kind(path)
    if kind != identity["kind"]:
        return False
    if kind == "absent":
        return True
    meta = os.lstat(path)
    if (
        meta.st_uid != identity["uid"]
        or meta.st_gid != identity["gid"]
        or stat.S_IMODE(meta.st_mode) != identity["mode"]
        or meta.st_nlink != identity["nlink"]
    ):
        return False
    if kind == "symlink":
        return os.readlink(path) == identity["target"]
    if kind == "regular":
        if data is None:
            return False
        try:
            current = _read_bounded(path)
        except (OSError, TransactionError):
            return False
        return len(current) == identity["bytes"] and _sha256(current) == identity["sha256"]
    return False


def _payload(tx_dir: Path, name: str, variant: str) -> bytes | None:
    path = tx_dir / f"{variant}-{name}"
    if not _lexists(path):
        return None
    return _read_bounded(path)


def _temp_path(path: Path) -> Path:
    return Path(f"{path}.agent-runtime-activation-next")


def _safe_recovery_temp(
    path: Path,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    baseline_data: bytes | None,
    candidate_data: bytes | None,
    *,
    expected_gid: int,
) -> bool:
    if not _lexists(path):
        return True
    if _matches(path, baseline, baseline_data) or _matches(path, candidate, candidate_data):
        return True
    meta = os.lstat(path)
    if stat.S_ISLNK(meta.st_mode):
        targets = {
            identity["target"]
            for identity in (baseline, candidate)
            if identity["kind"] == "symlink"
        }
        return (
            meta.st_uid == 0
            and meta.st_gid in {0, expected_gid}
            and meta.st_nlink == 1
            and os.readlink(path) in targets
        )
    # A kill can land after O_EXCL creation but before the payload, ownership,
    # or final mode is complete.  Only the fixed staging name, root ownership,
    # a single regular link, and a bounded size make that partial file safe to
    # discard.  A symlink has one legitimate prefix state: its exact raw target
    # exists but lchown has not yet moved it from root:root to root:ops_gid.
    if not (
        (baseline["kind"] == "regular" or candidate["kind"] == "regular")
        and stat.S_ISREG(meta.st_mode)
        and not stat.S_ISLNK(meta.st_mode)
        and meta.st_uid == 0
        and meta.st_gid in {0, expected_gid}
        and meta.st_nlink == 1
        and meta.st_size <= MAX_WRAPPER_BYTES
        and stat.S_IMODE(meta.st_mode)
        in {0o600, baseline.get("mode"), candidate.get("mode")}
    ):
        return False
    try:
        partial = _read_bounded(path)
    except (OSError, TransactionError):
        return False
    return any(
        payload.startswith(partial)
        for payload in (baseline_data, candidate_data)
        if payload is not None
    )


def _preflight_variant_union(tx_dir: Path, manifest: dict[str, Any]) -> None:
    identities = [
        (name, Path(manifest["paths"][name]), manifest["entries"][name], manifest["ops_gid"])
        for name in ENTRY_NAMES
    ]
    identities.append(
        (
            BROKER_NAME,
            Path(manifest["broker"]["unit_path"]),
            manifest["broker"],
            0,
        )
    )
    for name, path, entry, expected_gid in identities:
        baseline_data = _payload(tx_dir, name, "baseline")
        candidate_data = _payload(tx_dir, name, "candidate")
        if not (
            _matches(path, entry["baseline"], baseline_data)
            or _matches(path, entry["candidate"], candidate_data)
        ):
            _fail(f"managed entry drifted outside transaction identities: {name}")
        temp = _temp_path(path)
        if not _safe_recovery_temp(
            temp,
            entry["baseline"],
            entry["candidate"],
            baseline_data,
            candidate_data,
            expected_gid=expected_gid,
        ):
            _fail(f"activation staging entry is unsafe: {name}")


def _remove_existing(path: Path) -> None:
    if _lexists(path):
        os.unlink(path)
        _fsync_directory(path.parent)


def _publish_regular(path: Path, data: bytes, identity: dict[str, Any]) -> None:
    temp = _temp_path(path)
    if _lexists(temp):
        _fail(f"staging path already exists: {temp}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fchmod(fd, identity["mode"])
        os.fchown(fd, identity["uid"], identity["gid"])
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)
    os.replace(temp, path)
    _fsync_directory(path.parent)


def _publish_symlink(path: Path, identity: dict[str, Any]) -> None:
    temp = _temp_path(path)
    if _lexists(temp):
        _fail(f"staging path already exists: {temp}")
    os.symlink(identity["target"], temp)
    os.lchown(temp, identity["uid"], identity["gid"])
    _fsync_directory(path.parent)
    os.replace(temp, path)
    _fsync_directory(path.parent)


def _publish_identity(path: Path, identity: dict[str, Any], data: bytes | None) -> None:
    if identity["kind"] == "absent":
        _remove_existing(path)
    elif identity["kind"] == "regular":
        if data is None:
            _fail(f"missing payload for {path}")
        _publish_regular(path, data, identity)
    elif identity["kind"] == "symlink":
        _publish_symlink(path, identity)
    else:
        _fail(f"unsupported identity for {path}")


def _set_phase(tx_dir: Path, manifest: dict[str, Any], phase: str) -> None:
    if phase != "recovered":
        _fail("unsupported transaction phase")
    _write_phase_marker(tx_dir, "recovered", RECOVERED_MARKER_BYTES)
    manifest["phase"] = phase


def _all_identities(manifest: dict[str, Any]) -> list[tuple[str, Path, dict[str, Any]]]:
    values = [
        (name, Path(manifest["paths"][name]), manifest["entries"][name])
        for name in ENTRY_NAMES
    ]
    values.append(
        (BROKER_NAME, Path(manifest["broker"]["unit_path"]), manifest["broker"])
    )
    return values


def _require_live_variant(
    tx_dir: Path, manifest: dict[str, Any], variant: str, where: str
) -> None:
    if variant not in {"baseline", "candidate"}:
        _fail("unsupported live identity variant")
    for name, path, entry in _all_identities(manifest):
        if not _matches(path, entry[variant], _payload(tx_dir, name, variant)):
            _fail(f"{where} does not match: {name}")
        if _lexists(_temp_path(path)):
            _fail(f"{where} has staging residue: {name}")


def _reactivation_origin(tx_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    broker = manifest["broker"]
    if (
        manifest["phase"]
        not in {
            "recovered_active_intent",
            "recovered_intent_claimed",
            "recovered_intent_revoked",
        }
        or broker["desired_state"] != "active"
        or broker["desired_unit_file_state"] != "enabled"
        or broker["carried_baseline_state"] != "inactive"
        or broker["carried_baseline_unit_file_state"] != "disabled"
        or broker["baseline"]["kind"] != "regular"
        or manifest["previous_release"] is None
    ):
        _fail("recovered transaction is not an active broker intent carrier")
    existing = broker["reactivation_origin"]
    if existing is not None:
        return existing
    return {
        "schema": REACTIVATION_ORIGIN_SCHEMA,
        "source_manifest_sha256": _sha256(
            _read_bounded(tx_dir / "manifest.json", MAX_MANIFEST_BYTES)
        ),
        "failed_candidate_commit": manifest["candidate_commit"],
        "previous_release": manifest["previous_release"],
        "service_name": broker["service_name"],
        "baseline_unit_sha256": broker["baseline"]["sha256"],
        "desired_state": "active",
        "desired_unit_file_state": "enabled",
    }


def _claim_reactivation_carrier(
    tx_dir: Path, manifest: dict[str, Any]
) -> None:
    if manifest["phase"] == "recovered_intent_claimed":
        _fsync_directory(tx_dir)
        return
    if manifest["phase"] != "recovered_active_intent":
        _fail("recovered broker intent cannot be claimed from the current phase")
    intent = tx_dir / RECOVERED_INTENT_MARKER
    claimed = tx_dir / ADOPTION_CLAIMED_MARKER
    os.rename(intent, claimed)
    _fsync_directory(tx_dir)
    manifest["phase"] = "recovered_intent_claimed"


def _validate_carrier_binding(
    tx_dir: Path, manifest: dict[str, Any], origin: dict[str, Any]
) -> None:
    if manifest["phase"] != "recovered_intent_claimed":
        _fail("recovered broker intent was not atomically claimed for adoption")
    if _reactivation_origin(tx_dir, manifest) != origin:
        _fail("recovered broker intent origin mismatch")


def _retire_adopted_carrier(
    args: argparse.Namespace, manifest: dict[str, Any]
) -> None:
    origin = manifest["broker"]["reactivation_origin"]
    if origin is None:
        return
    pending_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    acknowledged = Path(f"{pending_dir}.recovered.acknowledged")
    retired = Path(f"{pending_dir}.recovered.retired")
    if _lexists(acknowledged) and _lexists(retired):
        _fail("multiple broker intent carrier identities exist")
    if not _lexists(acknowledged) and not _lexists(retired):
        return
    if _lexists(acknowledged):
        carrier_dir, carrier_manifest = _load_transaction(
            args, recovered_state="acknowledged"
        )
        _validate_carrier_binding(carrier_dir, carrier_manifest, origin)
        os.rename(acknowledged, retired)
        _fsync_directory(retired.parent)
    # Once the exact acknowledged carrier has been atomically renamed, the
    # pending manifest already owns its immutable origin binding.  Cleanup of
    # the retired identity is intentionally safe-name/idempotent rather than a
    # second strict transaction load, so SIGKILL after any unlink can replay.
    _cleanup_fixed_directory(retired, _transaction_cleanup_names())


def publish(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _retire_adopted_carrier(args, manifest)
    if manifest["phase"] != "publishing":
        _fail("recovered transaction cannot be republished")
    for name in ENTRY_NAMES:
        path = Path(manifest["paths"][name])
        identity = manifest["entries"][name]["baseline"]
        if not _matches(path, identity, _payload(tx_dir, name, "baseline")):
            _fail(f"pre-publication baseline changed: {name}")
        if _lexists(_temp_path(path)):
            _fail(f"pre-publication staging path exists: {name}")
    for name in ENTRY_NAMES:
        path = Path(manifest["paths"][name])
        identity = manifest["entries"][name]["candidate"]
        candidate_data = _payload(tx_dir, name, "candidate")
        if not _matches(path, identity, candidate_data):
            _publish_identity(path, identity, candidate_data)


def publish_broker(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _retire_adopted_carrier(args, manifest)
    if manifest["phase"] != "publishing":
        _fail("recovered transaction cannot publish a broker unit")
    path = Path(manifest["broker"]["unit_path"])
    entry = manifest["broker"]
    baseline_data = _payload(tx_dir, BROKER_NAME, "baseline")
    candidate_data = _payload(tx_dir, BROKER_NAME, "candidate")
    if not (
        _matches(path, entry["baseline"], baseline_data)
        or _matches(path, entry["candidate"], candidate_data)
    ):
        _fail("broker unit drifted outside transaction identities")
    temp = _temp_path(path)
    if _lexists(temp):
        _fail("broker staging path exists")
    if not _matches(path, entry["candidate"], candidate_data):
        _publish_identity(path, entry["candidate"], candidate_data)


def recover(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _retire_adopted_carrier(args, manifest)
    if _lexists(tx_dir / START_DISPATCH_MARKER):
        _fail("broker start dispatch is committed; recovery cannot redispatch or rewind")
    _preflight_variant_union(tx_dir, manifest)
    for name, path, _entry in _all_identities(manifest):
        _remove_existing(_temp_path(path))
    for name, path, entry in _all_identities(manifest):
        identity = entry["baseline"]
        data = _payload(tx_dir, name, "baseline")
        if not _matches(path, identity, data):
            _publish_identity(path, identity, data)
    for name, path, entry in _all_identities(manifest):
        identity = entry["baseline"]
        if not _matches(path, identity, _payload(tx_dir, name, "baseline")):
            _fail(f"baseline restoration did not converge: {name}")
    if manifest["phase"] == "publishing":
        _set_phase(tx_dir, manifest, "recovered")


def defer_broker_reactivation(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    broker = manifest["broker"]
    expected_previous = _safe_absolute(
        args.expected_previous_release, "expected_previous_release"
    )
    if (
        manifest["phase"] not in {"recovered", "recovered_active_intent"}
        or manifest["candidate_commit"] != args.expected_commit
        or manifest["previous_release"] != str(expected_previous)
        or broker["service_name"] != args.expected_service_name
        or broker["desired_state"] != "active"
        or broker["desired_unit_file_state"] != "enabled"
        or broker["carried_baseline_state"] != "inactive"
        or broker["carried_baseline_unit_file_state"] != "disabled"
    ):
        _fail("broker reactivation deferral authority mismatch")
    if broker["reactivation_origin"] is None and (
        broker["baseline_state"] != "active"
        or broker["baseline_unit_file_state"] != "enabled"
    ):
        _fail("broker reactivation deferral has no recorded active+enabled intent")
    _require_live_variant(tx_dir, manifest, "baseline", "deferred broker baseline")
    recovered = tx_dir / "recovered"
    intent = tx_dir / RECOVERED_INTENT_MARKER
    if _lexists(intent):
        if _read_bounded(intent, 128) != RECOVERED_MARKER_BYTES:
            _fail("broker reactivation intent marker mismatch")
        _fsync_directory(tx_dir)
        print("broker_reactivation_intent=preserved")
        return
    if not _lexists(recovered):
        _fail("broker reactivation deferral requires recovered phase")
    os.rename(recovered, intent)
    _fsync_directory(tx_dir)
    print("broker_reactivation_intent=recorded")


def revoke_broker_reactivation(args: argparse.Namespace) -> None:
    pending_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    if _lexists(pending_dir):
        _fail("broker reactivation authority already transferred to pending activation")
    tx_dir, manifest = _load_transaction(args, recovered_state="acknowledged")
    broker = manifest["broker"]
    origin = _reactivation_origin(tx_dir, manifest)
    expected_previous = _safe_absolute(
        args.expected_previous_release, "expected_previous_release"
    )
    if (
        manifest["candidate_commit"] != args.expected_commit
        or manifest["previous_release"] != str(expected_previous)
        or broker["service_name"] != args.expected_service_name
        or origin["source_manifest_sha256"] != args.expected_origin_sha256
    ):
        _fail("broker reactivation revocation authority mismatch")
    revoked = tx_dir / REVOKED_INTENT_MARKER
    if _lexists(revoked):
        _fsync_directory(tx_dir)
        print("broker_reactivation_revocation=preserved")
        return
    if manifest["phase"] == "recovered_intent_claimed":
        _fail("broker reactivation authority is already claimed for adoption")
    intent = tx_dir / RECOVERED_INTENT_MARKER
    if not _lexists(intent):
        _fail("broker reactivation revocation requires an exact carried intent")
    os.rename(intent, revoked)
    _fsync_directory(tx_dir)
    print("broker_reactivation_revocation=recorded")


def _broker_activation_phase(tx_dir: Path, manifest: dict[str, Any]) -> str:
    if manifest["phase"] == "recovered_active_intent":
        return "recovered_intent"
    if manifest["broker"]["reactivation_origin"] is None:
        return "none"
    if _lexists(tx_dir / ACTIVE_ATTESTED_MARKER):
        return "active_attested"
    if _lexists(tx_dir / START_DISPATCH_MARKER):
        return "start_dispatch_committed"
    return "candidate_bound"


def _validate_broker_activation_args(
    args: argparse.Namespace, tx_dir: Path, manifest: dict[str, Any]
) -> None:
    broker = manifest["broker"]
    if (
        manifest["candidate_commit"] != args.expected_commit
        or manifest["candidate_release"] != args.expected_candidate_release
        or broker["service_name"] != args.expected_service_name
        or broker["desired_state"] != "active"
        or broker["desired_unit_file_state"] != "enabled"
        or broker["reactivation_origin"] is None
    ):
        _fail("candidate broker activation binding mismatch")
    _require_live_variant(tx_dir, manifest, "candidate", "candidate broker activation")


def commit_broker_start(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _retire_adopted_carrier(args, manifest)
    _validate_broker_activation_args(args, tx_dir, manifest)
    phase = _broker_activation_phase(tx_dir, manifest)
    if phase != "candidate_bound":
        _fail("broker start dispatch cannot advance from the current phase")
    if not _write_phase_marker(
        tx_dir, START_DISPATCH_MARKER, b"start_dispatch_committed\n"
    ):
        _fail("broker start dispatch was already committed")
    print("broker_start_dispatch=committed")


def mark_broker_active(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _validate_broker_activation_args(args, tx_dir, manifest)
    phase = _broker_activation_phase(tx_dir, manifest)
    if phase == "active_attested":
        print("broker_active_attestation=preserved")
        return
    if phase != "start_dispatch_committed":
        _fail("broker active attestation requires a committed start dispatch")
    _write_phase_marker(tx_dir, ACTIVE_ATTESTED_MARKER, b"active_attested\n")
    print("broker_active_attestation=recorded")


def finalize(args: argparse.Namespace) -> None:
    tx_dir, manifest = _load_transaction(args)
    _retire_adopted_carrier(args, manifest)
    candidate_complete_dir = Path(f"{tx_dir}.complete")
    recovered_complete_dir = Path(f"{tx_dir}.recovered.complete")
    recovered_acknowledged_dir = Path(f"{tx_dir}.recovered.acknowledged")
    recovered_retired_dir = Path(f"{tx_dir}.recovered.retired")
    if (
        _lexists(candidate_complete_dir)
        or _lexists(recovered_complete_dir)
        or _lexists(recovered_acknowledged_dir)
        or _lexists(recovered_retired_dir)
    ):
        _fail("activation completion path already exists")
    variant = args.expect
    if variant not in {"baseline", "candidate"}:
        _fail("finalize expect must be baseline or candidate")
    if variant == "baseline" and manifest["phase"] not in {
        "recovered",
        "recovered_active_intent",
    }:
        _fail("baseline finalization requires a recovered transaction")
    if (
        variant == "baseline"
        and manifest["broker"]["reactivation_origin"] is not None
        and manifest["phase"] != "recovered_active_intent"
    ):
        _fail("carried broker intent must be re-deferred before baseline finalization")
    if variant == "candidate" and manifest["phase"] != "publishing":
        _fail("candidate finalization requires a publishing transaction")
    if (
        variant == "candidate"
        and manifest["broker"]["reactivation_origin"] is not None
        and _broker_activation_phase(tx_dir, manifest) != "active_attested"
    ):
        _fail("carried broker activation requires exact active attestation")
    complete_dir = (
        recovered_complete_dir if variant == "baseline" else candidate_complete_dir
    )
    for name, path, entry in _all_identities(manifest):
        identity = entry[variant]
        if not _matches(path, identity, _payload(tx_dir, name, variant)):
            _fail(f"cannot finalize nonmatching {variant} identity: {name}")
        if _lexists(_temp_path(path)):
            _fail(f"cannot finalize with staging residue: {name}")
    os.rename(tx_dir, complete_dir)
    _fsync_directory(complete_dir.parent)
    if variant == "baseline":
        # The recovered identity remains durable until an exact next-start
        # acknowledgement verifies the commit and complete baseline.  This
        # prevents a kill between recovery finalization and the shell's
        # terminal stop from being mistaken for a clean activation frontier.
        return
    for entry in list(os.scandir(complete_dir)):
        os.unlink(entry.path)
    _fsync_directory(complete_dir)
    os.rmdir(complete_dir)
    _fsync_directory(complete_dir.parent)


def show(args: argparse.Namespace) -> None:
    _tx_dir, manifest = _load_transaction(args)
    field = args.field
    if field not in {
        "candidate_commit",
        "candidate_release",
        "previous_release",
        "broker_state",
        "broker_unit_file_state",
        "broker_carried_baseline_state",
        "broker_carried_baseline_unit_file_state",
        "broker_desired_state",
        "broker_desired_unit_file_state",
        "broker_activation_phase",
        "broker_service_name",
    }:
        _fail("unsupported transaction field")
    if field == "broker_state":
        value = manifest["broker"]["baseline_state"]
    elif field == "broker_unit_file_state":
        value = manifest["broker"]["baseline_unit_file_state"]
    elif field == "broker_carried_baseline_state":
        value = manifest["broker"]["carried_baseline_state"]
    elif field == "broker_carried_baseline_unit_file_state":
        value = manifest["broker"]["carried_baseline_unit_file_state"]
    elif field == "broker_desired_state":
        value = manifest["broker"]["desired_state"]
    elif field == "broker_desired_unit_file_state":
        value = manifest["broker"]["desired_unit_file_state"]
    elif field == "broker_activation_phase":
        value = _broker_activation_phase(_tx_dir, manifest)
    elif field == "broker_service_name":
        value = manifest["broker"]["service_name"]
    else:
        value = manifest[field]
    if value is None:
        value = ""
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        _fail("transaction field is not a safe single line")
    print(value)


def _cleanup_fixed_directory(path: Path, allowed_names: set[str]) -> None:
    meta = os.lstat(path)
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != 0
        or meta.st_gid != 0
        or stat.S_IMODE(meta.st_mode) != 0o700
    ):
        _fail(f"unsafe abandoned staging path: {path}")
    entries = list(os.scandir(path))
    if any(entry.name not in allowed_names for entry in entries):
        _fail(f"abandoned staging path has unexpected entries: {path}")
    for entry in entries:
        child_meta = os.lstat(entry.path)
        if (
            not stat.S_ISREG(child_meta.st_mode)
            or stat.S_ISLNK(child_meta.st_mode)
            or child_meta.st_uid != 0
            or child_meta.st_gid != 0
            or stat.S_IMODE(child_meta.st_mode) != 0o600
            or child_meta.st_nlink != 1
        ):
            _fail(f"unsafe abandoned staging entry: {entry.path}")
    for entry in entries:
        os.unlink(entry.path)
    _fsync_directory(path)
    os.rmdir(path)
    _fsync_directory(path.parent)


def _transaction_cleanup_names() -> set[str]:
    return {
        "manifest.json",
        "recovered",
        RECOVERED_INTENT_MARKER,
        ADOPTION_CLAIMED_MARKER,
        REVOKED_INTENT_MARKER,
        START_DISPATCH_MARKER,
        ACTIVE_ATTESTED_MARKER,
        *(
            _phase_marker_temp(Path("."), marker).name
            for marker in ("recovered", START_DISPATCH_MARKER, ACTIVE_ATTESTED_MARKER)
        ),
        *(f"baseline-{name}" for name in (*REGULAR_NAMES, BROKER_NAME)),
        *(f"candidate-{name}" for name in (*REGULAR_NAMES, BROKER_NAME)),
    }


def acknowledge_recovered(args: argparse.Namespace) -> None:
    pending_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    if pending_dir.name != ".activation-transaction.pending":
        _fail("transaction path is not the fixed pending identity")
    complete_dir = Path(f"{pending_dir}.recovered.complete")
    acknowledged_dir = Path(f"{pending_dir}.recovered.acknowledged")
    retired_dir = Path(f"{pending_dir}.recovered.retired")
    existing = [
        path for path in (complete_dir, acknowledged_dir, retired_dir) if _lexists(path)
    ]
    if len(existing) > 1:
        _fail("multiple recovered completion identities exist")
    if _lexists(retired_dir):
        _cleanup_fixed_directory(retired_dir, _transaction_cleanup_names())
        print("recovered_completion_cleaned=yes")
        return
    if not existing:
        print("recovered_completion=absent")
        return
    recovered_state = "acknowledged" if _lexists(acknowledged_dir) else "complete"
    tx_dir, manifest = _load_transaction(args, recovered_state=recovered_state)
    if manifest["candidate_commit"] != args.expected_commit:
        _fail("recovered completion belongs to a different exact source commit")
    if manifest["broker"]["reactivation_origin"] is not None:
        allowed_origin_phases = (
            {"recovered_active_intent"}
            if recovered_state == "complete"
            else {
                "recovered_active_intent",
                "recovered_intent_claimed",
                "recovered_intent_revoked",
            }
        )
        if manifest["phase"] not in allowed_origin_phases:
            _fail("origin-bearing recovered completion lost its typed intent phase")
    for name, path, entry in _all_identities(manifest):
        identity = entry["baseline"]
        if not _matches(path, identity, _payload(tx_dir, name, "baseline")):
            _fail(f"recovered completion baseline does not match: {name}")
        if _lexists(_temp_path(path)):
            _fail(f"recovered completion has staging residue: {name}")
    if recovered_state == "complete":
        os.rename(complete_dir, acknowledged_dir)
        _fsync_directory(acknowledged_dir.parent)
        print("recovered_completion_acknowledged=yes")
        return
    if manifest["phase"] == "recovered_active_intent":
        _fsync_directory(acknowledged_dir.parent)
        print("broker_reactivation_intent=ready")
        return
    if manifest["phase"] == "recovered_intent_claimed":
        _fsync_directory(acknowledged_dir.parent)
        print("broker_reactivation_intent=adoption_claimed")
        return
    if manifest["phase"] == "recovered_intent_revoked":
        os.rename(acknowledged_dir, retired_dir)
        _fsync_directory(retired_dir.parent)
        _cleanup_fixed_directory(retired_dir, _transaction_cleanup_names())
        print("broker_reactivation_intent=revoked")
        return
    os.rename(acknowledged_dir, retired_dir)
    _fsync_directory(retired_dir.parent)
    _cleanup_fixed_directory(retired_dir, _transaction_cleanup_names())
    print("recovered_completion_cleaned=yes")


def cleanup_staging(args: argparse.Namespace) -> None:
    install_root = _safe_absolute(args.install_root, "install_root")
    tx_dir = _safe_absolute(args.transaction_dir, "transaction_dir")
    candidate_dir = _safe_absolute(args.candidate_dir, "candidate_dir")
    if tx_dir != install_root / ".activation-transaction.pending":
        _fail("transaction cleanup path is not the fixed install-root child")
    if candidate_dir != install_root / ".activation-candidate.prepare":
        _fail("candidate cleanup path is not the fixed install-root child")
    allowed = {
        candidate_dir,
        Path(f"{tx_dir}.new"),
        Path(f"{tx_dir}.complete"),
    }
    candidate_names = {*REGULAR_NAMES, "manifest-target", "current-target", "broker-unit"}
    transaction_names = _transaction_cleanup_names()
    for raw in args.path:
        path = _safe_absolute(raw, "staging path")
        if path not in allowed:
            _fail(f"staging cleanup path is not an exact reserved identity: {path}")
        if not _lexists(path):
            continue
        allowed_names = candidate_names if path == candidate_dir else transaction_names
        _cleanup_fixed_directory(path, allowed_names)


def fsync_tree(args: argparse.Namespace) -> None:
    releases_dir = _safe_absolute(args.releases_dir, "releases_dir")
    root = _safe_absolute(args.path, "path")
    if root.parent != releases_dir or not _lexists(root):
        _fail("durability tree must be an exact existing release child")
    root_meta = os.lstat(root)
    if not stat.S_ISDIR(root_meta.st_mode) or stat.S_ISLNK(root_meta.st_mode):
        _fail("durability tree root must be a fixed directory")
    directories: list[Path] = []
    count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        meta = os.lstat(directory)
        if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
            _fail(f"durability walk encountered an unsafe directory: {directory}")
        directories.append(directory)
        for entry in os.scandir(directory):
            count += 1
            if count > MAX_DURABILITY_ENTRIES:
                _fail("release durability tree exceeds the entry bound")
            entry_meta = entry.stat(follow_symlinks=False)
            path = Path(entry.path)
            if stat.S_ISDIR(entry_meta.st_mode):
                stack.append(path)
            elif stat.S_ISREG(entry_meta.st_mode):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                try:
                    opened = os.fstat(fd)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink)
                        != (
                            entry_meta.st_dev,
                            entry_meta.st_ino,
                            entry_meta.st_mode,
                            entry_meta.st_nlink,
                        )
                    ):
                        _fail(f"durability file changed type: {path}")
                    os.fsync(fd)
                    after = os.fstat(fd)
                    if (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_nlink,
                        opened.st_size,
                        opened.st_mtime_ns,
                        opened.st_ctime_ns,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                        after.st_nlink,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        _fail(f"durability file changed while flushing: {path}")
                finally:
                    os.close(fd)
            elif stat.S_ISLNK(entry_meta.st_mode):
                continue
            else:
                _fail(f"unsupported release entry type during durability flush: {path}")
    for directory in reversed(directories):
        _fsync_directory(directory)
    _fsync_directory(releases_dir)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(command: str) -> argparse.ArgumentParser:
        sub = subparsers.add_parser(command)
        sub.add_argument("--transaction-dir", required=True)
        sub.add_argument("--ops-gid", required=True, type=int)
        sub.add_argument("--opsctl-link", required=True)
        sub.add_argument("--mcp-link", required=True)
        sub.add_argument("--gemini-link", required=True)
        sub.add_argument("--manifest-link", required=True)
        sub.add_argument("--current-link", required=True)
        sub.add_argument("--broker-unit", required=True)
        return sub

    begin_parser = common("begin")
    begin_parser.add_argument("--install-root", required=True)
    begin_parser.add_argument("--releases-dir", required=True)
    begin_parser.add_argument("--candidate-dir", required=True)
    begin_parser.add_argument("--candidate-release", required=True)
    begin_parser.add_argument("--candidate-commit", required=True)
    begin_parser.add_argument("--previous-release", default="")
    begin_parser.add_argument("--broker-service-name", required=True)
    begin_parser.add_argument("--broker-state", required=True)
    begin_parser.add_argument("--broker-unit-file-state", required=True)
    common("publish")
    common("publish-broker")
    common("recover")
    defer_parser = common("defer-broker-reactivation")
    defer_parser.add_argument("--expected-commit", required=True)
    defer_parser.add_argument("--expected-previous-release", required=True)
    defer_parser.add_argument("--expected-service-name", required=True)
    revoke_parser = common("revoke-broker-reactivation")
    revoke_parser.add_argument("--expected-commit", required=True)
    revoke_parser.add_argument("--expected-previous-release", required=True)
    revoke_parser.add_argument("--expected-service-name", required=True)
    revoke_parser.add_argument("--expected-origin-sha256", required=True)
    for command in ("commit-broker-start", "mark-broker-active"):
        broker_parser = common(command)
        broker_parser.add_argument("--expected-commit", required=True)
        broker_parser.add_argument("--expected-candidate-release", required=True)
        broker_parser.add_argument("--expected-service-name", required=True)
    acknowledge_parser = common("ack-recovered")
    acknowledge_parser.add_argument("--expected-commit", required=True)
    finalize_parser = common("finalize")
    finalize_parser.add_argument("--expect", required=True)
    show_parser = common("show")
    show_parser.add_argument("--field", required=True)
    cleanup_parser = subparsers.add_parser("cleanup-staging")
    cleanup_parser.add_argument("--install-root", required=True)
    cleanup_parser.add_argument("--transaction-dir", required=True)
    cleanup_parser.add_argument("--candidate-dir", required=True)
    cleanup_parser.add_argument("--path", action="append", required=True)
    fsync_parser = subparsers.add_parser("fsync-tree")
    fsync_parser.add_argument("--releases-dir", required=True)
    fsync_parser.add_argument("--path", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if os.geteuid() != 0:
        _fail("activation transaction requires root")
    if args.command == "begin":
        begin(args)
    elif args.command == "publish":
        publish(args)
    elif args.command == "publish-broker":
        publish_broker(args)
    elif args.command == "recover":
        recover(args)
    elif args.command == "defer-broker-reactivation":
        defer_broker_reactivation(args)
    elif args.command == "revoke-broker-reactivation":
        revoke_broker_reactivation(args)
    elif args.command == "commit-broker-start":
        commit_broker_start(args)
    elif args.command == "mark-broker-active":
        mark_broker_active(args)
    elif args.command == "ack-recovered":
        acknowledge_recovered(args)
    elif args.command == "finalize":
        finalize(args)
    elif args.command == "show":
        show(args)
    elif args.command == "cleanup-staging":
        cleanup_staging(args)
    elif args.command == "fsync-tree":
        fsync_tree(args)
    else:  # pragma: no cover
        _fail("unsupported command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TransactionError, ValueError) as exc:
        print(f"activation_transaction_error={exc}", file=sys.stderr)
        raise SystemExit(1) from None
