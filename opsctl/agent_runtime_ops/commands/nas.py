from __future__ import annotations

import argparse
from datetime import datetime
import getpass
import json
import os
from pathlib import Path
import sys
import time

def _cli_mod():
    from .. import cli

    return cli


def _state_root(args: argparse.Namespace) -> Path:
    return _cli_mod()._state_root(args)


def _is_root() -> bool:
    return _cli_mod()._is_root()


def _now_iso() -> str:
    return _cli_mod()._now_iso()


def _run_text(command: list[str], timeout: int = 20):
    return _cli_mod()._run_text(command, timeout=timeout)


def _read_key_value_file(path: Path) -> dict[str, str]:
    return _cli_mod()._read_key_value_file(path)


def _atomic_write_key_value(path: Path, data: dict[str, str], mode: int, uid: int | None = None, gid: int | None = None) -> None:
    return _cli_mod()._atomic_write_key_value(path, data, mode, uid, gid)


def _slot_uid_gid(slot: str) -> tuple[int, int]:
    return _cli_mod()._slot_uid_gid(slot)


def _runtime_ids(slot: str) -> tuple[int, int, int]:
    return _cli_mod()._runtime_ids(slot)


def _ensure_customer_agent_dirs(slot: str) -> None:
    return _cli_mod()._ensure_customer_agent_dirs(slot)


def _read_password_from_stdin() -> str:
    return _cli_mod()._read_password_from_stdin()


def _write_credential_file(path: Path, username: str, password: str, domain: str | None, uid: int, gid: int) -> None:
    return _cli_mod()._write_credential_file(path, username, password, domain, uid, gid)


def _credential_file_is_safe_for_slot(slot: str, path: Path, uid: int | None = None) -> None:
    return _cli_mod()._credential_file_is_safe_for_slot(slot, path, uid=uid)


def _credential_presence(path: Path) -> str:
    return _cli_mod()._credential_presence(path)


def _host_write_managed_fstab_entry(*args, **kwargs) -> None:
    return _cli_mod()._host_write_managed_fstab_entry(*args, **kwargs)


def _remove_managed_fstab_entry(*args, **kwargs):
    return _cli_mod()._remove_managed_fstab_entry(*args, **kwargs)


def _safe_mountpoint_path(path: Path) -> None:
    return _cli_mod()._safe_mountpoint_path(path)


def _mounted_child_cifs_count(slot: str) -> int:
    return _cli_mod()._mounted_child_cifs_count(slot)


def _findmnt_one(path: Path | str):
    return _cli_mod()._findmnt_one(path)


def _findmnt_under(path: str):
    return _cli_mod()._findmnt_under(path)


def _host_mount_prepared_share(decision):
    return _cli_mod()._host_mount_prepared_share(decision)


def _is_readonly_mount(row: dict[str, str]) -> bool:
    return _cli_mod()._is_readonly_mount(row)


def load_runtime_bindings(state_root: Path):
    return _cli_mod().load_runtime_bindings(state_root)


def get_runtime_binding(target: str, state_root: Path):
    return _cli_mod().get_runtime_binding(target, state_root)


def load_runtime_target(target: str, state_root: Path):
    return _cli_mod().load_runtime_target(target, state_root)


def agent_nas_dir(slot: str) -> Path:
    return _cli_mod().agent_nas_dir(slot)


def check_nas_policy(slot: str, share: str, state_root: Path):
    return _cli_mod().check_nas_policy(slot, share, state_root)


def customer_credential_path(slot: str, share) -> Path:
    return _cli_mod().customer_credential_path(slot, share)


def history_dir(slot: str, status: str) -> Path:
    return _cli_mod().history_dir(slot, status)


def mountpoint_for_share(slot: str, share) -> Path:
    return _cli_mod().mountpoint_for_share(slot, share)


def parse_smb_share(value: str):
    return _cli_mod().parse_smb_share(value)


def request_dir(slot: str) -> Path:
    return _cli_mod().request_dir(slot)


def request_path(slot: str, share) -> Path:
    return _cli_mod().request_path(slot, share)


def root_credential_path(slot: str, share) -> Path:
    return _cli_mod().root_credential_path(slot, share)


def _official_credential_paths(slot: str, share) -> dict[str, Path]:
    return {
        "root": root_credential_path(slot, share),
        "customer": customer_credential_path(slot, share),
    }


def _combine_presence(*values: str) -> str:
    if "yes" in values:
        return "yes"
    if "unknown" in values:
        return "unknown"
    return "no"


def _official_credential_status(slot: str, share) -> dict[str, str]:
    paths = _official_credential_paths(slot, share)
    root_present = _credential_presence(paths["root"])
    customer_present = _credential_presence(paths["customer"])
    official_present = _combine_presence(root_present, customer_present)
    return {
        "root_credential_present": root_present,
        "customer_credential_present": customer_present,
        "official_credential_present": official_present,
        "remount_possible": "yes" if official_present == "yes" else official_present,
    }


def _print_official_credential_status(prefix: str, status: dict[str, str]) -> None:
    for key in [
        "root_credential_present",
        "customer_credential_present",
        "official_credential_present",
        "remount_possible",
    ]:
        print(f"{prefix}{key}={status[key]}")


def _write_managed_fstab_entry(
    slot: str,
    share: str,
    mountpoint: Path,
    credential_path: Path,
    *,
    claim_existing_same_source: bool = False,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> None:
    _host_write_managed_fstab_entry(
        slot,
        share,
        mountpoint,
        credential_path,
        slot_uid_gid=_slot_uid_gid,
        runtime_ids=_runtime_ids,
        claim_existing_same_source=claim_existing_same_source,
        fstab_path=fstab_path,
        lock_path=lock_path,
    )


def _append_action_log(state_root: Path, action: str, slot: str, target: str, status: str, detail: str = "") -> None:
    log_path = state_root / "actions.log"
    if state_root.is_symlink():
        raise ValueError(f"action log state root must not be symlink: {state_root}")
    state_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    if log_path.exists() and log_path.is_symlink():
        raise ValueError(f"action log must not be symlink: {log_path}")
    record = {
        "timestamp": _now_iso(),
        "action": action,
        "slot": slot,
        "target": target,
        "status": status,
        "detail": str(detail or "")[:500],
    }
    if action.startswith("nas_") or (isinstance(target, str) and target.startswith("//")):
        record["share"] = target
    with log_path.open("a", encoding="utf-8") as handle:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _prepare_mount_entry(
    slot: str,
    share_source: str,
    credential_path: Path,
    state_root: Path,
    *,
    claim_existing_same_source: bool = False,
) -> tuple[object, Path]:
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    _safe_mountpoint_path(decision.mountpoint)
    decision.mountpoint.mkdir(parents=True, exist_ok=True)
    _safe_mountpoint_path(decision.mountpoint)
    _credential_file_is_safe_for_slot(slot, credential_path)
    current_count = _mounted_child_cifs_count(decision.slot)
    existing_rc, _, existing_rows = _findmnt_one(decision.mountpoint)
    already_same_mount = (
        existing_rc == 0
        and bool(existing_rows)
        and existing_rows[0].get("source") == decision.share.source
    )
    if not already_same_mount and not _max_mounts_allows(decision.max_mounts, current_count):
        raise ValueError(f"max_mounts_exceeded: current={current_count} max={decision.max_mounts}")
    _write_managed_fstab_entry(
        decision.slot,
        decision.share.source,
        decision.mountpoint,
        credential_path,
        claim_existing_same_source=claim_existing_same_source,
    )
    return decision, decision.mountpoint


def _rollback_fstab_after_mount_failure(args: argparse.Namespace, slot: str, share: str) -> str:
    if getattr(args, "keep_fstab_on_failure", False):
        return "kept"
    try:
        return "removed" if _remove_managed_fstab_entry(slot, share) else "not_found"
    except Exception as exc:
        return f"failed:{exc}"


def _move_request(path: Path, slot: str, status: str) -> Path:
    target_dir = history_dir(slot, status)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{datetime.now().strftime('%Y%m%dT%H%M%S')}.{path.name}"
    os.replace(path, target)
    return target


def _safe_request_file(path: Path, slot: str) -> None:
    uid, _ = _slot_uid_gid(slot)
    if path.is_symlink():
        raise ValueError(f"request file must not be symlink: {path}")
    stat_result = path.stat()
    if stat_result.st_uid != uid:
        raise ValueError(f"request file owner mismatch: {path}")
    if stat_result.st_mode & 0o022:
        raise ValueError(f"request file must not be group/world writable: {path}")


def _approve_auto_once(state_root: Path) -> dict[str, int]:
    result = {"checked": 0, "approved": 0, "pending": 0, "rejected": 0, "failed": 0}
    for binding in load_runtime_bindings(state_root):
        if binding.runtime_class != "customer":
            continue
        slot = binding.linux_account
        pending_dir = request_dir(slot)
        if not pending_dir.is_dir():
            continue
        for path in sorted(pending_dir.glob("*.env")):
            result["checked"] += 1
            try:
                _safe_request_file(path, slot)
                data = _read_key_value_file(path)
                share_source = data.get("requested_share") or ""
                decision = check_nas_policy(slot, share_source, state_root)
                if not decision.allowed:
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, share_source, "rejected", decision.reason)
                    result["rejected"] += 1
                    continue
                credential_path = customer_credential_path(slot, decision.share)
                if not credential_path.exists():
                    print(f"pending target={slot} share={decision.share.source} reason=credential_missing")
                    result["pending"] += 1
                    continue
                slot_uid, _ = _slot_uid_gid(slot)
                _credential_file_is_safe_for_slot(slot, credential_path, uid=slot_uid)
                decision, _ = _prepare_mount_entry(slot, decision.share.source, credential_path, state_root)
                ok, reason = _host_mount_prepared_share(decision)
                if ok:
                    _move_request(path, slot, "approved")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "approved", reason)
                    result["approved"] += 1
                else:
                    rollback = "removed" if _remove_managed_fstab_entry(decision.slot, decision.share.source) else "not_found"
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "rejected", f"{reason} fstab_entry_rollback={rollback}")
                    result["rejected"] += 1
                    result["failed"] += 1
            except Exception as exc:
                try:
                    share_source = _read_key_value_file(path).get("requested_share", "")
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, share_source, "rejected", str(exc))
                except Exception:
                    pass
                print(f"rejected target={slot} file={path} reason={exc}")
                result["rejected"] += 1
                result["failed"] += 1
    return result


def cmd_nas_requests(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    total = 0
    for binding in load_runtime_bindings(state_root):
        if binding.runtime_class != "customer":
            continue
        slot = binding.linux_account
        pending_dir = request_dir(slot)
        if not pending_dir.is_dir():
            continue
        for path in sorted(pending_dir.glob("*.env")):
            if path.is_symlink():
                continue
            try:
                data = _read_key_value_file(path)
            except Exception as exc:
                print(f"request target={slot} file={path.name} status=unreadable reason={exc}")
                total += 1
                continue
            share = data.get("requested_share") or ""
            created_at = data.get("created_at") or ""
            print(f"request target={slot} share={share} created_at={created_at} file={path}")
            total += 1
    print(f"pending_request_count={total}")
    print("nas_requests_status=ok")
    print("mutates=false")
    return 0


def cmd_nas_approve_auto(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas approve-auto", file=sys.stderr)
        return 2

    def run_once() -> int:
        result = _approve_auto_once(_state_root(args))
        print(f"checked_request_count={result['checked']}")
        print(f"approved_request_count={result['approved']}")
        print(f"pending_request_count={result['pending']}")
        print(f"rejected_request_count={result['rejected']}")
        print(f"approve_auto_status={'ok' if result['failed'] == 0 else 'fail'}")
        return 0 if result["failed"] == 0 else 1

    if not args.watch:
        return run_once()

    interval = max(5, int(args.interval))
    while True:
        tick_started = _now_iso()
        result = _approve_auto_once(_state_root(args))
        print(
            "nas_request_watch_tick "
            f"checked={result['checked']} approved={result['approved']} "
            f"pending={result['pending']} rejected={result['rejected']} failed={result['failed']} "
            f"tick_at={tick_started}",
            flush=True,
        )
        import time

        time.sleep(interval)


def cmd_nas_policy_check(args: argparse.Namespace) -> int:
    try:
        decision = check_nas_policy(args.slot, args.share, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("policy_check_status=fail")
        print(f"reason={exc}")
        print("mutates=false")
        return 1
    print(f"target={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    print(f"matched_grant={decision.matched_grant or ''}")
    print(f"max_mounts={decision.max_mounts if decision.max_mounts is not None else ''}")
    print(f"policy_check_status={'pass' if decision.allowed else 'fail'}")
    print(f"reason={decision.reason}")
    print("mutates=false")
    return 0 if decision.allowed else 1


def _caller_customer_slot(state_root: Path) -> str:
    user = getpass.getuser()
    binding = get_runtime_binding(user, state_root)
    if binding.linux_account != user or binding.runtime_class != "customer":
        raise ValueError(f"this command must be run by a customer linux_account, got {user}")
    return user


def cmd_nas_request(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot(_state_root(args))
        decision = check_nas_policy(slot, args.share, _state_root(args))
        if not decision.allowed:
            raise ValueError(f"policy denied: {decision.reason}")
        _ensure_customer_agent_dirs(slot)
        path = request_path(slot, decision.share)
        uid, gid = _slot_uid_gid(slot)
        _atomic_write_key_value(
            path,
            {
                "slot": slot,
                "requested_share": decision.share.source,
                "mountpoint": str(decision.mountpoint),
                "created_at": _now_iso(),
            },
            0o600,
            uid,
            gid,
        )
    except Exception as exc:
        print("request_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={slot}")
    print(f"requested_share={decision.share.source}")
    print(f"request_file={path}")
    print(f"mountpoint={decision.mountpoint}")
    print("request_status=pending")
    print("next_action=run opsctl nas credential set //HOST/SHARE --username NAS_USER --password-stdin")
    return 0


def cmd_nas_credential_set(args: argparse.Namespace) -> int:
    try:
        state_root = _state_root(args)
        slot = _caller_customer_slot(state_root)
        decision = check_nas_policy(slot, args.share, state_root)
        if not decision.allowed:
            raise ValueError(f"policy denied: {decision.reason}")
        slot = decision.slot
        password = _read_password_from_stdin()
        _ensure_customer_agent_dirs(slot)
        credential_path = customer_credential_path(slot, decision.share)
        uid, gid = _slot_uid_gid(slot)
        _write_credential_file(credential_path, args.username, password, args.domain, uid, gid)
    except Exception as exc:
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={slot}")
    print(f"share={decision.share.source}")
    print(f"credential_file={credential_path}")
    print("credential_status=stored")
    print("secret_value_printed=no")
    return 0


def _max_mounts_allows(value: object, current_count: int) -> bool:
    if value in {None, "", "unlimited"}:
        return True
    try:
        return current_count < int(value)
    except (TypeError, ValueError):
        return False


def _print_mount_row(prefix: str, row: dict[str, str]) -> None:
    print(f"{prefix}_target={row.get('target', '')}")
    print(f"{prefix}_source={row.get('source', '')}")
    print(f"{prefix}_fstype={row.get('fstype', '')}")
    print(f"{prefix}_readonly={'yes' if _is_readonly_mount(row) else 'no'}")
    if row.get("propagation"):
        print(f"{prefix}_propagation={row.get('propagation')}")


def cmd_nas_credential_status(args: argparse.Namespace) -> int:
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    status = _official_credential_status(slot, share)
    print(f"target={slot}")
    print(f"share={share.source}")
    print("credential_scope=official")
    print("mutates=false")
    _print_official_credential_status("", status)
    print("credential_status=ok")
    print("secret_value_printed=no")
    return 0


def cmd_nas_mounted(args: argparse.Namespace) -> int:
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print("mounted_status=fail")
        print(f"reason={exc}")
        return 1
    root = Path("/home") / desired.slot / "nas_docs"
    rc, error, rows = _findmnt_under(str(root))
    print(f"target={desired.slot}")
    print(f"nas_root={root}")
    print("mutates=false")
    if rc != 0:
        print("mounted_status=fail")
        print(f"reason={error or 'findmnt_failed'}")
        return 1
    child_rows = [row for row in rows if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")]
    print(f"mounted_child_cifs_count={len(child_rows)}")
    for index, row in enumerate(child_rows, start=1):
        prefix = f"mount_{index}"
        _print_mount_row(prefix, row)
        try:
            share = parse_smb_share(row.get("source", ""))
            _print_official_credential_status(f"{prefix}_", _official_credential_status(desired.slot, share))
        except Exception:
            print(f"{prefix}_official_credential_present=unknown")
            print(f"{prefix}_remount_possible=unknown")
    print("mounted_status=ok")
    return 0


def cmd_nas_mount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas mount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    credential_source = ""
    try:
        state_root = _state_root(args)
        decision = check_nas_policy(args.slot, args.share, state_root)
        slot = decision.slot
        if args.username or args.password_stdin:
            if not args.username or not args.password_stdin:
                raise ValueError("--username and --password-stdin must be used together")
            password = _read_password_from_stdin()
            credential_path = root_credential_path(slot, decision.share)
            _write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
            credential_source = "stdin"
        else:
            credential_path = root_credential_path(slot, decision.share)
            if credential_path.exists():
                credential_source = "official_root"
            else:
                credential_path = customer_credential_path(slot, decision.share)
                if credential_path.exists():
                    credential_source = "official_customer"
                else:
                    raise ValueError("credential_missing: pass --username USER --password-stdin or create an official credential")
        decision, _ = _prepare_mount_entry(
            slot,
            args.share,
            credential_path,
            state_root,
            claim_existing_same_source=True,
        )
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("mount_status=fail")
        print(f"reason={exc}")
        return 1

    rc, _, rows = _findmnt_one(decision.mountpoint)
    if rc == 0 and rows:
        row = rows[0]
        print(f"target={decision.slot}")
        print(f"share={decision.share.source}")
        print(f"credential_source={credential_source or 'unknown'}")
        print("secret_value_printed=no")
        _print_mount_row("existing_mount", row)
        ok = row.get("source") == decision.share.source and row.get("fstype") == "cifs" and _is_readonly_mount(row)
        print(f"mount_status={'already_mounted' if ok else 'fail'}")
        if not ok:
            print("reason=mountpoint_has_unexpected_existing_mount")
        _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "already_mounted" if ok else "fail")
        return 0 if ok else 1

    ok, reason = _host_mount_prepared_share(decision)
    rc, error, rows = _findmnt_one(decision.mountpoint)
    print(f"target={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    print(f"credential_source={credential_source or 'unknown'}")
    print("secret_value_printed=no")
    if rows:
        _print_mount_row("mounted", rows[0])
    print(f"mount_status={'ok' if ok else 'fail'}")
    if not ok:
        print(f"reason={reason or error or 'mounted_state_did_not_match_expected_cifs_ro'}")
        rollback = _rollback_fstab_after_mount_failure(args, decision.slot, decision.share.source)
        print(f"fstab_entry_rollback={rollback}")
    _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "ok" if ok else "fail", reason)
    return 0 if ok else 1


def cmd_nas_unmount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas unmount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(slot, share)
        _safe_mountpoint_path(mountpoint)
        credential_status = _official_credential_status(slot, share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("unmount_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, args.share, "fail", str(exc))
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    if rc != 0 or not rows:
        print(f"target={slot}")
        print(f"share={share.source}")
        print(f"mountpoint={mountpoint}")
        _print_official_credential_status("", credential_status)
        print("credential_removed=no")
        print("unmount_status=already_unmounted")
        _append_action_log(_state_root(args), "nas_unmount", slot, share.source, "already_unmounted")
        return 0
    row = rows[0]
    _print_mount_row("existing_mount", row)
    if row.get("source") != share.source:
        print("unmount_status=fail")
        print("reason=mountpoint_source_does_not_match_requested_share")
        _append_action_log(_state_root(args), "nas_unmount", slot, share.source, "fail", "mountpoint_source_does_not_match_requested_share")
        return 1

    command = ["umount"]
    if args.lazy:
        command.append("--lazy")
    command.append(str(mountpoint))
    proc = _run_text(command, timeout=60)
    if proc.returncode != 0:
        print("unmount_status=fail")
        print(f"reason={(proc.stderr or proc.stdout).strip()}")
        _append_action_log(_state_root(args), "nas_unmount", slot, share.source, "fail", (proc.stderr or proc.stdout).strip())
        return proc.returncode or 1
    if args.delete_empty_dir:
        try:
            mountpoint.rmdir()
            print("empty_dir_removed=yes")
        except OSError:
            print("empty_dir_removed=no")
    _print_official_credential_status("", credential_status)
    print("credential_removed=no")
    print("unmount_status=ok")
    _append_action_log(_state_root(args), "nas_unmount", slot, share.source, "ok", "credential_removed=no")
    return 0


def _validate_official_credentials_for_delete(slot: str, share) -> None:
    paths = _official_credential_paths(slot, share)
    slot_uid, _ = _slot_uid_gid(slot)
    for name, path in paths.items():
        if _credential_presence(path) == "yes":
            _credential_file_is_safe_for_slot(slot, path, uid=0 if name == "root" else slot_uid)


def _delete_official_credentials(slot: str, share) -> dict[str, str]:
    paths = _official_credential_paths(slot, share)
    removed: dict[str, str] = {}
    for name, path in paths.items():
        if _credential_presence(path) == "yes":
            path.unlink()
            removed[f"{name}_credential_removed"] = "yes"
        else:
            removed[f"{name}_credential_removed"] = "no"
    return removed


def cmd_nas_remove(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas remove TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(slot, share)
        _safe_mountpoint_path(mountpoint)
        before_status = _official_credential_status(slot, share)
        # Validate credentials before mutating mount or fstab state.
        _validate_official_credentials_for_delete(slot, share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("remove_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_remove", args.slot, args.share, "fail", str(exc))
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    unmount_status = "already_unmounted"
    if rc == 0 and rows:
        row = rows[0]
        _print_mount_row("existing_mount", row)
        if row.get("source") != share.source:
            print("remove_status=fail")
            print("reason=mountpoint_source_does_not_match_requested_share")
            _append_action_log(_state_root(args), "nas_remove", slot, share.source, "fail", "mountpoint_source_does_not_match_requested_share")
            return 1
        command = ["umount"]
        if args.lazy:
            command.append("--lazy")
        command.append(str(mountpoint))
        proc = _run_text(command, timeout=60)
        if proc.returncode != 0:
            print("unmount_status=fail")
            print("remove_status=fail")
            print(f"reason={(proc.stderr or proc.stdout).strip()}")
            _append_action_log(_state_root(args), "nas_remove", slot, share.source, "fail", (proc.stderr or proc.stdout).strip())
            return proc.returncode or 1
        unmount_status = "ok"

    try:
        fstab_removed = _remove_managed_fstab_entry(slot, share.source)
        removed = _delete_official_credentials(slot, share)
    except Exception as exc:
        print("remove_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_remove", slot, share.source, "fail", str(exc))
        return 1
    if args.delete_empty_dir:
        try:
            mountpoint.rmdir()
            print("empty_dir_removed=yes")
        except OSError:
            print("empty_dir_removed=no")
    after_status = _official_credential_status(slot, share)
    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"mountpoint={mountpoint}")
    print(f"unmount_status={unmount_status}")
    print(f"fstab_entry_removed={'yes' if fstab_removed else 'no'}")
    print(f"root_credential_removed={removed['root_credential_removed']}")
    print(f"customer_credential_removed={removed['customer_credential_removed']}")
    print("credential_scope=official")
    print("credential_present_before=" + before_status["official_credential_present"])
    _print_official_credential_status("", after_status)
    print("remove_status=ok")
    detail = (
        f"unmount_status={unmount_status} "
        f"fstab_entry_removed={'yes' if fstab_removed else 'no'} "
        f"root_credential_removed={removed['root_credential_removed']} "
        f"customer_credential_removed={removed['customer_credential_removed']}"
    )
    _append_action_log(_state_root(args), "nas_remove", slot, share.source, "ok", detail)
    return 0


