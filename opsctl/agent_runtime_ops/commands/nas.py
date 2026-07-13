from __future__ import annotations

import argparse
import getpass
from pathlib import Path
import sys

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import is_root as _is_root
from ..domain.common import now_iso as _now_iso
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.nas_credentials import (
    delete_official_credentials,
    official_credential_status,
    validate_official_credentials_for_delete,
)
from ..domain.nas_mounts import prepare_mount_entry as _prepare_mount_entry
from ..domain.nas_mounts import write_managed_fstab_entry as _write_managed_fstab_entry
from ..domain.nas_requests import move_request, safe_request_file
from ..host.account_files import (
    atomic_write_key_value,
    credential_file_is_safe_for_slot,
    ensure_customer_agent_dirs,
    read_key_value_file,
    read_password_from_stdin,
    slot_uid_gid,
    write_credential_file,
)
from ..host.fstab import remove_managed_fstab_entry as _remove_managed_fstab_entry
from ..host.mounts import (
    findmnt_one as _findmnt_one,
    findmnt_under as _findmnt_under,
    is_readonly_mount as _is_readonly_mount,
    mount_prepared_share as _host_mount_prepared_share,
    safe_mountpoint_path as _safe_mountpoint_path,
)
from ..nas import (
    check_nas_policy,
    customer_credential_path,
    mountpoint_for_share,
    parse_smb_share,
    request_dir,
    request_path,
    root_credential_path,
    share_is_writable as _share_is_writable,
)
from ..routing import load_runtime_bindings, validate_linux_account
from ..state import load_runtime_target


def _print_official_credential_status(prefix: str, status: dict[str, str]) -> None:
    for key in [
        "root_credential_present",
        "customer_credential_present",
        "official_credential_present",
        "remount_possible",
    ]:
        print(f"{prefix}{key}={status[key]}")


def _rollback_fstab_after_mount_failure(args: argparse.Namespace, slot: str, share: str) -> str:
    if getattr(args, "keep_fstab_on_failure", False):
        return "kept"
    try:
        return "removed" if _remove_managed_fstab_entry(slot, share) else "not_found"
    except Exception as exc:
        return f"failed:{exc}"


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
                safe_request_file(path, slot)
                data = read_key_value_file(path)
                share_source = data.get("requested_share") or ""
                decision = check_nas_policy(slot, share_source, state_root)
                if not decision.allowed:
                    move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, share_source, "rejected", decision.reason)
                    result["rejected"] += 1
                    continue
                credential_path = customer_credential_path(slot, decision.share)
                if not credential_path.exists():
                    print(f"pending target={slot} share={decision.share.source} reason=credential_missing")
                    result["pending"] += 1
                    continue
                slot_uid, _ = slot_uid_gid(slot)
                credential_file_is_safe_for_slot(slot, credential_path, uid=slot_uid)
                decision, _ = _prepare_mount_entry(slot, decision.share.source, credential_path, state_root)
                ok, reason = _host_mount_prepared_share(decision, _share_is_writable(decision.share))
                if ok:
                    move_request(path, slot, "approved")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "approved", reason)
                    result["approved"] += 1
                else:
                    rollback = "removed" if _remove_managed_fstab_entry(decision.slot, decision.share.source) else "not_found"
                    move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "rejected", f"{reason} fstab_entry_rollback={rollback}")
                    result["rejected"] += 1
                    result["failed"] += 1
            except Exception as exc:
                try:
                    share_source = read_key_value_file(path).get("requested_share", "")
                    move_request(path, slot, "rejected")
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
                data = read_key_value_file(path)
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


def _caller_customer_slot() -> str:
    user = validate_linux_account(getpass.getuser())
    if user in {"root", "svcops"}:
        raise ValueError(f"this command must be run by a customer linux_account, got {user}")
    return user


def cmd_nas_request(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot()
        share = parse_smb_share(args.share)
        ensure_customer_agent_dirs(slot)
        path = request_path(slot, share)
        mountpoint = mountpoint_for_share(slot, share)
        uid, gid = slot_uid_gid(slot)
        atomic_write_key_value(
            path,
            {
                "slot": slot,
                "requested_share": share.source,
                "mountpoint": str(mountpoint),
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
    print(f"requested_share={share.source}")
    print(f"request_file={path}")
    print(f"mountpoint={mountpoint}")
    print("request_status=pending")
    print("next_action=run opsctl nas credential set //HOST/SHARE --username NAS_USER --password-stdin")
    return 0


def cmd_nas_credential_set(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot()
        share = parse_smb_share(args.share)
        password = read_password_from_stdin()
        ensure_customer_agent_dirs(slot)
        credential_path = customer_credential_path(slot, share)
        uid, gid = slot_uid_gid(slot)
        write_credential_file(credential_path, args.username, password, args.domain, uid, gid)
    except Exception as exc:
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"credential_file={credential_path}")
    print("credential_status=stored")
    print("secret_value_printed=no")
    return 0


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
    status = official_credential_status(slot, share)
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
            _print_official_credential_status(f"{prefix}_", official_credential_status(desired.slot, share))
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
            password = read_password_from_stdin()
            credential_path = root_credential_path(slot, decision.share)
            write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
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

    expect_rw = _share_is_writable(decision.share)
    rc, _, rows = _findmnt_one(decision.mountpoint)
    if rc == 0 and rows:
        row = rows[0]
        print(f"target={decision.slot}")
        print(f"share={decision.share.source}")
        print(f"credential_source={credential_source or 'unknown'}")
        print("secret_value_printed=no")
        _print_mount_row("existing_mount", row)
        ok = row.get("source") == decision.share.source and row.get("fstype") == "cifs" and _is_readonly_mount(row) != expect_rw
        print(f"mount_status={'already_mounted' if ok else 'fail'}")
        if not ok:
            print("reason=mountpoint_has_unexpected_existing_mount")
        _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "already_mounted" if ok else "fail")
        return 0 if ok else 1

    ok, reason = _host_mount_prepared_share(decision, expect_rw)
    rc, error, rows = _findmnt_one(decision.mountpoint)
    print(f"target={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    print(f"credential_source={credential_source or 'unknown'}")
    print(f"mount_access={'rw' if expect_rw else 'ro'}")
    print("secret_value_printed=no")
    if rows:
        _print_mount_row("mounted", rows[0])
    print(f"mount_status={'ok' if ok else 'fail'}")
    if not ok:
        print(f"reason={reason or error or 'mounted_state_did_not_match_expected'}")
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
        credential_status = official_credential_status(slot, share)
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
        before_status = official_credential_status(slot, share)
        # Validate credentials before mutating mount or fstab state.
        validate_official_credentials_for_delete(slot, share)
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
        removed = delete_official_credentials(slot, share)
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
    after_status = official_credential_status(slot, share)
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

