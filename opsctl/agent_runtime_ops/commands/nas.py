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
    migrate_customer_credential_to_root,
    official_credential_status,
    validate_official_credentials_for_delete,
)
from ..domain.nas_mounts import prepare_mount_entry as _prepare_mount_entry
from ..domain.workspace_bind import (
    assign_workspace_bind as _assign_workspace_bind,
    reconcile_workspace_bind as _reconcile_workspace_bind,
    rw_cifs_mounts as _rw_cifs_mounts,
    workspace_bound_source as _workspace_bound_source,
    workspace_status_has_signal as _workspace_status_has_signal,
    workspace_status_row as _workspace_status_row,
)
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
from ..host.fstab import read_managed_fstab_entries as _read_managed_fstab_entries
from ..host.fstab import read_managed_workspace_binds as _read_managed_workspace_binds
from ..host.fstab import remove_managed_fstab_entry as _remove_managed_fstab_entry
from ..host.fstab import update_managed_fstab_credentials as _update_managed_fstab_credentials
from ..domain.nas_probe import (
    probe_host as _probe_host,
    probe_mounts as _probe_mounts,
    smb_host_of as _smb_host_of,
)
from ..host.mounts import (
    findmnt_all_cifs as _findmnt_all_cifs,
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
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..profiles import load_profile as _load_profile
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
                corpus = not _share_is_writable(decision.share)
                if corpus:
                    # Corpus is operator-provisioned (nas view assign), never a
                    # customer self-service mount — resolve from the root vault only,
                    # migrating any stale slot-home copy out of customer reach.
                    migrate_customer_credential_to_root(slot, decision.share)
                    credential_path = root_credential_path(slot, decision.share)
                    cred_uid = 0
                else:
                    credential_path = customer_credential_path(slot, decision.share)
                    cred_uid, _ = slot_uid_gid(slot)
                if not credential_path.exists():
                    print(f"pending target={slot} share={decision.share.source} reason=credential_missing")
                    result["pending"] += 1
                    continue
                credential_file_is_safe_for_slot(slot, credential_path, uid=cred_uid)
                decision, _ = _prepare_mount_entry(slot, decision.share.source, credential_path, state_root)
                ok, reason = _host_mount_prepared_share(decision, _share_is_writable(decision.share))
                if ok and _share_is_writable(decision.share):
                    _reconcile_workspace_bind(slot)
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
    ws_root = Path("/home") / desired.slot / "workspace"
    print(f"workspace_root={ws_root}")
    print("mutates=false")
    if rc != 0:
        print("mounted_status=fail")
        print(f"reason={error or 'findmnt_failed'}")
        return 1
    child_rows = [row for row in rows if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")]
    # Writable (OCn) shares mount under nas_rw, one spot per source — count and
    # list them alongside corpus so the writable shares stay visible.
    rw_root = Path("/home") / desired.slot / "nas_rw"
    rw_rc, _, rw_rows = _findmnt_under(str(rw_root))
    if rw_rc == 0:
        child_rows += [
            row
            for row in rw_rows
            if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(rw_root) + "/")
        ]
    print(f"mounted_child_cifs_count={len(child_rows)}")
    # The workspace is a VIEW (bind) of one nas_rw mount — shown, not counted.
    ws_bind_rc, _, ws_bind_rows = _findmnt_one(ws_root)
    if ws_bind_rc == 0 and ws_bind_rows:
        print(f"workspace_bound_to={ws_bind_rows[0].get('source') or 'unknown'}")
    else:
        print("workspace_bound_to=none")
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


def cmd_nas_workspace_status(args: argparse.Namespace) -> int:
    """Fleet-wide live workspace reality in ONE call — what the assignment
    reconciler reads every tick, mirroring how `nas view status` serves the
    kakao-view axis. Read-only.

    Stamped slots (managed fstab entry or workspace bind) always get a line:
    a stamp with nothing live is exactly the drift worth showing. Unstamped
    /home candidates need a live signal to earn one, so ordinary service
    accounts stay out of the report.
    """
    entries = _read_managed_fstab_entries()
    binds = _read_managed_workspace_binds()
    stamped_bind_slots = {bind["slot"] for bind in binds}
    stamped_slots = {entry["slot"] for entry in entries} | stamped_bind_slots
    candidates = set(stamped_slots)
    home = Path("/home")
    if home.is_dir():
        candidates |= {path.name for path in home.iterdir() if path.is_dir()}
    print("mutates=false")
    rows: list[dict[str, object]] = []
    for slot in sorted(candidates):
        try:
            validate_linux_account(slot)
        except Exception:
            continue
        row = _workspace_status_row(
            slot,
            _rw_cifs_mounts(slot),
            _workspace_bound_source(slot),
            slot in stamped_bind_slots,
        )
        if slot in stamped_slots or _workspace_status_has_signal(row):
            rows.append(row)
    print(f"ws_count={len(rows)}")
    for index, row in enumerate(rows, start=1):
        print(f"ws_{index}_slot={row['slot']}")
        print(f"ws_{index}_bound_to={row['bound_to']}")
        print(f"ws_{index}_stamp_bind={'yes' if row['stamp_bind'] else 'no'}")
        sources = row["rw_sources"]
        print(f"ws_{index}_rw_count={len(sources)}")
        for rw_index, source in enumerate(sources, start=1):
            print(f"ws_{index}_rw_{rw_index}={source}")
    print("workspace_status=ok")
    return 0


def cmd_nas_probe(args: argparse.Namespace) -> int:
    """마운트됨 ≠ 연결됨 — 모든 cifs 마운트의 실제 읽기 생존을 잰다 (read-only).

    rc 0 = 전부 살아있음, 1 = 죽은 마운트 있음, 2 = 목록 수집 실패.
    마운트 테이블은 NAS 가 죽어도 그대로라(7/20 실측: 장비 다운 중에도 81개
    "mounted"), 복구 후 "진짜 다 붙었나"는 이 명령만이 답한다.
    """
    rc, error, rows = _findmnt_all_cifs()
    print("mutates=false")
    if rc != 0:
        print("nas_probe_status=fail")
        print(f"reason={error or 'findmnt_failed'}")
        return 2
    hosts = sorted({h for h in (_smb_host_of(r.get("source", "")) for r in rows) if h})
    for index, host in enumerate(hosts, start=1):
        print(f"host_{index}={host}")
        print(f"host_{index}_smb_open={'yes' if _probe_host(host) else 'no'}")
    results = _probe_mounts(rows)
    dead = [r for r in results if r["alive"] != "yes"]
    for index, r in enumerate(results, start=1):
        print(f"probe_{index}_target={r['target']}")
        print(f"probe_{index}_source={r['source']}")
        print(f"probe_{index}_alive={r['alive']}" + (f" reason={r['reason']}" if r["reason"] else ""))
    print(f"probe_alive={len(results) - len(dead)}/{len(results)}")
    print("nas_probe_status=ok")
    return 0 if not dead else 1


def cmd_nas_mount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas mount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    credential_source = ""
    try:
        state_root = _state_root(args)
        decision = check_nas_policy(args.slot, args.share, state_root)
        slot = decision.slot
        corpus = not _share_is_writable(decision.share)
        if args.username or args.password_stdin:
            if not args.username or not args.password_stdin:
                raise ValueError("--username and --password-stdin must be used together")
            password = read_password_from_stdin()
            if corpus:
                # Shared corpus (kakao-work, groupware, whatsapp) read via an infra
                # account. If the slot could read this key, a container-escape or
                # ssh-as-slot could self-mount the whole corpus — so it lives in the
                # root vault, root:root 0600, never slot-readable.
                credential_path = root_credential_path(slot, decision.share)
                write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
                # Drop any pre-fix customer-readable copy of the same corpus secret.
                customer_copy = customer_credential_path(slot, decision.share)
                if customer_copy.exists():
                    customer_copy.unlink()
            else:
                # Own-folder OCn share: the slot owns its data. Self-service cred is
                # slot-owned 0600 so the slot's own fstab entry mounts it and nobody
                # re-enters the password (owner decision 7/13).
                ensure_customer_agent_dirs(slot)
                uid, gid = slot_uid_gid(slot)
                credential_path = customer_credential_path(slot, decision.share)
                write_credential_file(credential_path, args.username, password, args.domain, uid, gid)
            credential_source = "stdin"
        elif corpus:
            # Corpus reuse: only the root vault is a safe source. Migrate any pre-fix
            # slot-home copy into the vault (same secret, no re-entry) and fail closed
            # rather than mount off a customer-readable corpus cred.
            migrated = migrate_customer_credential_to_root(slot, decision.share)
            credential_path = root_credential_path(slot, decision.share)
            if not credential_path.exists():
                raise ValueError("credential_missing: pass --username USER --password-stdin or create an official credential")
            credential_source = "migrated_root" if migrated else "official_root"
        else:
            credential_path = customer_credential_path(slot, decision.share)
            if credential_path.exists():
                credential_source = "official_customer"
            else:
                # transition-only read fallback; the vault is being emptied
                credential_path = root_credential_path(slot, decision.share)
                if credential_path.exists():
                    credential_source = "official_root"
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
    if ok and expect_rw:
        bind_ok, bind_detail = _reconcile_workspace_bind(decision.slot)
        print(f"workspace_bind={'ok' if bind_ok else 'fail'} {bind_detail}")
    _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "ok" if ok else "fail", reason)
    return 0 if ok else 1


def cmd_nas_credential_migrate_root(args: argparse.Namespace) -> int:
    """Move a corpus credential file out of the slot home into the root vault
    and repoint the existing fstab line's credentials= at the new place.

    The mount itself is not touched — mountpoint, mode, everything else stays
    byte for byte (oc1's kakao-work line serves the kw view stack at its own
    mountpoint, which a full rewrite would break at boot).
    """
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas credential migrate-to-root TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
        if _share_is_writable(share):
            raise ValueError("writable (OCn) credentials are legitimately slot-owned; migrate-to-root is for corpus shares")
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("credential_migrate_status=fail")
        print(f"reason={exc}")
        return 1

    try:
        moved = migrate_customer_credential_to_root(slot, share)
        vault_path = root_credential_path(slot, share)
        if not vault_path.exists():
            raise ValueError("no credential to migrate: neither slot home nor root vault has one")
        fstab_updated = _update_managed_fstab_credentials(slot, share.source, vault_path)
    except Exception as exc:
        print(f"target={slot}")
        print(f"share={share.source}")
        print("credential_migrate_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_credential_migrate_root", slot, share.source, "fail", str(exc))
        return 1

    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"vault_path={vault_path}")
    print(f"customer_copy_moved={'yes' if moved else 'no_already_vault_or_absent'}")
    print(f"fstab_credentials_updated={'yes' if fstab_updated else 'no_managed_entry'}")
    print("secret_value_printed=no")
    print("credential_migrate_status=ok")
    _append_action_log(
        _state_root(args),
        "nas_credential_migrate_root",
        slot,
        share.source,
        "ok",
        f"moved={'yes' if moved else 'no'} fstab_updated={'yes' if fstab_updated else 'no'}",
    )
    return 0


def cmd_nas_workspace_assign(args: argparse.Namespace) -> int:
    """Point the slot's workspace at one of its writable mounts.

    With one writable mount the tool auto-binds on mount/unmount and this
    command is unnecessary; with several this is the explicit choice — the
    entry point the slot-assignment web drives. The running container keeps
    the OLD view until recreated (bind roots do not propagate), so assign
    runs apply as one set unless --no-apply is given.
    """
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas workspace-assign TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
        if not _share_is_writable(share):
            raise ValueError("workspace-assign is for writable (OCn) shares; corpus shares stay under nas_docs")
        mountpoint = mountpoint_for_share(slot, share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("workspace_assign_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_workspace_assign", args.slot, args.share, "fail", str(exc))
        return 1

    ok, detail = _assign_workspace_bind(slot, mountpoint)
    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"mountpoint={mountpoint}")
    print(f"workspace_assign_status={'ok' if ok else 'fail'}")
    print(f"detail={detail}")
    _append_action_log(_state_root(args), "nas_workspace_assign", slot, share.source, "ok" if ok else "fail", detail)
    if not ok:
        return 1
    if getattr(args, "no_apply", False):
        print(f"apply_status=skipped next=sudo /usr/local/bin/opsctl apply {slot}")
        return 0
    profile = _load_profile(desired.runtime_profile)
    return _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=_state_root(args),
        allow_first_apply=False,
        action_name="nas_workspace_assign",
    )


def cmd_nas_unmount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas unmount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        slot = desired.slot
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(slot, share)
        _safe_mountpoint_path(mountpoint, root=Path("/home") / slot)
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
    if _share_is_writable(share):
        # The rw set changed: rebind the workspace to the remaining mount, or
        # clear the (now dangling) bind — a lingering bind would keep the
        # unmounted share's filesystem alive through the workspace.
        bind_ok, bind_detail = _reconcile_workspace_bind(slot)
        print(f"workspace_bind={'ok' if bind_ok else 'fail'} {bind_detail}")
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
        _safe_mountpoint_path(mountpoint, root=Path("/home") / slot)
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
    if _share_is_writable(share):
        bind_ok, bind_detail = _reconcile_workspace_bind(slot)
        print(f"workspace_bind={'ok' if bind_ok else 'fail'} {bind_detail}")
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

