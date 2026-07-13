from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import is_root as _is_root
from ..domain.common import now_iso as _now_iso
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.nas_mounts import write_managed_fstab_entry as _write_managed_fstab_entry
from ..domain.nas_views import (
    ViewPlan,
    build_view_plan,
    crontab_has_reboot_restore,
    fstab_boot_entry_present,
    hidden_master,
    load_views_state,
    managed_fstab_mount_targets,
    save_views_state,
    slot_entry,
    slot_views_root,
    validate_user_id,
    view_root,
)
from ..host.account_files import (
    read_password_from_stdin,
    write_credential_file,
)
from ..host.bind_mounts import bind_ro, unmount_tree
from ..host.nas_ready import failed_cifs_mount_units, wait_for_nas_ready
from ..host.fstab import remove_managed_fstab_entry as _remove_managed_fstab_entry
from ..host.mounts import findmnt_one as _findmnt_one
from ..host.mounts import is_readonly_mount as _is_readonly_mount
from ..nas import (
    check_nas_policy,
    customer_credential_path,
    mountpoint_for_share,
    parse_smb_share,
    root_credential_path,
)


def _require_root(command: str) -> bool:
    if _is_root():
        return True
    print(f"error: run as root/admin: sudo /usr/local/bin/opsctl nas view {command} ...", file=sys.stderr)
    return False


def _ensure_hidden_dirs(slot: str) -> None:
    from ..domain.nas_views import VIEWS_ROOT

    for path, mode in ((VIEWS_ROOT, 0o700), (slot_views_root(slot), 0o700)):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    hidden_master(slot).mkdir(parents=True, exist_ok=True)
    view_root(slot).mkdir(parents=True, exist_ok=True)


def _mount_master(master: Path, share_source: str) -> tuple[bool, str]:
    rc, _, rows = _findmnt_one(master)
    if rc == 0 and rows:
        row = rows[0]
        ok = row.get("source") == share_source and row.get("fstype") == "cifs" and _is_readonly_mount(row)
        return ok, "already_mounted" if ok else "master_has_unexpected_existing_mount"
    proc = _run_text(["mount", str(master)], timeout=60)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    rc, error, rows = _findmnt_one(master)
    ok = (
        rc == 0
        and bool(rows)
        and rows[0].get("source") == share_source
        and rows[0].get("fstype") == "cifs"
        and _is_readonly_mount(rows[0])
    )
    return ok, "ok" if ok else (error or "master_state_did_not_match_expected_cifs_ro")


def _apply_binds(plan: ViewPlan) -> tuple[bool, str, int]:
    ok, reason = bind_ro(plan.package_dir, plan.package_bind)
    if not ok:
        return False, f"package_bind:{reason}", 0
    bound_rooms = 0
    for source, target in plan.room_binds:
        ok, reason = bind_ro(source, target)
        if not ok:
            return False, f"room_bind:{target.name}:{reason}", bound_rooms
        bound_rooms += 1
    # --rbind: the package/media submounts under view must follow into the entry.
    ok, reason = bind_ro(plan.view, plan.entry, recursive=True)
    if not ok:
        return False, f"entry_bind:{reason}", bound_rooms
    return True, "ok", bound_rooms


def cmd_nas_view_assign(args: argparse.Namespace) -> int:
    if not _require_root("assign"):
        return 2
    state_root = _state_root(args)
    try:
        decision = check_nas_policy(args.slot, args.share, state_root)
        if not decision.allowed:
            raise ValueError(f"policy denied: {decision.reason}")
        slot = decision.slot
        user_id = validate_user_id(args.user_id)

        views = load_views_state(state_root)
        existing = views["views"].get(slot)
        if existing:
            raise ValueError(f"slot already has a view (user_id={existing.get('user_id')}) — run: opsctl nas view detach {slot}")

        full_mount = mountpoint_for_share(slot, decision.share)
        rc, _, rows = _findmnt_one(full_mount)
        if rc == 0 and rows:
            raise ValueError(f"share is fully mounted for slot at {full_mount} — run: opsctl nas unmount {slot} {decision.share.source}")

        if args.username or args.password_stdin:
            if not args.username or not args.password_stdin:
                raise ValueError("--username and --password-stdin must be used together")
            password = read_password_from_stdin()
            # Corpus master reads a SHARED corpus via an infra read account.
            # Unlike `nas mount` (own-folder self-service, slot-owned cred),
            # the customer must NOT be able to read this key — store root-owned.
            credential_path = root_credential_path(slot, decision.share)
            write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
        else:
            credential_path = root_credential_path(slot, decision.share)
            if not credential_path.exists():
                # transition-only read fallback: pre-fix slot-home creds
                credential_path = customer_credential_path(slot, decision.share)
            if not credential_path.exists():
                raise ValueError("credential_missing: pass --username USER --password-stdin or create an official credential")

        _ensure_hidden_dirs(slot)
        master = hidden_master(slot)
        _write_managed_fstab_entry(slot, decision.share.source, master, credential_path)
        ok, reason = _mount_master(master, decision.share.source)
        if not ok:
            raise ValueError(f"master_mount_failed: {reason}")

        plan = build_view_plan(slot, user_id, decision.share.source, state_root)
        ok, reason, bound_rooms = _apply_binds(plan)
        if not ok:
            raise ValueError(f"bind_failed: {reason}")
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"user_id={args.user_id}")
        print("view_assign_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "nas_view_assign", args.slot, args.share, "fail", str(exc))
        return 1

    views["views"][slot] = {
        "user_id": plan.user_id,
        "share": plan.share.source,
        "package": plan.package_dir.name,
        "rooms_bound": bound_rooms,
        "rooms_missing_media": list(plan.missing_rooms),
        "assigned_at": _now_iso(),
    }
    save_views_state(state_root, views)

    print(f"target={slot}")
    print(f"user_id={plan.user_id}")
    print(f"share={plan.share.source}")
    print(f"package={plan.package_dir.name}")
    print(f"entry={plan.entry}")
    print(f"rooms_bound={bound_rooms}")
    print(f"rooms_missing_media={len(plan.missing_rooms)}")
    print("secret_value_printed=no")
    print("view_assign_status=ok")
    _append_action_log(state_root, "nas_view_assign", slot, plan.share.source, "ok", f"user_id={plan.user_id} rooms={bound_rooms}")
    return 0


def cmd_nas_view_detach(args: argparse.Namespace) -> int:
    if not _require_root("detach"):
        return 2
    state_root = _state_root(args)
    try:
        views = load_views_state(state_root)
        record = views["views"].get(args.slot)
        slot = args.slot
        share_source = (record or {}).get("share") or args.share
        if not share_source:
            raise ValueError("view not recorded and no --share given — cannot resolve fstab entry")

        entry_failed, entry_errors = unmount_tree(slot_entry(slot))
        view_failed, view_errors = unmount_tree(view_root(slot))
        master_failed, master_errors = unmount_tree(hidden_master(slot))
        failures = entry_errors + view_errors + master_errors
        if entry_failed or view_failed or master_failed:
            raise ValueError("umount_failed: " + "; ".join(failures))
        fstab_removed = _remove_managed_fstab_entry(slot, share_source)
    except Exception as exc:
        print(f"target={args.slot}")
        print("view_detach_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "nas_view_detach", args.slot, "", "fail", str(exc))
        return 1

    had_record = record is not None
    if had_record:
        del views["views"][slot]
        save_views_state(state_root, views)
    print(f"target={slot}")
    print(f"share={share_source}")
    print(f"fstab_entry_removed={'yes' if fstab_removed else 'no'}")
    print(f"state_record_removed={'yes' if had_record else 'no'}")
    print("credential_removed=no")
    print("view_detach_status=ok")
    _append_action_log(state_root, "nas_view_detach", slot, share_source, "ok")
    return 0


def cmd_nas_view_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    views = load_views_state(state_root)
    records = views.get("views", {})
    print(f"view_count={len(records)}")
    print("mutates=false")
    exit_code = 0
    for index, (slot, record) in enumerate(sorted(records.items()), start=1):
        prefix = f"view_{index}"
        print(f"{prefix}_target={slot}")
        print(f"{prefix}_user_id={record.get('user_id', '')}")
        print(f"{prefix}_share={record.get('share', '')}")
        print(f"{prefix}_package={record.get('package', '')}")
        checks = {
            "master_mounted": hidden_master(slot),
            "entry_mounted": slot_entry(slot),
        }
        healthy = True
        for label, path in checks.items():
            rc, _, rows = _findmnt_one(path)
            mounted = rc == 0 and bool(rows)
            readonly = mounted and _is_readonly_mount(rows[0])
            print(f"{prefix}_{label}={'yes' if mounted else 'no'}")
            print(f"{prefix}_{label}_readonly={'yes' if readonly else 'no'}")
            if not mounted or not readonly:
                healthy = False
        print(f"{prefix}_healthy={'yes' if healthy else 'no'}")
        if not healthy:
            exit_code = 1

    # Boot persistence: a healthy view that will not survive a reboot is a
    # latent outage — the master needs its managed fstab pair, and the binds
    # need the @reboot `nas view restore` crontab line (root crontab, so this
    # half is only decidable when run via sudo).
    fstab_text = _read_fstab()
    if records:
        missing = [slot for slot, record in sorted(records.items()) if not fstab_boot_entry_present(slot, record.get("share", ""), fstab_text)]
        print(f"boot_fstab_entries={len(records) - len(missing)}/{len(records)}")
        if missing:
            print(f"boot_fstab_missing={','.join(missing)}")
            exit_code = 1
        if _is_root():
            proc = _run_text(["crontab", "-l"], timeout=10)
            # `crontab -l` exits non-zero when root has no crontab — that is
            # a definite "no", not an error.
            has_cron = proc.returncode == 0 and crontab_has_reboot_restore(proc.stdout)
            print(f"boot_restore_cron={'yes' if has_cron else 'no'}")
            if not has_cron:
                exit_code = 1
        else:
            print("boot_restore_cron=unknown_requires_root")

    # nofail keeps a lost boot race silent (mounts absent, boot "fine") —
    # surface failed CIFS mount units so the first status line after an
    # outage is loud instead.
    failed_units, failed_error = failed_cifs_mount_units()
    if failed_error is not None:
        print(f"failed_cifs_mount_units=unknown reason={failed_error}")
    else:
        print(f"failed_cifs_mount_units={len(failed_units)}")
        if failed_units:
            print("failed_cifs_mount_unit_names=" + ",".join(failed_units))
            exit_code = 1

    # Registration is not boot success (2026-07-07: every managed pair present,
    # zero mounted) — judge every managed fstab entry against live mounts,
    # covering slot shares beyond this command's own view records.
    declared = managed_fstab_mount_targets(fstab_text)
    unmounted = []
    for _, _, target in declared:
        rc, _, rows = _findmnt_one(Path(target))
        if rc != 0 or not rows:
            unmounted.append(target)
    print(f"managed_fstab_mounted={len(declared) - len(unmounted)}/{len(declared)}")
    if unmounted:
        print("managed_fstab_unmounted=" + ",".join(unmounted))
        exit_code = 1
    print("view_status=ok")
    return exit_code


def _read_fstab() -> str:
    try:
        return Path("/etc/fstab").read_text(encoding="utf-8")
    except OSError:
        return ""


@contextlib.contextmanager
def _restore_lock(lock_path: Path = Path("/run/agent-runtime-ops-nas-restore.lock")):
    """Serialize concurrent restores — the boot unit and a legacy @reboot cron
    line may fire together, and two restores rebuilding the same entry binds
    would tear each other down mid-flight. Degrades to unserialized where
    flock is unavailable (non-Linux test runs)."""
    try:
        import fcntl
    except ImportError:
        yield
        return
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.touch(exist_ok=True)
        handle = lock_path.open("r+")
    except OSError:
        yield
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        handle.close()


def cmd_nas_view_restore(args: argparse.Namespace) -> int:
    if not _require_root("restore"):
        return 2
    state_root = _state_root(args)
    views = load_views_state(state_root)
    records = views.get("views", {})
    print(f"view_count={len(records)}")
    boot_failed = 0
    with _restore_lock():
        if records:
            # After a power cut the server usually boots before the NAS answers —
            # wait for SMB, then remount every fstab CIFS entry that lost the boot
            # race (mount -a is idempotent: already-mounted entries are skipped).
            hosts = []
            for record in records.values():
                try:
                    hosts.append(parse_smb_share(record.get("share", "")).host)
                except ValueError:
                    continue
            wait_seconds = float(getattr(args, "nas_wait_seconds", 600.0))
            readiness = wait_for_nas_ready(hosts, total_seconds=wait_seconds)
            for host, ready in readiness.items():
                print(f"nas_ready host={host} ready={'yes' if ready else 'timeout'}")
                if not ready:
                    boot_failed += 1
            proc = _run_text(["mount", "-a", "-t", "cifs"], timeout=300)
            if proc.returncode != 0:
                boot_failed += 1
            print(f"cifs_mount_all={'ok' if proc.returncode == 0 else 'rc=' + str(proc.returncode)}")
        failed = _restore_views(state_root, records)
    ok = failed == 0 and boot_failed == 0
    print(f"view_restore_status={'ok' if ok else 'fail'}")
    return 0 if ok else 1


def _restore_views(state_root: Path, records: dict) -> int:
    failed = 0
    for slot, record in sorted(records.items()):
        share_source = record.get("share", "")
        user_id = record.get("user_id", "")
        try:
            _ensure_hidden_dirs(slot)
            ok, reason = _mount_master(hidden_master(slot), share_source)
            if not ok:
                raise ValueError(f"master_mount_failed: {reason}")
            plan = build_view_plan(slot, user_id, share_source, state_root)
            ok, reason, bound_rooms = _apply_binds(plan)
            if not ok:
                raise ValueError(f"bind_failed: {reason}")
            print(f"restored target={slot} user_id={user_id} rooms_bound={bound_rooms}")
            _append_action_log(state_root, "nas_view_restore", slot, share_source, "ok", f"user_id={user_id}")
        except Exception as exc:
            failed += 1
            print(f"restore_failed target={slot} reason={exc}")
            _append_action_log(state_root, "nas_view_restore", slot, share_source, "fail", str(exc))
    return failed
