from __future__ import annotations

import argparse
import contextlib
import json
import os
import sqlite3
import stat
import sys
import time
from pathlib import Path

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import is_root as _is_root
from ..domain.common import now_iso as _now_iso
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.nas_credentials import migrate_customer_credential_to_root
from ..domain.nas_mounts import write_managed_fstab_entry as _write_managed_fstab_entry
from ..domain.nas_views import (
    PRIMARY_CORPUS,
    ViewPlan,
    build_view_plan,
    corpus_named,
    corpus_for_share,
    crontab_has_reboot_restore,
    drop_view_record,
    fstab_boot_entry_present,
    shared_master_fstab_entry_present,
    get_view_record,
    hidden_master,
    iter_view_records,
    load_views_state,
    find_user_package,
    load_membership_rooms,
    load_package_room_summary,
    managed_fstab_mount_targets,
    put_view_record,
    save_views_state,
    slot_entry,
    slot_views_root,
    path_alias,
    validate_user_id,
    view_root,
)

from ..host.account_files import (
    read_password_from_stdin,
    write_credential_file,
)
from ..host.bind_mounts import (
    bind_ro,
    observe_mount_targets_under,
    observe_ro_view_grant,
    unmount_tree,
)
from ..host.nas_ready import failed_cifs_mount_units, wait_for_nas_ready
from ..host.fstab import (
    read_managed_fstab_entries as _read_managed_fstab_entries,
    remove_managed_fstab_entry as _remove_managed_fstab_entry,
)
from ..host.mounts import findmnt_one as _findmnt_one
from ..host.mounts import is_readonly_mount as _is_readonly_mount
from ..nas import (
    check_nas_policy,
    customer_credential_path,
    mountpoint_for_share,
    parse_smb_share,
    parse_cifs_mount_source,
    root_credential_path,
    share_is_writable,
    shared_credential_for_share,
    shared_master_for_share,
)


_MASTER_MODE_PER_SLOT = "per_slot_cifs"
_MASTER_MODE_SHARED = "shared_policy_mount"
_KAKAO_PACKAGE_ROOT = Path("/mnt/nas/kakao-work")
_GRANT_EVIDENCE_MAX_PATHS = 64
_GRANT_EVIDENCE_TIMEOUT_SECONDS = 15.0


def _view_grant_evidence(
    slot: str,
    corpus: str,
    record: dict,
    master: Path,
) -> tuple[str, list[dict], bool, bool]:
    """Observe granted child mounts; recorded paths remain intent, never proof."""
    try:
        _, spec = corpus_named(corpus)
    except ValueError:
        return "no", [], True, True
    if spec.layout != "granted_paths":
        return "no", [], True, True
    raw_paths = record.get("paths") or []
    if not isinstance(raw_paths, list) or len(raw_paths) > _GRANT_EVIDENCE_MAX_PATHS:
        return "yes", [], False, False
    if not raw_paths:
        return "yes", [], False, False
    deadline = time.monotonic() + _GRANT_EVIDENCE_TIMEOUT_SECONDS
    seen_paths: set[str] = set()
    seen_aliases: set[str] = set()
    planned: list[tuple[str, Path, Path]] = []
    expected_entries: set[str] = set()
    for raw_path in raw_paths:
        if not isinstance(raw_path, str):
            return "yes", [], False, False
        try:
            rel = raw_path
            alias = path_alias(rel)
        except ValueError:
            return "yes", [], False, False
        if rel in seen_paths or alias in seen_aliases:
            return "yes", [], False, False
        seen_paths.add(rel)
        seen_aliases.add(alias)
        entry = slot_entry(slot, corpus) / alias
        expected_entries.add(entry.as_posix())
        planned.append((rel, master / rel, entry))

    def observe_round() -> tuple[list[dict], bool, bool]:
        evidence: list[dict] = []
        complete = True
        green = True
        for rel, source, entry in planned:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return evidence, False, False
            item, item_complete, item_green = observe_ro_view_grant(
                source,
                entry,
                slot,
                allow_account_probe=_is_root(),
                timeout=min(3.0, remaining),
            )
            # Each worker result is an independent JSON projection. Copy it
            # before adding the recorded intent so mocked or reused mappings
            # cannot make both coherence rounds alias the same object.
            item = json.loads(json.dumps(item, sort_keys=True, separators=(",", ":")))
            item["path"] = rel
            evidence.append(item)
            complete = complete and item_complete
            green = green and item_green
        return evidence, complete, green

    # The target inventory is bracketed by two complete per-child rounds. This
    # prevents target-only inventory from combining stale uid/gid/mode/options
    # and access evidence with a same-target remount or path replacement.
    first_evidence, first_complete, first_green = observe_round()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return "yes", first_evidence, False, False
    targets, inventory_gap = observe_mount_targets_under(
        slot_entry(slot, corpus), min(3.0, remaining)
    )
    expected_targets = {slot_entry(slot, corpus).as_posix(), *expected_entries}
    second_evidence, second_complete, second_green = observe_round()
    coherent = first_evidence == second_evidence
    complete = (
        first_complete
        and second_complete
        and inventory_gap is None
        and targets == expected_targets
        and coherent
        and len(second_evidence) == len(planned)
    )
    green = complete and first_green and second_green
    return "yes", second_evidence, complete, green


def _require_root(command: str) -> bool:
    if _is_root():
        return True
    print(f"error: run as root/admin: sudo /usr/local/bin/opsctl nas view {command} ...", file=sys.stderr)
    return False


def _ensure_hidden_dirs(slot: str, corpus: str = PRIMARY_CORPUS) -> None:
    from ..domain.nas_views import VIEWS_ROOT

    # 0700 부모가 마스터 마운트를 슬롯에게서 가린다 — 코퍼스 하위 디렉터리도
    # 같은 규율로 만든다(슬롯은 bind 된 view 만 본다).
    roots = [(VIEWS_ROOT, 0o700), (slot_views_root(slot), 0o700)]
    if corpus != PRIMARY_CORPUS:
        roots.append((slot_views_root(slot, corpus), 0o700))
    for path, mode in roots:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    hidden_master(slot, corpus).mkdir(parents=True, exist_ok=True)
    view_root(slot, corpus).mkdir(parents=True, exist_ok=True)


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


def _assert_no_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError(f"shared_master_path_not_absolute:{path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ValueError(f"shared_master_path_unreadable:{current}:{exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"shared_master_path_symlink:{current}")


def _validate_shared_master(master: Path, share_source: str) -> dict[str, str]:
    """Validate an already-mounted root-policy source without trusting its path."""
    _assert_no_symlink_components(master)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(master, flags)
    except OSError as exc:
        raise ValueError(f"shared_master_open_failed:{master}:{exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError(f"shared_master_not_directory:{master}")
        rc, error, rows = _findmnt_one(master)
        if rc != 0 or len(rows) != 1:
            raise ValueError(error or f"shared_master_mount_not_exact:rows={len(rows)}")
        row = rows[0]
        if row.get("target") != str(master) or row.get("fstype") != "cifs":
            raise ValueError("shared_master_mount_identity_mismatch")
        observed, subpath = parse_cifs_mount_source(row.get("source", ""))
        expected = parse_smb_share(share_source)
        if subpath is not None or observed.host != expected.host or observed.share != expected.share:
            raise ValueError("shared_master_share_mismatch")
        after = os.fstat(fd)
        def identity(value) -> tuple[int, int, int]:
            return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)
        if identity(before) != identity(after):
            raise ValueError("shared_master_changed_during_validation")
        return row
    finally:
        os.close(fd)


def _record_master_mode(record: dict | None) -> str:
    # Records written before shared-master support are legacy per-slot CIFS.
    mode = str((record or {}).get("master_mode") or _MASTER_MODE_PER_SLOT)
    if mode not in {_MASTER_MODE_PER_SLOT, _MASTER_MODE_SHARED}:
        raise ValueError(f"unknown_master_mode:{mode}")
    return mode


def _shared_master_for_record(record: dict, share_source: str, state_root: Path) -> Path:
    configured = shared_master_for_share(parse_smb_share(share_source), state_root)
    if configured is None:
        raise ValueError("shared_master_policy_missing")
    recorded = str(record.get("master_path") or "")
    if not recorded or Path(recorded).as_posix() != configured.as_posix():
        raise ValueError("shared_master_policy_drift")
    _validate_shared_master(configured, share_source)
    return configured


def _remove_stale_per_slot_master_registration(slot: str, share_source: str, corpus: str) -> bool:
    """Remove only the exact, unmounted legacy entry superseded by shared mode."""
    matches = [
        entry
        for entry in _read_managed_fstab_entries()
        if entry.get("slot") == slot and entry.get("source") == share_source
    ]
    if not matches:
        return False
    if len(matches) != 1:
        raise ValueError("legacy_master_registration_ambiguous")
    expected = hidden_master(slot, corpus)
    entry = matches[0]
    if Path(entry.get("mountpoint", "")) != expected or entry.get("access") != "ro":
        raise ValueError("legacy_master_registration_identity_mismatch")
    rc, _, rows = _findmnt_one(expected)
    if rc == 0 and rows:
        raise ValueError("legacy_master_registration_still_mounted")
    if not _remove_managed_fstab_entry(slot, share_source):
        raise ValueError("legacy_master_registration_remove_failed")
    return True


def cmd_nas_view_preflight(args: argparse.Namespace) -> int:
    """Validate one intended view assignment without changing host state."""
    if not _require_root("preflight"):
        return 2
    state_root = _state_root(args)
    try:
        decision = check_nas_policy(args.slot, args.share, state_root)
        if not decision.allowed:
            raise ValueError(f"policy_denied:{decision.reason}")
        if share_is_writable(decision.share):
            raise ValueError("writable_share_not_a_corpus")
        slot = decision.slot
        user_id = validate_user_id(args.user_id)
        spec = corpus_for_share(decision.share.source)

        full_mount = mountpoint_for_share(slot, decision.share)
        rc, _, rows = _findmnt_one(full_mount)
        if rc == 0 and rows:
            raise ValueError("full_share_mount_conflicts_with_view")

        configured_master = shared_master_for_share(decision.share, state_root)
        if spec.master_contract == "shared_policy_required" and configured_master is None:
            raise ValueError("shared_master_policy_missing")

        if configured_master is not None:
            _validate_shared_master(configured_master, decision.share.source)
            plan = build_view_plan(
                slot,
                user_id,
                decision.share.source,
                state_root,
                list(getattr(args, "path", None) or []),
                master_override=configured_master,
            )
            master_mode = _MASTER_MODE_SHARED
            content_validation = "complete"
            master_path = configured_master
        else:
            root_credential = root_credential_path(slot, decision.share)
            shared_credential = shared_credential_for_share(decision.share, state_root)
            customer_credential = customer_credential_path(slot, decision.share)
            if not (
                root_credential.exists()
                or (shared_credential is not None and shared_credential.exists())
                or customer_credential.exists()
            ):
                raise ValueError("credential_missing")
            master_path = hidden_master(slot, spec.name)
            master_mode = _MASTER_MODE_PER_SLOT
            rc, _, rows = _findmnt_one(master_path)
            if rc == 0 and rows:
                plan = build_view_plan(
                    slot,
                    user_id,
                    decision.share.source,
                    state_root,
                    list(getattr(args, "path", None) or []),
                )
                content_validation = "complete"
            else:
                # A read-only command cannot create the per-slot CIFS mount.
                plan = None
                content_validation = "deferred_until_per_slot_mount"
                if bool(getattr(args, "require_content_ready", False)):
                    raise ValueError("content_validation_incomplete")

        print("view_preflight_schema=agent-runtime-nas-view-preflight/v1")
        print(f"target={slot}")
        print(f"corpus={spec.name}")
        print(f"share={decision.share.source}")
        print(f"master_contract={spec.master_contract}")
        print(f"master_mode={master_mode}")
        print(f"master_path={master_path.as_posix()}")
        print(f"content_validation={content_validation}")
        print(f"selected_bind_count={len(plan.room_binds) if plan is not None else 'unavailable'}")
        print("mutates=false")
        print("view_preflight_complete=yes")
        print("view_preflight_status=pass")
        return 0
    except Exception as exc:
        print("view_preflight_schema=agent-runtime-nas-view-preflight/v1")
        print(f"target={args.slot}")
        print("mutates=false")
        print("view_preflight_complete=yes")
        print("view_preflight_status=fail")
        print(f"reason={exc}")
        return 1


def _apply_binds(plan: ViewPlan) -> tuple[bool, str, int]:
    def fail(reason: str, bound_rooms: int) -> tuple[bool, str, int]:
        entry_failed, entry_errors = unmount_tree(plan.entry)
        view_failed, view_errors = unmount_tree(plan.view)
        rollback_errors = entry_errors + view_errors
        if entry_failed or view_failed:
            reason += ":rollback_failed:" + "; ".join(rollback_errors)
        return False, reason, bound_rooms

    # granted_paths 코퍼스는 단일 패키지가 없다 — 붙일 것이 전부 room_binds 에 있다.
    if plan.package_dir is not None and plan.package_bind is not None:
        ok, reason = bind_ro(plan.package_dir, plan.package_bind)
        if not ok:
            return fail(f"package_bind:{reason}", 0)
    bound_rooms = 0
    for source, target in plan.room_binds:
        ok, reason = bind_ro(source, target)
        if not ok:
            return fail(f"room_bind:{target.name}:{reason}", bound_rooms)
        bound_rooms += 1
    # --rbind: the package/media submounts under view must follow into the entry.
    ok, reason = bind_ro(plan.view, plan.entry, recursive=True)
    if not ok:
        return fail(f"entry_bind:{reason}", bound_rooms)
    # Some deployed kernels/filesystems do not propagate nested bind mounts
    # through an --rbind of a directory that is itself a bind mount. Keep the
    # recursive bind as the normal path, then explicitly bind corpus children
    # at the runtime entry so the agent path cannot be an empty shell.
    if plan.package_dir is not None and plan.package_bind is not None:
        try:
            package_rel = plan.package_bind.relative_to(plan.view)
        except ValueError:
            return fail("entry_package_target_outside_view", bound_rooms)
        ok, reason = bind_ro(plan.package_dir, plan.entry / package_rel)
        if not ok:
            return fail(f"entry_package_bind:{reason}", bound_rooms)
    for source, target in plan.room_binds:
        try:
            room_rel = target.relative_to(plan.view)
        except ValueError:
            return fail("entry_room_target_outside_view", bound_rooms)
        ok, reason = bind_ro(source, plan.entry / room_rel)
        if not ok:
            return fail(f"entry_room_bind:{target.name}:{reason}", bound_rooms)
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
        if share_is_writable(decision.share):
            raise ValueError("nas view is for shared corpus (kakao/groupware/whatsapp); OCn own-folder shares use `nas mount`")
        user_id = validate_user_id(args.user_id)
        # 소스별로 뷰가 선다: 카카오가 붙은 슬롯에도 그룹웨어를 나란히 붙일 수 있다
        # (사람이 슬롯에 오면 그 사람 것 '전부'가 보여야 한다). 같은 코퍼스를 두 번
        # 붙이는 것만 막는다 — 그건 교체이므로 detach 를 거쳐야 한다.
        spec = corpus_for_share(decision.share.source)
        views = load_views_state(state_root)
        existing = get_view_record(views, slot, spec.name)
        if existing:
            raise ValueError(
                f"slot already has a {spec.name} view (user_id={existing.get('user_id')}) — "
                f"run: opsctl nas view detach {slot} --corpus {spec.name}"
            )

        full_mount = mountpoint_for_share(slot, decision.share)
        rc, _, rows = _findmnt_one(full_mount)
        if rc == 0 and rows:
            raise ValueError(f"share is fully mounted for slot at {full_mount} — run: opsctl nas unmount {slot} {decision.share.source}")

        configured_master = shared_master_for_share(decision.share, state_root)
        if spec.master_contract == "shared_policy_required" and configured_master is None:
            raise ValueError("shared_master_policy_missing")
        legacy_fstab_removed = False
        plan: ViewPlan | None = None
        if configured_master is not None:
            if args.username or args.password_stdin:
                raise ValueError("shared master policy forbids per-slot credential override")
            _validate_shared_master(configured_master, decision.share.source)
            master = configured_master
            master_mode = _MASTER_MODE_SHARED
            # Resolve identity/grant paths against the exact live collector
            # before the first write (dirs or legacy fstab migration).
            plan = build_view_plan(
                slot,
                user_id,
                decision.share.source,
                state_root,
                list(getattr(args, "path", None) or []),
                master_override=master,
            )
            _ensure_hidden_dirs(slot, spec.name)
            # A failed older attempt may have stamped an unmounted per-slot CIFS
            # entry.  Remove only that exact legacy pair; never touch the global
            # collector mount or another slot's healthy legacy master.
            legacy_fstab_removed = _remove_stale_per_slot_master_registration(
                slot, decision.share.source, spec.name
            )
        else:
            master_mode = _MASTER_MODE_PER_SLOT
            _ensure_hidden_dirs(slot, spec.name)
            if args.username or args.password_stdin:
                if not args.username or not args.password_stdin:
                    raise ValueError("--username and --password-stdin must be used together")
                password = read_password_from_stdin()
                # Corpus master reads a SHARED corpus via an infra read account.
                # Unlike `nas mount` (own-folder self-service, slot-owned cred),
                # the customer must NOT be able to read this key — store root-owned.
                credential_path = root_credential_path(slot, decision.share)
                write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
                # Drop any pre-fix customer-readable copy of the same corpus secret.
                customer_copy = customer_credential_path(slot, decision.share)
                if customer_copy.exists():
                    customer_copy.unlink()
            else:
                # Corpus reuse: the root vault is the only safe source. Migrate any
                # pre-fix slot-home copy into the vault (same secret, no re-entry),
                # then fail closed rather than mount off a customer-readable cred.
                migrate_customer_credential_to_root(slot, decision.share)
                credential_path = root_credential_path(slot, decision.share)
                if not credential_path.exists():
                    shared = shared_credential_for_share(decision.share, state_root)
                    if shared is not None and shared.exists():
                        credential_path = shared
                    else:
                        raise ValueError("credential_missing: no per-slot copy, and no corpus credential declared/present for this share (nas-policy corpus_credentials) — or pass --username USER --password-stdin")
            master = hidden_master(slot, spec.name)
            _write_managed_fstab_entry(slot, decision.share.source, master, credential_path)
            ok, reason = _mount_master(master, decision.share.source)
            if not ok:
                raise ValueError(f"master_mount_failed: {reason}")

        if plan is None:
            plan = build_view_plan(
                slot,
                user_id,
                decision.share.source,
                state_root,
                list(getattr(args, "path", None) or []),
                master_override=master,
            )
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

    try:
        put_view_record(views, slot, plan.corpus, {
            "user_id": plan.user_id,
            "share": plan.share.source,
            "corpus": plan.corpus,
            "master_mode": master_mode,
            "master_path": master.as_posix(),
            "package": plan.package_dir.name if plan.package_dir else "",
            # 재부팅 복구가 같은 경로를 다시 세울 수 있게 원장에 남긴다(restore 는 DB 를 못 본다).
            "paths": list(plan.paths),
            "rooms_bound": bound_rooms,
            "rooms_missing_media": list(plan.missing_rooms),
            "assigned_at": _now_iso(),
        })
        save_views_state(state_root, views)
    except Exception as exc:
        # A mounted view without its recovery record is an invisible partial
        # assignment.  Tear down only this slot's binds and fail loudly.
        entry_failed, entry_errors = unmount_tree(plan.entry)
        view_failed, view_errors = unmount_tree(plan.view)
        rollback = entry_errors + view_errors
        reason = f"state_persist_failed:{exc}"
        if entry_failed or view_failed:
            reason += ":rollback_failed:" + "; ".join(rollback)
        print(f"target={args.slot}")
        print(f"user_id={args.user_id}")
        print("view_assign_status=fail")
        print(f"reason={reason}")
        _append_action_log(state_root, "nas_view_assign", args.slot, args.share, "fail", reason)
        return 1

    print(f"target={slot}")
    print(f"user_id={plan.user_id}")
    print(f"corpus={plan.corpus}")
    print(f"share={plan.share.source}")
    print(f"master_mode={master_mode}")
    print(f"legacy_fstab_removed={'yes' if legacy_fstab_removed else 'no'}")
    print(f"package={plan.package_dir.name if plan.package_dir else ''}")
    if plan.paths:
        print(f"paths_bound={bound_rooms}/{len(plan.paths)}")
        if plan.missing_rooms:
            print("paths_missing=" + ",".join(plan.missing_rooms))
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
        slot = args.slot
        # 어느 소스를 떼는가: --corpus 우선, 없으면 --share 에서 유도, 그것도 없으면
        # 카카오(기존 호출 호환). 슬롯에 여러 뷰가 설 수 있으므로 대상을 명시해야 한다.
        # 순서 주의: own-folder 가드가 코퍼스 판별보다 **먼저**다. `//host/OC3` 같은
        # 자기폴더 share 에는 "nas unmount 를 쓰라"는 안내가 나와야 하는데, 코퍼스
        # 미등록 오류가 먼저 터지면 그 안내가 사라진다.
        corpus = (getattr(args, "corpus", "") or "").strip()
        record = get_view_record(views, slot, corpus) if corpus else views["views"].get(slot)
        share_source = (record or {}).get("share") or args.share
        if not share_source:
            raise ValueError("view not recorded and no --share given — cannot resolve fstab entry")
        share = parse_smb_share(share_source)
        if share_is_writable(share):
            raise ValueError("nas view detach is for shared corpus; OCn own-folder shares use `nas unmount`")
        if not corpus:
            corpus = corpus_for_share(share_source).name
            if corpus != PRIMARY_CORPUS:
                record = get_view_record(views, slot, corpus)

        master_mode = _record_master_mode(record)
        entry_failed, entry_errors = unmount_tree(slot_entry(slot, corpus))
        view_failed, view_errors = unmount_tree(view_root(slot, corpus))
        if master_mode == _MASTER_MODE_PER_SLOT:
            master_failed, master_errors = unmount_tree(hidden_master(slot, corpus))
        else:
            # Never unmount a shared collector source while detaching one slot.
            master_failed, master_errors = 0, []
        failures = entry_errors + view_errors + master_errors
        if entry_failed or view_failed or master_failed:
            raise ValueError("umount_failed: " + "; ".join(failures))
        fstab_removed = (
            _remove_managed_fstab_entry(slot, share_source)
            if master_mode == _MASTER_MODE_PER_SLOT
            else False
        )
        # Corpus creds live root-owned in the vault (root:root 0600 — root-only,
        # safe) and are kept so re-attach needs no password re-entry. Only a
        # customer-readable copy (a pre-fix artifact) is a real exposure; remove it.
        customer_cred = customer_credential_path(slot, share)
        customer_cred_removed = customer_cred.exists()
        if customer_cred_removed:
            customer_cred.unlink()
    except Exception as exc:
        print(f"target={args.slot}")
        print("view_detach_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "nas_view_detach", args.slot, "", "fail", str(exc))
        return 1

    had_record = record is not None
    if had_record:
        drop_view_record(views, slot, corpus)
        save_views_state(state_root, views)
    print(f"target={slot}")
    print(f"corpus={corpus}")
    print(f"share={share_source}")
    print(f"master_mode={master_mode}")
    print(f"fstab_entry_removed={'yes' if fstab_removed else 'no'}")
    print(f"state_record_removed={'yes' if had_record else 'no'}")
    print(f"customer_credential_removed={'yes' if customer_cred_removed else 'no'}")
    print("root_credential_removed=no")
    print("view_detach_status=ok")
    _append_action_log(state_root, "nas_view_detach", slot, share_source, "ok")
    return 0


def cmd_nas_view_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    views = load_views_state(state_root)
    # 한 슬롯이 여러 소스 뷰를 가질 수 있다 — 전부 싣는다. 소비자(리컨실러)는
    # view_N_share/_corpus 로 소스를 가른다. 빠뜨리면 그 소스는 화면에서 사라지고,
    # 안 보이는 소스는 초록으로 오해된다.
    records = list(iter_view_records(views))
    issue_codes: list[str] = []
    observation_gaps: list[str] = []
    print("view_status_schema=agent-runtime-nas-view-status/v1")
    print(f"view_count={len(records)}")
    print("mutates=false")
    exit_code = 0
    for index, (slot, corpus, record) in enumerate(records, start=1):
        prefix = f"view_{index}"
        print(f"{prefix}_target={slot}")
        print(f"{prefix}_corpus={corpus}")
        print(f"{prefix}_user_id={record.get('user_id', '')}")
        print(f"{prefix}_share={record.get('share', '')}")
        print(f"{prefix}_package={record.get('package', '')}")
        print(f"{prefix}_paths_json={json.dumps(record.get('paths') or [], ensure_ascii=False, separators=(',', ':'))}")
        healthy = True
        try:
            master_mode = _record_master_mode(record)
            if master_mode == _MASTER_MODE_SHARED:
                master = _shared_master_for_record(record, record.get("share", ""), state_root)
                # The collector mount may be rw.  It is never exposed directly;
                # every selected child and the slot entry must still be ro.
                _, _, master_rows = _findmnt_one(master)
                master_mounted = bool(master_rows)
                master_readonly = master_mounted and _is_readonly_mount(master_rows[0])
                master_readonly_required = False
            else:
                master = hidden_master(slot, corpus)
                rc, _, master_rows = _findmnt_one(master)
                master_mounted = rc == 0 and bool(master_rows)
                master_readonly = master_mounted and _is_readonly_mount(master_rows[0])
                master_readonly_required = True
            master_validation = "ok"
        except Exception as exc:
            master_mode = str(record.get("master_mode") or _MASTER_MODE_PER_SLOT)
            master = Path(str(record.get("master_path") or hidden_master(slot, corpus)))
            master_mounted = False
            master_readonly = False
            master_readonly_required = master_mode != _MASTER_MODE_SHARED
            master_validation = str(exc)
            healthy = False
        print(f"{prefix}_master_mode={master_mode}")
        print(f"{prefix}_master_path={master.as_posix()}")
        print(f"{prefix}_master_mounted={'yes' if master_mounted else 'no'}")
        print(f"{prefix}_master_readonly={'yes' if master_readonly else 'no'}")
        print(f"{prefix}_master_readonly_required={'yes' if master_readonly_required else 'no'}")
        print(f"{prefix}_master_validation={master_validation}")
        if not master_mounted or (master_readonly_required and not master_readonly):
            healthy = False

        entry = slot_entry(slot, corpus)
        rc, _, rows = _findmnt_one(entry)
        entry_mounted = rc == 0 and bool(rows)
        entry_readonly = entry_mounted and _is_readonly_mount(rows[0])
        print(f"{prefix}_entry_mounted={'yes' if entry_mounted else 'no'}")
        print(f"{prefix}_entry_mounted_readonly={'yes' if entry_readonly else 'no'}")
        if not entry_mounted or not entry_readonly:
            healthy = False
        (
            evidence_applicable,
            grant_evidence,
            grant_evidence_complete,
            grant_evidence_green,
        ) = _view_grant_evidence(slot, corpus, record, master)
        print(f"{prefix}_grant_evidence_applicable={evidence_applicable}")
        print(f"{prefix}_grant_evidence_count={len(grant_evidence)}")
        print(
            f"{prefix}_grant_evidence_json="
            + json.dumps(grant_evidence, ensure_ascii=False, separators=(",", ":"))
        )
        print(f"{prefix}_grant_evidence_complete={'yes' if grant_evidence_complete else 'no'}")
        if evidence_applicable == "yes" and not grant_evidence_complete:
            observation_gaps.append("grant_evidence_incomplete")
        if evidence_applicable == "yes" and not grant_evidence_green:
            healthy = False
        print(f"{prefix}_healthy={'yes' if healthy else 'no'}")
        if not healthy:
            issue_codes.append("view_unhealthy")
            exit_code = 1

    # Boot persistence: a healthy view that will not survive a reboot is a
    # latent outage — the master needs its managed fstab pair, and the binds
    # need the @reboot `nas view restore` crontab line (root crontab, so this
    # half is only decidable when run via sudo).
    fstab_text = _read_fstab()
    if records:
        missing: list[str] = []
        for slot, corpus, record in records:
            try:
                mode = _record_master_mode(record)
                if mode == _MASTER_MODE_SHARED:
                    master = shared_master_for_share(parse_smb_share(record.get("share", "")), state_root)
                    present = (
                        master is not None
                        and Path(str(record.get("master_path") or "")).as_posix() == master.as_posix()
                        and shared_master_fstab_entry_present(record.get("share", ""), master, fstab_text)
                    )
                else:
                    present = fstab_boot_entry_present(slot, record.get("share", ""), fstab_text)
            except Exception:
                present = False
            if not present:
                missing.append(slot if corpus == PRIMARY_CORPUS else f"{slot}:{corpus}")
        print(f"boot_fstab_entries={len(records) - len(missing)}/{len(records)}")
        if missing:
            print(f"boot_fstab_missing={','.join(missing)}")
            issue_codes.append("boot_fstab_missing")
            exit_code = 1
        if _is_root():
            proc = _run_text(["crontab", "-l"], timeout=10)
            # `crontab -l` exits non-zero when root has no crontab — that is
            # a definite "no", not an error.
            has_cron = proc.returncode == 0 and crontab_has_reboot_restore(proc.stdout)
            print(f"boot_restore_cron={'yes' if has_cron else 'no'}")
            if not has_cron:
                issue_codes.append("boot_restore_missing")
                exit_code = 1
        else:
            print("boot_restore_cron=unknown_requires_root")
            observation_gaps.append("boot_restore_requires_root")

    # nofail keeps a lost boot race silent (mounts absent, boot "fine") —
    # surface failed CIFS mount units so the first status line after an
    # outage is loud instead.
    failed_units, failed_error = failed_cifs_mount_units()
    if failed_error is not None:
        print(f"failed_cifs_mount_units=unknown reason={failed_error}")
        observation_gaps.append("failed_cifs_mount_units_unavailable")
    else:
        print(f"failed_cifs_mount_units={len(failed_units)}")
        if failed_units:
            print("failed_cifs_mount_unit_names=" + ",".join(failed_units))
            issue_codes.append("failed_cifs_mount_units")
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
        issue_codes.append("managed_fstab_unmounted")
        exit_code = 1
    print(f"view_status={'ok' if exit_code == 0 else 'degraded'}")
    print(f"view_exit_code={exit_code}")
    print(
        "view_status_issues_json="
        + json.dumps(sorted(set(issue_codes)), ensure_ascii=False, separators=(",", ":"))
    )
    print(
        "view_observation_gaps_json="
        + json.dumps(sorted(set(observation_gaps)), ensure_ascii=False, separators=(",", ":"))
    )
    # This terminal marker is deliberately last.  Consumers may use an rc=1
    # degraded snapshot only when this line and every declared row arrived.
    print("view_snapshot_complete=yes")
    return exit_code


def cmd_nas_view_package_info(args: argparse.Namespace) -> int:
    """Read-only package evidence used by the scoped operator console."""
    if not _require_root("package-info"):
        return 2
    try:
        user_id = validate_user_id(args.user_id)
        rc, _, rows = _findmnt_one(_KAKAO_PACKAGE_ROOT)
        if rc != 0 or not rows or rows[0].get("fstype") != "cifs" or not _is_readonly_mount(rows[0]):
            raise ValueError("kakao package root is not a read-only CIFS mount")
        package = find_user_package(_KAKAO_PACKAGE_ROOT, user_id)
        rooms = load_package_room_summary(package)
        membership_count = len(load_membership_rooms(package))
    except Exception as exc:
        print(f"user_id={getattr(args, 'user_id', '')}")
        print("package_status=fail")
        print(f"reason={exc}")
        print("mutates=false")
        return 1
    print(f"user_id={user_id}")
    print(f"package={package.name}")
    print(f"membership_room_count={membership_count}")
    print(f"rooms_json={json.dumps(rooms, ensure_ascii=False, separators=(',', ':'))}")
    print("package_status=ok")
    print("mutates=false")
    return 0


def _kakao_catalog(root: Path) -> tuple[list[dict], dict[str, str]]:
    catalog_path = root / "users.json"
    rc, _, rows = _findmnt_one(root)
    if rc != 0 or not rows or rows[0].get("fstype") != "cifs" or not _is_readonly_mount(rows[0]):
        raise ValueError("kakao package root is not a read-only CIFS mount")
    document = json.loads(catalog_path.read_text(encoding="utf-8"))
    if document.get("schema") != "kw-users-catalog/1" or not isinstance(document.get("users"), list):
        raise ValueError("unexpected Kakao catalog schema")
    users = []
    for raw in document["users"]:
        if not isinstance(raw, dict):
            continue
        users.append({
            "user_id": validate_user_id(str(raw.get("user_id") or "")),
            "display_name": str(raw.get("display_name") or "")[:100],
            "job_title": str(raw.get("job_title") or "")[:100],
            "package_dir": str(raw.get("package_dir") or "")[:300],
        })
    return users, {"membership_complete": "true"}


def _whatsapp_catalog(root: Path) -> tuple[list[dict], dict[str, str]]:
    db = root / "whatsapp.db"
    rc, _, rows = _findmnt_one(root)
    if rc != 0 or not rows or rows[0].get("fstype") != "cifs" or not _is_readonly_mount(rows[0]):
        raise ValueError("WhatsApp root is not a read-only CIFS mount")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rooms_by_user: dict[str, list[dict[str, object]]] = {}
        for user_id, chat_id, room_name, message_count in conn.execute(
            "SELECT author, chat_id, COALESCE(MAX(NULLIF(TRIM(chat_name),'')),''), COUNT(*) "
            "FROM messages WHERE is_group=1 AND author IS NOT NULL AND TRIM(author)<>'' "
            "GROUP BY author, chat_id ORDER BY author, MAX(timestamp) DESC"
        ):
            rooms_by_user.setdefault(str(user_id), []).append({
                "chat_id": str(chat_id),
                "room_name": str(room_name)[:200],
                "message_count": int(message_count),
            })
        result = [{
            "user_id": validate_user_id(str(user_id)), "display_name": str(display_name)[:100],
            "message_count": int(message_count), "observed_room_count": int(room_count),
            "rooms": rooms_by_user.get(str(user_id), []),
        } for user_id, display_name, message_count, room_count in conn.execute(
            "SELECT author, COALESCE(MAX(NULLIF(TRIM(author_name),'')),''), COUNT(*), "
            "COUNT(DISTINCT chat_id) FROM messages "
            "WHERE is_group=1 AND author IS NOT NULL AND TRIM(author)<>'' "
            "GROUP BY author ORDER BY 2, author"
        )]
    finally:
        conn.close()
    return result, {"membership_complete": "false"}


_CATALOG_DRIVERS = {"kakao_package": _kakao_catalog, "whatsapp_author": _whatsapp_catalog}


def cmd_nas_view_catalog(args: argparse.Namespace) -> int:
    """Return sanitized observations for any registered catalog driver."""
    if not _require_root("catalog"):
        return 2
    source = str(getattr(args, "source", "kakao") or "kakao")
    try:
        share_name, corpus = corpus_named(source)
        driver = _CATALOG_DRIVERS[corpus.layout]
        result, metadata = driver(Path("/mnt/nas") / share_name)
    except Exception as exc:
        print("catalog_status=fail")
        print(f"reason={exc}")
        print("mutates=false")
        return 1
    print(f"catalog_count={len(result)}")
    print(f"catalog_json={json.dumps(result, ensure_ascii=False, separators=(',', ':'))}")
    for key, value in metadata.items():
        print(f"{key}={value}")
    print(f"source={source}")
    print("identity_authority=person_identity")
    print("catalog_status=ok")
    print("mutates=false")
    return 0


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
    records = list(iter_view_records(views))
    print(f"view_count={len(records)}")
    boot_failed = 0
    with _restore_lock():
        if records:
            # After a power cut the server usually boots before the NAS answers —
            # wait for SMB, then remount every fstab CIFS entry that lost the boot
            # race (mount -a is idempotent: already-mounted entries are skipped).
            hosts = []
            for _slot, _corpus, record in records:
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
        # A child view must never be rebuilt on an incomplete CIFS base. The
        # old flow could replace a healthy package bind with an empty directory
        # while still printing per-slot "restored" lines.
        if boot_failed:
            print("view_restore_status=fail")
            return 1
        failed = _restore_views(state_root, records)
    ok = failed == 0 and boot_failed == 0
    print(f"view_restore_status={'ok' if ok else 'fail'}")
    return 0 if ok else 1


def _restore_views(state_root: Path, records: list) -> int:
    """재부팅 복구 — 슬롯의 모든 소스 뷰를 되살린다. 한 소스가 실패해도 나머지는
    계속 복구한다(카카오가 죽어서 그룹웨어까지 못 돌아오는 일 없게)."""
    failed = 0
    for slot, corpus, record in records:
        share_source = record.get("share", "")
        user_id = record.get("user_id", "")
        try:
            _ensure_hidden_dirs(slot, corpus)
            master_mode = _record_master_mode(record)
            if master_mode == _MASTER_MODE_SHARED:
                master = _shared_master_for_record(record, share_source, state_root)
            else:
                master = hidden_master(slot, corpus)
                ok, reason = _mount_master(master, share_source)
                if not ok:
                    raise ValueError(f"master_mount_failed: {reason}")
            plan = build_view_plan(
                slot,
                user_id,
                share_source,
                state_root,
                list(record.get("paths") or []),
                master_override=master,
            )
            ok, reason, bound_rooms = _apply_binds(plan)
            if not ok:
                raise ValueError(f"bind_failed: {reason}")
            if getattr(plan, "corpus", None) == PRIMARY_CORPUS:
                entry = Path(plan.entry)
                required = (
                    entry / "package" / "membership.json",
                    entry / "package" / "messages.sqlite",
                    entry / "media",
                )
                missing = [path.as_posix() for path in required if not path.exists()]
                if missing:
                    unmount_tree(plan.entry)
                    unmount_tree(plan.view)
                    raise ValueError("view_content_missing:" + ",".join(missing))
            print(
                f"restored target={slot} corpus={corpus} user_id={user_id} "
                f"master_mode={master_mode} rooms_bound={bound_rooms}"
            )
            _append_action_log(state_root, "nas_view_restore", slot, share_source, "ok", f"user_id={user_id}")
        except Exception as exc:
            failed += 1
            print(f"restore_failed target={slot} reason={exc}")
            _append_action_log(state_root, "nas_view_restore", slot, share_source, "fail", str(exc))
    return failed
