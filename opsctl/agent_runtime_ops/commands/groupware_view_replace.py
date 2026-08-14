import argparse
from dataclasses import replace
from functools import partial
import os
from pathlib import Path
import shutil

from . import nas_view as legacy
from ..domain import groupware_runtime_observation as observation
from ..domain import nas_views
from ..host import bind_mounts
from ..host import mount_tree_transaction as mount_tx


_CORPUS = "groupware"
_STAGE_ROOT = Path("/run/agent-runtime-ops-nas-view-transactions")
_PENDING_SCHEMA = "agent-runtime-nas-view-replace-pending/v1"
_digest = partial(observation._digest, domain=b"agent-runtime-nas-view-replace/v1\0")
_tree = observation.groupware_mount_tree


def _persist(
    state_root: Path,
    state: dict,
    pending: dict | None = None,
    phase: str = "",
    stage: Path | None = None,
) -> None:
    if stage is not None and stage.exists():
        failed, _ = bind_mounts.unmount_tree(stage)
        if failed:
            raise RuntimeError("stage_cleanup_failed")
        shutil.rmtree(stage)
    if pending is None:
        state.pop("pending_replace", None)
    else:
        pending["phase"] = phase
        current = nas_views.get_view_record(state, pending["slot"], _CORPUS)
        sealed = {key: value for key, value in pending.items() if key != "authority_digest"}
        pending["authority_digest"] = _digest(
            {"pending": sealed, "record": current}
        )
        state["pending_replace"] = pending
    nas_views.save_views_state(state_root, state)


def _prepare_stage(stage: Path) -> None:
    for path in (_STAGE_ROOT, stage.parent, stage):
        path.mkdir(parents=True, exist_ok=True)
        info = path.lstat()
        if info.st_uid or path.is_symlink() or not path.is_dir():
            raise RuntimeError("stage_identity_invalid")
        path.chmod(0o711)
    for name in ("view", "candidate", "rollback"):
        (stage / name).mkdir()
    for command in (
        ["mount", "--bind", str(stage), str(stage)],
        ["mount", "--make-private", str(stage)],
    ):
        if legacy._run_text(command, timeout=20).returncode:
            raise RuntimeError("private_stage_failed")
    rc, _, rows = legacy._findmnt_one(stage)
    if rc or len(rows) != 1 or rows[0].get("propagation") != "private":
        raise RuntimeError("private_stage_unverified")


def _master(record: dict, slot: str) -> Path:
    share = str(record.get("share") or "")
    if legacy._record_master_mode(record) == legacy._MASTER_MODE_SHARED:
        raise RuntimeError("legacy_shared_master_requires_migration")
    master = nas_views.hidden_master(slot, _CORPUS)
    rc, _, rows = legacy._findmnt_one(master)
    if rc or observation._mount(rows, master.as_posix(), share) != (True, True, True):
        raise RuntimeError("master_mount_mismatch")
    return master


def _probe_candidate(record: dict, root: Path, principal) -> str:
    aliases, digest = _tree(root, record, require_complete=True)
    rows = observation._probe_namespace(
        1, principal, tuple((root / alias).as_posix() for alias in aliases)
    )
    readable = all(
        row.get("list_ok") is True
        and (
            row.get("open_read_ok") is True
            or (
                row.get("errno") is None
                and row.get("representative") == "no_regular_file_within_bound"
            )
        )
        for row in rows
    )
    if not readable:
        raise RuntimeError("candidate_principal_probe_failed")
    return digest


def _runtime_contract(result) -> str:
    if result.principal is None or result.reason_code == "runtime_observer_contract_mismatch":
        raise RuntimeError("runtime_contract_unverified")
    return _digest(
        {
            "desired": result.desired_digest,
            "profile": result.runtime_profile_digest,
            "principal": result.principal.identity_digest,
        }
    )


def _top_tree_digest(root: Path, inspection: Path, record: dict) -> str:
    failed, _ = bind_mounts.unmount_tree(inspection)
    if failed:
        raise RuntimeError("inspection_cleanup_failed")
    clone_fd = mount_tx._open_tree(root, clone=True)
    attached = False
    try:
        mount_tx._make_private_tree(clone_fd)
        mount_tx._move_mount(clone_fd, inspection, beneath=False)
        attached = True
        return _tree(inspection, record, require_private=True)[1]
    finally:
        try:
            if attached:
                mount_tx.detach_top(inspection)
        finally:
            os.close(clone_fd)


def recover_pending(state_root: Path, *, boot_restore_ready: bool = False) -> bool:
    state = nas_views.load_views_state(state_root)
    pending = state.get("pending_replace")
    if pending is None:
        return False
    if not isinstance(pending, dict) or pending.get("schema") != _PENDING_SCHEMA:
        raise RuntimeError("pending_replace_invalid")
    phase = str(pending.get("phase") or "")
    slot, generation = (
        str(pending.get("slot") or ""),
        str(pending.get("generation") or ""),
    )
    candidate = pending.get("candidate_record")
    if (
        nas_views.validate_linux_account(slot) != slot
        or len(generation) != 32
        or any(character not in "0123456789abcdef" for character in generation)
    ):
        raise RuntimeError("pending_replace_identity_invalid")
    current = nas_views.get_view_record(state, slot, _CORPUS)
    if phase not in {
        "prepared",
        "rollback_authoritative",
        "rollback_beneath",
        "commit_decided",
    }:
        raise RuntimeError("pending_replace_phase_invalid")
    if not isinstance(current, dict) or not isinstance(candidate, dict):
        raise RuntimeError("pending_replace_record_invalid")
    sealed = {key: value for key, value in pending.items() if key != "authority_digest"}
    if _digest({"pending": sealed, "record": current}) != str(
        pending.get("authority_digest") or ""
    ):
        raise RuntimeError("pending_replace_authority_mismatch")
    if (
        Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        != pending["boot_id"]
    ):
        if not boot_restore_ready:
            raise RuntimeError("pending_replace_boot_restore_required")
        if legacy._restore_views(state_root, list(nas_views.iter_view_records(state))):
            raise RuntimeError("pending_replace_boot_restore_failed")
        _persist(state_root, state)
        return True
    stage = _STAGE_ROOT / nas_views.validate_linux_account(slot) / generation
    live = nas_views.slot_entry(slot, _CORPUS)
    anchor = stage / "rollback"
    rc, error, rows = legacy._findmnt_one(anchor)
    anchor_present = (
        rc == 0 and len(rows) == 1 and rows[0].get("target") == anchor.as_posix()
    )
    if not anchor_present and (rc != 1 or rows):
        raise RuntimeError(error or "rollback_anchor_invalid")
    if phase == "commit_decided":
        if mount_tx.root_mount_layers(live) != 1:
            raise RuntimeError("committed_live_mismatch")
        candidate_digest = str(pending.get("candidate_tree_digest") or "")
        if _tree(live, candidate, require_complete=True)[1] != candidate_digest:
            raise RuntimeError("committed_live_mismatch")
        observed = observation.observe_groupware_runtime(
            slot, state_root, record_override=candidate
        )
        if _runtime_contract(observed) != pending.get("candidate_runtime_contract"):
            raise RuntimeError("committed_runtime_mismatch")
        try:
            canonical_digest = _tree(
                nas_views.view_root(slot, _CORPUS), candidate, require_complete=True
            )[1]
            if canonical_digest != candidate_digest:
                raise RuntimeError("canonical_view_mismatch")
        except RuntimeError:
            target = nas_views.view_root(slot, _CORPUS)
            ok, _ = bind_mounts.bind_ro(stage / "view", target, recursive=True)
            if not ok:
                raise RuntimeError("canonical_install_failed")
            if _tree(target, candidate, require_complete=True)[1] != candidate_digest:
                raise RuntimeError("canonical_install_mismatch")
        if anchor_present:
            mount_tx.detach_top(anchor)
        _persist(state_root, state, stage=stage)
        return False
    old_digest = str(pending.get("old_tree_digest") or "")
    candidate_digest = str(pending.get("candidate_tree_digest") or "")
    if not anchor_present:
        if _tree(live, current)[1] != old_digest:
            raise RuntimeError("old_live_mismatch")
        if _runtime_contract(
            observation.observe_groupware_runtime(
                slot, state_root, record_override=current
            )
        ) != pending.get("old_runtime_contract"):
            raise RuntimeError("old_runtime_mismatch")
        _persist(state_root, state, stage=stage)
        return False
    if _tree(anchor, current, require_private=True)[1] != old_digest:
        raise RuntimeError("rollback_anchor_mismatch")
    inspection = stage / "candidate"
    layers = mount_tx.root_mount_layers(live)
    try:
        top_digest = _top_tree_digest(live, inspection, current)
    except observation.GroupwareRuntimeObservationError:
        top_digest = _top_tree_digest(live, inspection, candidate)
    if phase in {"prepared", "rollback_authoritative"} and layers == 2:
        if top_digest != old_digest:
            raise RuntimeError("rollback_old_top_mismatch")
        mount_tx.detach_top(live)
        layers = 1
        top_digest = _top_tree_digest(live, inspection, candidate)
    elif phase == "rollback_beneath" and layers == 2:
        if top_digest != candidate_digest:
            raise RuntimeError("rollback_candidate_top_mismatch")
        mount_tx.detach_top(live)
        layers = 1
        top_digest = _top_tree_digest(live, inspection, current)
    if layers != 1 or top_digest not in {old_digest, candidate_digest}:
        raise RuntimeError("live_layer_count_invalid")
    if top_digest == candidate_digest:
        if phase != "rollback_beneath":
            _persist(state_root, state, pending, "rollback_beneath")
        anchor_fd = mount_tx._open_tree(anchor, clone=False)
        try:
            clone_fd = mount_tx._clone_tree_from_fd(anchor_fd)
            try:
                mount_tx._make_private_tree(clone_fd)
                mount_tx._move_mount(clone_fd, live, beneath=True)
            finally:
                os.close(clone_fd)
        finally:
            os.close(anchor_fd)
        if mount_tx.root_mount_layers(live) != 2:
            raise RuntimeError("rollback_beneath_unverified")
        if _top_tree_digest(live, inspection, candidate) != candidate_digest:
            raise RuntimeError("rollback_candidate_top_mismatch")
        mount_tx.detach_top(live)
    if _tree(live, current)[1] != old_digest:
        raise RuntimeError("rollback_live_mismatch")
    if _runtime_contract(
        observation.observe_groupware_runtime(
            slot, state_root, record_override=current
        )
    ) != pending.get("old_runtime_contract"):
        raise RuntimeError("rollback_runtime_mismatch")
    mount_tx.detach_top(anchor)
    _persist(state_root, state, stage=stage)
    return False


def _replace(args: argparse.Namespace, state_root: Path) -> None:
    state = nas_views.load_views_state(state_root)
    old = nas_views.get_view_record(state, args.slot, _CORPUS)
    if (
        not isinstance(old, dict)
        or old.get("share") != args.share
        or old.get("user_id") != args.user_id
        or not args.require_content_ready
    ):
        raise RuntimeError("replace_precondition_failed")
    if (
        legacy._groupware_runtime_desired_digest(args.slot, state_root)
        != args.expected_runtime_desired_digest
    ):
        raise RuntimeError("current_desired_digest_mismatch")
    runtime = observation._resolve_runtime(args.slot, state_root)
    principal = observation._service_principal(runtime)
    before = observation.observe_groupware_runtime(args.slot, state_root)
    if (
        before.principal is None
        or before.principal.identity_digest != principal.identity_digest
        or before.container_identity_digest != runtime.container_identity_digest
        or before.runtime_profile_digest != runtime.runtime_profile_digest
    ):
        raise RuntimeError("runtime_changed_during_preflight")
    plan = nas_views.build_view_plan(
        args.slot,
        args.user_id,
        args.share,
        state_root,
        list(args.path),
        master_override=_master(old, args.slot),
    )
    if plan.missing_rooms or len(plan.room_binds) != len(args.path):
        raise RuntimeError("content_not_ready")
    generation = os.urandom(16).hex()
    new = dict(
        old,
        paths=list(plan.paths),
        rooms_bound=len(plan.room_binds),
        rooms_missing_media=[],
        assigned_at=legacy._now_iso(),
    )
    pending = {
        "schema": _PENDING_SCHEMA,
        "phase": "prepared",
        "slot": args.slot,
        "generation": generation,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "candidate_record": new,
        "old_runtime_contract": _runtime_contract(before),
        "candidate_runtime_contract": "",
        "old_tree_digest": _tree(nas_views.slot_entry(args.slot, _CORPUS), old)[1],
        "candidate_tree_digest": "",
    }
    _persist(state_root, state, pending, "prepared")
    stage = _STAGE_ROOT / nas_views.validate_linux_account(args.slot) / generation
    _prepare_stage(stage)
    staged = replace(
        plan,
        view=stage / "view",
        entry=stage / "candidate",
        room_binds=[
            (source, stage / "view" / target.relative_to(plan.view))
            for source, target in plan.room_binds
        ],
    )
    ok, _, _ = legacy._apply_binds(staged)
    if not ok:
        raise RuntimeError("candidate_bind_failed")
    pending["candidate_tree_digest"] = _probe_candidate(new, staged.entry, principal)
    _persist(state_root, state, pending, "prepared")
    anchor_fd = candidate_fd = -1
    try:
        anchor_fd, candidate_fd = mount_tx.prepare_transaction(
            staged.entry, nas_views.slot_entry(args.slot, _CORPUS), stage / "rollback"
        )
        _persist(state_root, state, pending, "rollback_authoritative")
        mount_tx._move_mount(
            candidate_fd, nas_views.slot_entry(args.slot, _CORPUS), beneath=True
        )
        mount_tx.detach_top(nas_views.slot_entry(args.slot, _CORPUS))
    finally:
        for descriptor in (anchor_fd, candidate_fd):
            if descriptor >= 0:
                os.close(descriptor)
    if (
        mount_tx.root_mount_layers(nas_views.slot_entry(args.slot, _CORPUS)) != 1
        or _tree(
            nas_views.slot_entry(args.slot, _CORPUS),
            new,
            require_complete=True,
        )[1]
        != pending["candidate_tree_digest"]
    ):
        raise RuntimeError("candidate_live_tree_mismatch")
    observed = observation.observe_groupware_runtime(
        args.slot, state_root, record_override=new
    )
    if (
        observed.status != "healthy"
        or observed.principal is None
        or observed.principal.identity_digest != principal.identity_digest
        or observed.container_identity_digest != runtime.container_identity_digest
        or observed.runtime_profile_digest != runtime.runtime_profile_digest
    ):
        raise RuntimeError("candidate_runtime_mismatch")
    pending["candidate_runtime_contract"] = _runtime_contract(observed)
    nas_views.put_view_record(state, args.slot, _CORPUS, new)
    _persist(state_root, state, pending, "commit_decided")
    recover_pending(state_root)


@legacy._serialized_view_mutation
def cmd_nas_view_replace(args: argparse.Namespace) -> int:
    if not legacy._require_root("replace"):
        return 2
    state_root = legacy._state_root(args)
    try:
        _replace(args, state_root)
    except Exception as exc:
        reason = str(exc)
        if not reason or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789_:"
            for character in reason
        ):
            reason = "unexpected_error"
        recovery_status = "ok"
        try:
            recover_pending(state_root)
        except Exception:
            recovery_status = "failed"
        print(
            f"target={args.slot}\nview_replace_status=fail\nreason={reason}"
            f"\nrecovery_status={recovery_status}"
        )
        return 1
    print(f"target={args.slot}\npaths_bound={len(args.path)}\nview_replace_status=ok")
    return 0
