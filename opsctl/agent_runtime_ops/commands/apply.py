from __future__ import annotations

import argparse
import sys

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..domain.runtime_checks import (
    profile_startup_timeout_seconds as _profile_startup_timeout_seconds,
    run_live_slot_checks_with_wait as _run_live_slot_checks_with_wait,
)
from ..domain.runtime_backup import (
    latest_backup,
    load_backup_runtime_contract,
    restore_backup,
)
from ..domain.runtime_manifest import desired_from_runtime_manifest
from ..domain.retrieval_contract import run_retrieval_status_probe
from ..domain.runtime_truth import find_gateway_container_by_binding
from ..domain.runtime_paths import (
    slot_runtime_dir,
)


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = desired_from_runtime_manifest(args.slot, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "apply", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    return _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(args.allow_first_apply),
        action_name="apply",
    )


def cmd_rollback(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollback TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        runtime_dir = slot_runtime_dir(args.slot)
        backup_dir = latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = restore_backup(args.slot, runtime_dir, backup_dir, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollback", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"target={args.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_reason={reason}")
    if not ok:
        print("rollback_status=fail")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", reason)
        return 1

    try:
        desired, profile = load_backup_runtime_contract(args.slot, backup_dir, state_root)
    except Exception as exc:
        print("rollback_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", str(exc))
        return 1

    failed = 0
    for check_ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(check_ok, name, detail)
        if not check_ok:
            failed += 1
    if failed:
        print(f"rollback_status=fail live_failed={failed}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", f"live_failed={failed}")
        return 1

    if isinstance(desired.image_spec.get("retrieval_contract"), dict):
        container, lookup = find_gateway_container_by_binding(desired.route)
        if not container:
            print("rollback_status=fail")
            print(f"reason=retrieval_probe_container_failed:{lookup}")
            _append_action_log(
                state_root,
                "rollback",
                args.slot,
                str(backup_dir),
                "fail",
                "retrieval_probe_container_failed",
            )
            return 1
        try:
            status = run_retrieval_status_probe(container, desired.image_spec)
        except Exception as exc:
            print("rollback_status=fail")
            print(f"reason=retrieval_disable_observation_failed:{exc}")
            _append_action_log(
                state_root,
                "rollback",
                args.slot,
                str(backup_dir),
                "fail",
                "retrieval_disable_observation_failed",
            )
            return 1
        print(f"rollback_retrieval_enabled={'yes' if desired.image_spec.get('retrieval_enabled') is True else 'no'}")
        print(f"rollback_retrieval_binding_digest={desired.image_spec.get('retrieval_binding_digest') or 'none'}")
        print(f"rollback_retrieval_revocation_status={(status or {}).get('revocationStatus') or 'not_applicable'}")

    print("rollback_status=ok")
    _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "ok", reason)
    return 0
