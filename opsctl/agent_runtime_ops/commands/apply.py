from __future__ import annotations

import argparse
from pathlib import Path
import sys


def _cli_mod():
    from .. import cli

    return cli


def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def _is_root() -> bool:
    return _cli_mod()._is_root()


def _desired_from_runtime_manifest(slot: str, state_root: Path):
    return _cli_mod()._desired_from_runtime_manifest(slot, state_root)


def _append_action_log(*args, **kwargs):
    return _cli_mod()._append_action_log(*args, **kwargs)


def _apply_desired_slot(*args, **kwargs):
    return _cli_mod()._apply_desired_slot(*args, **kwargs)


def _slot_runtime_dir(slot: str) -> Path:
    return _cli_mod()._slot_runtime_dir(slot)


def _latest_backup(runtime_dir: Path):
    return _cli_mod()._latest_backup(runtime_dir)


def _restore_backup(slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path):
    return _cli_mod()._restore_backup(slot, runtime_dir, backup_dir, state_root)


def _load_backup_runtime_contract(slot: str, backup_dir: Path, state_root: Path):
    return _cli_mod()._load_backup_runtime_contract(slot, backup_dir, state_root)


def _run_live_slot_checks_with_wait(desired, profile, state_root: Path, timeout_seconds: int = 90):
    return _cli_mod()._run_live_slot_checks_with_wait(desired, profile, state_root, timeout_seconds=timeout_seconds)


def _profile_startup_timeout_seconds(profile) -> int:
    return _cli_mod()._profile_startup_timeout_seconds(profile)


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
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
        runtime_dir = _slot_runtime_dir(args.slot)
        backup_dir = _latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = _restore_backup(args.slot, runtime_dir, backup_dir, state_root)
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
        desired, profile = _load_backup_runtime_contract(args.slot, backup_dir, state_root)
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

    print("rollback_status=ok")
    _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "ok", reason)
    return 0
