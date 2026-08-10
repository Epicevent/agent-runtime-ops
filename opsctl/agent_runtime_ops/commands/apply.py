from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import redirect_stdout
import io
import json
import re
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
    MarkerBoundRecoveryError,
    existing_runtime_host_mutation_lock,
    existing_runtime_transaction_lock,
    finish_exact_rollback_transaction,
    finish_rollback_transaction,
    import_legacy_agent_runtime_backups,
    latest_backup,
    load_backup_runtime_contract,
    pending_rollback_backup,
    pending_rollback_identity,
    require_exact_pending_rollback,
    restore_backup,
    runtime_host_mutation_lock,
    runtime_transaction_lock,
    validate_expected_rollback_identity,
)
from ..domain.runtime_manifest import desired_from_runtime_manifest
from ..routing import get_runtime_binding
from ..domain.runtime_paths import (
    slot_runtime_dir,
)


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl apply TARGET",
            file=sys.stderr,
        )
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = desired_from_runtime_manifest(args.slot, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(
                state_root, "apply", args.slot, args.slot, "fail", str(exc)
            )
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


_MARKER_BOUND_RECOVERY_SCHEMA = "agent-runtime-marker-bound-recovery/v1"
_EXACT_RECOVERY_POST_COMMIT_LOG_FAILURE_RC = 3
_EXACT_RECOVERY_TARGET_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_MARKER_EXPECTATION_FIELDS = {
    "backup_metadata_sha256": "expected_backup_metadata_sha256",
    "backup_name": "expected_backup_name",
    "marker_sha256": "expected_marker_sha256",
    "transaction_id": "expected_transaction_id",
}


def _marker_expectations(args: argparse.Namespace) -> dict[str, str] | None:
    values = {
        field: getattr(args, attribute, None)
        for field, attribute in _MARKER_EXPECTATION_FIELDS.items()
    }
    present = {field for field, value in values.items() if value is not None}
    if not present:
        return None
    if present != set(values):
        raise MarkerBoundRecoveryError("exact_expectation_set_incomplete")
    if _EXACT_RECOVERY_TARGET_RE.fullmatch(str(args.slot)) is None:
        raise MarkerBoundRecoveryError("exact_target_invalid")
    expected = {field: str(value) for field, value in values.items()}
    validate_expected_rollback_identity(expected)
    return expected


def _validate_exact_recovery_target(state_root, target: str) -> None:
    try:
        binding = get_runtime_binding(target, state_root)
    except Exception as exc:
        raise MarkerBoundRecoveryError("exact_target_not_observable") from exc
    if not binding.enabled or binding.linux_account != target:
        raise MarkerBoundRecoveryError("exact_target_not_canonical")


def _emit_marker_recovery_receipt(
    args: argparse.Namespace,
    expected: dict[str, str],
    *,
    result: str,
    reason_code: str,
    runtime_mutation_started: bool,
    transaction_state: str,
    terminal_state: str,
) -> None:
    target = str(args.slot)
    if _EXACT_RECOVERY_TARGET_RE.fullmatch(target) is None:
        target = "unavailable"
    value = {
        "backup_metadata_sha256": expected["backup_metadata_sha256"],
        "backup_name": expected["backup_name"],
        "marker_sha256": expected["marker_sha256"],
        "reason_code": reason_code,
        "result": result,
        "runtime_mutation_started": runtime_mutation_started,
        "schema": _MARKER_BOUND_RECOVERY_SCHEMA,
        "target": target,
        "terminal_state": terminal_state,
        "transaction_id": expected["transaction_id"],
        "transaction_state": transaction_state,
        "writes": 1 if runtime_mutation_started else 0,
    }
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))


def _exact_recovery_post_state(
    state_root,
    slot: str,
    expected: dict[str, str],
    *,
    marker_finish_observed: bool = False,
) -> tuple[str, str]:
    try:
        observed = pending_rollback_identity(state_root, slot)
    except Exception:
        return "unavailable", "unknown"
    if observed is None:
        if marker_finish_observed:
            return "committed", "complete"
        return "absent", "incomplete"
    if observed == expected:
        return "pending", "incomplete"
    return "unavailable", "unknown"


def cmd_rollback(args: argparse.Namespace) -> int:
    try:
        exact_expected = _marker_expectations(args)
    except MarkerBoundRecoveryError as exc:
        placeholder = {
            field: "unavailable" for field in _MARKER_EXPECTATION_FIELDS
        }
        _emit_marker_recovery_receipt(
            args,
            placeholder,
            result="rejected",
            reason_code=exc.reason_code,
            runtime_mutation_started=False,
            transaction_state="unavailable",
            terminal_state="incomplete",
        )
        return 2
    if not _is_root():
        if exact_expected is not None:
            _emit_marker_recovery_receipt(
                args,
                exact_expected,
                result="rejected",
                reason_code="root_required",
                runtime_mutation_started=False,
                transaction_state="unavailable",
                terminal_state="incomplete",
            )
            return 2
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl rollback TARGET",
            file=sys.stderr,
        )
        return 2
    state_root = _state_root(args)
    if exact_expected is not None:
        execution_entered = False
        mutation_started = False
        locked_post_state = ("unavailable", "unknown")

        def observe_mutation_start() -> None:
            nonlocal mutation_started
            mutation_started = True

        try:
            _validate_exact_recovery_target(state_root, args.slot)
            # Admission is read-only before the existing persistent lock plane is
            # opened.  The exact identity is revalidated again under both locks.
            require_exact_pending_rollback(state_root, args.slot, exact_expected)
            with existing_runtime_host_mutation_lock(state_root):
                with existing_runtime_transaction_lock(state_root, args.slot):
                    backup_dir, _ = require_exact_pending_rollback(
                        state_root,
                        args.slot,
                        exact_expected,
                    )
                    hidden_output = io.StringIO()
                    try:
                        with redirect_stdout(hidden_output):
                            execution_entered = True
                            rc = _cmd_rollback_locked(
                                args,
                                state_root,
                                selected_backup=backup_dir,
                                exact_expected=exact_expected,
                                on_mutation_started=observe_mutation_start,
                            )
                    except BaseException:
                        locked_post_state = _exact_recovery_post_state(
                            state_root,
                            args.slot,
                            exact_expected,
                        )
                        raise
                    locked_post_state = _exact_recovery_post_state(
                        state_root,
                        args.slot,
                        exact_expected,
                        marker_finish_observed=(
                            rc
                            in {0, _EXACT_RECOVERY_POST_COMMIT_LOG_FAILURE_RC}
                        ),
                    )
        except MarkerBoundRecoveryError as exc:
            transaction_state, terminal_state = locked_post_state
            if not execution_entered and not exc.reason_code.startswith(
                "exact_target_"
            ):
                transaction_state, _ = _exact_recovery_post_state(
                    state_root,
                    args.slot,
                    exact_expected,
                )
            _emit_marker_recovery_receipt(
                args,
                exact_expected,
                result="failed" if mutation_started else "rejected",
                reason_code=exc.reason_code,
                runtime_mutation_started=mutation_started,
                transaction_state=transaction_state,
                terminal_state=(
                    terminal_state if execution_entered else "incomplete"
                ),
            )
            return 1
        except RuntimeError as exc:
            if execution_entered:
                transaction_state, terminal_state = locked_post_state
                _emit_marker_recovery_receipt(
                    args,
                    exact_expected,
                    result="failed" if mutation_started else "rejected",
                    reason_code=(
                        "recovery_execution_exception"
                        if mutation_started
                        else "recovery_execution_failed_before_mutation"
                    ),
                    runtime_mutation_started=mutation_started,
                    transaction_state=transaction_state,
                    terminal_state=terminal_state,
                )
                return 1
            reason_code = (
                "lock_unavailable"
                if str(exc).startswith("another runtime ")
                else "recovery_admission_failed"
            )
            _emit_marker_recovery_receipt(
                args,
                exact_expected,
                result="rejected",
                reason_code=reason_code,
                runtime_mutation_started=False,
                transaction_state="unavailable",
                terminal_state="incomplete",
            )
            return 1
        except Exception:
            if execution_entered:
                transaction_state, terminal_state = locked_post_state
                _emit_marker_recovery_receipt(
                    args,
                    exact_expected,
                    result="failed" if mutation_started else "rejected",
                    reason_code=(
                        "recovery_execution_exception"
                        if mutation_started
                        else "recovery_execution_failed_before_mutation"
                    ),
                    runtime_mutation_started=mutation_started,
                    transaction_state=transaction_state,
                    terminal_state=terminal_state,
                )
                return 1
            _emit_marker_recovery_receipt(
                args,
                exact_expected,
                result="rejected",
                reason_code="recovery_admission_failed",
                runtime_mutation_started=False,
                transaction_state="unavailable",
                terminal_state="incomplete",
            )
            return 1
        transaction_state, terminal_state = locked_post_state
        succeeded = (
            rc == 0 and mutation_started and transaction_state == "committed"
        )
        log_failed_after_commit = (
            rc == _EXACT_RECOVERY_POST_COMMIT_LOG_FAILURE_RC
            and transaction_state == "committed"
        )
        _emit_marker_recovery_receipt(
            args,
            exact_expected,
            result=(
                "complete"
                if succeeded
                else ("failed" if mutation_started else "rejected")
            ),
            reason_code=(
                "recovery_committed"
                if succeeded
                else (
                    "recovery_committed_action_log_failed"
                    if log_failed_after_commit
                    else (
                        "recovery_execution_failed"
                        if mutation_started
                        else "recovery_execution_failed_before_mutation"
                    )
                )
            ),
            runtime_mutation_started=mutation_started,
            transaction_state=transaction_state,
            terminal_state=terminal_state if succeeded else "incomplete",
        )
        return 0 if succeeded else 1
    try:
        with runtime_host_mutation_lock(state_root):
            with runtime_transaction_lock(state_root, args.slot):
                return _cmd_rollback_locked(args, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(
                state_root,
                "rollback",
                args.slot,
                args.slot,
                "fail",
                str(exc),
            )
        except Exception:
            pass
        return 1


def _cmd_rollback_locked(
    args: argparse.Namespace,
    state_root,
    *,
    selected_backup=None,
    exact_expected: dict[str, str] | None = None,
    on_mutation_started: Callable[[], None] | None = None,
) -> int:
    mutation_started = False

    def observe_mutation_start() -> None:
        nonlocal mutation_started
        mutation_started = True
        if on_mutation_started is not None:
            on_mutation_started()

    try:
        runtime_dir = slot_runtime_dir(args.slot)
        backup_dir = selected_backup
        if backup_dir is None:
            backup_dir = pending_rollback_backup(state_root, args.slot)
        if backup_dir is None:
            backup_dir = latest_backup(state_root, args.slot)
        if backup_dir is None:
            imported = import_legacy_agent_runtime_backups(
                args.slot,
                runtime_dir,
                state_root,
            )
            print(f"legacy_backups_imported={len(imported)}")
            backup_dir = latest_backup(state_root, args.slot)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = restore_backup(
            args.slot,
            runtime_dir,
            backup_dir,
            state_root,
            expected_transaction=exact_expected,
            on_mutation_started=(
                observe_mutation_start if exact_expected is not None else None
            ),
        )
    except MarkerBoundRecoveryError:
        raise
    except Exception as exc:
        print(f"target={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        if exact_expected is None or mutation_started:
            try:
                _append_action_log(
                    state_root, "rollback", args.slot, args.slot, "fail", str(exc)
                )
            except Exception:
                pass
        return 1
    print(f"target={args.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_reason={reason}")
    if not ok:
        print("rollback_status=fail")
        _append_action_log(
            state_root, "rollback", args.slot, str(backup_dir), "fail", reason
        )
        return 1

    if reason == "rollback_empty_baseline_restored":
        try:
            if exact_expected is None:
                finish_rollback_transaction(args.slot, state_root, backup_dir)
            else:
                finish_exact_rollback_transaction(
                    args.slot,
                    state_root,
                    backup_dir,
                    exact_expected,
                )
        except Exception as exc:
            print("rollback_status=fail")
            print(f"reason=rollback_transaction_finish_failed:{exc}")
            _append_action_log(
                state_root,
                "rollback",
                args.slot,
                str(backup_dir),
                "fail",
                "rollback_transaction_finish_failed",
            )
            return 1
        print("rollback_status=ok")
        print("rollback_empty_baseline=yes")
        try:
            _append_action_log(
                state_root,
                "rollback",
                args.slot,
                str(backup_dir),
                "ok",
                "rollback_empty_baseline_restored_verified",
            )
        except Exception:
            if exact_expected is None:
                raise
            return _EXACT_RECOVERY_POST_COMMIT_LOG_FAILURE_RC
        return 0

    try:
        desired, profile = load_backup_runtime_contract(
            args.slot, backup_dir, state_root
        )
    except Exception as exc:
        print("rollback_status=fail")
        print(f"reason={exc}")
        _append_action_log(
            state_root, "rollback", args.slot, str(backup_dir), "fail", str(exc)
        )
        return 1

    failed_checks: set[str] = set()
    for check_ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(check_ok, name, detail)
        if not check_ok:
            failed_checks.add(name)
    if failed_checks:
        print(f"rollback_status=fail live_failed={len(failed_checks)}")
        _append_action_log(
            state_root,
            "rollback",
            args.slot,
            str(backup_dir),
            "fail",
            "live_failed=" + ",".join(sorted(failed_checks)),
        )
        return 1

    try:
        if exact_expected is None:
            finish_rollback_transaction(args.slot, state_root, backup_dir)
        else:
            finish_exact_rollback_transaction(
                args.slot,
                state_root,
                backup_dir,
                exact_expected,
            )
    except Exception as exc:
        print("rollback_status=fail")
        print(f"reason=rollback_transaction_finish_failed:{exc}")
        _append_action_log(
            state_root,
            "rollback",
            args.slot,
            str(backup_dir),
            "fail",
            "rollback_transaction_finish_failed",
        )
        return 1
    print("rollback_status=ok")
    try:
        _append_action_log(
            state_root,
            "rollback",
            args.slot,
            str(backup_dir),
            "ok",
            reason,
        )
    except Exception:
        if exact_expected is None:
            raise
        return _EXACT_RECOVERY_POST_COMMIT_LOG_FAILURE_RC
    return 0
