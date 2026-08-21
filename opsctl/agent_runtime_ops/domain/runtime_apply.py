from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Callable

import os

from ..host.account_files import ensure_not_symlink_chain, runtime_ids
from ..redaction import redact
from ..renderer import render_compose
from ..runtime_socket_projection import require_runtime_socket_source
from ..routing import RuntimeBinding
from .actions import append_action_log
from .common import check_line, now_iso, run_text, run_text_cwd
from .runtime_checks import (
    profile_startup_timeout_seconds,
    run_live_slot_checks_with_wait,
    run_static_slot_checks,
)
from .config_contract import config_owner_run_as, run_config_validate_in_image
from .image_specs import image_spec_config_contract
from .runtime_backup import (
    backup_agent_runtime_state,
    begin_rollback_transaction,
    finish_rollback_transaction,
    load_backup_runtime_contract,
    restore_backup,
    restore_backup_env,
    runtime_host_mutation_lock,
    runtime_transaction_lock,
    pending_rollback_identity,
)
from .canary_transaction import begin as begin_canary_transaction
from .canary_transaction import finish as finish_canary_transaction
from .image_specs import digest_from_image_ref
from .runtime_manifest import write_slot_manifests
from .docker_compose import (
    docker_compose_command,
    env_file_keys,
    required_compose_variables,
)
from .runtime_paths import (
    agent_compose_path,
    agent_manifest_path,
    atomic_write,
    slot_config_dir,
    slot_runtime_dir,
    state_manifest_path,
)
from .runtime_truth import find_gateway_container
from .workspace_guidance import ensure_runtime_workspace_guidance


FINAL_WORKSPACE_GUIDANCE_STABILIZE_DELAYS_SECONDS = [10, 30, 60]


def ensure_nas_workspace_dir(slot: str) -> Path:
    """Guarantee the OCn workspace bind source exists before compose up.

    The compose templates bind {home}/workspace (the slot's writable OCn tree).
    Slot CREATION provisions it (admin), but every slot created before the
    split lacks it — and a long-form bind with a missing source fails compose
    up. apply must guarantee its own compose's prerequisites, for every slot
    it touches, not just newly created ones. Idempotent; same ownership shape
    as nas_docs (root:data_gid 0750 — rw arrives with the CIFS mount, an
    unmounted dir stays non-writable so nothing lands on local disk silently).
    """
    home = Path("/home") / slot
    workspace_dir = home / "workspace"
    ensure_not_symlink_chain(workspace_dir, home)
    workspace_dir.mkdir(parents=True, exist_ok=True)
    _, _, data_gid = runtime_ids(slot)
    os.chown(workspace_dir, 0, data_gid)
    os.chmod(workspace_dir, 0o750)
    return workspace_dir


def print_process_result(prefix: str, proc: subprocess.CompletedProcess[str], limit: int = 2000) -> None:
    detail = (proc.stderr or proc.stdout).strip()
    if detail:
        print(f"{prefix}={detail[:limit]}")


def print_live_check_progress(checks: list[tuple[bool, str, str | None]]) -> None:
    failed = sorted({name for ok, name, _ in checks if not ok})
    print("live_check_tick failed=" + (",".join(failed) if failed else "none"))


def write_failed_container_diagnostics(binding: RuntimeBinding, profile, backup_dir: Path) -> Path | None:
    try:
        container, lookup = find_gateway_container(binding, profile)
        diag_dir = backup_dir / "failed-container"
        diag_dir.mkdir(mode=0o700, exist_ok=True)
        (diag_dir / "lookup.txt").write_text(f"container={container or ''}\nlookup={lookup or ''}\n", encoding="utf-8")
        if not container:
            return diag_dir
        commands = {
            "inspect.json": ["docker", "inspect", container],
            "logs.txt": ["docker", "logs", "--tail", "300", container],
            "ports.txt": ["docker", "port", container],
            "top.txt": ["docker", "top", container],
        }
        for name, command in commands.items():
            proc = run_text(command, timeout=30)
            body = {
                "argv": command,
                "returncode": proc.returncode,
                "stdout": redact(proc.stdout or ""),
                "stderr": redact(proc.stderr or ""),
            }
            (diag_dir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return diag_dir
    except Exception as exc:
        try:
            diag_dir = backup_dir / "failed-container"
            diag_dir.mkdir(mode=0o700, exist_ok=True)
            (diag_dir / "error.txt").write_text(str(exc) + "\n", encoding="utf-8")
            return diag_dir
        except Exception:
            return None


def _restore_and_verify_backup(
    *,
    slot: str,
    runtime_dir: Path,
    backup_dir: Path,
    state_root: Path,
) -> tuple[bool, str]:
    restored, reason = restore_backup(slot, runtime_dir, backup_dir, state_root)
    if not restored:
        return False, reason
    if reason == "rollback_empty_baseline_restored":
        try:
            finish_rollback_transaction(slot, state_root, backup_dir)
            _finish_canary_rollback(slot=slot, state_root=state_root, backup_dir=backup_dir)
        except Exception as exc:
            return False, f"rollback_verification_failed:{exc}"
        return True, "rollback_empty_baseline_restored_verified"
    try:
        previous_desired, previous_profile = load_backup_runtime_contract(
            slot,
            backup_dir,
            state_root,
        )
        failed = {
            name
            for ok, name, _ in run_live_slot_checks_with_wait(
                previous_desired,
                previous_profile,
                state_root,
                timeout_seconds=profile_startup_timeout_seconds(previous_profile),
            )
            if not ok
        }
        if failed:
            return False, "rollback_live_failed:" + ",".join(sorted(failed))
        finish_rollback_transaction(slot, state_root, backup_dir)
        _finish_canary_rollback(slot=slot, state_root=state_root, backup_dir=backup_dir)
    except Exception as exc:
        return False, f"rollback_verification_failed:{exc}"
    return True, "rollback_applied_verified"


def _finish_canary_rollback(*, slot: str, state_root: Path, backup_dir: Path) -> None:
    """Consume the canary's one rollback exception only after live verification."""
    try:
        from .canary_transaction import load as load_canary_transaction

        tx = load_canary_transaction(state_root, slot)
    except ValueError as exc:
        if str(exc) == "canary transaction absent":
            return
        raise
    previous_desired, _ = load_backup_runtime_contract(slot, backup_dir, state_root)
    product_digest = digest_from_image_ref(previous_desired.image_spec.get("product_image"))
    wrapper_digest = digest_from_image_ref(previous_desired.image_spec.get("wrapper_image"))
    if not product_digest or not wrapper_digest:
        raise ValueError("rollback prestate image digests are unavailable")
    if tx["prestate_product_digest"] != product_digest or tx["prestate_wrapper_digest"] != wrapper_digest:
        raise ValueError("rollback prestate image digest mismatch")
    finish_canary_transaction(
        state_root,
        slot,
        outcome="rollback_succeeded",
        result_product_digest=product_digest,
        result_wrapper_digest=wrapper_digest,
    )


def apply_desired_slot(
    *,
    desired,
    profile,
    state_root: Path,
    allow_first_apply: bool,
    action_name: str = "apply",
    emit_progress: bool = False,
    prepare_runtime_env: Callable[[], None] | None = None,
    pre_apply_admission: Callable[[], None] | None = None,
) -> int:
    try:
        with runtime_host_mutation_lock(state_root):
            from ..commands.groupware_view_replace import recover_pending

            recover_pending(state_root)
            with runtime_transaction_lock(state_root, desired.slot):
                if pre_apply_admission is not None:
                    pre_apply_admission()
                return _apply_desired_slot_locked(
                    desired=desired,
                    profile=profile,
                    state_root=state_root,
                    allow_first_apply=allow_first_apply,
                    action_name=action_name,
                    emit_progress=emit_progress,
                    prepare_runtime_env=prepare_runtime_env,
                )
    except Exception as exc:
        print(f"target={getattr(desired, 'slot', '')}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(
                state_root,
                action_name,
                getattr(desired, "slot", ""),
                getattr(desired, "slot", ""),
                "fail",
                str(exc),
            )
        except Exception:
            pass
        return 1


def _apply_desired_slot_locked(
    *,
    desired,
    profile,
    state_root: Path,
    allow_first_apply: bool,
    action_name: str = "apply",
    emit_progress: bool = False,
    prepare_runtime_env: Callable[[], None] | None = None,
) -> int:
    backup_dir: Path | None = None
    runtime_env_prepared = False
    try:
        rendered = render_compose(profile, desired)
        static_failures = [
            name for ok, name, _ in run_static_slot_checks(desired, profile, rendered, state_root=state_root) if not ok
        ]
        if static_failures:
            raise ValueError(f"static contract check failed: {','.join(static_failures)}")
        # Fail before directory creation, backup publication, compose writes, or
        # container recreation. Docker must not dispatch a RAG-enabled runtime
        # without the exact source socket and its slot runtime peer grant.
        require_runtime_socket_source(profile, desired.slot)
        runtime_dir = slot_runtime_dir(desired.slot)
        compose_path = agent_compose_path(runtime_dir)
        manifest_path = agent_manifest_path(runtime_dir)
        state_manifest_file = state_manifest_path(state_root, desired.slot)
        if not manifest_path.exists() and not state_manifest_file.exists() and not allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        previous_manifest = state_manifest_file if state_manifest_file.exists() else manifest_path if manifest_path.exists() else None
        nas_workspace_dir = ensure_nas_workspace_dir(desired.slot)
        guidance_result = ensure_runtime_workspace_guidance(desired.slot, profile)
        # Config preflight (zero-downtime gate): validate the on-disk config against the
        # TARGET product image BEFORE anything is recreated. A config the target image
        # would reject at boot (e.g. a removed/legacy key) is gated here, so the running
        # container is never torn down into a crash loop. Migration is an explicit step
        # (opsctl config migrate). Families/images without a config contract are exempt.
        config_contract = image_spec_config_contract(desired.image_spec)
        if config_contract:
            host_config_dir = slot_config_dir(desired.slot)
            target_product_image = str(desired.image_spec.get("product_image") or "")
            valid, detail = run_config_validate_in_image(
                target_product_image, host_config_dir, config_contract, run_as=config_owner_run_as(host_config_dir)
            )
            if not valid:
                raise ValueError(
                    f"config preflight failed: on-disk config is invalid for target image "
                    f"({detail}); migrate first: sudo opsctl config migrate {desired.slot}"
                )
        backup_dir = backup_agent_runtime_state(desired.slot, runtime_dir, state_root)
        begin_rollback_transaction(desired.slot, state_root, backup_dir)
        if action_name.startswith("rollout_image_") and previous_manifest is not None:
            previous_desired, _ = load_backup_runtime_contract(desired.slot, backup_dir, state_root)
            candidate_product = digest_from_image_ref(desired.image_spec.get("product_image"))
            candidate_wrapper = digest_from_image_ref(desired.image_spec.get("wrapper_image"))
            prestate_product = digest_from_image_ref(previous_desired.image_spec.get("product_image"))
            prestate_wrapper = digest_from_image_ref(previous_desired.image_spec.get("wrapper_image"))
            pending_identity = pending_rollback_identity(state_root, desired.slot)
            if not all((candidate_product, candidate_wrapper, prestate_product, prestate_wrapper, pending_identity)):
                raise ValueError("canary transaction image or backup identity is incomplete")
            begin_canary_transaction(
                state_root,
                slot=desired.slot,
                family=str(desired.family or ""),
                candidate_product_digest=candidate_product,
                candidate_wrapper_digest=candidate_wrapper,
                prestate_product_digest=prestate_product,
                prestate_wrapper_digest=prestate_wrapper,
                backup_name=str(pending_identity["backup_name"]),
                backup_metadata_sha256=str(pending_identity["backup_metadata_sha256"]),
            )
        if prepare_runtime_env is not None:
            runtime_env_prepared = True
            prepare_runtime_env()
        env_path = runtime_dir / ".env"
        required = required_compose_variables(rendered.text)
        present = env_file_keys(env_path)
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"missing required .env keys: {','.join(missing)}")
        atomic_write(compose_path, rendered.text, 0o644)
    except Exception as exc:
        restore_error = ""
        if backup_dir is not None and runtime_env_prepared:
            try:
                restore_backup_env(runtime_dir, backup_dir)
            except Exception as restore_exc:
                restore_error = f"; runtime_env_restore_failed:{restore_exc}"
        failure_reason = f"{exc}{restore_error}"
        print(f"target={getattr(desired, 'slot', '')}")
        print("apply_status=fail")
        print(f"reason={failure_reason}")
        try:
            append_action_log(
                state_root,
                action_name,
                getattr(desired, "slot", ""),
                getattr(desired, "slot", ""),
                "fail",
                failure_reason,
            )
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_dir={runtime_dir}")
    print(f"compose_file={compose_path}")
    print(f"manifest={manifest_path}")
    print(f"state_manifest={state_manifest_file}")
    print(f"backup_dir={backup_dir}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")
    print(f"nas_workspace_dir={nas_workspace_dir}")
    for key, value in guidance_result.items():
        print(f"{key}={value}")

    if emit_progress:
        print("phase=compose_config")
    config = run_text_cwd(docker_compose_command(desired.slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print("apply_status=fail")
        print_process_result("compose_config_error", config)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_config_failed")
        return config.returncode or 1

    if emit_progress:
        print("phase=compose_up")
    up = run_text_cwd(
        docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print("apply_status=fail")
        print_process_result("compose_up_error", up)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_up_failed")
        return up.returncode or 1

    try:
        post_guidance_result = ensure_runtime_workspace_guidance(desired.slot, profile)
    except Exception as exc:
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print("apply_status=fail")
        print(f"reason=workspace_guidance_post_compose_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "workspace_guidance_post_compose_failed")
        return 1
    for key, value in post_guidance_result.items():
        print(f"post_{key}={value}")

    failed = 0
    if emit_progress:
        print("phase=live_check")
    for ok, name, detail in run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=profile_startup_timeout_seconds(profile),
        progress=print_live_check_progress if emit_progress else None,
    ):
        check_line(ok, name, detail)
        if not ok:
            failed += 1
    if failed:
        diagnostics_dir = write_failed_container_diagnostics(desired.route, profile, backup_dir)
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print(f"apply_status=fail live_failed={failed}")
        if diagnostics_dir:
            print(f"failure_diagnostics_dir={diagnostics_dir}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"live_failed={failed}")
        return 1

    for index, delay_seconds in enumerate(FINAL_WORKSPACE_GUIDANCE_STABILIZE_DELAYS_SECONDS, start=1):
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        try:
            stabilized_guidance_result = ensure_runtime_workspace_guidance(desired.slot, profile)
        except Exception as exc:
            ok, reason = _restore_and_verify_backup(
                slot=desired.slot,
                runtime_dir=runtime_dir,
                backup_dir=backup_dir,
                state_root=state_root,
            )
            print("apply_status=fail")
            print(f"reason=workspace_guidance_stabilize_failed:{exc}")
            print(f"rollback_status={'ok' if ok else 'fail'}")
            print(f"rollback_reason={reason}")
            append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "workspace_guidance_stabilize_failed")
            return 1
        for key, value in stabilized_guidance_result.items():
            print(f"stabilized_{index}_{key}={value}")

    try:
        final_guidance_result = ensure_runtime_workspace_guidance(desired.slot, profile)
    except Exception as exc:
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print("apply_status=fail")
        print(f"reason=workspace_guidance_final_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "workspace_guidance_final_failed")
        return 1
    for key, value in final_guidance_result.items():
        print(f"final_{key}={value}")

    applied_at = now_iso()
    try:
        write_slot_manifests(
            state_root=state_root,
            runtime_dir=runtime_dir,
            desired=desired,
            profile=profile,
            rendered=rendered,
            compose_path=compose_path,
            applied_at=applied_at,
            previous_manifest=previous_manifest,
        )
        finish_rollback_transaction(desired.slot, state_root, backup_dir)
        if action_name.startswith("rollout_image_"):
            candidate_product = digest_from_image_ref(desired.image_spec.get("product_image"))
            candidate_wrapper = digest_from_image_ref(desired.image_spec.get("wrapper_image"))
            if not candidate_product or not candidate_wrapper:
                raise ValueError("candidate image digests are unavailable")
            finish_canary_transaction(
                state_root,
                desired.slot,
                outcome="candidate_succeeded",
                result_product_digest=candidate_product,
                result_wrapper_digest=candidate_wrapper,
            )
        append_action_log(state_root, action_name, desired.slot, desired.image_name, "ok", rendered.sha256)
    except Exception as exc:
        ok, reason = _restore_and_verify_backup(
            slot=desired.slot,
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )
        print("apply_status=fail")
        print(f"reason=manifest_write_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        try:
            append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"manifest_write_failed:{exc}")
        except Exception:
            pass
        return 1
    print("apply_status=ok")
    return 0
