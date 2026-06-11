from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..redaction import redact
from ..renderer import render_compose
from ..routing import RuntimeBinding
from .actions import append_action_log
from .common import check_line, now_iso, run_text, run_text_cwd
from .runtime_checks import (
    profile_startup_timeout_seconds,
    run_live_slot_checks_with_wait,
    run_static_slot_checks,
)
from .runtime_backup import backup_agent_runtime_state, restore_backup
from .runtime_manifest import write_slot_manifests
from .runtime_state import (
    _agent_compose_path,
    _agent_manifest_path,
    _atomic_write,
    _docker_compose_command,
    _env_file_keys,
    _required_compose_variables,
    _slot_runtime_dir,
    _state_manifest_path,
)
from .runtime_truth import find_gateway_container
from .workspace_guidance import ensure_runtime_workspace_guidance


def print_process_result(prefix: str, proc: subprocess.CompletedProcess[str], limit: int = 2000) -> None:
    detail = (proc.stderr or proc.stdout).strip()
    if detail:
        print(f"{prefix}={detail[:limit]}")


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


def apply_desired_slot(
    *,
    desired,
    profile,
    state_root: Path,
    allow_first_apply: bool,
    action_name: str = "apply",
) -> int:
    try:
        rendered = render_compose(profile, desired)
        static_failures = [
            name for ok, name, _ in run_static_slot_checks(desired, profile, rendered) if not ok
        ]
        if static_failures:
            raise ValueError(f"static contract check failed: {','.join(static_failures)}")
        runtime_dir = _slot_runtime_dir(desired.slot)
        compose_path = _agent_compose_path(runtime_dir)
        manifest_path = _agent_manifest_path(runtime_dir)
        state_manifest_path = _state_manifest_path(state_root, desired.slot)
        env_path = runtime_dir / ".env"
        required = _required_compose_variables(rendered.text)
        present = _env_file_keys(env_path)
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"missing required .env keys: {','.join(missing)}")
        if not manifest_path.exists() and not state_manifest_path.exists() and not allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        previous_manifest = state_manifest_path if state_manifest_path.exists() else manifest_path if manifest_path.exists() else None
        guidance_result = ensure_runtime_workspace_guidance(desired.slot, profile)
        backup_dir = backup_agent_runtime_state(desired.slot, runtime_dir, state_root)
        _atomic_write(compose_path, rendered.text, 0o644)
    except Exception as exc:
        print(f"target={getattr(desired, 'slot', '')}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root, action_name, getattr(desired, "slot", ""), getattr(desired, "slot", ""), "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_dir={runtime_dir}")
    print(f"compose_file={compose_path}")
    print(f"manifest={manifest_path}")
    print(f"state_manifest={state_manifest_path}")
    print(f"backup_dir={backup_dir}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")
    for key, value in guidance_result.items():
        print(f"{key}={value}")

    config = run_text_cwd(_docker_compose_command(desired.slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        ok, reason = restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        print_process_result("compose_config_error", config)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_config_failed")
        return config.returncode or 1

    up = run_text_cwd(
        _docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        ok, reason = restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        print_process_result("compose_up_error", up)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_up_failed")
        return up.returncode or 1

    failed = 0
    for ok, name, detail in run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=profile_startup_timeout_seconds(profile),
    ):
        check_line(ok, name, detail)
        if not ok:
            failed += 1
    if failed:
        diagnostics_dir = write_failed_container_diagnostics(desired.route, profile, backup_dir)
        ok, reason = restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print(f"apply_status=fail live_failed={failed}")
        if diagnostics_dir:
            print(f"failure_diagnostics_dir={diagnostics_dir}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"live_failed={failed}")
        return 1

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
        append_action_log(state_root, action_name, desired.slot, desired.image_name, "ok", rendered.sha256)
    except Exception as exc:
        ok, reason = restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
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


_print_process_result = print_process_result
_write_failed_container_diagnostics = write_failed_container_diagnostics
_apply_desired_slot = apply_desired_slot
_backup_agent_runtime_state = backup_agent_runtime_state
_restore_backup = restore_backup
_write_slot_manifests = write_slot_manifests
