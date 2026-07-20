from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import run_text as _run_text
from ..domain.common import run_text_cwd as _run_text_cwd
from ..domain.common import state_root as _state_root
from ..domain.dev_recipe_runtime import upsert_runtime_env_file as _upsert_runtime_env_file
from ..domain.hermes_smoke import run_hermes_http_smoke as _run_hermes_http_smoke
from ..domain.secret_probe import (
    PROBE_VERIFIED as _PROBE_VERIFIED,
    PROVIDER_CHECKS as _PROVIDER_CHECKS,
    probe_key_in_container as _probe_key_in_container,
)
from ..domain.runtime_checks import profile_startup_timeout_seconds as _profile_startup_timeout_seconds
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..domain.docker_compose import compose_project_name, docker_compose_command
from ..domain.runtime_paths import agent_compose_path, slot_runtime_dir
from ..domain.runtime_truth import find_gateway_container as _find_gateway_container
from ..host.account_files import ensure_not_symlink_chain, runtime_ids, slot_home, slot_uid_gid
from ..profiles import load_profile
from ..runtime_secrets import (
    RUNTIME_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_runtime_secret_values,
)
from ..state import load_runtime_target


def _assert_secret_path_safe(slot: str, path: Path, *, create_parent: bool = False) -> None:
    if not path.is_absolute():
        raise ValueError(f"secret file path must be absolute: {path}")
    home = slot_home(slot).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"secret file path outside slot home: {path}")
    ensure_not_symlink_chain(path.parent, home)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    ensure_not_symlink_chain(path, home)
    if path.exists() and not path.is_file():
        raise ValueError(f"secret file path is not a regular file: {path}")
    if path.is_symlink():
        raise ValueError(f"secret file must not be a symlink: {path}")


def _read_root_secret_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.is_symlink():
        raise ValueError(f"env file must not be a symlink: {path}")
    stat_result = path.stat()
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError(f"env file must be regular: {path}")
    if stat_result.st_uid != 0 or stat_result.st_gid != 0:
        raise ValueError(f"env file must be root:root: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"env file must be mode 0600 or stricter: {path}")
    if stat_result.st_nlink != 1:
        raise ValueError(f"env file must not be hardlinked: {path}")
    return parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))


def _secret_values_from_args(args: argparse.Namespace) -> dict[str, str]:
    if args.env_file and (args.key or args.value_stdin):
        raise ValueError("use either --env-file or --key/--value-stdin, not both")
    if args.env_file:
        return validate_runtime_secret_values(_read_root_secret_env_file(Path(args.env_file)))
    if not args.key or not args.value_stdin:
        raise ValueError("use --env-file FILE or --key KEY --value-stdin")
    key = str(args.key)
    if key not in RUNTIME_SECRET_KEYS:
        raise ValueError(f"unsupported runtime secret key: {key}")
    value = sys.stdin.read().rstrip("\r\n")
    return validate_runtime_secret_values({key: value})


def _safe_write_secret_env(path: Path, text: str, uid: int, gid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise ValueError(f"secret file is not regular: {path}")
        if stat_result.st_nlink != 1:
            raise ValueError(f"secret file must not be hardlinked: {path}")
        os.ftruncate(fd, 0)
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(path, uid, gid)
    os.chmod(path, 0o600)


def _secret_owner_ids(slot: str, owner_mode: str) -> tuple[int, int]:
    if owner_mode == "runtime":
        runtime_uid, _, data_gid = runtime_ids(slot)
        return runtime_uid, data_gid
    return 0, 0


def _upsert_runtime_secret_file(slot: str, profile, values: dict[str, str]) -> Path:
    secret_file = primary_profile_secret_file(profile, slot)
    _assert_secret_path_safe(slot, secret_file.path, create_parent=True)
    existing_text = secret_file.path.read_text(encoding="utf-8", errors="replace") if secret_file.path.exists() else ""
    uid, gid = _secret_owner_ids(slot, secret_file.owner_mode)
    if secret_file.owner_mode == "runtime":
        secret_file.path.parent.chmod(0o750)
        os.chown(secret_file.path.parent, uid, gid)
    _safe_write_secret_env(secret_file.path, render_upserted_secret_env(existing_text, values), uid, gid)
    return secret_file.path


def _sync_runtime_compose_env_for_secret_values(slot: str, runtime_dir: Path, values: dict[str, str]) -> list[str]:
    updates: dict[str, str] = {}
    if values.get("API_SERVER_KEY"):
        updates["API_SERVER_KEY"] = values["API_SERVER_KEY"]
    if not updates:
        return []
    uid, gid = slot_uid_gid(slot)
    _upsert_runtime_env_file(runtime_dir / ".env", updates, uid, gid)
    return sorted(updates)


def _unsafe_service_recreate_after_runtime_secret_set(desired, profile, runtime_dir: Path) -> tuple[bool, str]:
    compose_path = agent_compose_path(runtime_dir)
    service = str(profile.metadata.get("service") or "openclaw-gateway")
    if compose_path.is_file():
        command = docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", service)
        restart_mode = "agent-runtime-compose"
    else:
        legacy_compose = runtime_dir / "docker-compose.yml"
        if not legacy_compose.is_file():
            return False, f"compose_missing:{compose_path},{legacy_compose}"
        compose_files = [legacy_compose]
        source_compose = runtime_dir / "docker-compose.source.yml"
        if source_compose.is_file():
            compose_files.append(source_compose)
        if profile.metadata.get("family") != "hermes":
            for name in (
                "docker-compose.extra.yml",
                "docker-compose.host-user.yml",
                "docker-compose.shared-ollama.yml",
                "docker-compose.sandbox.yml",
            ):
                item = runtime_dir / name
                if item.is_file():
                    compose_files.append(item)
        command = ["docker", "compose", "-p", compose_project_name(desired.slot)]
        for item in compose_files:
            command.extend(["-f", str(item)])
        command.extend(["up", "-d", "--force-recreate", service])
        restart_mode = "legacy-compose"
    up = _run_text_cwd(
        command,
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "runtime_secret_restart_failed"
    return True, restart_mode


def _secret_value_matches_container_env(container: str, key: str, intended_value: str) -> tuple[bool, str, str | None]:
    expected_hash = hashlib.sha256(intended_value.encode("utf-8")).hexdigest()
    script = f'''
set -eu
expected="$(cat)"
actual="${{{key}:-}}"
test -n "$actual"
actual_hash=""
if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(printf "%s" "$actual" | sha256sum | awk '{{print $1}}')"
elif command -v node >/dev/null 2>&1; then
  actual_hash="$(printf "%s" "$actual" | node -e 'const crypto=require("crypto"); const chunks=[]; process.stdin.on("data", c => chunks.push(c)); process.stdin.on("end", () => process.stdout.write(crypto.createHash("sha256").update(Buffer.concat(chunks)).digest("hex")));')"
elif command -v python3 >/dev/null 2>&1; then
  actual_hash="$(printf "%s" "$actual" | python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
else
  echo "hash_tool_missing" >&2
  exit 127
fi
test "$actual_hash" = "$expected"
'''
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "sh", "-lc", script],
            input=expected_hash,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError as exc:
        proc = subprocess.CompletedProcess(["docker"], 127, "", str(exc))
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(["docker"], 124, "", "timeout")
    detail = "secret_value_printed=no"
    return proc.returncode == 0, f"runtime_secret_{key.lower()}_matches_intended_value", detail


def _run_runtime_secret_container_checks(desired, profile, intended_values: dict[str, str]) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not _is_root():
        return [(False, "runtime_secret_check_requires_root", "run as root/admin")]
    docker = shutil.which("docker")
    checks.append((bool(docker), "runtime_secret_docker_cli_available", docker))
    if not docker:
        return checks
    container, lookup = _find_gateway_container(desired.route, profile)
    checks.append((bool(container), "runtime_secret_container_lookup", lookup))
    if not container:
        return checks
    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "runtime_secret_container_exists", container))
    if inspect.returncode != 0:
        return checks
    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "runtime_secret_container_inspect_parse_ok", str(exc)))
        return checks
    state = info.get("State") or {}
    running = str(state.get("Running")).lower()
    health_data = state.get("Health") or {}
    health = str(health_data.get("Status") or "none")
    checks.append((running == "true", "runtime_secret_container_running", f"running={running}"))
    checks.append((health in {"healthy", "none", ""}, "runtime_secret_container_health_ok", f"health={health}"))
    for key in sorted(intended_values):
        checks.append(_secret_value_matches_container_env(container, key, intended_values[key]))
        if key == "API_SERVER_KEY":
            token_proc = _run_text(
                [
                    "docker",
                    "exec",
                    container,
                    "sh",
                    "-lc",
                    'test -n "${HERMES_API_TOKEN:-}" && test "${API_SERVER_KEY:-}" = "${HERMES_API_TOKEN:-}"',
                ]
            )
            checks.append(
                (
                    token_proc.returncode == 0,
                    "runtime_secret_hermes_api_token_matches_api_server_key",
                    "secret_value_printed=no",
                )
            )
    return checks


def _run_runtime_secret_container_checks_with_wait(desired, profile, intended_values: dict[str, str], timeout_seconds: int) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    while True:
        checks = _run_runtime_secret_container_checks(desired, profile, intended_values)
        last_checks = checks
        if not any(not ok for ok, _, _ in checks):
            return checks
        if time.monotonic() >= deadline:
            return last_checks
        time.sleep(5)


def _secret_status_rows(path: Path) -> tuple[str, dict[str, bool]]:
    if not path.exists():
        return "missing", {}
    if path.is_symlink():
        return "symlink_refused", {}
    if not path.is_file():
        return "not_regular", {}
    try:
        values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    except Exception:
        return "parse_failed", {}
    return "present", {key: bool(values.get(key)) for key in sorted(RUNTIME_SECRET_KEYS)}


def cmd_runtime_secret_set(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret set TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired = load_runtime_target(args.slot, state_root)
        profile = load_profile(desired.runtime_profile)
        values = _secret_values_from_args(args)
        secret_path = _upsert_runtime_secret_file(desired.slot, profile, values)
        runtime_dir = slot_runtime_dir(desired.slot)
        runtime_env_synced_keys = _sync_runtime_compose_env_for_secret_values(desired.slot, runtime_dir, values)
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "runtime_secret_set", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"secret_file={secret_path}")
    print("secret_value_printed=no")
    print("secret_keys_imported=" + ",".join(sorted(values)))
    print("runtime_env_synced_keys=" + (",".join(runtime_env_synced_keys) if runtime_env_synced_keys else "none"))
    print("phase=secret_write")

    if args.no_restart:
        print("restart=skipped")
        _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "restart=skipped keys=" + ",".join(sorted(values)))
        print("runtime_secret_status=stored")
        return 0

    if getattr(args, "unsafe_service_recreate", False):
        print("phase=unsafe_service_recreate")
        print("warning=unsafe_service_recreate_bypasses_full_apply_live_check")
        restart_ok, restart_reason = _unsafe_service_recreate_after_runtime_secret_set(desired, profile, runtime_dir)
        print(f"restart_status={'ok' if restart_ok else 'fail'}")
        print(f"restart_reason={restart_reason}")
        if not restart_ok:
            _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", restart_reason)
            print("runtime_secret_status=fail")
            return 1
    else:
        print("phase=full_recreate")
        apply_rc = _apply_desired_slot(
            desired=desired,
            profile=profile,
            state_root=state_root,
            allow_first_apply=False,
            action_name="runtime_secret_recreate",
            emit_progress=True,
        )
        if apply_rc != 0:
            _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", f"full_recreate_failed rc={apply_rc}")
            print("runtime_secret_status=fail")
            return apply_rc or 1

    if args.check:
        print("phase=secret_check")
        failed = 0
        for check_ok, name, detail in _run_runtime_secret_container_checks_with_wait(
            desired,
            profile,
            values,
            timeout_seconds=_profile_startup_timeout_seconds(profile),
        ):
            _check_line(check_ok, name, detail)
            if not check_ok:
                failed += 1
        if failed:
            _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", f"live_failed={failed}")
            print(f"runtime_secret_status=fail live_failed={failed}")
            return 1
        if profile.metadata.get("family") == "hermes":
            print("phase=hermes_smoke")
            container, lookup = _find_gateway_container(desired.route, profile)
            smoke_checks: list[tuple[bool, str, str | None]]
            if not container:
                smoke_checks = [(False, "hermes_smoke_container_lookup", lookup)]
            else:
                provider_secret_changed = bool(set(values) & {"GOOGLE_API_KEY", "GEMINI_API_KEY"})
                smoke_checks = _run_hermes_http_smoke(container, chat_smoke=provider_secret_changed)
            smoke_failed = 0
            for check_ok, name, detail in smoke_checks:
                _check_line(check_ok, name, detail)
                if not check_ok:
                    smoke_failed += 1
            if smoke_failed:
                _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", f"hermes_smoke_failed={smoke_failed}")
                print(f"runtime_secret_status=fail hermes_smoke_failed={smoke_failed}")
                return 1

    _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "keys=" + ",".join(sorted(values)))
    print(f"runtime_secret_status={'stored_checked' if args.check else 'stored'}")
    return 0


def cmd_runtime_secret_status(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret status TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        secret_file = primary_profile_secret_file(profile, desired.slot)
        _assert_secret_path_safe(desired.slot, secret_file.path)
        file_state, key_state = _secret_status_rows(secret_file.path)
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"secret_file={secret_file.path}")
    print(f"secret_file_state={file_state}")
    for key in sorted(RUNTIME_SECRET_KEYS):
        if key in key_state:
            print(f"{key.lower()}={'present' if key_state[key] else 'absent'}")
    print("secret_value_printed=no")
    print("runtime_secret_status=ok")
    return 0


def cmd_runtime_secret_probe(args: argparse.Namespace) -> int:
    """저장됨 ≠ 유효함 — 키가 실제로 provider 에 먹히는지 잰다 (read-only).

    status 는 배관(값이 env 에 있나)만 본다. probe 는 그 값으로 provider 에 가장
    싼 인증 콜을 한 번 날려 유효/무효를 가린다. 값은 컨테이너 안에서만 쓰이고
    상태코드만 돌아온다(secret_probe 모듈 참조).

    이 명령이 존재하는 이유는 사고 재발 방지다: 키를 확인하려고 쓰기 명령(set)을
    쓸 필요가 없어진다. probe 는 아무것도 쓰지 않는다.

    rc: 0 전부 유효(또는 잴 키 없음) · 1 무효 있음 · 2 컨테이너/실행 실패.
    """
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret probe TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        container, lookup = _find_gateway_container(desired.route, profile)
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_secret_probe=fail")
        print(f"reason={exc}")
        return 2

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print("mutates=false")
    if not container:
        print("runtime_secret_probe=fail")
        print(f"reason=gateway container not found ({lookup})")
        return 2

    # 라이브로 실증된 provider 만 잰다. --key 지정 시 그 하나(미검증이면 거부).
    if args.key:
        key = args.key.strip().upper()
        if key not in _PROVIDER_CHECKS:
            print("runtime_secret_probe=fail")
            print(f"reason=no probe defined for key {key}")
            return 2
        if key not in _PROBE_VERIFIED:
            print("runtime_secret_probe=fail")
            print(f"reason={key} probe not live-verified yet (only {sorted(_PROBE_VERIFIED)})")
            return 2
        keys = [key]
    else:
        keys = sorted(_PROBE_VERIFIED)

    print(f"secret_value_printed=no")
    any_invalid = False
    for index, key in enumerate(keys, start=1):
        status, detail = _probe_key_in_container(container, _PROVIDER_CHECKS[key])
        print(f"probe_{index}_key={key.lower()}")
        print(f"probe_{index}_status={status}" + (f" detail={detail}" if detail else ""))
        if status == "invalid":
            any_invalid = True
    print("runtime_secret_probe=ok")
    return 1 if any_invalid else 0
