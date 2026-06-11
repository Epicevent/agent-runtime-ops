from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

def _cli_mod():
    from .. import cli

    return cli
from ..runtime_secrets import (
    RUNTIME_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_runtime_secret_values,
)


def _state_root(args: argparse.Namespace) -> Path:
    return _cli_mod()._state_root(args)


def _is_root() -> bool:
    return _cli_mod()._is_root()


def _slot_home(slot: str) -> Path:
    return _cli_mod()._slot_home(slot)


def _ensure_not_symlink_chain(path: Path, stop_at: Path) -> None:
    return _cli_mod()._ensure_not_symlink_chain(path, stop_at)


def _runtime_ids(slot: str) -> tuple[int, int, int]:
    return _cli_mod()._runtime_ids(slot)


def _slot_runtime_dir(slot: str) -> Path:
    return _cli_mod()._slot_runtime_dir(slot)


def _agent_compose_path(runtime_dir: Path) -> Path:
    return _cli_mod()._agent_compose_path(runtime_dir)


def _docker_compose_command(slot: str, compose_path: Path, *args: str) -> list[str]:
    return _cli_mod()._docker_compose_command(slot, compose_path, *args)


def _compose_project_name(slot: str) -> str:
    return _cli_mod()._compose_project_name(slot)


def _run_text(command: list[str], timeout: int = 20):
    return _cli_mod()._run_text(command, timeout=timeout)


def _run_text_cwd(command: list[str], cwd: Path, timeout: int = 20):
    return _cli_mod()._run_text_cwd(command, cwd, timeout=timeout)


def _container_name(slot: str, profile) -> str:
    return _cli_mod()._container_name(slot, profile)


def _find_gateway_container(binding, profile):
    service_label = "gateway"
    by_label = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.instance-id={binding.instance_id}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if by_label.returncode == 0:
        ids = [line.strip() for line in by_label.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "instance_label"
        if len(ids) > 1:
            return None, f"multiple_instance_label_matches:{len(ids)}"
    legacy = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={binding.linux_account}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if legacy.returncode == 0:
        ids = [line.strip() for line in legacy.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "legacy_linux_account_label"
        if len(ids) > 1:
            return None, f"multiple_legacy_label_matches:{len(ids)}"
    return _container_name(binding.linux_account, profile), "fallback_name"


def _profile_startup_timeout_seconds(profile) -> int:
    return _cli_mod()._profile_startup_timeout_seconds(profile)


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    return _cli_mod()._check_line(ok, name, detail)


def _append_action_log(state_root: Path, action: str, slot: str, target: str, status: str, detail: str = "") -> None:
    return _cli_mod()._append_action_log(state_root, action, slot, target, status, detail)


def load_runtime_target(target: str, state_root: Path):
    return _cli_mod().load_runtime_target(target, state_root)


def load_profile(name: str):
    return _cli_mod().load_profile(name)


def _assert_secret_path_safe(slot: str, path: Path, *, create_parent: bool = False) -> None:
    if not path.is_absolute():
        raise ValueError(f"secret file path must be absolute: {path}")
    home = _slot_home(slot).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"secret file path outside slot home: {path}")
    _ensure_not_symlink_chain(path.parent, home)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_not_symlink_chain(path, home)
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
        runtime_uid, _, data_gid = _runtime_ids(slot)
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


def _restart_runtime_secret_slot(desired, profile, runtime_dir: Path) -> tuple[bool, str]:
    compose_path = _agent_compose_path(runtime_dir)
    service = str(profile.metadata.get("service") or "openclaw-gateway")
    if compose_path.is_file():
        command = _docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", service)
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
        command = ["docker", "compose", "-p", _compose_project_name(desired.slot)]
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


def _run_runtime_secret_container_checks(desired, profile, keys: set[str]) -> list[tuple[bool, str, str | None]]:
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
    for key in sorted(keys):
        proc = _run_text(["docker", "exec", container, "sh", "-lc", f'test -n "${{{key}:-}}"'])
        checks.append((proc.returncode == 0, f"runtime_secret_{key.lower()}_present_in_container", "secret_value_printed=no"))
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


def _run_runtime_secret_container_checks_with_wait(desired, profile, keys: set[str], timeout_seconds: int) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    while True:
        checks = _run_runtime_secret_container_checks(desired, profile, keys)
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
        runtime_dir = _slot_runtime_dir(desired.slot)
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

    if args.no_restart:
        print("restart=skipped")
        _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "restart=skipped keys=" + ",".join(sorted(values)))
        print("runtime_secret_status=stored")
        return 0

    restart_ok, restart_reason = _restart_runtime_secret_slot(desired, profile, runtime_dir)
    print(f"restart_status={'ok' if restart_ok else 'fail'}")
    print(f"restart_reason={restart_reason}")
    if not restart_ok:
        _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", restart_reason)
        print("runtime_secret_status=fail")
        return 1

    if args.check:
        failed = 0
        for check_ok, name, detail in _run_runtime_secret_container_checks_with_wait(
            desired,
            profile,
            set(values),
            timeout_seconds=_profile_startup_timeout_seconds(profile),
        ):
            _check_line(check_ok, name, detail)
            if not check_ok:
                failed += 1
        if failed:
            _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", f"live_failed={failed}")
            print(f"runtime_secret_status=fail live_failed={failed}")
            return 1

    _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "keys=" + ",".join(sorted(values)))
    print("runtime_secret_status=stored")
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


