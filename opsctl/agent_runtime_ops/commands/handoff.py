from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..host.account_files import ensure_not_symlink_chain, slot_home
from ..profiles import load_profile
from ..runtime_secrets import parse_secret_env_text
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


def _json_path_present(path: Path, keys: list[str]) -> tuple[str, str]:
    if not path.exists():
        return "missing", "absent"
    if path.is_symlink():
        return "symlink_refused", "unknown"
    if not path.is_file():
        return "not_regular", "unknown"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return "parse_failed", "unknown"
    value = data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return "present", "absent"
        value = value[key]
    return "present", "present" if isinstance(value, str) and bool(value) else "absent"


def _env_key_present(path: Path, key: str) -> tuple[str, str]:
    if not path.exists():
        return "missing", "absent"
    if path.is_symlink():
        return "symlink_refused", "unknown"
    if not path.is_file():
        return "not_regular", "unknown"
    try:
        values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    except Exception:
        return "parse_failed", "unknown"
    return "present", "present" if values.get(key) else "absent"


def _json_path_value(path: Path, keys: list[str]) -> str:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    value = data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return ""
        value = value[key]
    return value if isinstance(value, str) else ""


def _env_key_value(path: Path, key: str) -> str:
    values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    return values.get(key, "")


def _handoff_value_command(slot: str) -> str:
    return shlex.join(["sudo", "/usr/local/bin/opsctl", "handoff", "print", slot])


def cmd_handoff_status(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl handoff status TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        family = str(profile.metadata.get("family") or desired.family or "")
    except Exception as exc:
        print(f"target={args.slot}")
        print("handoff_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"family={family}")
    print("handoff_value_printed=no")

    if family == "openclaw":
        config_path = slot_home(desired.slot) / ".openclaw" / "openclaw.json"
        try:
            _assert_secret_path_safe(desired.slot, config_path)
            file_state, token_state = _json_path_present(config_path, ["gateway", "auth", "token"])
        except Exception as exc:
            file_state, token_state = "invalid", "unknown"
            print(f"reason={exc}")
        print("handoff_kind=openclaw_gateway_token")
        print(f"handoff_secret_file={config_path}")
        print("handoff_secret_json_path=gateway.auth.token")
        print("handoff_container_file=/home/node/.openclaw/openclaw.json")
        print(f"handoff_file_state={file_state}")
        print(f"handoff_token={token_state}")
        print("handoff_value_retrieval=manual_cli")
        print(f"handoff_value_command={_handoff_value_command(desired.slot)}")
        print(f"handoff_status={'ok' if file_state == 'present' and token_state == 'present' else 'fail'}")
        return 0 if file_state == "present" and token_state == "present" else 1

    if family == "hermes":
        secret_file = _state_root(args) / "handoff" / f"hermes-workspace-{desired.slot}.env"
        file_state, password_state = _env_key_present(secret_file, "password")
        print("handoff_kind=hermes_workspace_password")
        print(f"handoff_secret_file={secret_file}")
        print("handoff_secret_key=password")
        print(f"handoff_file_state={file_state}")
        print(f"handoff_password={password_state}")
        print("handoff_value_retrieval=manual_cli")
        print(f"handoff_value_command={_handoff_value_command(desired.slot)}")
        print(f"handoff_status={'ok' if file_state == 'present' and password_state == 'present' else 'fail'}")
        return 0 if file_state == "present" and password_state == "present" else 1

    print("handoff_status=fail")
    print("reason=unsupported_runtime_family")
    return 1


def cmd_handoff_value_command(args: argparse.Namespace) -> int:
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print("handoff_value_command_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print("handoff_value_printed=no")
    print(f"handoff_value_command={_handoff_value_command(desired.slot)}")
    print("handoff_value_command_status=ok")
    return 0


def cmd_handoff_print(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl handoff print TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        family = str(profile.metadata.get("family") or desired.family or "")
    except Exception as exc:
        print(f"target={args.slot}")
        print("handoff_print_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"family={family}")
    print("handoff_value_printed=yes")

    try:
        if family == "openclaw":
            config_path = slot_home(desired.slot) / ".openclaw" / "openclaw.json"
            _assert_secret_path_safe(desired.slot, config_path)
            token = _json_path_value(config_path, ["gateway", "auth", "token"])
            if not token:
                raise ValueError("handoff_token=missing")
            print("handoff_kind=openclaw_gateway_token")
            print(f"handoff_secret_file={config_path}")
            print(f"token={token}")
        elif family == "hermes":
            secret_file = _state_root(args) / "handoff" / f"hermes-workspace-{desired.slot}.env"
            file_state, password_state = _env_key_present(secret_file, "password")
            if file_state != "present" or password_state != "present":
                raise ValueError(f"handoff_password={password_state} file_state={file_state}")
            password = _env_key_value(secret_file, "password")
            if not password:
                raise ValueError("handoff_password=missing")
            print("handoff_kind=hermes_workspace_password")
            print(f"handoff_secret_file={secret_file}")
            print("handoff_secret_key=password")
            print(f"password={password}")
        else:
            raise ValueError("unsupported_runtime_family")
    except Exception as exc:
        print("handoff_print_status=fail")
        print(f"reason={exc}")
        return 1

    print("handoff_print_status=ok")
    return 0


