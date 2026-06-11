from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from ..domain.common import is_root as _is_root
from ..domain.runtime_state import agent_backup_root, slot_runtime_dir
from ..redaction import redact
from ..routing import validate_linux_account
from ..yamlio import load_yaml


def _is_under_path(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_diagnostics_dir(slot: str, value: str | None = None) -> Path:
    backup_root = agent_backup_root(slot_runtime_dir(slot)).resolve(strict=False)
    if value:
        requested = Path(value)
        if not requested.is_absolute():
            raise ValueError("diagnostics path must be absolute")
        path = requested.resolve(strict=False)
        if path.name != "failed-container":
            path = path / "failed-container"
    else:
        if not backup_root.is_dir():
            raise ValueError(f"backup root not found: {backup_root}")
        backups = sorted(item for item in backup_root.iterdir() if item.is_dir())
        if not backups:
            raise ValueError(f"no backups found for target: {slot}")
        path = backups[-1].resolve(strict=False) / "failed-container"
    path = path.resolve(strict=False)
    if not _is_under_path(path, backup_root):
        raise ValueError("diagnostics path must stay under the target backup root")
    if path.is_symlink():
        raise ValueError(f"diagnostics path must not be symlink: {path}")
    if not path.is_dir():
        raise ValueError(f"diagnostics dir not found: {path}")
    return path


def _load_diagnostics_payload(path: Path) -> dict:
    data = load_yaml(path)
    return data if isinstance(data, dict) else {}


def _format_command_list(value) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    if value in {None, ""}:
        return "empty"
    return str(value)


def _redacted_tail(text: str, *, lines: int, chars: int = 12000) -> str:
    redacted = redact(text or "")
    parts = redacted.splitlines()
    if lines > 0:
        redacted = "\n".join(parts[-lines:])
    return redacted[-chars:]


def _print_block(name: str, text: str) -> None:
    print(f"{name}_begin")
    if text:
        print(text)
    print(f"{name}_end")


def _print_inspect_summary(diag_dir: Path) -> None:
    path = diag_dir / "inspect.json"
    if not path.is_file():
        print("inspect_status=missing")
        return
    payload = _load_diagnostics_payload(path)
    print(f"inspect_returncode={payload.get('returncode')}")
    if payload.get("returncode") != 0:
        stderr = _redacted_tail(str(payload.get("stderr") or payload.get("stdout") or ""), lines=20)
        _print_block("inspect_error", stderr)
        return
    try:
        rows = json.loads(str(payload.get("stdout") or "[]"))
        info = rows[0] if isinstance(rows, list) and rows else {}
    except Exception as exc:
        print(f"inspect_parse_status=fail reason={exc}")
        return
    state = info.get("State") if isinstance(info, dict) else {}
    config = info.get("Config") if isinstance(info, dict) else {}
    health = state.get("Health") if isinstance(state, dict) else {}
    print("inspect_status=ok")
    print(f"container_id={str(info.get('Id') or '')[:12]}")
    print(f"container_name={info.get('Name') or ''}")
    print(f"container_image={config.get('Image') or ''}")
    print(f"container_running={state.get('Running')}")
    print(f"container_pid={state.get('Pid')}")
    print(f"container_exit_code={state.get('ExitCode')}")
    print(f"container_health={(health or {}).get('Status') if isinstance(health, dict) else 'none'}")
    print(f"container_entrypoint={_format_command_list(config.get('Entrypoint'))}")
    print(f"container_cmd={_format_command_list(config.get('Cmd'))}")
    print(f"container_working_dir={config.get('WorkingDir') or ''}")


def cmd_diagnostics_show(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics show TARGET", file=sys.stderr)
        return 2
    try:
        slot = str(args.slot)
        validate_linux_account(slot)
        diag_dir = _resolve_diagnostics_dir(slot, getattr(args, "dir", None))
        tail_lines = max(1, min(int(getattr(args, "tail", 120)), 300))
    except Exception as exc:
        print("diagnostics_status=fail")
        print(f"reason={exc}")
        return 1

    print("diagnostics_status=ok")
    print(f"target={slot}")
    print(f"diagnostics_dir={diag_dir}")
    print("secret_value_printed=no")
    lookup_path = diag_dir / "lookup.txt"
    if lookup_path.is_file():
        print(redact(lookup_path.read_text(encoding="utf-8", errors="replace").strip()))
    _print_inspect_summary(diag_dir)
    for stem in ("ports", "top", "logs"):
        path = diag_dir / f"{stem}.txt"
        if not path.is_file():
            print(f"{stem}_status=missing")
            continue
        payload = _load_diagnostics_payload(path)
        print(f"{stem}_returncode={payload.get('returncode')}")
        text = "\n".join(part for part in (str(payload.get("stdout") or ""), str(payload.get("stderr") or "")) if part)
        _print_block(f"{stem}_tail", _redacted_tail(text, lines=tail_lines))
    return 0
