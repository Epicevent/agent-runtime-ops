from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
import subprocess
from pathlib import Path

from ..apache import parse_apache_route


def state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


def apache_public_host(slot: str) -> str:
    try:
        return parse_apache_route(slot).public_host
    except Exception:
        return ""


def container_name(slot: str, profile) -> str:
    service = profile.metadata.get("service") or "openclaw-gateway"
    return f"openclaw-{slot}-{service}-1"


def run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def run_text_cwd(command: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


_state_root = state_root
_is_root = is_root
_now_iso = now_iso
_check_line = check_line
_apache_public_host = apache_public_host
_container_name = container_name
_run_text = run_text
_run_text_cwd = run_text_cwd
