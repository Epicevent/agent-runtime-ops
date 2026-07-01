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


# Accounts allowed to operate on production (customer) slots. Everyone else with a
# deploy grant is a developer and is scoped to their own dev-* slots (see invoking_user).
OPERATOR_ACCOUNTS = frozenset({"root", "svcops"})


def is_dev_slot(name: object) -> bool:
    """A dev-owned (non-production) slot: identified by the `dev-` account-name prefix.

    This is the production/environment boundary the rollout layer already trusts for
    `image-promote` (`_is_dev_named_target`). `dev-oc` (source) and `dev-oc-img`
    (image-mode validation) are both dev-owned; real customer slots (`oc1`..) are not.
    """
    return str(name or "").startswith("dev-")


def sudo_user() -> str:
    """The account that ran `sudo opsctl ...`, or empty when not invoked via sudo.

    Only `SUDO_USER` is trusted (set by sudo itself after env_reset); there is no `USER`
    fallback on purpose. This is used for AUTHORIZATION and runs after the `is_root()`
    check, so an empty result means a real root shell (an operator), not an unknown user.
    """
    return os.environ.get("SUDO_USER", "")


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
