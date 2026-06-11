from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.update_policy import (
    UPDATE_POLICY_NAME,
    approved_update_from_policy,
    installed_source_commit,
    validate_update_target,
    write_update_policy,
)


def cmd_self_update(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl self-update", file=sys.stderr)
        return 2
    if shutil.which("git") is None:
        print("error: missing command: git", file=sys.stderr)
        return 2
    if shutil.which("bash") is None:
        print("error: missing command: bash", file=sys.stderr)
        return 2

    try:
        repo_url, ref = approved_update_from_policy(_state_root(args))
        policy_source = str(_state_root(args) / UPDATE_POLICY_NAME)
        validate_update_target(repo_url, ref)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"hint: approve a full commit in {_state_root(args) / UPDATE_POLICY_NAME}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="agent-runtime-ops-update.") as tmp:
        repo = Path(tmp) / "agent-runtime-ops"
        print(f"update_repo={repo_url}")
        print(f"approved_ref={ref}")
        print(f"policy_source={policy_source}")
        try:
            subprocess.run(["git", "clone", "--no-checkout", repo_url, str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "fetch", "--depth", "1", "origin", ref], check=True)
            subprocess.run(["git", "-C", str(repo), "checkout", "--detach", ref], check=True)
            resolved = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            if resolved != ref:
                print(f"error: checkout mismatch: expected {ref}, got {resolved}", file=sys.stderr)
                return 1
            env = os.environ.copy()
            env["AGENT_RUNTIME_OPS_REF"] = ref
            subprocess.run(["bash", str(repo / "install.sh"), "install"], check=True, env=env)
        except subprocess.CalledProcessError as exc:
            return exc.returncode or 1
    return 0


def cmd_update_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl update approve FULL_SHA", file=sys.stderr)
        return 2
    try:
        policy_path = write_update_policy(_state_root(args), args.ref)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"approved_ref={args.ref}")
    print(f"policy_file={policy_path}")
    return 0


def cmd_update_status(args: argparse.Namespace) -> int:
    installed_ref = installed_source_commit()
    try:
        repo_url, ref = approved_update_from_policy(_state_root(args))
        validate_update_target(repo_url, ref)
    except Exception as exc:
        print("update_status=not_ready")
        if installed_ref:
            print(f"installed_ref={installed_ref}")
        print(f"reason={exc}")
        return 1
    matches = bool(installed_ref) and installed_ref == ref
    print(f"update_status={'current' if matches else 'ready'}")
    if installed_ref:
        print(f"installed_ref={installed_ref}")
    print(f"repo_url={repo_url}")
    print(f"approved_ref={ref}")
    print(f"approved_matches_installed={'yes' if matches else 'no'}")
    return 0
