from __future__ import annotations

import re
import subprocess
from pathlib import Path


def redact_git_url(value: str) -> str:
    return re.sub(r"://[^/@]+@", "://<redacted>@", value)


def git_source_command(source: Path, *args: str) -> list[str]:
    safe_source = str(source.resolve(strict=False))
    return ["git", "-c", f"safe.directory={safe_source}", "-C", safe_source, *args]


def _run_text(command: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def source_provenance(source: Path) -> dict[str, object]:
    data: dict[str, object] = {
        "path": str(source),
        "status": "unknown",
        "git_head": "",
        "git_dirty": None,
        "git_toplevel": "",
        "git_remote_origin": "",
    }
    rev = _run_text(git_source_command(source, "rev-parse", "--show-toplevel", "HEAD"), timeout=30)
    if rev.returncode != 0:
        data["status"] = "no_git"
        return data
    lines = [line.strip() for line in rev.stdout.splitlines() if line.strip()]
    if len(lines) >= 2:
        data["git_toplevel"] = lines[0]
        data["git_head"] = lines[1]
    status = _run_text(git_source_command(source, "status", "--porcelain"), timeout=30)
    data["git_dirty"] = bool(status.stdout.strip()) if status.returncode == 0 else None
    remote = _run_text(git_source_command(source, "remote", "get-url", "origin"), timeout=30)
    if remote.returncode == 0:
        data["git_remote_origin"] = redact_git_url(remote.stdout.strip())
    data["status"] = "git"
    return data


def require_fresh_clean_source_provenance(dev_recipe: dict[str, object]) -> dict[str, object]:
    source_output_text = str(dev_recipe.get("source_output") or "")
    if not source_output_text:
        raise ValueError("dev recipe state is missing source_output")
    source_output = Path(source_output_text)
    if not source_output.is_absolute():
        raise ValueError("dev recipe source_output must be absolute")

    stored = dev_recipe.get("source_provenance")
    if not isinstance(stored, dict):
        raise ValueError("dev recipe state is missing source provenance")

    # Capture must validate the source tree as it exists now, not a clean bit
    # saved by a previous apply-dev run.
    current = source_provenance(source_output)
    if current.get("status") != "git":
        raise ValueError(f"current source provenance is not git-backed: status={current.get('status') or 'missing'}")
    if current.get("git_dirty") is not False:
        raise ValueError(f"current source provenance must be clean: git_dirty={current.get('git_dirty')}")

    stored_head = str(stored.get("git_head") or "")
    current_head = str(current.get("git_head") or "")
    if not stored_head:
        raise ValueError("stored source provenance is missing git_head")
    if not current_head:
        raise ValueError("current source provenance is missing git_head")
    if stored_head != current_head:
        raise ValueError(f"source git head changed since apply-dev: stored={stored_head} current={current_head}")
    return current
