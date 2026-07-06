from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

OCI_SOURCE_LABEL = "org.opencontainers.image.source"


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


def verify_commit_on_default_branch(repo_url: str, commit_sha: str) -> str:
    """Return the default branch name iff commit_sha is reachable from it.

    Ancestry gate for approvals, engraved from the 2026-07 incident: a production
    image was approved from an unmerged feature branch, the default branch stayed
    stale, and an ops review measuring main concluded the shipped feature was
    fiction. The repo to check comes from the image's own OCI source label — an
    artifact fact, not prose config. Uses a throwaway blobless single-branch
    clone: full default-branch history, no file contents, so the oracle is cheap.

    Raises ValueError with a merge-first hint when the commit is not on the
    default branch, and with the git error on infrastructure failures.
    """
    if not shutil.which("git"):
        raise ValueError("git is required to verify source-commit ancestry")
    not_merged = (
        f"source commit {commit_sha} is not merged to the default branch of {redact_git_url(repo_url)}; "
        "merge it first (approvals must be default-branch commits)"
    )
    with tempfile.TemporaryDirectory(prefix="agent-runtime-ops-provenance.") as tmp:
        repo = Path(tmp) / "src.git"
        clone = _run_text(
            ["git", "clone", "--bare", "--filter=blob:none", "--single-branch", repo_url, str(repo)],
            timeout=300,
        )
        if clone.returncode != 0:
            raise ValueError(
                f"could not clone {redact_git_url(repo_url)} for ancestry verification: "
                f"{clone.stderr.strip() or clone.stdout.strip()}"
            )
        head = _run_text(git_source_command(repo, "symbolic-ref", "HEAD"))
        branch_ref = (head.stdout or "").strip()
        branch = branch_ref.removeprefix("refs/heads/") or "HEAD"
        present = _run_text(git_source_command(repo, "cat-file", "-e", f"{commit_sha}^{{commit}}"))
        if present.returncode != 0:
            raise ValueError(not_merged)
        ancestry = _run_text(
            git_source_command(repo, "merge-base", "--is-ancestor", commit_sha, branch_ref or "HEAD")
        )
        if ancestry.returncode == 1:
            raise ValueError(not_merged)
        if ancestry.returncode != 0:
            raise ValueError(
                f"ancestry verification failed for {commit_sha}: "
                f"{ancestry.stderr.strip() or ancestry.stdout.strip()}"
            )
        return branch
