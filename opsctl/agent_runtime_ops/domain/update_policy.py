from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import tempfile

from ..paths import REPO_ROOT
from ..yamlio import dump_yaml, load_yaml


DEFAULT_REPO_URL = "https://github.com/Epicevent/agent-runtime-ops.git"
UPDATE_POLICY_NAME = "ops-update.yaml"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def approved_update_from_policy(state_root: Path) -> tuple[str, str]:
    policy_path = state_root / UPDATE_POLICY_NAME
    data = load_yaml(policy_path)
    item = (data.get("updates") or {}).get("agent-runtime-ops")
    if not isinstance(item, dict):
        raise ValueError(f"missing updates.agent-runtime-ops in {policy_path}")
    repo_url = item.get("repo_url", DEFAULT_REPO_URL)
    ref = item.get("approved_ref")
    return str(repo_url), str(ref or "")


def validate_update_target(repo_url: str, ref: str) -> None:
    if repo_url != DEFAULT_REPO_URL:
        raise ValueError(f"unapproved update repository: {repo_url}")
    if not FULL_SHA_RE.match(ref):
        raise ValueError("self-update requires an approved full 40-character commit sha")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def installed_source_commit() -> str:
    manifest_path = REPO_ROOT / ".agent-runtime-ops-manifest"
    try:
        for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
            key, _, value = raw_line.partition("=")
            if key == "source_commit":
                return value.strip()
    except OSError:
        return ""
    return ""


def write_update_policy(state_root: Path, ref: str) -> Path:
    validate_update_target(DEFAULT_REPO_URL, ref)
    if not state_root.is_dir():
        raise FileNotFoundError(state_root)

    policy_path = state_root / UPDATE_POLICY_NAME
    data = {
        "meta": {
            "schema_version": 1,
            "updated_at": now_iso(),
            "scope": "private_server_state",
        },
        "updates": {
            "agent-runtime-ops": {
                "repo_url": DEFAULT_REPO_URL,
                "approved_ref": ref,
                "approved_at": now_iso(),
                "approved_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
            }
        },
    }

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_root, delete=False) as fh:
        tmp_path = Path(fh.name)
        fh.write(dump_yaml(data))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        if hasattr(os, "chown"):
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, policy_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return policy_path
