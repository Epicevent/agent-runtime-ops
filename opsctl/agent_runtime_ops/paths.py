from __future__ import annotations

import os
from pathlib import Path


def _find_repo_root() -> Path:
    env_root = os.environ.get("AGENT_RUNTIME_OPS_ROOT")
    if env_root:
        return Path(env_root).resolve()
    for start in (Path.cwd(), Path(__file__).resolve()):
        current = start if start.is_dir() else start.parent
        for candidate in (current, *current.parents):
            if (candidate / "profiles" / "runtime").is_dir():
                return candidate
    return Path.cwd()


REPO_ROOT = _find_repo_root()
PROFILE_ROOT = REPO_ROOT / "profiles" / "runtime"
DEFAULT_STATE_ROOT = Path("/srv/openclaw-ops")


def state_path(root: Path, name: str) -> Path:
    return root / name
