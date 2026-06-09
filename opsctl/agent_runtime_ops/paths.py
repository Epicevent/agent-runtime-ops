from __future__ import annotations

import os
from pathlib import Path


def _find_repo_root() -> Path:
    env_root = os.environ.get("AGENT_RUNTIME_OPS_ROOT")
    if env_root and os.environ.get("AGENT_RUNTIME_OPS_DEV") == "1":
        return Path(env_root).resolve()

    installed_current = Path("/opt/agent-runtime-ops/current")
    try:
        if (installed_current / "profiles" / "runtime").is_dir():
            return installed_current
    except OSError:
        pass

    starts = [Path(__file__).resolve()]
    try:
        starts.append(Path.cwd())
    except OSError:
        pass

    for start in starts:
        try:
            current = start if start.is_dir() else start.parent
        except OSError:
            current = start.parent
        for candidate in (current, *current.parents):
            try:
                has_profiles = (candidate / "profiles" / "runtime").is_dir()
            except OSError:
                has_profiles = False
            if has_profiles:
                return candidate
    return Path(__file__).resolve().parent


REPO_ROOT = _find_repo_root()
PROFILE_ROOT = REPO_ROOT / "profiles" / "runtime"
RUNTIME_RECIPE_ROOT = REPO_ROOT / "recipes" / "runtime"
DEFAULT_STATE_ROOT = Path("/srv/openclaw-ops")


def state_path(root: Path, name: str) -> Path:
    return root / name
