from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .paths import PROFILE_ROOT
from .yamlio import load_yaml


PROFILE_FILES = (
    "profile.yaml",
    "compose.yml.tpl",
    "env.contract.yaml",
    "checks.contract.yaml",
)


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    path: Path
    metadata: dict
    digest: str


def list_profile_names(profile_root: Path = PROFILE_ROOT) -> list[str]:
    if not profile_root.exists():
        return []
    return sorted(p.name for p in profile_root.iterdir() if p.is_dir())


def profile_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for filename in PROFILE_FILES:
        target = path / filename
        if not target.is_file():
            raise FileNotFoundError(target)
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(target.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def load_profile(name: str, profile_root: Path = PROFILE_ROOT) -> RuntimeProfile:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ValueError(f"invalid runtime profile name: {name}")
    path = profile_root / name
    metadata = load_yaml(path / "profile.yaml")
    declared = metadata.get("id")
    if declared != name:
        raise ValueError(f"profile id mismatch: path={name} declared={declared!r}")
    return RuntimeProfile(
        name=name,
        path=path,
        metadata=metadata,
        digest=profile_digest(path),
    )

