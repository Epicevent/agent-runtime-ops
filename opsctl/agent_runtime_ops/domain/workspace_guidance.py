from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..host.account_files import ensure_not_symlink_chain, runtime_ids, slot_home
from ..paths import REPO_ROOT


def workspace_guidance_paths(slot: str, family: str) -> tuple[Path, Path, list[Path], Path, str, str]:
    home = slot_home(slot)
    expected_home = Path("/home") / slot
    if home != expected_home:
        raise ValueError(f"unexpected slot home: {home}")
    if home.exists() and home.is_symlink():
        raise ValueError(f"managed home must not be symlink: {home}")
    if family == "hermes":
        app_home = home / ".hermes"
        workspace = app_home / "workspace"
        source = REPO_ROOT / "images" / "shared-document-tools" / "hermes-workspace-guidance.md"
        begin = "<!-- BEGIN OPENCLAW HERMES GUIDANCE -->"
        end = "<!-- END OPENCLAW HERMES GUIDANCE -->"
        names = ["AGENTS.md", "CLAUDE.md", "GEMINI.md"]
    elif family == "openclaw":
        app_home = home / ".openclaw"
        workspace = app_home / "workspace"
        source = REPO_ROOT / "images" / "shared-document-tools" / "openclaw-workspace-guidance.md"
        begin = "<!-- BEGIN OPENCLAW WORKSPACE GUIDANCE -->"
        end = "<!-- END OPENCLAW WORKSPACE GUIDANCE -->"
        names = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", "TOOLS.md"]
    else:
        raise ValueError(f"unsupported runtime family for workspace guidance: {family}")
    targets = [workspace / name for name in names]
    return app_home, workspace, targets, source, begin, end


def upsert_managed_guidance_block(existing: str, source_text: str, begin: str, end: str) -> str:
    block = f"{begin}\n{source_text.rstrip()}\n{end}\n"
    has_begin = begin in existing
    has_end = end in existing
    if has_begin != has_end:
        raise ValueError("managed workspace guidance marker is incomplete")
    if has_begin and has_end:
        before, rest = existing.split(begin, 1)
        _old, after = rest.split(end, 1)
        return before.rstrip() + "\n\n" + block + after.lstrip()
    if existing.strip():
        return existing.rstrip() + "\n\n" + block
    return block


def atomic_write_owned_text(path: Path, text: str, mode: int, uid: int, gid: int) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed guidance file must not be symlink: {path}")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError(f"managed guidance parent is not a safe directory: {path.parent}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.chown(tmp_path, uid, gid)
        os.replace(tmp_path, path)
        try:
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            pass
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def ensure_runtime_workspace_guidance(slot: str, profile) -> dict[str, str]:
    family = str(profile.metadata.get("family") or "")
    if family not in {"hermes", "openclaw"}:
        return {"workspace_guidance": "skipped", "workspace_guidance_reason": f"family={family or 'unknown'}"}
    app_home, workspace, targets, source, begin, end = workspace_guidance_paths(slot, family)
    if not source.is_file() or source.is_symlink():
        raise FileNotFoundError(f"workspace guidance source missing: {source}")

    home = slot_home(slot)
    ensure_not_symlink_chain(app_home, home)
    ensure_not_symlink_chain(workspace, home)
    for target in targets:
        ensure_not_symlink_chain(target, home)
        if target.exists() and target.is_symlink():
            raise ValueError(f"managed guidance file must not be symlink: {target}")

    if family == "hermes":
        uid, _runtime_gid, data_gid = runtime_ids(slot)
        gid = data_gid
        app_mode = 0o750
        workspace_mode = 0o750
    else:
        uid, gid, _data_gid = runtime_ids(slot)
        app_mode = 0o750
        workspace_mode = 0o750

    app_home.mkdir(mode=app_mode, parents=True, exist_ok=True)
    workspace.mkdir(mode=workspace_mode, parents=True, exist_ok=True)
    ensure_not_symlink_chain(workspace, home)
    os.chown(app_home, uid, gid)
    os.chmod(app_home, app_mode)
    os.chown(workspace, uid, gid)
    os.chmod(workspace, workspace_mode)

    source_text = source.read_text(encoding="utf-8")
    changed = 0
    for target in targets:
        existing = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else ""
        updated = upsert_managed_guidance_block(existing, source_text, begin, end)
        if updated != existing:
            changed += 1
        atomic_write_owned_text(target, updated, 0o644, uid, gid)
    return {
        "workspace_guidance": "updated" if changed else "present",
        "workspace_guidance_family": family,
        "workspace_guidance_workspace": str(workspace),
        "workspace_guidance_files": ",".join(str(target) for target in targets),
    }
