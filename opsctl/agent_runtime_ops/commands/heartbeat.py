from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..host.account_files import _ensure_not_symlink_chain, _runtime_ids, _slot_home
from ..profiles import load_profile
from ..state import RuntimeTarget, load_runtime_target


def _assert_secret_path_safe(slot: str, path: Path, *, create_parent: bool = False) -> None:
    if not path.is_absolute():
        raise ValueError(f"secret file path must be absolute: {path}")
    home = _slot_home(slot).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"secret file path outside slot home: {path}")
    _ensure_not_symlink_chain(path.parent, home)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_not_symlink_chain(path, home)
    if path.exists() and not path.is_file():
        raise ValueError(f"secret file path is not a regular file: {path}")
    if path.is_symlink():
        raise ValueError(f"secret file must not be a symlink: {path}")


def _require_openclaw_target(slot: str, state_root: Path) -> tuple[RuntimeTarget, object]:
    desired = load_runtime_target(slot, state_root)
    profile = load_profile(desired.runtime_profile)
    family = str(profile.metadata.get("family") or desired.family or "")
    if family != "openclaw":
        raise ValueError(f"heartbeat is supported only for openclaw targets: family={family or 'unknown'}")
    return desired, profile


def _openclaw_config_path(slot: str) -> Path:
    return _slot_home(slot) / ".openclaw" / "openclaw.json"


def _heartbeat_files(slot: str) -> list[Path]:
    workspace = _slot_home(slot) / ".openclaw" / "workspace"
    if not workspace.is_dir():
        return []
    rows: list[Path] = []
    for path in workspace.rglob("HEARTBEAT.md"):
        try:
            relative = path.relative_to(workspace)
        except ValueError:
            continue
        if len(relative.parts) <= 5 and (path.is_file() or path.is_symlink()):
            rows.append(path)
    return sorted(rows, key=lambda item: str(item))


def _heartbeat_summary(data: dict[str, object] | None) -> tuple[str, str, str, list[tuple[str, str]], str]:
    if data is None:
        return "missing", "30m", "", [], "yes"
    agents = data.get("agents")
    agents_data = agents if isinstance(agents, dict) else {}
    defaults = agents_data.get("defaults")
    defaults_data = defaults if isinstance(defaults, dict) else {}
    heartbeat = defaults_data.get("heartbeat")
    default_every = "30m"
    model = ""
    config_state = "absent"
    if isinstance(heartbeat, dict):
        config_state = "present"
        if heartbeat.get("every"):
            default_every = str(heartbeat.get("every"))
        if heartbeat.get("model"):
            model = str(heartbeat.get("model"))
    agent_entries = agents_data.get("list")
    overrides: list[tuple[str, str]] = []
    if isinstance(agent_entries, list):
        for index, entry in enumerate(agent_entries):
            if not isinstance(entry, dict):
                continue
            agent_heartbeat = entry.get("heartbeat")
            if isinstance(agent_heartbeat, dict):
                agent_id = str(entry.get("id") or index)
                every = str(agent_heartbeat.get("every") or default_every)
                overrides.append((agent_id, every))
    if overrides:
        enabled = any(every != "0m" for _, every in overrides)
    else:
        enabled = default_every != "0m"
    return config_state, default_every, model, overrides, "yes" if enabled else "no"


def _read_openclaw_config_for_heartbeat(slot: str, path: Path) -> tuple[str, dict[str, object] | None]:
    if not path.exists():
        return "missing", None
    _assert_secret_path_safe(slot, path)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        raise ValueError(f"heartbeat_config_parse_error={exc.__class__.__name__}") from exc
    if not isinstance(data, dict):
        raise ValueError("heartbeat_config_parse_error=not_object")
    return "present", data


def _print_heartbeat_status(slot: str, profile_name: str) -> int:
    files = _heartbeat_files(slot)
    print(f"target={slot}")
    print(f"runtime_profile={profile_name}")
    print("family=openclaw")
    for index, path in enumerate(files, 1):
        print(f"heartbeat_file_{index}={path}")
        try:
            stat_result = path.lstat()
            kind = "symlink" if path.is_symlink() else "regular"
            print(f"heartbeat_file_{index}_type={kind}")
            print(f"heartbeat_file_{index}_mode={stat.S_IMODE(stat_result.st_mode):03o}")
            print(f"heartbeat_file_{index}_size={stat_result.st_size}")
        except OSError as exc:
            print(f"heartbeat_file_{index}_stat_error={exc.__class__.__name__}")
    print(f"heartbeat_files_count={len(files)}")
    print("heartbeat_files_note=optional_checklist_not_the_scheduler")
    config_path = _openclaw_config_path(slot)
    file_state, data = _read_openclaw_config_for_heartbeat(slot, config_path)
    config_state, every, model, overrides, enabled = _heartbeat_summary(data)
    print(f"heartbeat_config_file={config_path}")
    print(f"heartbeat_config_file_state={file_state}")
    print(f"heartbeat_config={config_state}")
    print(f"heartbeat_config_every={every}")
    print(f"heartbeat_config_model={model}")
    print(f"heartbeat_agent_overrides_count={len(overrides)}")
    for index, (agent_id, every_value) in enumerate(overrides, 1):
        print(f"heartbeat_agent_{index}_id={agent_id}")
        print(f"heartbeat_agent_{index}_every={every_value}")
    print(f"heartbeat_config_enabled={enabled}")
    print("heartbeat_status=ok")
    return 0


def cmd_heartbeat_status(args: argparse.Namespace) -> int:
    try:
        desired, profile = _require_openclaw_target(args.slot, _state_root(args))
        return _print_heartbeat_status(desired.slot, profile.name)
    except Exception as exc:
        print(f"target={args.slot}")
        print("heartbeat_status=fail")
        print(f"reason={exc}")
        return 1


def _write_openclaw_config(slot: str, path: Path, data: dict[str, object]) -> None:
    _assert_secret_path_safe(slot, path, create_parent=True)
    runtime_uid, runtime_gid, _ = _runtime_ids(slot)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp_path, 0o600)
    os.chown(tmp_path, runtime_uid, runtime_gid)
    os.replace(tmp_path, path)


def cmd_heartbeat_disable(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl heartbeat disable TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _require_openclaw_target(args.slot, state_root)
        files = _heartbeat_files(desired.slot)
        config_path = _openclaw_config_path(desired.slot)
        _, data = _read_openclaw_config_for_heartbeat(desired.slot, config_path)
        if data is None:
            data = {}
        agents = data.setdefault("agents", {})
        if not isinstance(agents, dict):
            agents = {}
            data["agents"] = agents
        defaults = agents.setdefault("defaults", {})
        if not isinstance(defaults, dict):
            defaults = {}
            agents["defaults"] = defaults
        heartbeat = defaults.setdefault("heartbeat", {})
        if not isinstance(heartbeat, dict):
            heartbeat = {}
            defaults["heartbeat"] = heartbeat
        heartbeat["every"] = "0m"
        overrides_disabled = 0
        agent_entries = agents.get("list")
        if isinstance(agent_entries, list):
            for entry in agent_entries:
                if not isinstance(entry, dict):
                    continue
                agent_heartbeat = entry.get("heartbeat")
                if isinstance(agent_heartbeat, dict):
                    agent_heartbeat["every"] = "0m"
                    overrides_disabled += 1
        _write_openclaw_config(desired.slot, config_path, data)
        print(f"target={desired.slot}")
        print(f"runtime_profile={profile.name}")
        print("family=openclaw")
        print(f"heartbeat_files_count={len(files)}")
        print("heartbeat_files_action=left_untouched_optional_checklist")
        print("heartbeat_config_disabled=yes")
        print("heartbeat_config_every=0m")
        print(f"heartbeat_agent_overrides_disabled={overrides_disabled}")
        _append_action_log(state_root, "heartbeat_disable", desired.slot, str(config_path), "ok", "every=0m")
        rc = _print_heartbeat_status(desired.slot, profile.name)
        print("heartbeat_disable_status=ok")
        return rc
    except Exception as exc:
        print(f"target={args.slot}")
        print("heartbeat_disable_status=fail")
        print(f"reason={exc}")
        return 1


