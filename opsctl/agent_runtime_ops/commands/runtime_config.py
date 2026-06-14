from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import re
import stat
import sys

from ..domain.actions import append_action_log
from ..domain.common import is_root, state_root
from ..host.account_files import ensure_not_symlink_chain, runtime_ids, slot_home
from ..host.files import fsync_parent
from ..state import load_runtime_target
from ..yamlio import dump_yaml, load_yaml


GOOGLE_GEMINI_31_PRO_PREVIEW = "gemini-3.1-pro-preview"
_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}$")
RUNTIME_PROVIDER_ALIASES = {
    "google": "gemini",
    "google-ai": "gemini",
    "google_ai": "gemini",
    "google-gemini": "gemini",
    "google_gemini": "gemini",
    "gemini": "gemini",
}
RUNTIME_CONFIG_SECRET_OVERRIDE_PATHS = (
    ("providers", "google", "api_key"),
    ("providers", "google", "apiKey"),
    ("providers", "google", "key"),
    ("providers", "gemini", "api_key"),
    ("providers", "gemini", "apiKey"),
    ("providers", "gemini", "key"),
    ("auth", "google", "api_key"),
    ("auth", "gemini", "api_key"),
)


def _assert_name(value: str, pattern: re.Pattern[str], label: str) -> str:
    item = value.strip()
    if not item or not pattern.match(item):
        raise ValueError(f"invalid {label}: {value!r}")
    return item


def runtime_provider_id(value: str) -> str:
    raw = value.strip().lower()
    return RUNTIME_PROVIDER_ALIASES.get(raw, raw)


def _hermes_config_path(slot: str) -> Path:
    home = slot_home(slot).resolve(strict=False)
    path = home / ".hermes" / "config.yaml"
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"config path outside slot home: {path}")
    ensure_not_symlink_chain(path.parent, home)
    if path.exists() and path.is_symlink():
        raise ValueError(f"config file must not be a symlink: {path}")
    return path


def _read_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError(f"config path is not a regular file: {path}")
    data = load_yaml(path, default={})
    if not isinstance(data, dict):
        raise ValueError(f"config must be a mapping: {path}")
    return dict(data)


def _current_model(config: dict[str, object]) -> tuple[str, str, str]:
    model_value = config.get("model")
    provider = str(config.get("provider") or "").strip()
    if isinstance(model_value, dict):
        nested_provider = str(model_value.get("provider") or provider).strip()
        nested_model = str(model_value.get("default") or model_value.get("model") or "").strip()
        return nested_provider, nested_model, "nested"
    if isinstance(model_value, str):
        return provider, model_value.strip(), "flat"
    return provider, "", "missing"


def _write_config(slot: str, path: Path, config: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = path.stat()
        uid, gid = current.st_uid, current.st_gid
        mode = stat.S_IMODE(current.st_mode) or 0o600
    else:
        uid, _, gid = runtime_ids(slot)
        mode = 0o600
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(dump_yaml(config))
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _remove_nested_config_key(config: dict[str, object], path: tuple[str, ...]) -> tuple[bool, bool]:
    node: object = config
    for part in path[:-1]:
        if not isinstance(node, dict):
            return False, False
        node = node.get(part)
    if not isinstance(node, dict):
        return False, False
    leaf = path[-1]
    if leaf not in node:
        return False, False
    value = node.pop(leaf)
    return True, bool(value)


def _load_hermes_target(slot: str, args: argparse.Namespace):
    desired = load_runtime_target(slot, state_root(args))
    if desired.family != "hermes":
        raise ValueError(f"runtime config is only supported for hermes targets: family={desired.family}")
    return desired


def cmd_runtime_config_status(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime config-status TARGET", file=sys.stderr)
        return 2
    try:
        desired = _load_hermes_target(args.slot, args)
        config_path = _hermes_config_path(desired.slot)
        config = _read_config(config_path)
        provider, model, source = _current_model(config)
        provider_runtime = runtime_provider_id(provider) if provider else ""
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_config_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"config_file={config_path}")
    print(f"provider={provider_runtime or 'missing'}")
    print(f"provider_raw={provider or 'missing'}")
    print(f"provider_runtime={provider_runtime or 'missing'}")
    print(f"model={model or 'missing'}")
    print(f"model_source={source}")
    print("secret_value_printed=no")
    print("runtime_config_status=ok")
    return 0


def cmd_runtime_set_model(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime set-model TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        provider_raw = _assert_name(str(args.provider), _PROVIDER_RE, "provider")
        provider = runtime_provider_id(provider_raw)
        model = _assert_name(str(args.model), _MODEL_RE, "model")
        desired = _load_hermes_target(target, args)
        config_path = _hermes_config_path(desired.slot)
        config = _read_config(config_path)
        previous_provider, previous_model, previous_source = _current_model(config)
        previous_provider_runtime = runtime_provider_id(previous_provider) if previous_provider else ""
        config["provider"] = provider
        current_model_value = config.get("model")
        if isinstance(current_model_value, dict):
            next_model = dict(current_model_value)
            next_model["default"] = model
            next_model["provider"] = provider
            config["model"] = next_model
        else:
            config["model"] = model
        _write_config(desired.slot, config_path, config)
    except Exception as exc:
        print(f"target={target}")
        print("runtime_config_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_set_model", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"config_file={config_path}")
    print(f"previous_provider={previous_provider or 'missing'}")
    print(f"previous_provider_runtime={previous_provider_runtime or 'missing'}")
    print(f"previous_model={previous_model or 'missing'}")
    print(f"previous_model_source={previous_source}")
    print(f"provider_raw={provider_raw}")
    print(f"provider={provider}")
    print(f"provider_runtime={provider}")
    print(f"model={model}")
    print("secret_value_printed=no")
    print("runtime_config_status=updated")
    append_action_log(
        state_root(args),
        "runtime_set_model",
        desired.slot,
        desired.slot,
        "ok",
        f"{previous_provider_runtime or previous_provider or 'missing'}/{previous_model or 'missing'} -> {provider}/{model}",
    )
    return 0


def cmd_runtime_config_sanitize(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime config-sanitize TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        desired = _load_hermes_target(target, args)
        config_path = _hermes_config_path(desired.slot)
        config = _read_config(config_path)
        sanitized = copy.deepcopy(config)
        removed: list[tuple[tuple[str, ...], bool]] = []
        for path in RUNTIME_CONFIG_SECRET_OVERRIDE_PATHS:
            did_remove, value_present = _remove_nested_config_key(sanitized, path)
            if did_remove:
                removed.append((path, value_present))
        apply_changes = bool(getattr(args, "apply", False))
        if apply_changes and removed:
            _write_config(desired.slot, config_path, sanitized)
    except Exception as exc:
        print(f"target={target}")
        print("runtime_config_sanitize_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_config_sanitize", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    mode = "apply" if bool(getattr(args, "apply", False)) else "dry_run"
    print(f"target={desired.slot}")
    print(f"config_file={config_path}")
    print(f"runtime_config_sanitize_mode={mode}")
    for path, value_present in removed:
        print(
            f"remove_path={'.'.join(path)} "
            f"value_present={'yes' if value_present else 'no'} "
            "secret_value_printed=no"
        )
    print(f"remove_count={len(removed)}")
    print("secret_value_printed=no")
    print(f"runtime_config_sanitize_status={'updated' if mode == 'apply' else 'dry_run'}")
    if mode == "apply":
        append_action_log(
            state_root(args),
            "runtime_config_sanitize",
            desired.slot,
            desired.slot,
            "ok",
            f"removed={len(removed)} secret_value_printed=no",
        )
    return 0
