from __future__ import annotations

import argparse
import re
import sys

from ..domain.actions import append_action_log
from ..domain.common import is_root, state_root
from ..domain.hermes_config import (
    current_model,
    hermes_config_path,
    read_hermes_config,
    runtime_provider_id,
    sanitize_config_secret_overrides,
    write_hermes_config,
)
from ..state import load_runtime_target


_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}$")


def _assert_name(value: str, pattern: re.Pattern[str], label: str) -> str:
    item = value.strip()
    if not item or not pattern.match(item):
        raise ValueError(f"invalid {label}: {value!r}")
    return item


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
        config_path = hermes_config_path(desired.slot)
        config = read_hermes_config(config_path)
        provider, model, source = current_model(config)
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
        config_path = hermes_config_path(desired.slot)
        config = read_hermes_config(config_path)
        previous_provider, previous_model, previous_source = current_model(config)
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
        write_hermes_config(desired.slot, config_path, config)
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
        config_path = hermes_config_path(desired.slot)
        config = read_hermes_config(config_path)
        sanitized, removed = sanitize_config_secret_overrides(config)
        apply_changes = bool(getattr(args, "apply", False))
        if apply_changes and removed:
            write_hermes_config(desired.slot, config_path, sanitized)
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
