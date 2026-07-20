from __future__ import annotations

import argparse
import re
import sys

from ..domain.actions import append_action_log
from ..domain.common import is_root, state_root
from ..domain.config_contract import config_json_diff
from ..domain.hermes_config import (
    current_model,
    hermes_config_path,
    model_endpoint_drift,
    read_hermes_config,
    read_version_notes,
    remove_version_note,
    runtime_provider_id,
    sanitize_config_secret_overrides,
    upsert_version_note,
    version_notes_path,
    write_hermes_config,
    write_version_notes,
)
from ..domain.openclaw_config import (
    build_model_ref,
    current_openclaw_model,
    openclaw_config_path,
    openclaw_version_notes_path,
    read_openclaw_config,
    read_openclaw_version_notes,
    run_openclaw_models_set,
    write_openclaw_version_notes,
)
from ..domain.runtime_truth import find_gateway_container
from ..profiles import load_profile
from ..state import load_runtime_target


_PROVIDER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}$")

# runtime config (model read/write) is supported for these product families.
_CONFIG_FAMILIES = frozenset({"hermes", "openclaw"})


def _assert_name(value: str, pattern: re.Pattern[str], label: str) -> str:
    item = value.strip()
    if not item or not pattern.match(item):
        raise ValueError(f"invalid {label}: {value!r}")
    return item


def _load_config_target(slot: str, args: argparse.Namespace):
    desired = load_runtime_target(slot, state_root(args))
    if desired.family not in _CONFIG_FAMILIES:
        raise ValueError(
            f"runtime config is only supported for {sorted(_CONFIG_FAMILIES)} targets: family={desired.family}"
        )
    return desired


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
        desired = _load_config_target(args.slot, args)
        if desired.family == "openclaw":
            config_path = openclaw_config_path(desired.slot)
            config = read_openclaw_config(config_path)
            provider, model, ref, source = current_openclaw_model(config)
            provider_runtime = provider  # openclaw provider ids are used verbatim (e.g. "google")
        else:
            config_path = hermes_config_path(desired.slot)
            config = read_hermes_config(config_path)
            provider, model, source = current_model(config)
            provider_runtime = runtime_provider_id(provider) if provider else ""
            ref = f"{provider}/{model}" if provider and model else (model or "")
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_config_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"config_file={config_path}")
    print(f"provider={provider_runtime or 'missing'}")
    print(f"provider_raw={provider or 'missing'}")
    print(f"provider_runtime={provider_runtime or 'missing'}")
    print(f"model={model or 'missing'}")
    print(f"model_ref={ref or 'missing'}")
    print(f"model_source={source}")
    if desired.family == "hermes":
        drift = model_endpoint_drift(config)
        verdict = str(drift["verdict"])
        routing_keys = drift["routing_keys"]
        print(f"model_base_url_host={drift['host'] or 'none'}")
        print(f"model_routing_keys={','.join(routing_keys) if routing_keys else 'none'}")
        print(f"model_endpoint_drift={'yes' if verdict == 'drift' else verdict if verdict == 'unknown' else 'no'}")
        if verdict != "clean":
            print(f"model_endpoint_drift_reason={drift['reason']}")
    print("secret_value_printed=no")
    print("runtime_config_status=ok")
    return 0


def _set_model_openclaw(desired, provider_raw: str, model: str) -> tuple[str, list[str], str, str, str, str]:
    """Change the slot's default model with the product's OWN ``models set`` command, run inside
    the live gateway container (``docker exec``). This preserves the canonical
    ``agents.defaults.models`` entry, provider-plugin repair, and load-time validation that a raw
    JSON write would skip. A before/after diff of the on-disk config is returned so the operator
    SEES exactly what the product changed. Provider is verbatim (``google/gemini-3.5-flash``).
    Returns (config_path, diff_lines, previous_ref, new_ref, source, container).
    """
    profile = load_profile(desired.runtime_profile)
    container, method = find_gateway_container(desired.route, profile)
    if not container:
        raise ValueError(f"no running gateway container for {desired.slot}: {method}")
    config_path = openclaw_config_path(desired.slot)
    before = read_openclaw_config(config_path)
    _prev_provider, _prev_model, previous_ref, source = current_openclaw_model(before)
    new_ref = build_model_ref(provider_raw, model)
    ok, detail = run_openclaw_models_set(container, new_ref)
    if not ok:
        raise ValueError(f"product models set failed (container={container}): {detail}")
    after = read_openclaw_config(config_path)
    diff_lines = config_json_diff(before, after)
    return str(config_path), diff_lines, previous_ref, new_ref, source, f"{container}:{method}"


def cmd_runtime_set_model(args: argparse.Namespace) -> int:
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime set-model TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    diff_lines: list[str] = []
    container = ""
    try:
        provider_raw = _assert_name(str(args.provider), _PROVIDER_RE, "provider")
        model = _assert_name(str(args.model), _MODEL_RE, "model")
        desired = _load_config_target(target, args)
        if desired.family == "openclaw":
            # openclaw: provider verbatim, ref = provider/model, applied via the product's own
            # `models set` in the live container (diff shows exactly what the product changed).
            provider = provider_raw
            provider_runtime = provider_raw
            config_path, diff_lines, previous_ref, new_ref, previous_source, container = _set_model_openclaw(
                desired, provider_raw, model
            )
        else:
            provider = runtime_provider_id(provider_raw)
            provider_runtime = provider
            config_path = hermes_config_path(desired.slot)
            config = read_hermes_config(config_path)
            previous_provider, previous_model, previous_source = current_model(config)
            previous_provider_runtime = runtime_provider_id(previous_provider) if previous_provider else ""
            previous_ref = f"{previous_provider_runtime or previous_provider or 'missing'}/{previous_model or 'missing'}"
            new_ref = f"{provider}/{model}"
            config["provider"] = provider
            current_model_value = config.get("model")
            if isinstance(current_model_value, dict):
                next_model = dict(current_model_value)
                next_model["default"] = model
                next_model["provider"] = provider
                # Drop provider-specific routing left over from the previous
                # provider. A stale base_url/api_key/api_mode (e.g. an OpenRouter
                # base_url carried onto a gemini/google provider) misroutes every
                # request to the wrong endpoint — the exact config drift that made
                # a dev slot's gemini traffic 401 against keyless OpenRouter.
                # set-model writes the canonical provider/model; a custom endpoint
                # must be configured deliberately, not silently inherited.
                for _stale_key in ("base_url", "api_key", "api_mode"):
                    next_model.pop(_stale_key, None)
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
    print(f"family={desired.family}")
    print(f"config_file={config_path}")
    print(f"exec_container={container or 'n/a'}")
    print(f"previous_model_ref={previous_ref or 'missing'}")
    print(f"previous_model_source={previous_source}")
    print(f"provider_raw={provider_raw}")
    print(f"provider={provider}")
    print(f"provider_runtime={provider_runtime}")
    print(f"model={model}")
    print(f"model_ref={new_ref}")
    for line in diff_lines:
        print(f"config_diff {line}")
    print(f"config_diff_lines={len(diff_lines)}")
    print("secret_value_printed=no")
    print("runtime_config_status=updated")
    append_action_log(
        state_root(args),
        "runtime_set_model",
        desired.slot,
        desired.slot,
        "ok",
        f"{previous_ref or 'missing'} -> {new_ref}",
    )
    return 0


def cmd_runtime_version_note(args: argparse.Namespace) -> int:
    """Operator-authored patch notes for the in-app version modal — one pen
    for BOTH families (owner rule: the mechanisms must not diverge).

    hermes:   <slot home>/.hermes/version-notes.json, entries
              [{version, date?, notes: [...]}] — one bullet per --note.
    openclaw: <slot home>/.openclaw/version-notes.json, {version: "note"}
              (the product's version-notes-store contract, single string —
              repeated --note values are joined with ", "; --date is baked
              in the OC timeline and not accepted here).

    Both are live overlays on mounted state: the product re-reads the file,
    so edits show on next modal open — no rebuild, no restart.
    """
    if not is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime version-note TARGET", file=sys.stderr)
        return 2
    target = str(args.slot)
    try:
        desired = _load_config_target(target, args)
        version = str(getattr(args, "version", "") or "")
        notes = [str(n) for n in (getattr(args, "note", None) or [])]
        date = str(getattr(args, "date", "") or "")
        clear = bool(getattr(args, "clear", False))
        if clear and not version:
            raise ValueError("--clear requires --version")
        if notes and not version:
            raise ValueError("--note requires --version")
        action = "show"

        if desired.family == "openclaw":
            if date:
                raise ValueError("openclaw notes carry no date (it comes from the baked build timeline)")
            path = openclaw_version_notes_path(desired.slot)
            oc_notes = read_openclaw_version_notes(path)
            if version and clear:
                removed = version in oc_notes
                oc_notes.pop(version, None)
                write_openclaw_version_notes(desired.slot, path, oc_notes)
                action = "cleared" if removed else "clear_noop"
            elif version:
                joined = ", ".join(n.strip() for n in notes if n.strip())
                # reuse the hermes validator for version format + length limits
                upsert_version_note([], version, [joined] if joined else [])
                oc_notes[version] = joined
                write_openclaw_version_notes(desired.slot, path, oc_notes)
                action = "written"
            print(f"target={desired.slot}")
            print(f"family={desired.family}")
            print(f"notes_file={path}")
            print(f"action={action}")
            print(f"entry_count={len(oc_notes)}")
            for entry_version in sorted(oc_notes, reverse=True):
                print(f"entry {entry_version}")
                print(f"  - {oc_notes[entry_version]}")
        else:
            path = version_notes_path(desired.slot)
            entries = read_version_notes(path)
            if version and clear:
                entries, removed = remove_version_note(entries, version)
                write_version_notes(desired.slot, path, entries)
                action = "cleared" if removed else "clear_noop"
            elif version:
                entries = upsert_version_note(entries, version, notes, date=date)
                write_version_notes(desired.slot, path, entries)
                action = "written"
            print(f"target={desired.slot}")
            print(f"family={desired.family}")
            print(f"notes_file={path}")
            print(f"action={action}")
            print(f"entry_count={len(entries)}")
            for entry in entries:
                entry_notes = entry.get("notes") or []
                print(f"entry {entry.get('version', '?')} date={entry.get('date', '-')} notes={len(entry_notes) if isinstance(entry_notes, list) else '?'}")
                if isinstance(entry_notes, list):
                    for note in entry_notes:
                        print(f"  - {note}")
    except Exception as exc:
        print(f"target={target}")
        print("runtime_version_note_status=fail")
        print(f"reason={exc}")
        try:
            append_action_log(state_root(args), "runtime_version_note", target, target, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("runtime_version_note_status=ok")
    if action in {"written", "cleared"}:
        append_action_log(
            state_root(args),
            "runtime_version_note",
            desired.slot,
            desired.slot,
            "ok",
            f"{action} {version}",
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
