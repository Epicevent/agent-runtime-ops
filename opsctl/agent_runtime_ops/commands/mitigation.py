from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.mitigations import (
    env_key_present,
    evaluate_env_mitigation,
    load_mitigations,
    new_env_mitigation,
    running_product_version,
    save_mitigations,
)
from ..routing import load_runtime_bindings


def _require_root(action: str) -> bool:
    if _is_root():
        return True
    print(f"error: run as root/admin: sudo /usr/local/bin/opsctl mitigation {action} ...", file=sys.stderr)
    return False


def cmd_mitigation_add(args: argparse.Namespace) -> int:
    if not _require_root("add"):
        return 2
    state_root = _state_root(args)
    try:
        entries = load_mitigations(state_root)
        if any(entry.get("id") == args.mitigation_id for entry in entries):
            raise ValueError(f"mitigation id already exists: {args.mitigation_id}")
        entry = new_env_mitigation(
            mitigation_id=args.mitigation_id,
            slots=list(args.slots),
            env_key=args.env_key,
            reason=args.reason,
            expires_product_version=args.expires_product_version,
        )
        entries.append(entry)
        path = save_mitigations(state_root, entries)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"mitigation_added={args.mitigation_id}")
    print(f"register_file={path}")
    return 0


def cmd_mitigation_list(args: argparse.Namespace) -> int:
    if not _require_root("list"):
        return 2
    entries = load_mitigations(_state_root(args))
    print(f"mitigation_count={len(entries)}")
    for entry in entries:
        print(
            f"mitigation id={entry.get('id')} kind={entry.get('kind')} "
            f"slots={','.join(entry.get('slots') or [])} env_key={entry.get('env_key')} "
            f"added={entry.get('added')} expires_product_version={entry.get('expires_product_version')}"
        )
    return 0


def _slot_env_path(slot: str) -> Path:
    # The compose project dir per slot; env_file: .env in the runtime profiles.
    return Path("/home") / slot / "openclaw" / ".env"


def cmd_mitigation_check(args: argparse.Namespace) -> int:
    if not _require_root("check"):
        return 2
    state_root = _state_root(args)
    entries = load_mitigations(state_root)
    only_slot = getattr(args, "slot", None)
    bindings = {binding.linux_account: binding for binding in load_runtime_bindings(state_root)}

    checked = 0
    actionable = 0
    for entry in entries:
        if entry.get("kind") != "env":
            _check_line(False, "mitigation_kind_supported", f"id={entry.get('id')} kind={entry.get('kind')}")
            actionable += 1
            continue
        key = str(entry.get("env_key") or "")
        for slot in entry.get("slots") or []:
            if only_slot and slot != only_slot:
                continue
            checked += 1
            present = env_key_present(_slot_env_path(slot), key)
            running_version = None
            probe_error = None
            if present:
                binding = bindings.get(slot)
                if binding is None:
                    probe_error = "no runtime binding"
                else:
                    try:
                        running_version = running_product_version(binding)
                    except Exception as exc:
                        probe_error = str(exc)
            status, detail = evaluate_env_mitigation(
                entry, slot, present=present, running_version=running_version, probe_error=probe_error
            )
            ok = status in ("active", "cleared")
            _check_line(ok, f"mitigation_{entry.get('id')}_{status}", detail)
            if not ok:
                actionable += 1

    print(f"mitigation_check_status={'pass' if actionable == 0 else 'fail'} checked={checked}")
    return 0 if actionable == 0 else 1


def cmd_mitigation_remove(args: argparse.Namespace) -> int:
    if not _require_root("remove"):
        return 2
    state_root = _state_root(args)
    entries = load_mitigations(state_root)
    remaining = [entry for entry in entries if entry.get("id") != args.mitigation_id]
    if len(remaining) == len(entries):
        print(f"error: unknown mitigation id: {args.mitigation_id}", file=sys.stderr)
        return 2
    save_mitigations(state_root, remaining)
    print(f"mitigation_removed={args.mitigation_id}")
    return 0
