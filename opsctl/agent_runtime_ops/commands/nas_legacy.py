from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.nas_legacy import legacy_fstab_entries, remove_fstab_lines
from ..host.fstab import _backup_fstab, _lock_exclusive, _replace_fstab
from ..host.mounts import findmnt_one as _findmnt_one
from ..nas import parse_smb_share, root_credential_path
from ..routing import validate_linux_account

FSTAB_PATH = Path("/etc/fstab")
FSTAB_LOCK_PATH = Path("/run/agent-runtime-ops-fstab.lock")


def _read_fstab() -> str:
    try:
        return FSTAB_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""


def _require_root(command: str) -> bool:
    if _is_root():
        return True
    print(f"error: run as root/admin: sudo /usr/local/bin/opsctl nas legacy {command} ...", file=sys.stderr)
    return False


def _matching_entries(slot: str, share_source: str, fstab_text: str):
    return [
        entry
        for entry in legacy_fstab_entries(fstab_text)
        if entry.slot == slot and parse_smb_share(entry.share).source == share_source
    ]


def cmd_nas_legacy_status(args: argparse.Namespace) -> int:
    entries = sorted(legacy_fstab_entries(_read_fstab()), key=lambda e: (e.slot, e.share))
    print(f"legacy_entry_count={len(entries)}")
    print("mutates=false")
    print("secret_value_printed=no")
    for index, entry in enumerate(entries, start=1):
        prefix = f"legacy_{index}"
        print(f"{prefix}_target_slot={entry.slot}")
        print(f"{prefix}_share={entry.share}")
        print(f"{prefix}_mount_target={entry.target}")
        print(f"{prefix}_noauto={'yes' if entry.noauto else 'no'}")
        rc, _, rows = _findmnt_one(Path(entry.target))
        print(f"{prefix}_mounted={'yes' if rc == 0 and rows else 'no'}")
        if _is_root():
            declared_present = bool(entry.credential_path) and Path(entry.credential_path).exists()
            print(f"{prefix}_declared_credential_present={'yes' if declared_present else 'no'}")
            try:
                official = root_credential_path(entry.slot, parse_smb_share(entry.share))
                print(f"{prefix}_official_root_credential_present={'yes' if official.exists() else 'no'}")
            except ValueError:
                print(f"{prefix}_official_root_credential_present=unknown")
        else:
            print(f"{prefix}_declared_credential_present=unknown_requires_root")
    print("legacy_status=ok")
    return 0


def cmd_nas_legacy_adopt(args: argparse.Namespace) -> int:
    if not _require_root("adopt"):
        return 2
    state_root = _state_root(args)
    try:
        slot = validate_linux_account(args.slot)
        share = parse_smb_share(args.share)
        entries = _matching_entries(slot, share.source, _read_fstab())
        if not entries:
            raise ValueError("legacy_entry_not_found")
        destination = root_credential_path(slot, share)
        if destination.exists():
            promotion = "already_official"
        else:
            declared = {entry.credential_path for entry in entries if entry.credential_path}
            if not declared:
                raise ValueError("no_declared_credential_in_fstab")
            if len(declared) > 1:
                raise ValueError(f"ambiguous_declared_credentials:{sorted(declared)}")
            source_path = Path(next(iter(declared)))
            if not source_path.exists():
                raise ValueError(f"declared_credential_missing:{source_path}")
            # Promote the file as-is: the value is never read into this
            # process's output — copy, then clamp to root-only.
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination)
            os.chmod(destination, 0o600)
            os.chmod(destination.parent, 0o700)
            if hasattr(os, "chown"):
                os.chown(destination, 0, 0)
            promotion = "promoted"
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("adopt_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "nas_legacy_adopt", args.slot, args.share, "fail", str(exc))
        return 1
    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"official_credential={destination}")
    print(f"credential_promotion={promotion}")
    print("secret_value_printed=no")
    print("adopt_status=ok")
    print(f"next=sudo /usr/local/bin/opsctl nas mount {slot} {share.source}")
    _append_action_log(state_root, "nas_legacy_adopt", slot, share.source, "ok", promotion)
    return 0


def cmd_nas_legacy_retire(args: argparse.Namespace) -> int:
    if not _require_root("retire"):
        return 2
    state_root = _state_root(args)
    try:
        slot = validate_linux_account(args.slot)
        share = parse_smb_share(args.share)
        FSTAB_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        FSTAB_LOCK_PATH.touch(exist_ok=True)
        with FSTAB_LOCK_PATH.open("r+") as lock_handle:
            _lock_exclusive(lock_handle)
            fstab_text = _read_fstab()
            entries = _matching_entries(slot, share.source, fstab_text)
            if not entries:
                raise ValueError("legacy_entry_not_found")
            for entry in entries:
                rc, _, rows = _findmnt_one(Path(entry.target))
                if rc == 0 and rows:
                    raise ValueError(f"still_mounted:{entry.target} — unmount first: opsctl nas unmount {slot} {share.source}")
            _backup_fstab(FSTAB_PATH)
            _replace_fstab(FSTAB_PATH, remove_fstab_lines(fstab_text, {entry.line_number for entry in entries}))
        credentials_deleted = 0
        if args.delete_credential:
            for path_text in sorted({entry.credential_path for entry in entries if entry.credential_path}):
                path = Path(path_text)
                if path.exists():
                    path.unlink()
                    credentials_deleted += 1
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("retire_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "nas_legacy_retire", args.slot, args.share, "fail", str(exc))
        return 1
    print(f"target={slot}")
    print(f"share={share.source}")
    print(f"fstab_entries_removed={len(entries)}")
    print(f"legacy_credentials_deleted={credentials_deleted if args.delete_credential else 'not_requested'}")
    print("secret_value_printed=no")
    print("retire_status=ok")
    _append_action_log(state_root, "nas_legacy_retire", slot, share.source, "ok", f"entries={len(entries)}")
    return 0
