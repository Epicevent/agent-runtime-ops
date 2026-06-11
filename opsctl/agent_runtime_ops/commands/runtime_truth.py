from __future__ import annotations

import argparse
from pathlib import Path
import sys

from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.runtime_truth import live_runtime_truth
from ..routing import load_runtime_bindings


def _print_key_values(data: dict[str, object]) -> None:
    for key, value in data.items():
        print(f"{key}={value}")


def cmd_runtime_truth(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime truth ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        all_slots = bool(getattr(args, "all", False))
        slot_arg = getattr(args, "slot", None)
        if all_slots and slot_arg:
            raise ValueError("provide either TARGET or --all, not both")
        if not all_slots and not slot_arg:
            raise ValueError("provide TARGET or --all")
        if all_slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        else:
            slots = [str(slot_arg)]
        all_ok = True
        for slot in slots:
            truth, checks = live_runtime_truth(slot, state_root)
            if len(slots) > 1:
                summary = " ".join(f"{key}={value}" for key, value in truth.items())
                print(summary)
            else:
                _print_key_values(truth)
                for ok, name, detail in checks:
                    _check_line(ok, name, detail)
            if truth.get("truth_status") != "ok":
                all_ok = False
            if any(not ok for ok, _, _ in checks):
                all_ok = False
    except Exception as exc:
        print("runtime_truth_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"runtime_truth_status={'ok' if all_ok else 'fail'} count={len(slots)}")
    return 0 if all_ok else 1


