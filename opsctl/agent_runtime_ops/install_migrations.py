from __future__ import annotations

import argparse
import os
from pathlib import Path

from .domain.runtime_backup import (
    import_legacy_agent_runtime_backups,
    runtime_transaction_lock,
)
from .domain.runtime_paths import legacy_agent_backup_root, slot_runtime_dir
from .routing import load_runtime_bindings


def migrate_legacy_runtime_backups(state_root: Path) -> tuple[int, int]:
    bindings_path = state_root / "runtime-bindings.json"
    if not bindings_path.exists() and not bindings_path.is_symlink():
        print("legacy_runtime_backup_migration=skipped reason=runtime_bindings_absent")
        return 0, 0
    # Older server state included observed upstream fields in declarations.
    # They are ignored only during this one-way install migration; normal
    # callers retain strict schema validation.
    bindings = load_runtime_bindings(state_root, allow_legacy_fields=True)
    observed = 0
    imported = 0
    for binding in bindings:
        candidate_runtime_dir = Path("/home") / binding.linux_account / "openclaw"
        legacy_root = legacy_agent_backup_root(candidate_runtime_dir)
        try:
            legacy_root.lstat()
        except FileNotFoundError:
            continue
        runtime_dir = slot_runtime_dir(binding.linux_account)
        observed += 1
        with runtime_transaction_lock(state_root, binding.linux_account):
            imported_paths = import_legacy_agent_runtime_backups(
                binding.linux_account,
                runtime_dir,
                state_root,
            )
        imported += len(imported_paths)
        print(
            "legacy_runtime_backup_target="
            f"{binding.linux_account} observed=yes imported={len(imported_paths)}"
        )
    print(
        "legacy_runtime_backup_migration=complete "
        f"targets_observed={observed} backups_imported={imported}"
    )
    return observed, imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args(argv)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        parser.error("legacy runtime backup migration must run as root")
    migrate_legacy_runtime_backups(args.state_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
