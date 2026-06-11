from __future__ import annotations

from pathlib import Path

from ..host.account_files import credential_file_is_safe_for_slot, credential_presence, slot_uid_gid
from ..nas import customer_credential_path, root_credential_path


def official_credential_paths(slot: str, share) -> dict[str, Path]:
    return {
        "root": root_credential_path(slot, share),
        "customer": customer_credential_path(slot, share),
    }


def combine_credential_presence(*values: str) -> str:
    if "yes" in values:
        return "yes"
    if "unknown" in values:
        return "unknown"
    return "no"


def official_credential_status(slot: str, share) -> dict[str, str]:
    paths = official_credential_paths(slot, share)
    root_present = credential_presence(paths["root"])
    customer_present = credential_presence(paths["customer"])
    official_present = combine_credential_presence(root_present, customer_present)
    return {
        "root_credential_present": root_present,
        "customer_credential_present": customer_present,
        "official_credential_present": official_present,
        "remount_possible": "yes" if official_present == "yes" else official_present,
    }


def validate_official_credentials_for_delete(slot: str, share) -> None:
    paths = official_credential_paths(slot, share)
    slot_uid, _ = slot_uid_gid(slot)
    for name, path in paths.items():
        if credential_presence(path) == "yes":
            credential_file_is_safe_for_slot(slot, path, uid=0 if name == "root" else slot_uid)


def delete_official_credentials(slot: str, share) -> dict[str, str]:
    paths = official_credential_paths(slot, share)
    removed: dict[str, str] = {}
    for name, path in paths.items():
        if credential_presence(path) == "yes":
            path.unlink()
            removed[f"{name}_credential_removed"] = "yes"
        else:
            removed[f"{name}_credential_removed"] = "no"
    return removed
