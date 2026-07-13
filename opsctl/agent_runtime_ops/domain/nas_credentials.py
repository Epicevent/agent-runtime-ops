from __future__ import annotations

from pathlib import Path

from ..host.account_files import (
    credential_file_is_safe_for_slot,
    credential_presence,
    read_key_value_file,
    slot_uid_gid,
    write_credential_file,
)
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


def migrate_customer_credential_to_root(slot: str, share) -> bool:
    """Heal a pre-fix corpus credential: move a slot-home (customer-readable) copy
    into the root vault (root:root 0600) and delete the customer copy.

    Corpus creds must never be slot-readable; earlier builds wrote them under the
    customer home. Migrating keeps the same secret (no password re-entry) while
    closing the exposure. Guarantees no customer-readable copy remains afterward.
    Returns True only when it moved the secret into the vault; returns False when
    there was nothing to migrate (no customer copy) or the vault was already
    authoritative — in the latter case the redundant exposed copy is still removed.
    Callers must only invoke this for corpus shares (customer-readable == wrong)."""
    paths = official_credential_paths(slot, share)
    src, dst = paths["customer"], paths["root"]
    if credential_presence(src) != "yes":
        return False
    if credential_presence(dst) == "yes":
        # Vault already authoritative — clear the redundant customer-readable copy.
        src.unlink()
        return False
    data = read_key_value_file(src)
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        raise ValueError(f"legacy credential missing username/password: {src}")
    write_credential_file(dst, username, password, data.get("domain") or None, 0, 0)
    src.unlink()
    return True
