from __future__ import annotations

from pathlib import Path

from ..host.account_files import credential_file_is_safe_for_slot, runtime_ids, slot_uid_gid
from ..host.fstab import write_managed_fstab_entry as host_write_managed_fstab_entry
from ..host.mounts import findmnt_one, mounted_child_cifs_count, safe_mountpoint_path
from ..nas import check_nas_policy


def write_managed_fstab_entry(
    slot: str,
    share: str,
    mountpoint: Path,
    credential_path: Path,
    *,
    claim_existing_same_source: bool = False,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> None:
    host_write_managed_fstab_entry(
        slot,
        share,
        mountpoint,
        credential_path,
        slot_uid_gid=slot_uid_gid,
        runtime_ids=runtime_ids,
        claim_existing_same_source=claim_existing_same_source,
        fstab_path=fstab_path,
        lock_path=lock_path,
    )


def max_mounts_allows(value: object, current_count: int) -> bool:
    if value in {None, "", "unlimited"}:
        return True
    try:
        return current_count < int(value)
    except (TypeError, ValueError):
        return False


def prepare_mount_entry(
    slot: str,
    share_source: str,
    credential_path: Path,
    state_root: Path,
    *,
    claim_existing_same_source: bool = False,
) -> tuple[object, Path]:
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    safe_mountpoint_path(decision.mountpoint)
    decision.mountpoint.mkdir(parents=True, exist_ok=True)
    safe_mountpoint_path(decision.mountpoint)
    credential_file_is_safe_for_slot(slot, credential_path)
    current_count = mounted_child_cifs_count(decision.slot)
    existing_rc, _, existing_rows = findmnt_one(decision.mountpoint)
    already_same_mount = (
        existing_rc == 0
        and bool(existing_rows)
        and existing_rows[0].get("source") == decision.share.source
    )
    if not already_same_mount and not max_mounts_allows(decision.max_mounts, current_count):
        raise ValueError(f"max_mounts_exceeded: current={current_count} max={decision.max_mounts}")
    write_managed_fstab_entry(
        decision.slot,
        decision.share.source,
        decision.mountpoint,
        credential_path,
        claim_existing_same_source=claim_existing_same_source,
    )
    return decision, decision.mountpoint
