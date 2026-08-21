from __future__ import annotations

from pathlib import Path

from ..host.fstab import (
    remove_managed_workspace_bind_entry,
    write_managed_workspace_bind_entry,
)
from ..host.mounts import bind_mount, findmnt_one, findmnt_under, simple_umount
from ..nas import nas_rw_root, parse_cifs_mount_source, share_is_writable, workspace_root
from .workspace_probe import workspace_local_entry_count


def rw_cifs_mounts(slot: str) -> list[dict[str, str]]:
    root = nas_rw_root(slot)
    rc, _, rows = findmnt_under(str(root))
    if rc != 0:
        return []
    return [
        row
        for row in rows
        if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")
    ]


def choose_workspace_assignment(rw_rows: list[dict[str, str]]) -> tuple[str, str | None]:
    """Pure decision: what should the workspace show?

    - one writable mount   -> ("assign", its mountpoint): nothing to choose
    - none                 -> ("clear", None): workspace shows the empty dir
    - two or more          -> ("manual", None): somebody must pick — this is
      the seam the slot-assignment web will drive via `nas workspace-assign`.
    """
    if len(rw_rows) == 1:
        return "assign", rw_rows[0].get("target") or None
    if not rw_rows:
        return "clear", None
    return "manual", None


def _workspace_current_row(slot: str) -> dict[str, str] | None:
    rc, _, rows = findmnt_one(workspace_root(slot))
    if rc != 0 or not rows:
        return None
    return rows[0]


def workspace_bound_source(slot: str) -> str:
    """The share the workspace currently shows, or "none". The bind's SOURCE
    in the mount table is the underlying //host/share — the identity the
    assignment ledger speaks, so consumers compare it directly."""
    row = _workspace_current_row(slot)
    if row is None:
        return "none"
    return row.get("source") or "none"


def workspace_status_row(
    slot: str,
    rw_rows: list[dict[str, str]],
    bound_source: str,
    stamped_bind: bool,
) -> dict[str, object]:
    """One slot's live workspace reality, shaped for the fleet readout."""
    return {
        "slot": slot,
        "bound_to": bound_source or "none",
        "rw_sources": [row.get("source", "") for row in rw_rows],
        "stamp_bind": stamped_bind,
    }


def workspace_status_has_signal(row: dict[str, object]) -> bool:
    """Whether an UNSTAMPED candidate earns a line. Stamped slots always get
    one — a stamp with nothing live is itself the drift worth showing."""
    return row["bound_to"] != "none" or bool(row["rw_sources"]) or bool(row["stamp_bind"])


def _release_workspace(slot: str, row: dict[str, str]) -> tuple[bool, str]:
    """Unmount whatever view currently sits at the workspace.

    Only a view of a writable-class (OCn) share may be replaced — a bind and
    the cifs mount itself are indistinguishable in the mount table, and both
    are safe to drop (the data lives on the NAS; the real mount, if any,
    stays under nas_rw). Anything else at this path is not ours to touch.
    """
    source = row.get("source") or ""
    try:
        share, _subpath = parse_cifs_mount_source(source)
        if not share_is_writable(share):
            return False, f"workspace_holds_non_writable_source={source}"
    except ValueError:
        return False, f"workspace_holds_unknown_source={source}"
    ok, detail = simple_umount(workspace_root(slot))
    if not ok:
        return False, f"workspace_busy_or_umount_failed={detail}"
    return True, "released"


def assign_workspace_bind(slot: str, source_mountpoint: Path) -> tuple[bool, str]:
    """Point the workspace at one writable mount: live bind + fstab stamp."""
    root = nas_rw_root(slot)
    resolved = source_mountpoint.resolve(strict=False)
    if root.resolve(strict=False) not in resolved.parents:
        return False, f"assign_source_outside_nas_rw={source_mountpoint}"
    rc, _, src_rows = findmnt_one(source_mountpoint)
    if rc != 0 or not src_rows or src_rows[0].get("fstype") != "cifs":
        return False, f"assign_source_not_mounted={source_mountpoint}"
    target = workspace_root(slot)
    current = _workspace_current_row(slot)
    if current is None:
        try:
            hidden_count = workspace_local_entry_count(target)
        except OSError as exc:
            return False, f"workspace_local_preflight_failed errno={exc.errno}"
        if hidden_count:
            return False, f"workspace_local_data_present count={hidden_count}"
    if current is not None:
        if current.get("source") == src_rows[0].get("source"):
            write_managed_workspace_bind_entry(slot, source_mountpoint, target)
            return True, f"already_bound source={current.get('source')}"
        released, release_detail = _release_workspace(slot, current)
        if not released:
            return False, release_detail
    ok, detail = bind_mount(source_mountpoint, target)
    if not ok:
        return False, f"bind_mount_failed={detail}"
    write_managed_workspace_bind_entry(slot, source_mountpoint, target)
    return True, f"bound source={src_rows[0].get('source')} mountpoint={source_mountpoint}"


def clear_workspace_bind(slot: str) -> tuple[bool, str]:
    current = _workspace_current_row(slot)
    if current is not None:
        released, release_detail = _release_workspace(slot, current)
        if not released:
            return False, release_detail
    removed = remove_managed_workspace_bind_entry(slot)
    return True, f"cleared fstab_bind_removed={'yes' if removed else 'no'}"


def reconcile_workspace_bind(slot: str) -> tuple[bool, str]:
    """Keep the workspace pointing at the right writable mount.

    Called after any mount/unmount/remove of a writable share. With exactly
    one writable mount there is nothing to decide, so the tool binds it; with
    none it clears; with several it does NOT guess — explicit
    `nas workspace-assign` (the slot-assignment web's entry point) decides.
    """
    action, mountpoint = choose_workspace_assignment(rw_cifs_mounts(slot))
    if action == "assign" and mountpoint:
        ok, detail = assign_workspace_bind(slot, Path(mountpoint))
        return ok, f"auto_assign {detail}"
    if action == "clear":
        ok, detail = clear_workspace_bind(slot)
        return ok, f"auto_clear {detail}"
    return True, "manual_assign_required multiple_rw_mounts"
