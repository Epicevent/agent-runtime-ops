from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil


def fstab_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "")


def fstab_unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 3 < len(value) + 1:
            chunk = value[i + 1 : i + 4]
            if chunk == "040":
                out.append(" ")
                i += 4
                continue
            if chunk == "011":
                out.append("\t")
                i += 4
                continue
            if value[i : i + 2] == "\\\\":
                out.append("\\")
                i += 2
                continue
        out.append(value[i])
        i += 1
    return "".join(out)


_MARKER_RE = re.compile(r"^# agent-runtime-ops nas slot=(?P<slot>\S+) source=(?P<source>.+)$")


def read_managed_fstab_entries(fstab_path: Path = Path("/etc/fstab")) -> list[dict[str, str]]:
    """Parse the managed (marker + entry) pairs this tool stamped into fstab.

    Returns one dict per entry: slot, source (from the marker — the ledger
    key), mountpoint, access ("rw"/"ro" from the options), credentials path
    (empty if absent). The marker is the key; the entry line is the stamped
    value — exactly the pair the drift check compares against today's
    derivation.
    """
    if not fstab_path.exists():
        return []
    lines = fstab_path.read_text(encoding="utf-8").splitlines()
    entries: list[dict[str, str]] = []
    for index, line in enumerate(lines):
        match = _MARKER_RE.match(line)
        if not match or index + 1 >= len(lines):
            continue
        columns = lines[index + 1].split()
        if len(columns) < 4:
            continue
        options = columns[3].split(",")
        credentials = ""
        for part in options:
            if part.startswith("credentials="):
                credentials = fstab_unescape(part.split("=", 1)[1])
        entries.append(
            {
                "slot": match.group("slot"),
                "source": match.group("source"),
                "mountpoint": fstab_unescape(columns[1]),
                "access": "rw" if "rw" in options else "ro",
                "credentials": credentials,
            }
        )
    return entries


def managed_fstab_marker(slot: str, share: str) -> str:
    return f"# agent-runtime-ops nas slot={slot} source={share}"


def _lock_exclusive(lock_handle) -> None:
    try:
        import fcntl

        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
    except ImportError:
        pass


def _fsync_parent(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup_fstab(fstab_path: Path) -> Path | None:
    if not fstab_path.exists():
        return None
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    backup = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.bak.{stamp}")
    suffix = 1
    while backup.exists():
        suffix += 1
        backup = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.bak.{stamp}.{suffix}")
    shutil.copy2(fstab_path, backup)
    return backup


def _replace_fstab(fstab_path: Path, text: str) -> None:
    tmp = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, fstab_path)
    _fsync_parent(fstab_path)


def write_managed_fstab_entry(
    slot: str,
    share: str,
    mountpoint: Path,
    credential_path: Path,
    *,
    slot_uid_gid: Callable[[str], tuple[int, int]],
    runtime_ids: Callable[[str], tuple[int, int, int]],
    claim_existing_same_source: bool = False,
    read_write: bool = False,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> None:
    slot_uid, _ = slot_uid_gid(slot)
    _, _, data_gid = runtime_ids(slot)
    escaped_target = fstab_escape(str(mountpoint))
    escaped_source = fstab_escape(share)
    access = "rw" if read_write else "ro"
    # rw (OCn own-folder): the WRITER is the container runtime user, which is a
    # member of {slot}_data (compose group_add) — not the slot owner uid. So the
    # group needs write, or the agent can only read its own workspace (measured
    # on oc2: runtime uid=994 got EACCES under 0750/0640 while owner and root
    # wrote fine). ro (corpus) stays group-read-only.
    file_mode = "0660" if read_write else "0440"
    dir_mode = "0770" if read_write else "0550"
    options = ",".join(
        [
            f"credentials={fstab_escape(str(credential_path))}",
            access,
            "nosuid",
            "nodev",
            "vers=3.1.1",
            "iocharset=utf8",
            "noserverino",
            f"uid={slot_uid}",
            "forceuid",
            f"gid={data_gid}",
            "forcegid",
            f"file_mode={file_mode}",
            f"dir_mode={dir_mode}",
            "soft",
            "nofail",
            "_netdev",
        ]
    )
    marker = managed_fstab_marker(slot, share)
    entry = f"{escaped_source} {escaped_target} cifs {options} 0 0"

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        _lock_exclusive(lock_handle)
        lines = fstab_path.read_text(encoding="utf-8").splitlines() if fstab_path.exists() else []
        new_lines: list[str] = []
        skip_next = False
        replaced = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                skip_next = True
                if not replaced:
                    new_lines.extend([marker, entry])
                    replaced = True
                continue
            columns = line.split()
            if columns and not line.lstrip().startswith("#") and len(columns) >= 2 and columns[1] == escaped_target:
                if claim_existing_same_source and len(columns) >= 3 and columns[0] == escaped_source and columns[2] == "cifs":
                    new_lines.append("# disabled by agent-runtime-ops nas claim: " + line)
                    continue
                raise ValueError(f"non-managed fstab entry already owns mountpoint: {mountpoint}")
            new_lines.append(line)
        if not replaced:
            if new_lines and new_lines[-1] != "":
                new_lines.append("")
            new_lines.extend([marker, entry])
        _backup_fstab(fstab_path)
        _replace_fstab(fstab_path, "\n".join(new_lines) + "\n")


def remove_managed_fstab_entry(
    slot: str,
    share: str,
    *,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> bool:
    marker = managed_fstab_marker(slot, share)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        _lock_exclusive(lock_handle)
        lines = fstab_path.read_text(encoding="utf-8").splitlines() if fstab_path.exists() else []
        new_lines: list[str] = []
        removed = False
        skip_next = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                removed = True
                skip_next = True
                continue
            new_lines.append(line)
        if not removed:
            return False
        _backup_fstab(fstab_path)
        _replace_fstab(fstab_path, "\n".join(new_lines) + "\n")
        return True
