from __future__ import annotations

from pathlib import Path
import re
import shlex
import subprocess


def _run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def decode_findmnt_value(value: str) -> str:
    def replace_hex(match: re.Match[str]) -> str:
        raw = match.group(0).encode("latin1").decode("unicode_escape").encode("latin1")
        return raw.decode("utf-8", errors="replace")

    return re.sub(r"(?:\\x[0-9A-Fa-f]{2})+", replace_hex, value)


def parse_findmnt_pairs(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        item: dict[str, str] = {}
        for part in shlex.split(line):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            item[key.lower()] = decode_findmnt_value(value)
        if item:
            rows.append(item)
    return rows


def decode_mountinfo_field(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(0)[1:], 8))

    return re.sub(r"\\[0-7]{3}", replace, value)


def mountinfo_propagation(optional_fields: list[str]) -> str:
    has_shared = any(field.startswith("shared:") for field in optional_fields)
    has_master = any(field.startswith("master:") for field in optional_fields)
    if has_shared:
        return "shared"
    if has_master:
        return "slave"
    if "unbindable" in optional_fields:
        return "unbindable"
    return "private"


def mountinfo_under(container_pid: int, path: str) -> tuple[int, str, list[dict[str, str]]]:
    mountinfo_path = Path("/proc") / str(container_pid) / "mountinfo"
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return 1, str(exc), []
    return 0, "", parse_mountinfo_lines(lines, path)


def parse_mountinfo_lines(lines: list[str], path: str) -> list[dict[str, str]]:
    root = path.rstrip("/") or "/"
    rows: list[dict[str, str]] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 3 or separator < 6:
            continue
        target = decode_mountinfo_field(fields[4])
        if target != root and not target.startswith(root + "/"):
            continue
        mount_options = fields[5]
        optional = fields[6:separator]
        fstype = fields[separator + 1]
        source = decode_mountinfo_field(fields[separator + 2])
        # Field 3 is the mount's root within its filesystem. findmnt serializes a
        # non-"/" root as SOURCE[/root] — the notation subtree binds (kw-NAS views)
        # carry. These rows are compared against host-side findmnt rows, so they
        # must serialize identically or every view slot fails the comparison.
        fs_root = decode_mountinfo_field(fields[3])
        if fs_root != "/":
            source = f"{source}[{fs_root}]"
        super_options = fields[separator + 3]
        options = ",".join(part for part in (mount_options, super_options) if part)
        rows.append(
            {
                "target": target,
                "source": source,
                "fstype": fstype,
                "options": options,
                "propagation": mountinfo_propagation(optional),
            }
        )
    return rows


def findmnt_tree(path: str, container_pid: int | None = None) -> tuple[int, str, list[dict[str, str]]]:
    if container_pid is not None:
        return mountinfo_under(container_pid, path)
    proc = _run_text(["findmnt", "-R", "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION", path])
    return proc.returncode, (proc.stderr or proc.stdout).strip(), parse_findmnt_pairs(proc.stdout)


def findmnt_under(path: str, container_pid: int | None = None) -> tuple[int, str, list[dict[str, str]]]:
    if container_pid is not None:
        return mountinfo_under(container_pid, path)
    proc = _run_text(["findmnt", "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION"])
    rows = [
        row
        for row in parse_findmnt_pairs(proc.stdout)
        if row.get("target") == path or row.get("target", "").startswith(path.rstrip("/") + "/")
    ]
    return proc.returncode, (proc.stderr or proc.stdout).strip(), rows


def findmnt_one(path: Path) -> tuple[int, str, list[dict[str, str]]]:
    proc = _run_text(["findmnt", "-M", str(path), "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION"])
    return proc.returncode, (proc.stderr or proc.stdout).strip(), parse_findmnt_pairs(proc.stdout)


def is_readonly_mount(row: dict[str, str]) -> bool:
    options = row.get("options", "")
    return "ro" in {part.strip() for part in options.split(",") if part.strip()}


def propagation_satisfies(actual: str | None, required: str | None) -> bool:
    if not required:
        return True
    value = (actual or "").lower()
    if required in {"rslave", "slave"}:
        return value in {"slave", "rslave", "shared", "rshared"}
    if required in {"rshared", "shared"}:
        return value in {"shared", "rshared"}
    return value == required


def ensure_managed_child_path(path: Path, root: Path, label: str) -> None:
    root_resolved = root.resolve(strict=False)
    path_resolved = path.resolve(strict=False)
    if path_resolved != root_resolved and root_resolved not in path_resolved.parents:
        raise ValueError(f"{label} escaped managed root: {path}")
    current = path
    checked: list[Path] = []
    while True:
        checked.append(current)
        if current == root:
            break
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(checked):
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"{label} path component must not be symlink: {candidate}")


def safe_mountpoint_path(mountpoint: Path, root: Path | None = None) -> None:
    managed_root = root or mountpoint.parents[1]
    ensure_managed_child_path(mountpoint, managed_root, "mountpoint")


def mounted_child_cifs_count(slot: str) -> int:
    home = Path("/home") / slot
    count = 0
    # corpus: read-only cifs nested under nas_docs
    nas_root = home / "nas_docs"
    rc, _, rows = findmnt_under(str(nas_root))
    if rc == 0:
        count += sum(
            1
            for row in rows
            if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(nas_root) + "/")
        )
    # OCN own-folder: a single flat cifs mount AT {home}/workspace (the mount is
    # the dir itself). Counted so max_mounts keeps its pre-split "total mounts"
    # meaning — the budget stays a root-owned nas-policy value with no code-side
    # exemption for OCN.
    ws_root = home / "workspace"
    rc_ws, _, rows_ws = findmnt_under(str(ws_root))
    if rc_ws == 0:
        count += sum(
            1
            for row in rows_ws
            if row.get("fstype") == "cifs"
            and (row.get("target") == str(ws_root) or row.get("target", "").startswith(str(ws_root) + "/"))
        )
    return count


def _mode_matches(row: dict[str, str], expect_readwrite: bool) -> bool:
    return is_readonly_mount(row) != expect_readwrite


def mount_prepared_share(decision, expect_readwrite: bool = False) -> tuple[bool, str]:
    rc, _, rows = findmnt_one(decision.mountpoint)
    if rc == 0 and rows:
        row = rows[0]
        ok = row.get("source") == decision.share.source and row.get("fstype") == "cifs" and _mode_matches(row, expect_readwrite)
        return ok, "already_mounted" if ok else "mountpoint_has_unexpected_existing_mount"

    proc = _run_text(["mount", str(decision.mountpoint)], timeout=60)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()

    rc, error, rows = findmnt_one(decision.mountpoint)
    ok = (
        rc == 0
        and bool(rows)
        and rows[0].get("source") == decision.share.source
        and rows[0].get("fstype") == "cifs"
        and _mode_matches(rows[0], expect_readwrite)
    )
    expected = "rw" if expect_readwrite else "ro"
    return ok, "ok" if ok else (error or f"mounted_state_did_not_match_expected_cifs_{expected}")
