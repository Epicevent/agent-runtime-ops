"""Read-only bind mounts for NAS slot views."""

from __future__ import annotations

import json
import os
import select
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .mounts import _run_text, findmnt_one, findmnt_under, parse_findmnt_pairs


def _is_safe_view_mount(row: dict[str, str]) -> bool:
    options = {part.strip() for part in row.get("options", "").split(",") if part.strip()}
    return {"ro", "nosuid", "nodev"}.issubset(options)


def _reject_existing_symlink_components(path: Path, label: str) -> None:
    current = Path(path.anchor) if path.is_absolute() else Path()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label}_path_symlink:{current}")


def _path_identity(info) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _grant_identity(info) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        stat.S_IMODE(info.st_mode),
    )


_PROBE_PAYLOAD_MAX_BYTES = 32 * 1024
_MOUNT_INVENTORY_MAX_TARGETS = 65  # entry root plus 64 admitted grant paths
_MOUNT_INVENTORY_MAX_TARGET_CHARS = 640  # 512-char alias plus canonical root
_MOUNT_INVENTORY_PAYLOAD_MAX_BYTES = (
    4096
    + _MOUNT_INVENTORY_MAX_TARGETS * _MOUNT_INVENTORY_MAX_TARGET_CHARS * 4
)


def _stop_probe_pid(pid: int) -> None:
    """Best-effort terminate/reap without registering an interpreter finalizer."""
    try:
        if os.getpgid(pid) == pid:
            os.killpg(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass


def _run_isolated_json_probe(
    probe: Callable[[], Any],
    timeout: float,
    *,
    max_payload_bytes: int = _PROBE_PAYLOAD_MAX_BYTES,
) -> tuple[Any | None, str | None]:
    """Run a content-free probe under a hard parent deadline.

    A raw fork is intentionally used instead of multiprocessing: if a child is
    stuck in uninterruptible I/O after SIGKILL, no Python finalizer can join it
    and defeat the caller's wall-clock bound.
    """
    if os.name != "posix" or timeout <= 0:
        return None, "probe_unavailable"
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        return None, "probe_unavailable"
    if pid == 0:
        try:
            os.close(read_fd)
            os.setsid()
            try:
                value = probe()
                envelope = {"ok": True, "value": value}
            except BaseException:
                envelope = {"ok": False}
            payload = json.dumps(
                envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            if len(payload) > max_payload_bytes:
                payload = b'{"ok":false}'
            offset = 0
            while offset < len(payload):
                offset += os.write(write_fd, payload[offset:])
        except BaseException:
            pass
        finally:
            try:
                os.close(write_fd)
            except OSError:
                pass
            os._exit(0)
    os.close(write_fd)
    os.set_blocking(read_fd, False)
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    total = 0
    gap = "probe_unavailable"
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                gap = "probe_timeout"
                return None, gap
            try:
                ready, _, _ = select.select([read_fd], [], [], remaining)
            except OSError:
                return None, gap
            if not ready:
                gap = "probe_timeout"
                return None, gap
            try:
                chunk = os.read(read_fd, 8192)
            except OSError:
                return None, gap
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_payload_bytes:
                return None, gap
        try:
            envelope = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, gap
        if not isinstance(envelope, dict):
            return None, gap
        if set(envelope) == {"ok"} and envelope.get("ok") is False:
            return None, gap
        if set(envelope) != {"ok", "value"} or envelope.get("ok") is not True:
            return None, gap
        return envelope["value"], None
    finally:
        os.close(read_fd)
        _stop_probe_pid(pid)


def _open_directory_nofollow(path: Path) -> int:
    """Open every path component without following links; caller closes the fd."""
    if not path.is_absolute():
        raise ValueError(f"grant_path_not_absolute:{path}")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("nofollow_directory_open_unavailable")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = os.O_NOFOLLOW
    current = os.open(path.anchor, flags | nofollow)
    try:
        for part in path.parts[1:]:
            following = os.open(part, flags | nofollow, dir_fd=current)
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _slot_account_identity(slot: str) -> tuple[int, int]:
    import pwd

    account = pwd.getpwnam(slot)
    return int(account.pw_uid), int(account.pw_gid)


def _probe_slot_access(slot: str, entry: Path, flag: str, timeout: float) -> tuple[bool | None, str | None]:
    mode = {"-x": "x", "-r": "r"}.get(flag)
    if mode is None:
        return None, "probe_unavailable"
    code = (
        "import os,sys;"
        "m={'x':os.X_OK,'r':os.R_OK}[sys.argv[1]];"
        "print('allow' if os.access(sys.argv[2],m) else 'deny')"
    )
    try:
        proc = _run_text(
            [
                "/usr/sbin/runuser", "-u", slot, "--", "/usr/bin/python3", "-I", "-c",
                code, mode, entry.as_posix(),
            ],
            timeout=max(0.1, timeout),
        )
    except subprocess.TimeoutExpired:
        return None, "probe_timeout"
    except OSError:
        return None, "probe_unavailable"
    if proc.returncode != 0:
        return None, "probe_unavailable"
    observed = proc.stdout.strip()
    if observed == "allow":
        return True, None
    if observed == "deny":
        return False, None
    return None, "probe_unavailable"


def _findmnt_exact(entry: Path, timeout: float) -> tuple[int, list[dict[str, str]]]:
    proc = _run_text(
        [
            "/usr/bin/findmnt",
            "-M",
            entry.as_posix(),
            "-P",
            "-o",
            "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION",
        ],
        timeout=max(0.1, timeout),
    )
    return proc.returncode, parse_findmnt_pairs(proc.stdout)


def _observe_mount_targets_under_core(entry_root: Path, timeout: float) -> list[str]:
    proc = _run_text(
        [
            "/usr/bin/findmnt", "-R", "-M", entry_root.as_posix(), "-P", "-o", "TARGET",
        ],
        timeout=max(0.1, timeout),
    )
    if proc.returncode == 1 and not proc.stdout.strip():
        return []
    if proc.returncode != 0:
        raise OSError("mount_inventory_failed")
    rows = parse_findmnt_pairs(proc.stdout)
    targets = [row.get("target", "") for row in rows]
    prefix = entry_root.as_posix().rstrip("/") + "/"
    if (
        not targets
        or any(not target or (target != entry_root.as_posix() and not target.startswith(prefix)) for target in targets)
        or len(targets) != len(set(targets))
    ):
        raise ValueError("mount_inventory_invalid")
    return sorted(targets)


def observe_mount_targets_under(entry_root: Path, timeout: float) -> tuple[set[str] | None, str | None]:
    """Return exact mounted targets under a hard wall-clock supervisor."""
    value, gap = _run_isolated_json_probe(
        lambda: _observe_mount_targets_under_core(entry_root, timeout),
        timeout,
        max_payload_bytes=_MOUNT_INVENTORY_PAYLOAD_MAX_BYTES,
    )
    if gap is not None:
        return None, gap
    if (
        not isinstance(value, list)
        or any(not isinstance(target, str) for target in value)
        or len(value) > _MOUNT_INVENTORY_MAX_TARGETS
        or any(
            len(target) > _MOUNT_INVENTORY_MAX_TARGET_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in target)
            for target in value
        )
        or len(value) != len(set(value))
    ):
        return None, "probe_unavailable"
    return set(value), None


def _empty_grant_item(entry: Path) -> dict[str, Any]:
    return {
        "path": "",
        "entry_path": entry.as_posix(),
        "mount_exact": False,
        "mount_readonly": False,
        "mount_safe_options": False,
        "source_identity_match": False,
        "source_uid": None,
        "source_gid": None,
        "source_mode": None,
        "entry_uid": None,
        "entry_gid": None,
        "entry_mode": None,
        "account_uid": None,
        "account_gid": None,
        "account_traverse": None,
        "account_read": None,
        "issues": [],
        "gaps": [],
    }


def _observe_ro_view_grant_core(
    source: Path,
    entry: Path,
    slot: str,
    *,
    allow_account_probe: bool,
    timeout: float,
) -> tuple[dict[str, Any], bool, bool]:
    """Probe one grant in an isolated worker without reading directory contents."""
    item = _empty_grant_item(entry)
    issues: list[str] = item["issues"]
    gaps: list[str] = item["gaps"]
    source_fd = entry_fd = source_after_fd = entry_after_fd = None
    source_before = entry_before = None
    baseline_rc = -1
    baseline_rows: list[dict[str, str]] = []
    complete = True
    deadline = time.monotonic() + max(0.1, timeout)
    try:
        source_fd = _open_directory_nofollow(source)
        entry_fd = _open_directory_nofollow(entry)
        source_before = os.fstat(source_fd)
        entry_before = os.fstat(entry_fd)
        item.update({
            "source_uid": int(source_before.st_uid),
            "source_gid": int(source_before.st_gid),
            "source_mode": f"{stat.S_IMODE(source_before.st_mode):04o}",
            "entry_uid": int(entry_before.st_uid),
            "entry_gid": int(entry_before.st_gid),
            "entry_mode": f"{stat.S_IMODE(entry_before.st_mode):04o}",
        })
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("grant_metadata", timeout)
        try:
            rc, rows = _findmnt_exact(entry, remaining)
        except subprocess.TimeoutExpired:
            gaps.append("probe_timeout")
            complete = False
            rc, rows = -1, []
        except OSError:
            gaps.append("probe_unavailable")
            complete = False
            rc, rows = -1, []
        if rc not in {-1, 0, 1} or (rc == 0 and not rows):
            gaps.append("probe_unavailable")
            complete = False
            rc, rows = -1, []
        baseline_rc, baseline_rows = rc, rows
        exact_rows = [row for row in rows if row.get("target") == entry.as_posix()]
        item["mount_exact"] = rc == 0 and len(exact_rows) == 1
        if item["mount_exact"]:
            row = exact_rows[0]
            options = {part.strip() for part in row.get("options", "").split(",") if part.strip()}
            item["mount_readonly"] = "ro" in options
            item["mount_safe_options"] = {"ro", "nosuid", "nodev"}.issubset(options)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("grant_metadata", timeout)
        source_after_fd = _open_directory_nofollow(source)
        entry_after_fd = _open_directory_nofollow(entry)
        source_after = os.fstat(source_after_fd)
        entry_after = os.fstat(entry_after_fd)
        try:
            rc_after, rows_after = _findmnt_exact(entry, remaining)
        except subprocess.TimeoutExpired:
            gaps.append("probe_timeout")
            complete = False
            rc_after, rows_after = -1, []
        except OSError:
            gaps.append("probe_unavailable")
            complete = False
            rc_after, rows_after = -1, []
        if rc_after != rc or rows_after != rows:
            gaps.append("probe_unavailable")
            complete = False
        item["source_identity_match"] = (
            _grant_identity(source_before) == _grant_identity(source_after)
            and _grant_identity(entry_before) == _grant_identity(entry_after)
            and _grant_identity(source_after) == _grant_identity(entry_after)
        )
    except FileNotFoundError:
        issues.append("path_missing")
        complete = False
    except subprocess.TimeoutExpired:
        gaps.append("probe_timeout")
        complete = False
    except (OSError, ValueError):
        issues.append("metadata_invalid")
        complete = False
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if entry_fd is not None:
            os.close(entry_fd)
        if source_after_fd is not None:
            os.close(source_after_fd)
        if entry_after_fd is not None:
            os.close(entry_after_fd)

    if complete:
        if not item["mount_exact"]:
            issues.append("path_not_mounted")
        elif not item["mount_readonly"]:
            issues.append("path_not_readonly")
        if item["mount_exact"] and not item["mount_safe_options"]:
            issues.append("mount_safe_options_missing")
        if not item["source_identity_match"]:
            issues.append("source_identity_mismatch")

    try:
        account_uid, account_gid = _slot_account_identity(slot)
        item["account_uid"] = account_uid
        item["account_gid"] = account_gid
    except (ImportError, KeyError, OSError):
        issues.append("account_not_found")
        complete = False

    if item["account_uid"] is not None:
        if not allow_account_probe:
            gaps.append("account_probe_requires_root")
            complete = False
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                traverse, traverse_gap = None, "probe_timeout"
            else:
                traverse, traverse_gap = _probe_slot_access(slot, entry, "-x", remaining)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                read, read_gap = None, "probe_timeout"
            else:
                read, read_gap = _probe_slot_access(slot, entry, "-r", remaining)
            item["account_traverse"] = traverse
            item["account_read"] = read
            for gap in (traverse_gap, read_gap):
                if gap is not None:
                    gaps.append(gap)
                    complete = False
            if traverse is False:
                issues.append("account_traverse_denied")
            if read is False:
                issues.append("account_read_denied")

    # Access is pathname-based. Re-open and re-read after both account probes
    # so uid/gid/mode, inode identity, and exact mount options all belong to the
    # same final state as the reported allow/deny decisions.
    if source_before is not None and entry_before is not None:
        final_source_fd = final_entry_fd = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("grant_final_coherence", timeout)
            final_source_fd = _open_directory_nofollow(source)
            final_entry_fd = _open_directory_nofollow(entry)
            final_source = os.fstat(final_source_fd)
            final_entry = os.fstat(final_entry_fd)
            final_rc, final_rows = _findmnt_exact(entry, remaining)
            if (
                _grant_identity(source_before) != _grant_identity(final_source)
                or _grant_identity(entry_before) != _grant_identity(final_entry)
                or final_rc != baseline_rc
                or final_rows != baseline_rows
            ):
                item["source_identity_match"] = False
                issues.append("source_identity_mismatch")
                gaps.append("probe_unavailable")
                complete = False
            elif _grant_identity(final_source) != _grant_identity(final_entry):
                # A stable wrong-source bind is fully observed but unhealthy;
                # incompleteness is reserved for state that changed mid-probe.
                item["source_identity_match"] = False
        except subprocess.TimeoutExpired:
            gaps.append("probe_timeout")
            complete = False
        except (OSError, ValueError):
            gaps.append("probe_unavailable")
            complete = False
        finally:
            if final_source_fd is not None:
                os.close(final_source_fd)
            if final_entry_fd is not None:
                os.close(final_entry_fd)

    item["issues"] = sorted(set(issues))
    item["gaps"] = sorted(set(gaps))
    green = complete and not item["issues"] and not item["gaps"] and all(
        item[field] is True
        for field in (
            "mount_exact",
            "mount_readonly",
            "mount_safe_options",
            "source_identity_match",
            "account_traverse",
            "account_read",
        )
    )
    return item, complete, green


def observe_ro_view_grant(
    source: Path,
    entry: Path,
    slot: str,
    *,
    allow_account_probe: bool,
    timeout: float,
) -> tuple[dict[str, Any], bool, bool]:
    """Return one content-free grant observation within a hard wall-clock bound."""
    item = _empty_grant_item(entry)
    if os.name != "posix" or timeout <= 0:
        item["gaps"] = ["probe_unavailable"]
        return item, False, False

    def probe() -> dict[str, Any]:
        result = _observe_ro_view_grant_core(
            source,
            entry,
            slot,
            allow_account_probe=allow_account_probe,
            timeout=timeout,
        )
        return {"item": result[0], "complete": result[1], "green": result[2]}

    value, gap = _run_isolated_json_probe(
        probe, timeout
    )
    if gap is not None:
        item["gaps"] = [gap]
        return item, False, False
    if not isinstance(value, dict) or set(value) != {"item", "complete", "green"}:
        item["gaps"] = ["probe_unavailable"]
        return item, False, False
    if (
        not isinstance(value["item"], dict)
        or not isinstance(value["complete"], bool)
        or not isinstance(value["green"], bool)
    ):
        item["gaps"] = ["probe_unavailable"]
        return item, False, False
    return value["item"], value["complete"], value["green"]


def bind_ro(source: Path, target: Path, *, recursive: bool = False) -> tuple[bool, str]:
    """Bind source onto target and remount it read-only.

    An existing mount at target is never trusted — a failed earlier assign can
    leave a stale bind pointing at another user's slice, and findmnt source
    strings for subtree binds are not reliable to compare — so it is torn down
    and rebuilt. recursive=True uses --rbind so submounts (package/media binds)
    are included."""
    try:
        _reject_existing_symlink_components(source, "bind_source")
        _reject_existing_symlink_components(target, "bind_target")
        source_before = source.lstat()
    except (OSError, ValueError) as exc:
        return False, str(exc)
    if not (stat.S_ISDIR(source_before.st_mode) or stat.S_ISREG(source_before.st_mode)):
        return False, f"bind_source_not_regular_or_directory:{source}"
    rc, _, rows = findmnt_one(target)
    if rc == 0 and rows:
        failed, errors = unmount_tree(target)
        if failed:
            return False, "stale_mount_unmount_failed:" + "; ".join(errors)
    if stat.S_ISREG(source_before.st_mode):
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not target.is_file():
            return False, f"bind_target_type_mismatch:{target}"
        target.touch(exist_ok=True)
    else:
        if target.exists() and not target.is_dir():
            return False, f"bind_target_type_mismatch:{target}"
        target.mkdir(parents=True, exist_ok=True)
    proc = _run_text(["mount", "--rbind" if recursive else "--bind", str(source), str(target)], timeout=30)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    proc = _run_text(["mount", "-o", "remount,ro,nosuid,nodev,bind", str(target)], timeout=30)
    if proc.returncode != 0:
        unmount_tree(target)
        return False, "ro_remount_failed:" + (proc.stderr or proc.stdout).strip()
    try:
        source_after = source.lstat()
    except OSError:
        unmount_tree(target)
        return False, "bind_source_changed_during_mount"
    if _path_identity(source_before) != _path_identity(source_after):
        unmount_tree(target)
        return False, "bind_source_changed_during_mount"
    rc, error, rows = findmnt_one(target)
    if rc != 0 or not rows or not _is_safe_view_mount(rows[0]):
        unmount_tree(target)
        return False, error or "bind_mounted_state_not_ro_nosuid_nodev"
    return True, "ok"


def unmount_tree(root: Path) -> tuple[int, list[str]]:
    """Unmount every mount at or under root, deepest first. Returns (failed, errors)."""
    rc, error, rows = findmnt_under(str(root))
    if rc != 0:
        return 1, [error or "findmnt_failed"]
    targets = sorted({row["target"] for row in rows if row.get("target")}, key=len, reverse=True)
    failures: list[str] = []
    for target in targets:
        proc = _run_text(["umount", target], timeout=60)
        if proc.returncode != 0:
            failures.append(f"{target}: {(proc.stderr or proc.stdout).strip()}")
    return len(failures), failures
