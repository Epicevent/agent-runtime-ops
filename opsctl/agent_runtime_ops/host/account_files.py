from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from ..nas import agent_nas_dir, history_dir, request_dir


def read_key_value_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        data[key] = value
    return data


def atomic_write_key_value(path: Path, data: dict[str, str], mode: int, uid: int | None = None, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, value in data.items():
                handle.write(f"{key}={value}\n")
        os.chmod(tmp_path, mode)
        ensure_owner_if_needed(tmp_path, uid, gid)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def ensure_owner_if_needed(path: Path, uid: int | None, gid: int | None) -> None:
    if uid is None or gid is None or not hasattr(os, "chown"):
        return
    current = path.stat()
    if current.st_uid == uid and current.st_gid == gid:
        return
    if current.st_uid == uid:
        os.chown(path, -1, gid)
        return
    os.chown(path, uid, gid)


def passwd_record(name: str):
    import pwd

    return pwd.getpwnam(name)


def group_gid(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


def slot_uid_gid(slot: str) -> tuple[int, int]:
    record = passwd_record(slot)
    return int(record.pw_uid), int(record.pw_gid)


def slot_home(slot: str) -> Path:
    return Path(passwd_record(slot).pw_dir)


def runtime_ids(slot: str) -> tuple[int, int, int]:
    runtime = passwd_record(f"{slot}_rt")
    data_gid = group_gid(f"{slot}_data")
    return int(runtime.pw_uid), int(runtime.pw_gid), data_gid


def ensure_group_member(user: str, group: str) -> str:
    import grp

    user_record = passwd_record(user)
    group_record = grp.getgrnam(group)
    if user_record.pw_gid == group_record.gr_gid or user in group_record.gr_mem:
        return "present"
    proc = subprocess.run(["usermod", "-a", "-G", group, user], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        raise RuntimeError(f"usermod failed: {detail[:240]}")
    return "added"


def ensure_not_symlink_chain(path: Path, stop_at: Path) -> None:
    current = path
    checked: list[Path] = []
    while True:
        checked.append(current)
        if current == stop_at:
            break
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(checked):
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"path component must not be symlink: {candidate}")


def ensure_customer_agent_dirs(slot: str) -> None:
    uid, gid = slot_uid_gid(slot)
    base = agent_nas_dir(slot)
    home = Path("/home") / slot
    ensure_not_symlink_chain(base, home)
    for path, mode in [
        (base, 0o700),
        (request_dir(slot), 0o700),
        (base / "credentials", 0o700),
        (base / "history", 0o700),
        (history_dir(slot, "approved"), 0o700),
        (history_dir(slot, "rejected"), 0o700),
    ]:
        path.mkdir(parents=True, exist_ok=True)
        ensure_owner_if_needed(path, uid, gid)
        os.chmod(path, mode)


def read_password_from_stdin() -> str:
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    if password.endswith("\r"):
        password = password[:-1]
    if not password:
        raise ValueError("password stdin is empty")
    return password


def write_credential_file(path: Path, username: str, password: str, domain: str | None, uid: int, gid: int) -> None:
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    ensure_not_symlink_chain(path.parent, path.parents[2] if len(path.parents) > 2 else path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_owner_if_needed(path.parent, uid, gid)
    os.chmod(path.parent, 0o700)
    data = {"username": username, "password": password}
    if domain:
        data["domain"] = domain
    atomic_write_key_value(path, data, 0o600, uid, gid)


def credential_file_is_safe(path: Path, uid: int | None = None) -> None:
    if path.is_symlink():
        raise ValueError(f"credential file must not be symlink: {path}")
    stat_result = path.stat()
    if not path.is_file():
        raise ValueError(f"credential path is not a regular file: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"credential file must be 0600: {path}")
    if uid is not None and stat_result.st_uid != uid:
        raise ValueError(f"credential file owner mismatch: {path}")


def credential_file_is_safe_for_slot(slot: str, path: Path, uid: int | None = None) -> None:
    customer_root = agent_nas_dir(slot) / "credentials"
    root_credential_root = Path("/root") / "agent-runtime-ops" / "nas-credentials" / slot
    resolved = path.resolve(strict=False)
    if str(resolved).startswith(str(customer_root.resolve(strict=False)) + os.sep):
        ensure_not_symlink_chain(path.parent, Path("/home") / slot)
    elif str(resolved).startswith(str(root_credential_root.resolve(strict=False)) + os.sep):
        ensure_not_symlink_chain(path.parent, Path("/root"))
    else:
        raise ValueError(f"credential path outside managed roots: {path}")
    credential_file_is_safe(path, uid=uid)


def credential_presence(path: Path) -> str:
    try:
        path.stat()
        return "yes"
    except FileNotFoundError:
        return "no"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"
