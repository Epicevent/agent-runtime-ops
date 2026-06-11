from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from ..nas import agent_nas_dir, history_dir, request_dir


def _read_key_value_file(path: Path) -> dict[str, str]:
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


def _atomic_write_key_value(path: Path, data: dict[str, str], mode: int, uid: int | None = None, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, value in data.items():
                handle.write(f"{key}={value}\n")
        os.chmod(tmp_path, mode)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            os.chown(tmp_path, uid, gid)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _passwd_record(name: str):
    import pwd

    return pwd.getpwnam(name)


def _group_gid(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


def _slot_uid_gid(slot: str) -> tuple[int, int]:
    record = _passwd_record(slot)
    return int(record.pw_uid), int(record.pw_gid)


def _slot_home(slot: str) -> Path:
    return Path(_passwd_record(slot).pw_dir)


def _runtime_ids(slot: str) -> tuple[int, int, int]:
    runtime = _passwd_record(f"{slot}_rt")
    data_gid = _group_gid(f"{slot}_data")
    return int(runtime.pw_uid), int(runtime.pw_gid), data_gid


def _ensure_not_symlink_chain(path: Path, stop_at: Path) -> None:
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


def _ensure_customer_agent_dirs(slot: str) -> None:
    uid, gid = _slot_uid_gid(slot)
    base = agent_nas_dir(slot)
    home = Path("/home") / slot
    _ensure_not_symlink_chain(base, home)
    for path, mode in [
        (base, 0o700),
        (request_dir(slot), 0o700),
        (base / "credentials", 0o700),
        (base / "history", 0o700),
        (history_dir(slot, "approved"), 0o700),
        (history_dir(slot, "rejected"), 0o700),
    ]:
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def _read_password_from_stdin() -> str:
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    if password.endswith("\r"):
        password = password[:-1]
    if not password:
        raise ValueError("password stdin is empty")
    return password


def _write_credential_file(path: Path, username: str, password: str, domain: str | None, uid: int, gid: int) -> None:
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    _ensure_not_symlink_chain(path.parent, path.parents[2] if len(path.parents) > 2 else path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, uid, gid)
    os.chmod(path.parent, 0o700)
    data = {"username": username, "password": password}
    if domain:
        data["domain"] = domain
    _atomic_write_key_value(path, data, 0o600, uid, gid)


def _credential_file_is_safe(path: Path, uid: int | None = None) -> None:
    if path.is_symlink():
        raise ValueError(f"credential file must not be symlink: {path}")
    stat_result = path.stat()
    if not path.is_file():
        raise ValueError(f"credential path is not a regular file: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"credential file must be 0600: {path}")
    if uid is not None and stat_result.st_uid != uid:
        raise ValueError(f"credential file owner mismatch: {path}")


def _credential_file_is_safe_for_slot(slot: str, path: Path, uid: int | None = None) -> None:
    customer_root = agent_nas_dir(slot) / "credentials"
    root_credential_root = Path("/root") / "agent-runtime-ops" / "nas-credentials" / slot
    resolved = path.resolve(strict=False)
    if str(resolved).startswith(str(customer_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/home") / slot)
    elif str(resolved).startswith(str(root_credential_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/root"))
    else:
        raise ValueError(f"credential path outside managed roots: {path}")
    _credential_file_is_safe(path, uid=uid)


def _credential_presence(path: Path) -> str:
    try:
        path.stat()
        return "yes"
    except FileNotFoundError:
        return "no"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"
