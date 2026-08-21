from __future__ import annotations

import os
from pathlib import Path
import pwd
import secrets


def workspace_local_entry_count(path: Path) -> int:
    """Count names that a bind mount would hide, without reading contents."""
    with os.scandir(path) as entries:
        return sum(1 for _entry in entries)


def probe_workspace_write(path: Path, runtime_user: str) -> tuple[bool, str]:
    """Create, fsync, and remove one private file as the runtime identity."""
    if os.geteuid() != 0:
        return False, "root_required"
    try:
        account = pwd.getpwnam(runtime_user)
    except KeyError:
        return False, "runtime_user_missing"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        return False, f"workspace_open_failed errno={exc.errno}"
    filename = f".opsctl-write-probe-{secrets.token_hex(16)}"
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except OSError as exc:
        os.close(read_fd)
        os.close(write_fd)
        os.close(directory_fd)
        return False, f"probe_fork_failed errno={exc.errno}"
    if pid == 0:
        os.close(read_fd)
        file_fd = -1
        try:
            # Root enters the fixed mount first; *_rt need not traverse /home/ocN.
            os.fchdir(directory_fd)
            os.initgroups(runtime_user, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            file_fd = os.open(filename, create_flags, 0o600, dir_fd=directory_fd)
            os.write(file_fd, b"workspace-write-probe\n")
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = -1
            os.unlink(filename, dir_fd=directory_fd)
            os._exit(0)
        except BaseException as exc:
            if file_fd >= 0:
                try:
                    os.close(file_fd)
                except OSError:
                    pass
            errno = getattr(exc, "errno", None)
            message = f"{type(exc).__name__}" + (f" errno={errno}" if errno is not None else "")
            try:
                os.write(write_fd, message.encode("ascii", "replace")[:160])
            except OSError:
                pass
            os._exit(1)
    os.close(write_fd)
    try:
        _waited_pid, status = os.waitpid(pid, 0)
        detail = os.read(read_fd, 160).decode("ascii", "replace")
    finally:
        os.close(read_fd)
        try:
            os.unlink(filename, dir_fd=directory_fd)
        except OSError:
            pass
        finally:
            os.close(directory_fd)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return True, "create_fsync_remove_ok"
    return False, f"runtime_identity_write_failed {detail or 'child_failed'}"
