from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
import re
import signal
import subprocess
import threading
from pathlib import Path

from ..apache import parse_apache_route


def state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


# Accounts allowed to operate on production (customer) slots. Everyone else with a
# deploy grant is a developer and is scoped to their own dev-* slots (see invoking_user).
OPERATOR_ACCOUNTS = frozenset({"root", "svcops"})


def is_dev_slot(name: object) -> bool:
    """A dev-owned (non-production) slot: identified by the `dev-` account-name prefix.

    This is the production/environment boundary the rollout layer already trusts for
    `image-promote` (`_is_dev_named_target`). `dev-oc` (source) and `dev-oc-img`
    (image-mode validation) are both dev-owned; real customer slots (`oc1`..) are not.
    """
    return str(name or "").startswith("dev-")


def sudo_user() -> str:
    """The account that ran `sudo opsctl ...`, or empty when not invoked via sudo.

    Only `SUDO_USER` is trusted (set by sudo itself after env_reset); there is no `USER`
    fallback on purpose. This is used for AUTHORIZATION and runs after the `is_root()`
    check, so an empty result means a real root shell (an operator), not an unknown user.
    """
    return os.environ.get("SUDO_USER", "")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


def apache_public_host(slot: str) -> str:
    try:
        return parse_apache_route(slot).public_host
    except Exception:
        return ""


def container_name(slot: str, profile) -> str:
    service = profile.metadata.get("service") or "openclaw-gateway"
    return f"openclaw-{slot}-{service}-1"


def run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


_READONLY_DOCKER_STREAM_LIMIT_BYTES = 1024 * 1024
_READONLY_DOCKER_TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _validate_readonly_docker_command(command: list[str]) -> None:
    if not isinstance(command, list) or not all(
        isinstance(item, str) for item in command
    ):
        raise ValueError("readonly_docker_argv_invalid")
    if not command or command[0] not in {"docker", "/usr/bin/docker"}:
        raise ValueError("readonly_docker_executable_invalid")
    if len(command) == 3 and command[1] == "inspect":
        if _READONLY_DOCKER_TARGET_RE.fullmatch(command[2]) is None:
            raise ValueError("readonly_docker_inspect_target_invalid")
        return
    if len(command) < 7 or command[1:3] != ["ps", "-a"]:
        raise ValueError("readonly_docker_operation_not_allowed")
    index = 3
    saw_format = False
    while index < len(command):
        option = command[index]
        if option == "--filter" and index + 1 < len(command):
            value = command[index + 1]
            if not value.startswith("label=") or any(
                character in value for character in "\r\n\x00"
            ):
                raise ValueError("readonly_docker_filter_invalid")
            index += 2
            continue
        if option == "--format" and index + 1 < len(command):
            if saw_format or command[index + 1] != "{{.ID}}":
                raise ValueError("readonly_docker_format_invalid")
            saw_format = True
            index += 2
            continue
        raise ValueError("readonly_docker_argv_invalid")
    if not saw_format:
        raise ValueError("readonly_docker_format_required")


def _kill_isolated_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def run_readonly_docker(
    command: list[str],
    timeout: int = 20,
    *,
    maximum_stream_bytes: int = _READONLY_DOCKER_STREAM_LIMIT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run only Docker ps/inspect with bounded streams and isolated cleanup."""

    _validate_readonly_docker_command(command)
    if not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("readonly_docker_timeout_invalid")
    if not isinstance(maximum_stream_bytes, int) or maximum_stream_bytes <= 0:
        raise ValueError("readonly_docker_stream_bound_invalid")
    kwargs: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **kwargs)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))

    streams: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    overflow: list[str] = []
    overflow_lock = threading.Lock()

    def consume(name: str, stream) -> None:
        observed = 0
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            observed += len(chunk)
            if observed > maximum_stream_bytes:
                with overflow_lock:
                    if not overflow:
                        overflow.append(name)
                _kill_isolated_process(process)
                return
            streams[name].append(chunk)

    threads = [
        threading.Thread(
            target=consume,
            args=(name, stream),
            daemon=True,
        )
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_isolated_process(process)
        try:
            returncode = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            returncode = 124
    for thread in threads:
        thread.join(timeout=2)
    stdout_bytes = b"".join(streams["stdout"])
    stderr_bytes = b"".join(streams["stderr"])
    if timed_out:
        return subprocess.CompletedProcess(command, 124, "", "readonly_command_timeout")
    if overflow:
        return subprocess.CompletedProcess(
            command,
            125,
            "",
            f"readonly_{overflow[0]}_exceeds_bound",
        )
    try:
        stdout = stdout_bytes.decode("utf-8")
        stderr = stderr_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return subprocess.CompletedProcess(
            command, 126, "", "readonly_output_invalid_utf8"
        )
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def run_text_cwd(
    command: list[str], cwd: Path, timeout: int = 20
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))
