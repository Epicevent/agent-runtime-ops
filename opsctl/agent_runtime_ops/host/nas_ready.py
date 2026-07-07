"""NAS readiness probe and failed CIFS mount-unit inventory.

Cold-start ordering is the normal failure mode here, not the exception: after
a power cut the server boots before the NAS answers, fstab's nofail hides the
failed CIFS mounts, and a one-shot @reboot `nas view restore` loses the race
(measured 2026-07-07). Waiting for the NAS turns that one-shot into an
eventually-consistent boot step; surfacing failed mount units removes the
silence nofail buys.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterable

from .mounts import _run_text

SMB_PORT = 445


def tcp_probe(host: str, port: int = SMB_PORT, timeout_seconds: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def wait_for_nas_ready(
    hosts: Iterable[str],
    *,
    total_seconds: float,
    probe: Callable[[str], bool] = tcp_probe,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, bool]:
    """Wait (bounded, exponential backoff) until every host answers SMB.

    Returns host -> ready. total_seconds=0 degrades to a single probe pass,
    so callers always get a readiness report even with waiting disabled."""
    pending: dict[str, bool] = {host: False for host in dict.fromkeys(hosts)}
    if not pending:
        return pending
    deadline = monotonic() + max(0.0, total_seconds)
    delay = 5.0
    while True:
        for host, ready in list(pending.items()):
            if not ready and probe(host):
                pending[host] = True
        if all(pending.values()) or monotonic() >= deadline:
            return pending
        sleep(min(delay, max(0.5, deadline - monotonic())))
        delay = min(delay * 2, 60.0)


def failed_cifs_mount_units(
    runner: Callable[..., object] = _run_text,
) -> tuple[list[str], str | None]:
    """List systemd mount units in failed state whose source is an SMB share.

    Returns (unit_names, error). error is set when systemctl is unusable —
    callers report unknown instead of a false zero."""
    try:
        proc = runner(["systemctl", "list-units", "--failed", "--type=mount", "--plain", "--no-legend"])
    except OSError as exc:
        return [], str(exc)
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout).strip() or f"systemctl_rc={proc.returncode}"
    units = [line.split()[0] for line in proc.stdout.splitlines() if line.strip()]
    cifs_units: list[str] = []
    for unit in units:
        try:
            show = runner(["systemctl", "show", unit, "-p", "What", "--value"])
        except OSError as exc:
            return cifs_units, str(exc)
        if (show.stdout or "").strip().startswith("//"):
            cifs_units.append(unit)
    return cifs_units, None
