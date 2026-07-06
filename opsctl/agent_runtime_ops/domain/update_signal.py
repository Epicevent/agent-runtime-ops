from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from ..host.account_files import slot_home
from ..routing import load_runtime_bindings

"""Announce an approved product image to running slots.

The file contract is owned by the PRODUCT (openclaw-jitech
src/infra/update-signal.ts + its tests), not by prose: the gateway reads
<stateDir>/update-signal.json, requires envelope version 1 plus
`availableVersion`, treats a missing/malformed file as "no update", and
re-reads hourly. Writing here is announce-only: it must never gate or
break an approval.
"""

UPDATE_SIGNAL_FILENAME = "update-signal.json"
SIGNAL_ENVELOPE_VERSION = 1
# `openclaw --version` prints e.g. "OpenClaw 2026.7.6"; accept pre-release suffixes.
_VERSION_TOKEN_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z][0-9A-Za-z.]*)?)\b")
_PROBE_TIMEOUT_SECONDS = 600  # covers a cold image pull


def probe_image_version(
    image_ref: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str:
    """Ask the image's own runtime for its version (never a label or a tag guess).

    An image's displayed version has already lied to us once when inferred from
    metadata; `openclaw.mjs --version` is what the product actually reports.
    """
    docker = shutil.which("docker")
    if not docker:
        raise ValueError("docker is required to probe the product image version")
    argv = [docker, "run", "--rm", "--entrypoint", "node", str(image_ref), "/app/openclaw.mjs", "--version"]
    proc = runner(argv, capture_output=True, text=True, timeout=_PROBE_TIMEOUT_SECONDS)
    if proc.returncode != 0:
        raise ValueError(
            f"version probe failed (exit {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    match = _VERSION_TOKEN_RE.search(proc.stdout or "")
    if not match:
        raise ValueError(f"version probe output had no version token: {proc.stdout.strip()!r}")
    return match.group(1)


def _write_slot_signal(state_dir: Path, payload: dict[str, object]) -> Path:
    target = state_dir / UPDATE_SIGNAL_FILENAME
    tmp = state_dir / f".{UPDATE_SIGNAL_FILENAME}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    chown = getattr(os, "chown", None)
    if chown is not None:
        # Keep the file owned like its directory so the slot account stays tidy.
        stat = state_dir.stat()
        chown(tmp, stat.st_uid, stat.st_gid)
    os.replace(tmp, target)
    return target


def write_update_signals(
    state_root: Path,
    family: str,
    image_ref: str,
    *,
    available_version: str,
    note: str | None = None,
    bindings: Iterable[object] | None = None,
    home_resolver: Callable[[str], Path] = slot_home,
) -> list[tuple[str, bool, str]]:
    """Write the signal to every enabled slot of the family; report per-slot outcomes.

    Returns (slot, ok, detail) tuples; the caller prints them. A slot failure is
    reported, never raised — announcing must not block the approval that triggered it.
    """
    payload_base: dict[str, object] = {
        "version": SIGNAL_ENVELOPE_VERSION,
        "availableVersion": available_version,
        "imageTag": str(image_ref),
        "approvedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if note:
        payload_base["note"] = note

    results: list[tuple[str, bool, str]] = []
    slot_bindings = bindings if bindings is not None else load_runtime_bindings(state_root)
    for binding in slot_bindings:
        if getattr(binding, "family", None) != family or not getattr(binding, "enabled", False):
            continue
        slot = str(getattr(binding, "linux_account"))
        try:
            state_dir = home_resolver(slot) / ".openclaw"
            if not state_dir.is_dir():
                raise ValueError(f"state dir missing: {state_dir}")
            target = _write_slot_signal(state_dir, dict(payload_base))
            results.append((slot, True, str(target)))
        except Exception as exc:
            results.append((slot, False, str(exc)))
    return results
