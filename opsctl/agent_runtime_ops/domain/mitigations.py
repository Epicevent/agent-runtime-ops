from __future__ import annotations

import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Callable

import yaml

from .runtime_truth import find_gateway_container_by_binding

"""Register of temporary mitigations with machine-evaluated expiry.

Why this exists (2026-07 incident class): interim workarounds (env overrides,
config toggles) were applied to slots with no removal condition recorded; later
nobody knew whether they were still present, still needed, or silently masking
the real fix (an OPENCLAW_VERSION env override masks the image's stamped
version). Prose lists rot, so the register is a machine-checked file:
`opsctl mitigation check` probes the live slot for the mitigation's presence and
compares the running product version against the recorded expiry, then reports
active / expired-but-still-present / cleared per slot.
"""

MITIGATIONS_FILE_NAME = "mitigations.yaml"
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def mitigations_path(state_root: Path) -> Path:
    return state_root / MITIGATIONS_FILE_NAME


def load_mitigations(state_root: Path) -> list[dict]:
    path = mitigations_path(state_root)
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("mitigations") if isinstance(data, dict) else None
    return [entry for entry in (entries or []) if isinstance(entry, dict)]


def save_mitigations(state_root: Path, entries: list[dict]) -> Path:
    path = mitigations_path(state_root)
    path.write_text(
        yaml.safe_dump({"mitigations": entries}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def new_env_mitigation(
    *,
    mitigation_id: str,
    slots: list[str],
    env_key: str,
    reason: str,
    expires_product_version: str,
) -> dict:
    if parse_version_triple(expires_product_version) is None:
        raise ValueError(f"expires-product-version must look like X.Y.Z: {expires_product_version!r}")
    return {
        "id": mitigation_id,
        "kind": "env",
        "slots": list(slots),
        "env_key": env_key,
        "reason": reason,
        "added": date.today().isoformat(),
        "expires_product_version": expires_product_version,
    }


def env_key_present(env_path: Path, key: str) -> bool:
    """Presence only — never read or return the value (env files hold secrets)."""
    if not env_path.exists():
        return False
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _ENV_LINE_RE.match(line)
        if match and match.group(1) == key:
            return True
    return False


def parse_version_triple(text: str | None) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(str(text or ""))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def running_product_version(
    binding,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> str:
    """The running container's own answer (its package.json), not a label or a guess."""
    container, lookup = find_gateway_container_by_binding(binding)
    if not container:
        raise ValueError(f"gateway container not found: {lookup}")
    proc = runner(
        ["docker", "exec", container, "node", "-p", "require('/app/package.json').version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise ValueError(f"version probe failed: {proc.stderr.strip() or proc.stdout.strip()}")
    version = (proc.stdout or "").strip()
    if parse_version_triple(version) is None:
        raise ValueError(f"version probe returned no version: {version!r}")
    return version


def evaluate_env_mitigation(
    entry: dict,
    slot: str,
    *,
    present: bool,
    running_version: str | None,
    probe_error: str | None = None,
) -> tuple[str, str]:
    """Return (status, detail) for one slot of an env mitigation.

    - cleared: the override is gone; the register entry can be retired
    - active: still present and the fix has not shipped to this slot yet
    - expired_still_present: the fix is running but the override still masks it — act
    - unknown: could not determine the running version — loud, not silent
    """
    expires = str(entry.get("expires_product_version") or "")
    if not present:
        return "cleared", f"slot={slot} env_key absent; retire this entry"
    if probe_error is not None or running_version is None:
        return "unknown", f"slot={slot} version probe failed: {probe_error or 'no version'}"
    running = parse_version_triple(running_version)
    threshold = parse_version_triple(expires)
    if running is None or threshold is None:
        return "unknown", f"slot={slot} unparsable versions running={running_version!r} expires={expires!r}"
    if running >= threshold:
        return (
            "expired_still_present",
            f"slot={slot} running={running_version} >= expires={expires}; remove the override",
        )
    return "active", f"slot={slot} running={running_version} < expires={expires}"
