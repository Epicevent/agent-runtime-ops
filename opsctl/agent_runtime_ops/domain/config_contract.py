"""Product-attested on-disk config validation and migration.

The product image carries its own config commands in plain-string labels
(``config-validate.command`` / ``config-migrate.command``), inherited by the wrapper
and surfaced as ``image_spec_config_contract``. opsctl never reimplements the config
schema; it runs the product's own commands:

* **validate** — before recreating a container, check the on-disk config against the
  TARGET image. A config the image would reject (e.g. a removed/legacy key) is gated
  here, so the running container is never torn down into a crash loop (zero-downtime).
  Also used as a drift check against the image a RUNNING container already uses.
* **migrate** — run the product's own ``doctor --fix`` (atomic write + ``.bak`` backup)
  to bring the config into compliance. This is an explicit operator step
  (``opsctl config migrate``), never silent during apply.

Trust is anchored by the root-approved image digest (``opsctl image approve``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .common import run_text


CONTAINER_CONFIG_DIR = "/home/node/.openclaw"
CONFIG_VALID_CHECK = "config_disk_valid_for_running_image_ok"


def config_owner_run_as(host_config_dir: Path) -> str:
    """Return ``uid:gid`` of the on-disk config so the product runs as its real owner.

    The config tree is owned by the slot's *runtime* account (the uid the gateway
    container runs as), not the slot login account, and the dir is mode 0700. Deriving
    the user from the actual file ownership lets the product validate/migrate read the
    dir and write the file with the same ownership it already has — no account-model
    assumptions. Prefers the config file, falls back to the dir.
    """
    config_file = host_config_dir / "openclaw.json"
    target = config_file if config_file.exists() else host_config_dir
    st = os.stat(target)
    return f"{st.st_uid}:{st.st_gid}"


def _command(contract: dict[str, Any], key: str) -> list[str]:
    return [str(arg) for arg in (contract.get(key) or [])]


def _timeout(contract: dict[str, Any], key: str, default: int) -> int:
    raw = contract.get(key)
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else default


def _interpret_validate(proc) -> tuple[bool, str]:
    """Map a ``config validate --json`` result to (valid, detail).

    Prefer the structured ``{"valid": bool, "issues": [...]}`` payload; fall back to
    the process exit code when stdout is not parseable JSON.
    """
    out = (proc.stdout or "").strip()
    payload: Any = None
    if out:
        try:
            payload = json.loads(out)
        except Exception:
            # tolerate a leading log line before the JSON object
            start = out.find("{")
            if start != -1:
                try:
                    payload = json.loads(out[start:])
                except Exception:
                    payload = None
    if isinstance(payload, dict) and "valid" in payload:
        valid = bool(payload["valid"])
        issues = payload.get("issues")
        if valid:
            return True, "valid"
        if isinstance(issues, list) and issues:
            paths = ",".join(str(i.get("path") or i.get("message") or "?") for i in issues if isinstance(i, dict))
            return False, f"invalid:{paths}"[:200]
        err = payload.get("error")
        return False, f"invalid:{err or 'schema'}"[:200]
    # No machine-readable verdict — trust the exit code.
    if proc.returncode == 0:
        return True, "exit=0"
    return False, ((proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}")[:200]


def run_config_validate_in_container(container: str, contract: dict[str, Any]) -> tuple[bool, str]:
    """Drift check: validate the on-disk config against the image the RUNNING container uses.

    Runs the product's ``config validate`` via ``docker exec`` inside the live container,
    which already has the config bind-mounted. Surfaces a config that has drifted out of
    schema for its own running image — a latent crash-on-restart — before any restart.
    """
    command = _command(contract, "validate_command")
    if not command:
        return False, "config_contract has no validate_command"
    proc = run_text(["docker", "exec", container, *command], timeout=_timeout(contract, "validate_timeout_seconds", 120))
    return _interpret_validate(proc)


def run_config_validate_in_image(
    image_ref: str,
    host_config_dir: Path,
    contract: dict[str, Any],
    *,
    run_as: str | None = None,
) -> tuple[bool, str]:
    """Preflight: validate the on-disk config against a TARGET image via a one-shot
    ``docker run`` with the config dir mounted read-only. Touches no running container.
    """
    command = _command(contract, "validate_command")
    if not command:
        return False, "config_contract has no validate_command"
    argv = ["docker", "run", "--rm"]
    if run_as:
        argv += ["--user", run_as]
    argv += [
        "-e", f"OPENCLAW_CONFIG_PATH={CONTAINER_CONFIG_DIR}/openclaw.json",
        "-v", f"{host_config_dir}:{CONTAINER_CONFIG_DIR}:ro",
        "--entrypoint", command[0],
        image_ref,
        *command[1:],
    ]
    proc = run_text(argv, timeout=_timeout(contract, "validate_timeout_seconds", 120))
    return _interpret_validate(proc)


def run_config_migrate_in_image(
    image_ref: str,
    host_config_dir: Path,
    contract: dict[str, Any],
    *,
    run_as: str,
) -> tuple[bool, str]:
    """Migrate the on-disk config by running the product's own ``doctor --fix`` against the
    TARGET image, with the config dir mounted read-write as the slot user. The product
    writes atomically and rotates a ``.bak`` backup. Returns (ok, detail).
    """
    command = _command(contract, "migrate_command")
    if not command:
        return False, "config_contract has no migrate_command"
    argv = [
        "docker", "run", "--rm",
        "--user", run_as,
        "-e", "HOME=/home/node",
        "-e", f"OPENCLAW_CONFIG_PATH={CONTAINER_CONFIG_DIR}/openclaw.json",
        "-v", f"{host_config_dir}:{CONTAINER_CONFIG_DIR}",
        "--entrypoint", command[0],
        image_ref,
        *command[1:],
    ]
    proc = run_text(argv, timeout=_timeout(contract, "migrate_timeout_seconds", 180))
    if proc.returncode != 0:
        return False, ((proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}")[:200]
    return True, "migrated"
