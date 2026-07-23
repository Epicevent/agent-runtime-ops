from __future__ import annotations

import json
import os
from pathlib import Path

from ..host.account_files import ensure_not_symlink_chain, runtime_ids, slot_home
from ..host.files import fsync_parent
from .common import run_text


# Changing the model with the product's OWN `models set` command (rather than hand-writing
# openclaw.json) preserves the canonical `agents.defaults.models` entry, provider-plugin repair,
# and load-time validation. The container entrypoint differs across images — production CMD is
# `node openclaw.mjs gateway`, the dev recipe overrides to `node dist/index.js gateway`, and the
# npm `openclaw` bin may be on PATH — so we try candidate invocations until one runs. A wrong
# entry fails before `models set` executes, leaving the config untouched, so trying in order is safe.
OPENCLAW_MODELS_SET_ENTRIES: tuple[tuple[str, ...], ...] = (
    ("openclaw", "models", "set"),
    ("node", "openclaw.mjs", "models", "set"),
    ("node", "dist/index.js", "models", "set"),
)


def openclaw_config_path(slot: str) -> Path:
    home = slot_home(slot).resolve(strict=False)
    path = home / ".openclaw" / "openclaw.json"
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"config path outside slot home: {path}")
    ensure_not_symlink_chain(path.parent, home)
    if path.exists() and path.is_symlink():
        raise ValueError(f"config file must not be a symlink: {path}")
    return path


# ── Version-notes overlay (operator-authored patch notes) ────────────────────
#
# OpenClaw's version modal reads a live overlay keyed by build version:
# <stateDir>/version-notes.json = {"2026.7.16": "note text", ...} — a SINGLE
# string per version (the product's version-notes-store.ts contract; empty
# clears). stateDir is the mounted /home/<slot>/.openclaw, so a root write
# here shows up in the modal on next open, no rebuild. Same operator pen as
# the hermes overlay — one opsctl command serves both families.

def openclaw_version_notes_path(slot: str) -> Path:
    home = slot_home(slot).resolve(strict=False)
    path = home / ".openclaw" / "version-notes.json"
    ensure_not_symlink_chain(path.parent, home)
    if path.exists() and path.is_symlink():
        raise ValueError(f"version-notes file must not be a symlink: {path}")
    return path


def read_openclaw_version_notes(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError(f"version-notes path is not a regular file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"version-notes must be a JSON object: {path}")
    return {k: v for k, v in data.items() if isinstance(v, str)}


def write_openclaw_version_notes(slot: str, path: Path, notes: dict[str, str]) -> None:
    """Atomic write, owned by the slot runtime user so the in-container
    gateway (which reads it for the version modal) can open it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    uid, _, gid = runtime_ids(slot)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(notes, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def read_openclaw_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError(f"config path is not a regular file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"config must be a mapping: {path}")
    return dict(data)


def write_openclaw_config(slot: str, path: Path, config: dict[str, object]) -> None:
    """Atomically persist an OpenClaw config with the slot runtime ownership."""
    home = slot_home(slot).resolve(strict=False)
    ensure_not_symlink_chain(path.parent, home)
    if path.exists() and path.is_symlink():
        raise ValueError(f"config file must not be a symlink: {path}")
    uid, _, gid = runtime_ids(slot)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def ensure_provider_model(config: dict[str, object], provider: str, model: str) -> bool:
    """Register a provider model required by OpenClaw's runtime resolver.

    The product's ``models set`` command can update ``agents.defaults.model`` without adding the
    matching ``models.providers[provider].models[]`` entry.  In that partial state the config
    looks updated but every model roundtrip fails.  Preserve all existing provider fields and
    model objects, adding only the missing ``{"id": model}`` entry.
    """
    models_root = config.setdefault("models", {})
    if not isinstance(models_root, dict):
        raise ValueError("openclaw models must be an object")
    providers = models_root.setdefault("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("openclaw models.providers must be an object")
    provider_config = providers.setdefault(provider, {})
    if not isinstance(provider_config, dict):
        raise ValueError(f"openclaw models.providers[{provider!r}] must be an object")
    registered = provider_config.setdefault("models", [])
    if not isinstance(registered, list):
        raise ValueError(f"openclaw models.providers[{provider!r}].models must be an array")
    for entry in registered:
        if isinstance(entry, dict) and entry.get("id") == model:
            return False
        if entry == model:
            return False
    registered.append({"id": model})
    return True


def provider_model_registration(config: dict[str, object], provider: str, model: str) -> tuple[bool, int]:
    """Return whether the selected model is registered and the provider model count."""
    models_root = config.get("models")
    providers = models_root.get("providers") if isinstance(models_root, dict) else None
    provider_config = providers.get(provider) if isinstance(providers, dict) else None
    registered = provider_config.get("models") if isinstance(provider_config, dict) else None
    if not isinstance(registered, list):
        return False, 0
    found = any(
        (isinstance(entry, dict) and entry.get("id") == model) or entry == model
        for entry in registered
    )
    return found, len(registered)


def _model_field(config: dict[str, object]) -> object:
    agents = config.get("agents")
    if not isinstance(agents, dict):
        return None
    defaults = agents.get("defaults")
    if not isinstance(defaults, dict):
        return None
    return defaults.get("model")


def _split_ref(ref: str) -> tuple[str, str]:
    """openclaw embeds provider in the model string as ``provider/model``.

    Returns (provider, model). A bare string with no slash has no explicit provider.
    """
    text = ref.strip()
    slash = text.find("/")
    if slash == -1:
        return "", text
    return text[:slash].strip(), text[slash + 1 :].strip()


def current_openclaw_model(config: dict[str, object]) -> tuple[str, str, str, str]:
    """Return (provider, model, ref, source) for the primary model.

    ``agents.defaults.model`` is either a ``"provider/model"`` string or an object with a
    ``primary`` (and optional ``fallbacks``). ``source`` is one of string|object|missing.
    """
    value = _model_field(config)
    if isinstance(value, str):
        provider, model = _split_ref(value)
        return provider, model, value.strip(), "string"
    if isinstance(value, dict):
        primary = value.get("primary")
        if isinstance(primary, str):
            provider, model = _split_ref(primary)
            return provider, model, primary.strip(), "object"
    return "", "", "", "missing"


def build_model_ref(provider: str, model: str) -> str:
    """Compose the openclaw ``provider/model`` ref. Provider is used verbatim (no alias
    remapping — openclaw's provider ids like ``google`` live in the ref itself)."""
    prov = provider.strip()
    mdl = model.strip()
    return f"{prov}/{mdl}" if prov else mdl


def run_openclaw_models_set(container: str, ref: str, *, timeout: int = 180) -> tuple[bool, str]:
    """Change the slot's default model by running the product's own ``models set`` inside the
    live gateway container (``docker exec``). The container bind-mounts ``~/.openclaw`` from the
    host, so the write lands on the host config and hot-reloads. Tries candidate entrypoints and
    returns on the first that succeeds. Returns (ok, detail); detail names the entry that ran.
    """
    attempts: list[str] = []
    for entry in OPENCLAW_MODELS_SET_ENTRIES:
        proc = run_text(["docker", "exec", container, *entry, ref], timeout=timeout)
        if proc.returncode == 0:
            return True, f"entry={' '.join(entry)} exit=0"
        detail = ((proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}")[:150]
        attempts.append(f"'{' '.join(entry)}': {detail}")
    return False, "all entrypoints failed: " + " | ".join(attempts)
