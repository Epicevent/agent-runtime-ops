from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
from urllib.parse import urlparse

from ..host.account_files import ensure_not_symlink_chain, runtime_ids, slot_home
from ..host.files import fsync_parent
from ..yamlio import dump_yaml, load_yaml


RUNTIME_PROVIDER_ALIASES = {
    "google": "gemini",
    "google-ai": "gemini",
    "google_ai": "gemini",
    "google-gemini": "gemini",
    "google_gemini": "gemini",
    "gemini": "gemini",
}
RUNTIME_CONFIG_SECRET_OVERRIDE_PATHS = (
    ("providers", "google", "api_key"),
    ("providers", "google", "apiKey"),
    ("providers", "google", "key"),
    ("providers", "gemini", "api_key"),
    ("providers", "gemini", "apiKey"),
    ("providers", "gemini", "key"),
    ("auth", "google", "api_key"),
    ("auth", "gemini", "api_key"),
)


def runtime_provider_id(value: str) -> str:
    raw = value.strip().lower()
    return RUNTIME_PROVIDER_ALIASES.get(raw, raw)


# Canonical first-party endpoint host (substring) by normalized provider id.
# A model.base_url whose host is inconsistent with the provider misroutes every
# request: a gemini/google provider pointed at openrouter.ai authenticates a
# Google key against a keyless aggregator and 401s (the exact drift that made a
# dev slot's gemini traffic hang). set-model writes NO base_url for these
# providers, so a lingering one — carried over from a previous provider — is
# drift. Providers absent from this map (deliberate custom gateways) are judged
# "unknown" rather than flagged, so intentional endpoints are not false-positived.
_PROVIDER_CANONICAL_HOST = {
    "gemini": "googleapis.com",  # google/google-ai aliases normalize to gemini
    "anthropic": "anthropic.com",
    "openai": "openai.com",
    "openrouter": "openrouter.ai",
}

# model-level keys that pin request routing to a specific endpoint/protocol.
# set-model drops all three on a provider change; a leftover misroutes traffic.
_MODEL_ROUTING_KEYS = ("base_url", "api_key", "api_mode")


def _url_host(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url if "://" in url else "//" + url)
    except Exception:
        return ""
    return (parsed.hostname or "").lower()


def model_endpoint_drift(config: dict[str, object]) -> dict[str, object]:
    """Assess whether ``config.model`` carries request-routing overrides that are
    inconsistent with its provider — the misroute drift that ``set-model`` clears.

    verdict:
      * ``"clean"``   — no base_url, or base_url host matches the provider.
      * ``"drift"``   — base_url host does not match a known first-party provider.
      * ``"unknown"`` — a custom base_url on a provider with no canonical host
                         (a deliberate gateway we cannot second-guess).

    ``routing_keys`` lists which of base_url/api_key/api_mode are present, so a
    stale api_key/api_mode left behind is visible even when the verdict is clean.
    """
    model_value = config.get("model")
    if isinstance(model_value, dict):
        provider_raw = str(model_value.get("provider") or config.get("provider") or "").strip()
        base_url = str(model_value.get("base_url") or "").strip()
        routing_keys = [key for key in _MODEL_ROUTING_KEYS if model_value.get(key)]
    else:
        provider_raw = str(config.get("provider") or "").strip()
        base_url = ""
        routing_keys = []
    provider = runtime_provider_id(provider_raw) if provider_raw else ""
    host = _url_host(base_url)
    expected_host = _PROVIDER_CANONICAL_HOST.get(provider, "")

    if not base_url:
        verdict = "clean"
        reason = "no custom endpoint"
    elif not expected_host:
        verdict = "unknown"
        reason = f"provider={provider or 'missing'} has no canonical host; base_url={host or base_url}"
    elif host and expected_host in host:
        verdict = "clean"
        reason = f"base_url host {host} matches provider {provider}"
    else:
        verdict = "drift"
        reason = f"base_url host {host or base_url!r} does not match provider {provider} (expected *{expected_host})"

    return {
        "verdict": verdict,
        "reason": reason,
        "provider": provider,
        "base_url": base_url,
        "host": host,
        "expected_host": expected_host,
        "routing_keys": routing_keys,
    }


def hermes_config_path(slot: str) -> Path:
    home = slot_home(slot).resolve(strict=False)
    path = home / ".hermes" / "config.yaml"
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"config path outside slot home: {path}")
    ensure_not_symlink_chain(path.parent, home)
    if path.exists() and path.is_symlink():
        raise ValueError(f"config file must not be a symlink: {path}")
    return path


def read_hermes_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError(f"config path is not a regular file: {path}")
    data = load_yaml(path, default={})
    if not isinstance(data, dict):
        raise ValueError(f"config must be a mapping: {path}")
    return dict(data)


def current_model(config: dict[str, object]) -> tuple[str, str, str]:
    model_value = config.get("model")
    provider = str(config.get("provider") or "").strip()
    if isinstance(model_value, dict):
        nested_provider = str(model_value.get("provider") or provider).strip()
        nested_model = str(model_value.get("default") or model_value.get("model") or "").strip()
        return nested_provider, nested_model, "nested"
    if isinstance(model_value, str):
        return provider, model_value.strip(), "flat"
    return provider, "", "missing"


def write_hermes_config(slot: str, path: Path, config: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        current = path.stat()
        uid, gid = current.st_uid, current.st_gid
        mode = stat.S_IMODE(current.st_mode) or 0o600
    else:
        uid, _, gid = runtime_ids(slot)
        mode = 0o600
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(dump_yaml(config))
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _remove_nested_config_key(config: dict[str, object], path: tuple[str, ...]) -> tuple[bool, bool]:
    node: object = config
    for part in path[:-1]:
        if not isinstance(node, dict):
            return False, False
        node = node.get(part)
    if not isinstance(node, dict):
        return False, False
    leaf = path[-1]
    if leaf not in node:
        return False, False
    value = node.pop(leaf)
    return True, bool(value)


def sanitize_config_secret_overrides(config: dict[str, object]) -> tuple[dict[str, object], list[tuple[tuple[str, ...], bool]]]:
    sanitized = copy.deepcopy(config)
    removed: list[tuple[tuple[str, ...], bool]] = []
    for path in RUNTIME_CONFIG_SECRET_OVERRIDE_PATHS:
        did_remove, value_present = _remove_nested_config_key(sanitized, path)
        if did_remove:
            removed.append((path, value_present))
    return sanitized, removed
