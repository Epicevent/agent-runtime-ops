from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
from typing import Any

LINUX_ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TARGET_RE = re.compile(
    r"^(?:[a-z][a-z0-9-]{0,31}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$"
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
SENSITIVE_ARGUMENTS = {
    "api_key",
    "apikey",
    "key_value",
    "password",
    "passwd",
    "raw_secret",
    "secret",
    "secret_value",
    "token",
    "value",
}


def default_secret_roots() -> list[Path]:
    raw = os.environ.get(
        "AGENT_RUNTIME_OPS_SECRET_ROOTS",
        "/home/svcops/.codex-secrets:/home/svcops/.secrets:/srv/openclaw-ops/secrets",
    )
    return [Path(item).expanduser() for item in raw.split(os.pathsep) if item]


def parse_key_value_tokens(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for token in shlex.split(text):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def reject_unknown(args: dict[str, Any], allowed: set[str], *, error_type: type[Exception]) -> None:
    unknown = sorted(set(args) - allowed)
    if unknown:
        lowered = {item.lower().replace("-", "_") for item in unknown}
        if lowered & SENSITIVE_ARGUMENTS:
            raise error_type("raw secret argument rejected; pass an allowed secret_file path or a manual stdin flow")
        raise error_type("unsupported argument(s): " + ",".join(unknown))


def reject_sensitive_raw_args(args: dict[str, Any], *, allowed: set[str] | None = None, error_type: type[Exception]) -> None:
    allowed = allowed or set()
    for key in args:
        normalized = key.lower().replace("-", "_")
        if key not in allowed and normalized in SENSITIVE_ARGUMENTS:
            raise error_type("raw secret argument rejected; pass an allowed secret_file path or a manual stdin flow")


def linux_account(value: Any, *, error_type: type[Exception]) -> str:
    account = str(value or "").strip()
    if not LINUX_ACCOUNT_RE.match(account):
        raise error_type("linux_account must be a safe Unix account name")
    return account


def target(value: Any, *, error_type: type[Exception]) -> str:
    target_value = str(value or "").strip().lower().rstrip(".")
    if not TARGET_RE.match(target_value):
        raise error_type("target must be a linux account, public host, or instance UUID")
    return target_value


def family(value: Any, *, error_type: type[Exception]) -> str:
    family_value = str(value or "")
    if family_value not in {"hermes", "openclaw"}:
        raise error_type("family must be hermes or openclaw")
    return family_value


def safe_name(value: Any, *, error_type: type[Exception]) -> str:
    name = str(value or "")
    if not SAFE_NAME_RE.match(name):
        raise error_type("name must contain only letters, numbers, '.', '_', or '-'")
    return name


def image_ref(value: Any, *, error_type: type[Exception]) -> str:
    image_ref_value = str(value or "")
    if not IMAGE_REF_RE.match(image_ref_value):
        raise error_type("image reference must be digest-pinned as REGISTRY/IMAGE@sha256:<64 hex>")
    return image_ref_value


def host(value: Any, *, error_type: type[Exception]) -> str:
    host_value = str(value or "").strip().lower().rstrip(".")
    if not HOST_RE.match(host_value):
        raise error_type("host must be a DNS name without scheme, port, path, or whitespace")
    return host_value


def safe_text(value: Any, name: str, *, error_type: type[Exception]) -> str:
    text = str(value or "").strip()
    if text and not SAFE_TEXT_RE.match(text):
        raise error_type(f"{name} must not contain control characters")
    return text


def boolean_arg(args: dict[str, Any], name: str, *, default: bool, error_type: type[Exception]) -> bool:
    if name not in args:
        return default
    value = args[name]
    if not isinstance(value, bool):
        raise error_type(f"{name} must be a boolean")
    return value


def path_text(value: Any, name: str, *, error_type: type[Exception]) -> str:
    text = safe_text(value, name, error_type=error_type)
    if not text.startswith("/"):
        raise error_type(f"{name} must be an absolute path")
    return text


def slots(args: dict[str, Any], *, error_type: type[Exception]) -> list[str]:
    has_slot = args.get("target") is not None
    has_slots = args.get("targets") is not None
    has_runtime_class = args.get("runtime_class") is not None
    if sum([has_slot, has_slots, has_runtime_class]) != 1:
        raise error_type("provide exactly one of target, targets, or runtime_class")
    if has_slot:
        return [linux_account(args.get("target"), error_type=error_type)]
    if has_runtime_class:
        raise error_type("runtime_class requires current target resolution")
    raw_slots = args.get("targets")
    if not isinstance(raw_slots, list) or not raw_slots:
        raise error_type("targets must be a non-empty array")
    return [linux_account(item, error_type=error_type) for item in raw_slots]


def resolve_slots(server, args: dict[str, Any], *, error_type: type[Exception]) -> tuple[list[str], list[dict[str, Any]]]:
    if args.get("runtime_class") is None:
        return slots(args, error_type=error_type), []
    runtime_class = str(args.get("runtime_class") or "")
    if runtime_class not in {"customer", "dev"}:
        raise error_type("runtime_class must be customer or dev")
    family_value = args.get("family")
    if family_value is not None:
        family_value = str(family_value)
        if family_value not in {"hermes", "openclaw"}:
            raise error_type("family must be hermes or openclaw")
    binding_list = server._run([server.opsctl, "binding", "list"], timeout=60)
    if binding_list["returncode"] != 0:
        return [], [binding_list]
    runs = [binding_list]
    slot_values: list[str] = []
    for raw_line in binding_list["stdout"].splitlines():
        row = parse_key_value_tokens(raw_line)
        if row.get("runtime_class") != runtime_class:
            continue
        slot_value = row.get("linux_account") or row.get("target")
        if family_value and row.get("family") != family_value:
            continue
        if slot_value:
            slot_values.append(linux_account(slot_value, error_type=error_type))
    if not slot_values:
        raise error_type("no targets matched runtime_class/family")
    return slot_values, runs


def share(value: Any, *, error_type: type[Exception]) -> str:
    share_value = str(value or "")
    if not share_value.startswith("//") or any(ch in share_value for ch in "\r\n\t"):
        raise error_type("share must be an SMB path like //HOST/SHARE")
    return share_value


def read_allowed_secret_file(value: Any, secret_roots: list[Path], *, error_type: type[Exception]) -> str:
    if not value:
        raise error_type("secret_file is required")
    path = Path(str(value)).expanduser()
    try:
        if path.is_symlink():
            raise error_type("secret_file must not be a symlink")
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise error_type(f"secret_file is not readable: {exc}") from exc
    allowed_roots = [root.expanduser().resolve(strict=False) for root in secret_roots]
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise error_type("secret_file must be under an allowed secret root")
    if not resolved.is_file():
        raise error_type("secret_file must be a regular file")
    value_text = resolved.read_text(encoding="utf-8", errors="replace").strip()
    if not value_text:
        raise error_type("secret_file is empty")
    return value_text
