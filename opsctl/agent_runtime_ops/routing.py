from __future__ import annotations

from dataclasses import dataclass
import json
import re
import uuid
from pathlib import Path
from typing import Any

from .paths import DEFAULT_STATE_ROOT
RUNTIME_BINDINGS_NAME = "runtime-bindings.json"

LINUX_ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
UPSTREAM_KINDS = {"managed-rootful", "developer-rootless"}

ALLOWED_BINDING_KEYS = {
    "instance_id",
    "linux_account",
    "public_host",
    "family",
    "runtime_class",
    "gateway_port",
    "bridge_port",
    "enabled",
    "upstream_kind",
    "upstream_owner",
    "upstream_container",
}
FORBIDDEN_BINDING_KEYS = {
    "lane",
    "release",
    "runtime_profile",
    "wrapper_image",
    "product_image",
    "canonical_recipe_name",
    "canonical_recipe_digest",
}


@dataclass(frozen=True)
class RuntimeBinding:
    instance_id: str
    linux_account: str
    public_host: str
    family: str
    runtime_class: str
    gateway_port: int
    bridge_port: int
    enabled: bool = True
    upstream_kind: str = "managed-rootful"
    upstream_owner: str = ""
    upstream_container: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "instance_id": self.instance_id,
            "linux_account": self.linux_account,
            "public_host": self.public_host,
            "family": self.family,
            "runtime_class": self.runtime_class,
            "gateway_port": self.gateway_port,
            "bridge_port": self.bridge_port,
            "enabled": self.enabled,
            "upstream_kind": self.upstream_kind,
            "upstream_owner": self.upstream_owner,
            "upstream_container": self.upstream_container,
        }


def runtime_bindings_path(state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    return state_root / RUNTIME_BINDINGS_NAME


def validate_linux_account(value: object) -> str:
    account = str(value or "").strip()
    if not LINUX_ACCOUNT_RE.match(account):
        raise ValueError("linux_account must be a safe Unix account name")
    return account


def validate_runtime_class(value: object) -> str:
    runtime_class = str(value or "").strip()
    if runtime_class not in {"customer", "dev"}:
        raise ValueError("runtime_class must be customer or dev")
    return runtime_class


def validate_family(value: object) -> str:
    family = str(value or "").strip()
    if not FAMILY_RE.match(family):
        raise ValueError("family must be a safe lower-case name")
    return family


def validate_instance_id(value: object) -> str:
    instance_id = str(value or "").strip().lower()
    if not instance_id:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(instance_id))
    except ValueError as exc:
        raise ValueError("instance_id must be a UUID") from exc


def validate_public_host(value: object) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not HOST_RE.match(host):
        raise ValueError("public_host must be a DNS name without scheme, port, path, or whitespace")
    return host


def _port(value: object, name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer port") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be in 1..65535")
    return port


def _binding_from_item(item: dict[str, Any]) -> RuntimeBinding:
    keys = set(item)
    forbidden = sorted(keys & FORBIDDEN_BINDING_KEYS)
    if forbidden:
        raise ValueError("runtime binding must not contain runtime result fields: " + ",".join(forbidden))
    unknown = sorted(keys - ALLOWED_BINDING_KEYS)
    if unknown:
        raise ValueError("runtime binding has unknown fields: " + ",".join(unknown))
    upstream_kind = str(item.get("upstream_kind") or "managed-rootful")
    if upstream_kind not in UPSTREAM_KINDS:
        raise ValueError("upstream_kind must be managed-rootful or developer-rootless")
    upstream_owner = validate_linux_account(item.get("upstream_owner")) if item.get("upstream_owner") else ""
    upstream_container = validate_linux_account(item.get("upstream_container")) if item.get("upstream_container") else ""
    if upstream_kind == "developer-rootless" and (not upstream_owner or not upstream_container):
        raise ValueError("developer-rootless binding requires upstream owner and container")
    if upstream_kind == "managed-rootful" and (upstream_owner or upstream_container):
        raise ValueError("managed-rootful binding must not name a rootless upstream")
    return RuntimeBinding(
        instance_id=validate_instance_id(item.get("instance_id")),
        linux_account=validate_linux_account(item.get("linux_account")),
        public_host=validate_public_host(item.get("public_host")),
        family=validate_family(item.get("family")),
        runtime_class=validate_runtime_class(item.get("runtime_class")),
        gateway_port=_port(item.get("gateway_port"), "gateway_port"),
        bridge_port=_port(item.get("bridge_port"), "bridge_port"),
        enabled=bool(item.get("enabled", True)),
        upstream_kind=upstream_kind,
        upstream_owner=upstream_owner,
        upstream_container=upstream_container,
    )


def _validate_unique_bindings(bindings: list[RuntimeBinding]) -> None:
    seen: dict[str, set[object]] = {
        "instance_id": set(),
        "linux_account": set(),
        "public_host": set(),
        "gateway_port": set(),
        "bridge_port": set(),
    }
    for binding in bindings:
        values = {
            "instance_id": binding.instance_id,
            "linux_account": binding.linux_account,
            "public_host": binding.public_host,
            "gateway_port": binding.gateway_port,
            "bridge_port": binding.bridge_port,
        }
        for name, value in values.items():
            if value in seen[name]:
                raise ValueError(f"duplicate {name} in runtime bindings: {value}")
            seen[name].add(value)


def load_runtime_bindings(state_root: Path = DEFAULT_STATE_ROOT) -> list[RuntimeBinding]:
    path = runtime_bindings_path(state_root)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw_bindings = data.get("bindings") if isinstance(data, dict) else None
    if not isinstance(raw_bindings, list):
        raise ValueError("runtime-bindings.json must contain a bindings list")
    bindings = [_binding_from_item(item) for item in raw_bindings if isinstance(item, dict)]
    if len(bindings) != len(raw_bindings):
        raise ValueError("runtime-bindings.json bindings must be objects")
    _validate_unique_bindings(bindings)
    return bindings


def dump_runtime_bindings(bindings: list[RuntimeBinding]) -> str:
    _validate_unique_bindings(bindings)
    data = {
        "schema": "v1",
        "description": (
            "Runtime binding declarations. Apache is actual route state; running image labels are actual runtime state."
        ),
        "bindings": [binding.to_json() for binding in bindings],
    }
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def get_runtime_binding(target: str, state_root: Path = DEFAULT_STATE_ROOT) -> RuntimeBinding:
    normalized = str(target or "").strip().lower().rstrip(".")
    for binding in load_runtime_bindings(state_root):
        if normalized in {binding.instance_id, binding.linux_account, binding.public_host}:
            return binding
    raise KeyError(f"runtime binding not found: {target}")


def replace_runtime_binding(
    bindings: list[RuntimeBinding],
    instance_id: str,
    replacement: RuntimeBinding,
) -> list[RuntimeBinding]:
    changed = False
    rows: list[RuntimeBinding] = []
    for binding in bindings:
        if binding.instance_id == instance_id:
            rows.append(replacement)
            changed = True
        else:
            rows.append(binding)
    if not changed:
        raise KeyError(f"runtime binding not found: {instance_id}")
    _validate_unique_bindings(rows)
    return rows
