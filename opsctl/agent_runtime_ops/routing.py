from __future__ import annotations

from dataclasses import dataclass
import json
import re
import uuid
from pathlib import Path
from typing import Any

from .paths import DEFAULT_STATE_ROOT
from .yamlio import load_yaml

LEGACY_ROUTING_REGISTRY_NAME = "slot-registry.json"
RUNTIME_BINDINGS_NAME = "runtime-bindings.json"

LINUX_ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FAMILY_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

ALLOWED_BINDING_KEYS = {
    "instance_id",
    "linux_account",
    "public_host",
    "family",
    "runtime_class",
    "gateway_port",
    "bridge_port",
    "enabled",
}
ALLOWED_LEGACY_ROUTE_KEYS = {"slot", "gateway_port", "bridge_port", "enabled", "public_host", "notes", "instance_id"}
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
        }


def legacy_routing_registry_path(state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    return state_root / LEGACY_ROUTING_REGISTRY_NAME


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
    return RuntimeBinding(
        instance_id=validate_instance_id(item.get("instance_id")),
        linux_account=validate_linux_account(item.get("linux_account")),
        public_host=validate_public_host(item.get("public_host")),
        family=validate_family(item.get("family")),
        runtime_class=validate_runtime_class(item.get("runtime_class")),
        gateway_port=_port(item.get("gateway_port"), "gateway_port"),
        bridge_port=_port(item.get("bridge_port"), "bridge_port"),
        enabled=bool(item.get("enabled", True)),
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


def _legacy_slot_lanes(state_root: Path) -> dict[str, dict[str, str]]:
    slots_data = load_yaml(state_root / "slots.yaml")
    lanes_data = load_yaml(state_root / "lanes.yaml")
    slots = slots_data.get("slots") if isinstance(slots_data, dict) else None
    lanes = lanes_data.get("lanes") if isinstance(lanes_data, dict) else None
    if not isinstance(lanes, dict):
        raise ValueError("lanes.yaml must contain a lanes mapping")
    if isinstance(slots, dict):
        iterable = [(str(name), data) for name, data in slots.items()]
    elif isinstance(slots, list):
        iterable = [(str(item.get("slot")), item) for item in slots if isinstance(item, dict) and item.get("slot")]
    else:
        raise ValueError("slots.yaml must contain a slots mapping or list")

    rows: dict[str, dict[str, str]] = {}
    for account, data in iterable:
        lane = data.get("lane") if isinstance(data, dict) else None
        lane_data = lanes.get(lane) if lane else None
        if not isinstance(lane_data, dict):
            raise ValueError(f"lane not found for linux_account={account}: {lane}")
        rows[account] = {
            "family": validate_family(lane_data.get("family")),
            "runtime_class": validate_runtime_class(lane_data.get("slot_class")),
        }
    return rows


def _load_legacy_route_items(state_root: Path) -> list[dict[str, Any]]:
    path = legacy_routing_registry_path(state_root)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw_routes = data.get("slots") if isinstance(data, dict) else None
    if not isinstance(raw_routes, list):
        raise ValueError("slot-registry.json must contain a slots list")
    if not all(isinstance(item, dict) for item in raw_routes):
        raise ValueError("slot-registry.json slots must be objects")
    return raw_routes


def _legacy_public_host(account: str, item: dict[str, Any]) -> str:
    if item.get("public_host"):
        return validate_public_host(item.get("public_host"))
    try:
        from .apache import parse_apache_route

        return parse_apache_route(account).public_host
    except Exception:
        return validate_public_host(f"{account}.ji-tech.co.kr")


def migrate_legacy_runtime_bindings(state_root: Path = DEFAULT_STATE_ROOT) -> list[RuntimeBinding]:
    metadata = _legacy_slot_lanes(state_root)
    bindings: list[RuntimeBinding] = []
    for item in _load_legacy_route_items(state_root):
        keys = set(item)
        forbidden = sorted(keys & FORBIDDEN_BINDING_KEYS)
        if forbidden:
            raise ValueError("legacy slot-registry contains runtime result fields: " + ",".join(forbidden))
        unknown = sorted(keys - ALLOWED_LEGACY_ROUTE_KEYS)
        if unknown:
            raise ValueError("legacy slot-registry has unknown fields: " + ",".join(unknown))
        account = validate_linux_account(item.get("slot"))
        if account not in metadata:
            raise ValueError(f"cannot resolve legacy family/runtime_class for linux_account={account}")
        bindings.append(
            RuntimeBinding(
                instance_id=validate_instance_id(item.get("instance_id")),
                linux_account=account,
                public_host=_legacy_public_host(account, item),
                family=metadata[account]["family"],
                runtime_class=metadata[account]["runtime_class"],
                gateway_port=_port(item.get("gateway_port"), "gateway_port"),
                bridge_port=_port(item.get("bridge_port"), "bridge_port"),
                enabled=bool(item.get("enabled", True)),
            )
        )
    _validate_unique_bindings(bindings)
    return bindings
