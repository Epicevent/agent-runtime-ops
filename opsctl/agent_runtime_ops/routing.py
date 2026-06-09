from __future__ import annotations

from dataclasses import dataclass
import json
import re
from pathlib import Path
from typing import Any

from .paths import DEFAULT_STATE_ROOT
from .yamlio import load_yaml

ROUTING_REGISTRY_NAME = "slot-registry.json"
CUSTOMER_SLOT_RE = re.compile(r"^oc[0-9]+$")
DEV_SLOT_RE = re.compile(r"^dev-[a-z0-9-]+$")
ALLOWED_ROUTE_KEYS = {"slot", "gateway_port", "bridge_port", "enabled"}
LEGACY_ROUTE_KEYS = {"public_host", "notes"}
FORBIDDEN_ROUTE_KEYS = {
    "family",
    "lane",
    "release",
    "runtime_profile",
    "wrapper_image",
    "product_image",
    "canonical_recipe_name",
    "canonical_recipe_digest",
}


@dataclass(frozen=True)
class SlotRoute:
    slot: str
    gateway_port: int
    bridge_port: int
    enabled: bool = True

    @property
    def slot_class(self) -> str:
        return slot_class_from_name(self.slot)

    def as_render_vars(self) -> dict[str, str]:
        return {
            "gateway_port": str(self.gateway_port),
            "bridge_port": str(self.bridge_port),
        }

    def to_json(self) -> dict[str, object]:
        data: dict[str, object] = {
            "slot": self.slot,
            "gateway_port": self.gateway_port,
            "bridge_port": self.bridge_port,
            "enabled": self.enabled,
        }
        return data


def routing_registry_path(state_root: Path = DEFAULT_STATE_ROOT) -> Path:
    return state_root / ROUTING_REGISTRY_NAME


def slot_class_from_name(slot: str) -> str:
    if CUSTOMER_SLOT_RE.match(slot):
        return "customer"
    if DEV_SLOT_RE.match(slot):
        return "dev"
    raise ValueError(f"invalid slot name: {slot}")


def _port(value: object, name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer port") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be in 1..65535")
    return port


def _route_from_item(item: dict[str, Any]) -> SlotRoute:
    keys = set(item)
    forbidden = sorted(keys & FORBIDDEN_ROUTE_KEYS)
    if forbidden:
        raise ValueError("routing registry must not contain runtime truth fields: " + ",".join(forbidden))
    unknown = sorted(keys - ALLOWED_ROUTE_KEYS - LEGACY_ROUTE_KEYS)
    if unknown:
        raise ValueError("routing registry has unknown fields: " + ",".join(unknown))
    slot = str(item.get("slot") or "").strip()
    slot_class_from_name(slot)
    return SlotRoute(
        slot=slot,
        gateway_port=_port(item.get("gateway_port"), "gateway_port"),
        bridge_port=_port(item.get("bridge_port"), "bridge_port"),
        enabled=bool(item.get("enabled", True)),
    )


def load_routing_registry(state_root: Path = DEFAULT_STATE_ROOT) -> list[SlotRoute]:
    path = routing_registry_path(state_root)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw_routes = data.get("slots") if isinstance(data, dict) else None
    if not isinstance(raw_routes, list):
        raise ValueError("slot-registry.json must contain a slots list")
    routes = [_route_from_item(item) for item in raw_routes if isinstance(item, dict)]
    if len(routes) != len(raw_routes):
        raise ValueError("slot-registry.json slots must be objects")
    seen_slots: set[str] = set()
    seen_ports: set[int] = set()
    for route in routes:
        if route.slot in seen_slots:
            raise ValueError(f"duplicate slot in routing registry: {route.slot}")
        seen_slots.add(route.slot)
        for port_name, port in (("gateway_port", route.gateway_port), ("bridge_port", route.bridge_port)):
            if port in seen_ports:
                raise ValueError(f"duplicate {port_name} in routing registry: {port}")
            seen_ports.add(port)
    return routes


def get_slot_route(slot: str, state_root: Path = DEFAULT_STATE_ROOT) -> SlotRoute:
    for route in load_routing_registry(state_root):
        if route.slot == slot:
            return route
    raise KeyError(f"slot route not found: {slot}")


def _legacy_seed_ports(slot: str) -> tuple[int, int]:
    if slot == "dev-oc":
        return 30789, 30790
    if slot == "dev-hermess":
        return 30889, 30890
    match = re.match(r"^oc([0-9]+)$", slot)
    if not match:
        raise ValueError(f"cannot seed ports for slot: {slot}")
    gateway_port = 28789 + (int(match.group(1)) - 1) * 100
    return gateway_port, gateway_port + 1


def legacy_slot_names(state_root: Path = DEFAULT_STATE_ROOT) -> list[str]:
    data = load_yaml(state_root / "slots.yaml")
    slots = data.get("slots") if isinstance(data, dict) else None
    names: list[str] = []
    if isinstance(slots, dict):
        names = [str(name) for name in slots]
    elif isinstance(slots, list):
        names = [str(item.get("slot")) for item in slots if isinstance(item, dict) and item.get("slot")]
    else:
        raise ValueError("slots.yaml must contain a slots mapping or list")
    return sorted(names, key=lambda value: (slot_class_from_name(value), value))


def seed_routes_from_legacy_slots(state_root: Path = DEFAULT_STATE_ROOT) -> list[SlotRoute]:
    routes: list[SlotRoute] = []
    for slot in legacy_slot_names(state_root):
        gateway_port, bridge_port = _legacy_seed_ports(slot)
        routes.append(
            SlotRoute(
                slot=slot,
                gateway_port=gateway_port,
                bridge_port=bridge_port,
                enabled=True,
            )
        )
    return routes


def dump_routing_registry(routes: list[SlotRoute]) -> str:
    data = {
        "schema": "v2",
        "description": "Slot port allocation only. Public host truth is read from Apache; runtime image truth is not stored here.",
        "slots": [route.to_json() for route in routes],
    }
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
