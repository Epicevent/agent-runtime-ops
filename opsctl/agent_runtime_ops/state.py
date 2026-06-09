from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .paths import DEFAULT_STATE_ROOT, state_path
from .routing import SlotRoute, get_slot_route
from .yamlio import load_yaml


@dataclass(frozen=True)
class DesiredSlot:
    slot: str
    lane: str
    lane_data: dict
    release_name: str
    release_data: dict
    runtime_profile: str
    route: SlotRoute | None = None


def _lookup_slot(slots_data: dict, slot: str) -> dict:
    slots = slots_data.get("slots", {})
    if isinstance(slots, dict):
        data = slots.get(slot)
        if data is None:
            raise KeyError(f"slot not found: {slot}")
        return data or {}
    if isinstance(slots, list):
        for item in slots:
            if isinstance(item, dict) and item.get("slot") == slot:
                return item
    raise KeyError(f"slot not found: {slot}")


def load_desired_slot(slot: str, state_root: Path = DEFAULT_STATE_ROOT) -> DesiredSlot:
    slots_data = load_yaml(state_path(state_root, "slots.yaml"))
    lanes_data = load_yaml(state_path(state_root, "lanes.yaml"))
    releases_data = load_yaml(state_path(state_root, "releases.yaml"))

    slot_data = _lookup_slot(slots_data, slot)
    lane = slot_data.get("lane")
    if not lane:
        raise ValueError(f"slot has no lane: {slot}")

    lanes = lanes_data.get("lanes", {})
    lane_data = lanes.get(lane)
    if not isinstance(lane_data, dict):
        raise KeyError(f"lane not found: {lane}")

    release_name = lane_data.get("release")
    runtime_profile = lane_data.get("runtime_profile")
    if not release_name or not runtime_profile:
        raise ValueError(f"lane is missing release/runtime_profile: {lane}")

    releases = releases_data.get("releases", {})
    release_data = releases.get(release_name)
    if not isinstance(release_data, dict):
        raise KeyError(f"release not found: {release_name}")

    return DesiredSlot(
        slot=slot,
        lane=lane,
        lane_data=lane_data,
        release_name=release_name,
        release_data=release_data,
        runtime_profile=runtime_profile,
        route=get_slot_route(slot, state_root),
    )
