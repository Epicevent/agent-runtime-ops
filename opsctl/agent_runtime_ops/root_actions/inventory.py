from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
import re
from typing import Any

INVENTORY_SCHEMA = "agent-runtime-root-action-historical-inventory/v1"
EXPECTED_HISTORICAL_ACTION_COUNT = 59
EXPECTED_FAMILY_COUNTS = {
    "audit.verify": 30,
    "projection.staging_selftest": 3,
    "agent_loop.campaign_run": 7,
    "kwrag.candidate_build": 12,
    "kwrag.artifact_finalize": 3,
    "kwrag.runtime_verify": 2,
    "kwrag.network_ensure": 2,
}
_TOP_KEYS = {"schema", "source", "families"}
_SOURCE_KEYS = {
    "logical_root",
    "cutoff",
    "universe",
    "evidence_locator",
    "classification_boundary",
}
_FAMILY_KEYS = {"operation_id", "actions"}
_ACTION_RE = re.compile(r"[a-z0-9][a-z0-9.-]*\.sh")


class InventoryValidationError(ValueError):
    """Historical inventory membership or registry coverage is incomplete."""


@dataclass(frozen=True)
class InventoryCoverage:
    actual_count: int
    family_counts: tuple[tuple[str, int], ...]
    operation_ids: tuple[str, ...]


def load_historical_inventory() -> dict[str, Any]:
    resource = files(__package__).joinpath("historical_inventory_v1.json")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise InventoryValidationError(f"duplicate inventory key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            resource.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryValidationError(
            "historical inventory is not readable JSON"
        ) from exc
    if not isinstance(value, dict):
        raise InventoryValidationError("historical inventory must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise InventoryValidationError(f"{field} field set mismatch")
    return value


def validate_inventory_coverage(value: dict[str, Any]) -> InventoryCoverage:
    root = _exact_keys(value, _TOP_KEYS, "inventory")
    if root["schema"] != INVENTORY_SCHEMA:
        raise InventoryValidationError("inventory schema mismatch")
    source = _exact_keys(root["source"], _SOURCE_KEYS, "inventory.source")
    if any(not isinstance(source[key], str) or not source[key] for key in _SOURCE_KEYS):
        raise InventoryValidationError("inventory source metadata is incomplete")
    families = root["families"]
    if not isinstance(families, list):
        raise InventoryValidationError("inventory.families must be a list")

    family_counts: dict[str, int] = {}
    action_names: list[str] = []
    for index, raw_family in enumerate(families):
        family = _exact_keys(raw_family, _FAMILY_KEYS, f"inventory.families[{index}]")
        operation_id = family["operation_id"]
        if not isinstance(operation_id, str):
            raise InventoryValidationError("inventory operation_id must be a string")
        if operation_id in family_counts:
            raise InventoryValidationError(
                f"duplicate inventory family: {operation_id}"
            )
        actions = family["actions"]
        if not isinstance(actions, list) or not actions:
            raise InventoryValidationError(f"inventory family is empty: {operation_id}")
        if any(
            not isinstance(name, str) or _ACTION_RE.fullmatch(name) is None
            for name in actions
        ):
            raise InventoryValidationError(
                f"invalid action filename in family: {operation_id}"
            )
        family_counts[operation_id] = len(actions)
        action_names.extend(actions)

    if len(set(action_names)) != len(action_names):
        raise InventoryValidationError(
            "historical inventory contains duplicate actions"
        )
    if len(action_names) != EXPECTED_HISTORICAL_ACTION_COUNT:
        raise InventoryValidationError(
            f"historical inventory count mismatch expected={EXPECTED_HISTORICAL_ACTION_COUNT} "
            f"actual={len(action_names)}"
        )
    if family_counts != EXPECTED_FAMILY_COUNTS:
        raise InventoryValidationError(
            f"historical family counts mismatch expected={EXPECTED_FAMILY_COUNTS} "
            f"actual={family_counts}"
        )
    return InventoryCoverage(
        actual_count=len(action_names),
        family_counts=tuple(sorted(family_counts.items())),
        operation_ids=tuple(sorted(family_counts)),
    )


HISTORICAL_INVENTORY = load_historical_inventory()
INVENTORY_COVERAGE = validate_inventory_coverage(HISTORICAL_INVENTORY)
