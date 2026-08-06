from __future__ import annotations

import json
import re
from typing import Any

OPERATION_ID = "nas.observe_oc_slots"
OPERATION_VERSION = 1
PROFILE = "oc16-oc20-groupware-and-oc17-detach-prestate-v1"
SOURCE_CONTRACT_DIGEST = (
    "sha256:52555cee9658da2886594f06aaff48b20c5050f2de626ac14385e867a2269321"
)
RECEIPT_SCHEMA = "agent-runtime-root-action-nas-observe-oc-slots-receipt/v1"
PUBLIC_FACT_ORDER = (
    "nas_observation_header",
    "nas_observation_oc16",
    "nas_observation_oc20",
    "nas_observation_oc17",
    "nas_observation_component_receipts",
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ID_RE = re.compile(r"[a-z][a-z0-9._-]{0,127}")
_HEADER_KEYS = (
    "schema",
    "profile",
    "source_contract_digest",
    "expected_nonroot_prestate_digest",
    "observed_nonroot_prestate_match",
    "observation_complete",
    "operational_verdict",
    "writes",
)
_SLOT_KEYS = (
    "slot",
    "alias_ordinals",
    "present_bits",
    "readonly_bits",
    "readable_bits",
    "count_complete_bits",
    "alias_identity_digests",
    "runtime_identity_digest",
    "reason_codes",
)
_OC17_KEYS = (
    "ops_release_matches",
    "ops_release_digest",
    "host_mount_count",
    "host_mount_digest",
    "container_mount_count",
    "container_mount_digest",
    "logical_record_count",
    "logical_record_digest",
    "intent_status",
    "assignment_count",
    "recreation_blocker_count",
    "recreation_blocker_digest",
    "workspace_mount_count",
    "workspace_mount_digest",
    "session_count",
    "session_digest",
    "process_count",
    "process_digest",
    "gpu_process_count",
    "gpu_process_digest",
    "credential_count",
    "credential_digest",
    "protected_read_guard_stable",
    "reason_codes",
)
_OC17_COUNT_DIGEST_PAIRS = (
    ("host_mount_count", "host_mount_digest"),
    ("container_mount_count", "container_mount_digest"),
    ("logical_record_count", "logical_record_digest"),
    ("recreation_blocker_count", "recreation_blocker_digest"),
    ("workspace_mount_count", "workspace_mount_digest"),
    ("session_count", "session_digest"),
    ("process_count", "process_digest"),
    ("gpu_process_count", "gpu_process_digest"),
    ("credential_count", "credential_digest"),
)


class NasObservationValidationError(ValueError):
    pass


def _exact(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise NasObservationValidationError(f"{label} field set is invalid")
    return value


def _digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise NasObservationValidationError(f"{label} is not a canonical digest")


def _count(value: Any, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 1_000_000
    ):
        raise NasObservationValidationError(f"{label} is not a bounded count")


def _reasons(value: Any, label: str, max_items: int) -> None:
    if (
        not isinstance(value, list)
        or len(value) > max_items
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str) or _ID_RE.fullmatch(item) is None
            for item in value
        )
    ):
        raise NasObservationValidationError(f"{label} is not a bounded reason list")


def _slot(value: Any, slot: str, ordinals: tuple[int, ...]) -> None:
    item = _exact(value, _SLOT_KEYS, slot)
    if item["slot"] != slot or item["alias_ordinals"] != list(ordinals):
        raise NasObservationValidationError(f"{slot} identity is invalid")
    for name in (
        "present_bits",
        "readonly_bits",
        "readable_bits",
        "count_complete_bits",
    ):
        bits = item[name]
        if (
            not isinstance(bits, list)
            or len(bits) != len(ordinals)
            or any(type(bit) is not bool for bit in bits)
        ):
            raise NasObservationValidationError(f"{slot}.{name} is invalid")
    digests = item["alias_identity_digests"]
    if not isinstance(digests, list) or len(digests) != len(ordinals):
        raise NasObservationValidationError(f"{slot} alias identities are incomplete")
    for index, digest in enumerate(digests):
        _digest(digest, f"{slot}.alias_identity_digests[{index}]")
    _digest(item["runtime_identity_digest"], f"{slot}.runtime_identity_digest")
    _reasons(item["reason_codes"], f"{slot}.reason_codes", 16)


def _oc17(value: Any) -> None:
    item = _exact(value, _OC17_KEYS, "oc17")
    if (
        type(item["ops_release_matches"]) is not bool
        or type(item["protected_read_guard_stable"]) is not bool
    ):
        raise NasObservationValidationError("oc17 boolean summary is invalid")
    _digest(item["ops_release_digest"], "oc17.ops_release_digest")
    for count_name, digest_name in _OC17_COUNT_DIGEST_PAIRS:
        _count(item[count_name], f"oc17.{count_name}")
        _digest(item[digest_name], f"oc17.{digest_name}")
    _count(item["assignment_count"], "oc17.assignment_count", nullable=True)
    if item["intent_status"] not in {"present", "absent", "unknown"}:
        raise NasObservationValidationError("oc17.intent_status is invalid")
    _reasons(item["reason_codes"], "oc17.reason_codes", 24)


def validate_public_projection(value: Any) -> dict[str, Any]:
    keys = (*_HEADER_KEYS, "oc16", "oc20", "oc17", "component_receipt_digests")
    projection = _exact(value, keys, "nas observation")
    if (
        projection["schema"] != RECEIPT_SCHEMA
        or projection["profile"] != PROFILE
        or projection["source_contract_digest"] != SOURCE_CONTRACT_DIGEST
        or projection["writes"] != 0
        or projection["operational_verdict"]
        not in {"green", "red", "observation_failed"}
        or type(projection["observed_nonroot_prestate_match"]) is not bool
        or type(projection["observation_complete"]) is not bool
    ):
        raise NasObservationValidationError("nas observation fixed values are invalid")
    _digest(
        projection["expected_nonroot_prestate_digest"],
        "expected_nonroot_prestate_digest",
    )
    _slot(projection["oc16"], "oc16", (1, 2))
    _slot(projection["oc20"], "oc20", (3, 4, 5))
    _oc17(projection["oc17"])
    receipts = _exact(
        projection["component_receipt_digests"],
        ("oc16_20_groupware", "oc17_prestate"),
        "component receipts",
    )
    for name, digest in receipts.items():
        _digest(digest, f"component_receipt_digests.{name}")
    canonical = json.dumps(
        projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    if len(canonical.encode("utf-8")) > 4096:
        raise NasObservationValidationError(
            "nas observation projection exceeds 4096 bytes"
        )
    return projection


def public_facts(value: Any) -> tuple[tuple[str, str], ...]:
    projection = validate_public_projection(value)
    header = {name: projection[name] for name in _HEADER_KEYS}
    parts = (
        header,
        projection["oc16"],
        projection["oc20"],
        projection["oc17"],
        projection["component_receipt_digests"],
    )
    facts = tuple(
        (
            name,
            json.dumps(part, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        for name, part in zip(PUBLIC_FACT_ORDER, parts, strict=True)
    )
    return facts


def validate_public_facts(facts: tuple[tuple[str, str], ...]) -> None:
    if tuple(name for name, _value in facts) != PUBLIC_FACT_ORDER:
        raise NasObservationValidationError(
            "nas observation facts are incomplete or unordered"
        )
    try:
        parts = [json.loads(raw) for _name, raw in facts]
    except json.JSONDecodeError as exc:
        raise NasObservationValidationError("nas observation fact is not JSON") from exc
    canonical = [
        json.dumps(part, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for part in parts
    ]
    if canonical != [raw for _name, raw in facts]:
        raise NasObservationValidationError(
            "nas observation fact is not canonical JSON"
        )
    header, oc16, oc20, oc17, component_receipts = parts
    validate_public_projection(
        {
            **header,
            "oc16": oc16,
            "oc20": oc20,
            "oc17": oc17,
            "component_receipt_digests": component_receipts,
        }
    )
