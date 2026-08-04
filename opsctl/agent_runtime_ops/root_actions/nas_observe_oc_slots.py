from __future__ import annotations

import json
import re
from typing import Any


OPERATION_ID = "nas.observe_oc_slots"
OPERATION_VERSION = 1
PROFILE = "oc16-oc20-groupware-and-oc17-detach-prestate-v1"
SOURCE_CONTRACT_DIGEST = (
    "sha256:5ed971d0dd41a7deee0e3e58a253e17847beec1edcde874192c57c5effbe72e7"
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
_SAFE_ID_RE = re.compile(r"[a-z][a-z0-9._-]{0,127}")
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
    "slot", "alias_count", "alias_ordinals", "alias_target_digests",
    "mount_exact_bits", "mount_readonly_bits", "exists_bits", "directory_bits",
    "readable_bits", "count_complete_bits", "entry_uid_values", "entry_gid_values",
    "entry_mode_values", "file_counts", "directory_counts", "symlink_counts",
    "other_counts", "container_identity_digest", "image_identity_digest",
    "host_bind_identity_digest", "container_bind_identity_digest", "issues",
)
_OC17_KEYS = (
    "ops_release_matches", "ops_release_digest", "mount_count",
    "mount_identity_digest", "container_mount_count",
    "container_mount_identity_digest", "logical_record_count",
    "logical_record_identity_digest", "intent_status", "assignment_count",
    "recreation_blocker_count", "recreation_blocker_digest", "workspace_mount_count",
    "workspace_identity_digest", "other_slot_mount_identity_digest", "session_count",
    "session_identity_digest", "process_count", "process_identity_digest",
    "gpu_process_count", "gpu_identity_digest", "credential_count",
    "credential_metadata_digests", "protected_read_guard_stable", "reason_codes",
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
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
        raise NasObservationValidationError(f"{label} is not a bounded count")


def _bool(value: Any, label: str) -> None:
    if not isinstance(value, bool):
        raise NasObservationValidationError(f"{label} is not boolean")


def _ids(value: Any, label: str) -> None:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or any(not isinstance(item, str) or _SAFE_ID_RE.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        raise NasObservationValidationError(f"{label} is not a bounded identifier list")


def _slot(value: Any, slot: str, ordinals: tuple[int, ...]) -> None:
    item = _exact(value, _SLOT_KEYS, slot)
    if item["slot"] != slot or item["alias_count"] != len(ordinals):
        raise NasObservationValidationError(f"{slot} identity or alias count is invalid")
    if item["alias_ordinals"] != list(ordinals):
        raise NasObservationValidationError(f"{slot} alias ordinals are invalid")
    vector_keys = (
        "alias_target_digests", "mount_exact_bits", "mount_readonly_bits", "exists_bits",
        "directory_bits", "readable_bits", "count_complete_bits", "entry_uid_values",
        "entry_gid_values", "entry_mode_values", "file_counts", "directory_counts",
        "symlink_counts", "other_counts",
    )
    if any(not isinstance(item[name], list) or len(item[name]) != len(ordinals) for name in vector_keys):
        raise NasObservationValidationError(f"{slot} vectors do not match its aliases")
    for index, digest in enumerate(item["alias_target_digests"]):
        _digest(digest, f"{slot}.alias_target_digests[{index}]")
    for name in (
        "mount_exact_bits", "mount_readonly_bits", "exists_bits", "directory_bits",
        "readable_bits", "count_complete_bits",
    ):
        for index, bit in enumerate(item[name]):
            _bool(bit, f"{slot}.{name}[{index}]")
    for name in ("entry_uid_values", "entry_gid_values", "entry_mode_values"):
        for index, count in enumerate(item[name]):
            _count(count, f"{slot}.{name}[{index}]", nullable=True)
    for name in ("file_counts", "directory_counts", "symlink_counts", "other_counts"):
        for index, count in enumerate(item[name]):
            _count(count, f"{slot}.{name}[{index}]")
    for name in (
        "container_identity_digest", "image_identity_digest", "host_bind_identity_digest",
        "container_bind_identity_digest",
    ):
        _digest(item[name], f"{slot}.{name}")
    _ids(item["issues"], f"{slot}.issues")


def _oc17(value: Any) -> None:
    item = _exact(value, _OC17_KEYS, "oc17")
    for name in ("ops_release_matches", "protected_read_guard_stable"):
        _bool(item[name], f"oc17.{name}")
    for name in (
        "mount_count", "container_mount_count", "logical_record_count", "assignment_count",
        "recreation_blocker_count", "workspace_mount_count", "session_count", "process_count",
        "gpu_process_count", "credential_count",
    ):
        _count(item[name], f"oc17.{name}", nullable=name == "assignment_count")
    for name in (
        "ops_release_digest", "mount_identity_digest", "container_mount_identity_digest",
        "logical_record_identity_digest", "recreation_blocker_digest",
        "workspace_identity_digest", "other_slot_mount_identity_digest",
        "session_identity_digest", "process_identity_digest", "gpu_identity_digest",
    ):
        _digest(item[name], f"oc17.{name}")
    if item["intent_status"] not in {"present", "absent", "unknown"}:
        raise NasObservationValidationError("oc17.intent_status is invalid")
    if not isinstance(item["credential_metadata_digests"], list) or len(item["credential_metadata_digests"]) > 64:
        raise NasObservationValidationError("oc17 credential digest list is invalid")
    for index, digest in enumerate(item["credential_metadata_digests"]):
        _digest(digest, f"oc17.credential_metadata_digests[{index}]")
    _ids(item["reason_codes"], "oc17.reason_codes")


def validate_public_projection(value: Any) -> dict[str, Any]:
    keys = (*_HEADER_KEYS, "oc16", "oc20", "oc17", "component_receipt_digests")
    projection = _exact(value, keys, "nas observation")
    if (
        projection["schema"] != RECEIPT_SCHEMA
        or projection["profile"] != PROFILE
        or projection["source_contract_digest"] != SOURCE_CONTRACT_DIGEST
        or projection["writes"] != 0
        or projection["operational_verdict"] not in {"green", "red", "observation_failed"}
    ):
        raise NasObservationValidationError("nas observation fixed values are invalid")
    _digest(projection["expected_nonroot_prestate_digest"], "expected_nonroot_prestate_digest")
    _bool(projection["observed_nonroot_prestate_match"], "observed_nonroot_prestate_match")
    _bool(projection["observation_complete"], "observation_complete")
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
    return projection


def public_facts(value: Any) -> tuple[tuple[str, str], ...]:
    projection = validate_public_projection(value)
    header = {name: projection[name] for name in _HEADER_KEYS}
    parts = (header, projection["oc16"], projection["oc20"], projection["oc17"], projection["component_receipt_digests"])
    facts = tuple(
        (name, json.dumps(part, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        for name, part in zip(PUBLIC_FACT_ORDER, parts, strict=True)
    )
    if any(len(encoded.encode("utf-8")) > 4096 for _name, encoded in facts):
        raise NasObservationValidationError("nas observation public fact exceeds its bound")
    return facts


def validate_public_facts(facts: tuple[tuple[str, str], ...]) -> None:
    if tuple(name for name, _value in facts) != PUBLIC_FACT_ORDER:
        raise NasObservationValidationError("nas observation facts are incomplete or unordered")
    try:
        parts = [json.loads(value) for _name, value in facts]
    except json.JSONDecodeError as exc:
        raise NasObservationValidationError("nas observation fact is not JSON") from exc
    if any(json.dumps(part, ensure_ascii=False, sort_keys=True, separators=(",", ":")) != raw for part, (_name, raw) in zip(parts, facts, strict=True)):
        raise NasObservationValidationError("nas observation fact is not canonical JSON")
    header, oc16, oc20, oc17, component_receipts = parts
    validate_public_projection({**header, "oc16": oc16, "oc20": oc20, "oc17": oc17, "component_receipt_digests": component_receipts})
