from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import sys

from ..domain.nas_views import (
    iter_view_records,
    load_views_state,
    requested_and_effective_granted_paths,
)
from ..paths import DEFAULT_STATE_ROOT
from ..routing import load_runtime_bindings, validate_linux_account
from .client import RootActionBrokerClient, RootActionRequestHandle
from .contracts import MANIFEST_SCHEMA, canonical_manifest_bytes, seal_typed_manifest
from .registry import REGISTRY_VERSION
from .storage import SubmissionLimits


OPERATION_ID = "nas.observe_groupware_runtime"
OPERATION_VERSION = 1
BUCKET_MINUTES = 15
MAX_BUCKET_AGE_SECONDS = BUCKET_MINUTES * 60 - 1
# Keep one cycle below the broker's simultaneous-open limit. The six declared
# product slots therefore remain admissible without fire-and-forget overflow.
MAX_GROUPWARE_SLOTS_PER_CYCLE = min(
    SubmissionLimits().max_jobs_per_uid_window // 4,
    SubmissionLimits().max_open_per_uid,
)
REPLY_TARGET = "ops-groupware-reobserver"


class GroupwareReobservationError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class PlannedReobservation:
    slot: str
    manifest: bytes


@dataclass(frozen=True)
class ReobservationCycle:
    bucket: str
    slots: tuple[str, ...]
    handles: tuple[RootActionRequestHandle, ...]


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise GroupwareReobservationError("clock_not_timezone_aware")
    offset = value.utcoffset()
    if offset is None:
        raise GroupwareReobservationError("clock_not_timezone_aware")
    return value.astimezone(timezone.utc)


def observation_bucket(value: datetime) -> datetime:
    current = _utc(value)
    return current.replace(
        minute=(current.minute // BUCKET_MINUTES) * BUCKET_MINUTES,
        second=0,
        microsecond=0,
    )


def _bucket_timestamp(bucket: datetime) -> str:
    value = _utc(bucket)
    if value != observation_bucket(value):
        raise GroupwareReobservationError("observation_bucket_not_aligned")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _bucket_token(bucket: datetime) -> str:
    return _utc(bucket).strftime("%Y%m%dt%Hz")


def build_groupware_reobservation_manifest(slot: str, bucket: datetime) -> bytes:
    normalized_slot = validate_linux_account(slot)
    submitted_at = _bucket_timestamp(bucket)
    token = _bucket_token(bucket)
    job_id = f"groupware-reobserve.{normalized_slot}.{token}"
    value = {
        "schema": MANIFEST_SCHEMA,
        "registry_version": REGISTRY_VERSION,
        "job_id": job_id,
        "operation_id": OPERATION_ID,
        "operation_version": OPERATION_VERSION,
        "request": {
            "request_id": job_id,
            "lineage_id": f"groupware-reobserve.{normalized_slot}",
            "reply_target": REPLY_TARGET,
            "submitted_at": submitted_at,
        },
        "parameters": {"slot": normalized_slot},
        "expected_pre_state": {"kind": "none", "digest": None},
        "review": {
            "purpose": "Refresh one bounded groupware runtime observation.",
            "premises": [
                {
                    "claim": "The registered operation observes runtime state without repairing it.",
                    "basis": "direct_observation",
                    "anchor": {
                        "source": "nas.observe_groupware_runtime/v1 handler contract",
                        "quote": "writes=0",
                    },
                    "falsifier": "Any runtime repair or apply action invalidates this job.",
                }
            ],
            "targets": [f"groupware runtime slot {normalized_slot}"],
            "changes": ["No runtime repair or product-state change"],
            "recovery": ["No rollback is required for a read-only observation"],
            "risk_delta": {
                "baseline": "The last groupware runtime receipt may be stale.",
                "added": [],
                "removed": [],
                "maximum_consequence": "The bounded observation may fail closed.",
            },
        },
    }
    sealed = seal_typed_manifest(canonical_manifest_bytes(value))
    return sealed.canonical_manifest


def declared_groupware_slots(state_root: Path) -> tuple[str, ...]:
    bindings = {item.linux_account: item for item in load_runtime_bindings(state_root)}
    slots: set[str] = set()
    for raw_slot, corpus, record in iter_view_records(load_views_state(state_root)):
        if corpus != "groupware":
            continue
        try:
            slot = validate_linux_account(raw_slot)
        except ValueError as exc:
            raise GroupwareReobservationError("groupware_slot_invalid") from exc
        binding = bindings.get(slot)
        if not isinstance(record, dict):
            raise GroupwareReobservationError("groupware_view_record_invalid")
        try:
            requested_and_effective_granted_paths(record)
        except (TypeError, ValueError) as exc:
            raise GroupwareReobservationError("groupware_view_record_invalid") from exc
        if binding is None or not binding.enabled:
            raise GroupwareReobservationError("groupware_slot_not_enabled")
        if slot in slots:
            raise GroupwareReobservationError("groupware_slot_duplicate")
        slots.add(slot)
    if len(slots) > MAX_GROUPWARE_SLOTS_PER_CYCLE:
        raise GroupwareReobservationError("groupware_slot_cap_exceeded")
    return tuple(sorted(slots))


def plan_groupware_reobservations(
    state_root: Path,
    *,
    now: datetime,
) -> tuple[PlannedReobservation, ...]:
    current = _utc(now)
    bucket = observation_bucket(current)
    age = (current - bucket).total_seconds()
    if age < 0 or age > MAX_BUCKET_AGE_SECONDS:
        raise GroupwareReobservationError("observation_bucket_stale")
    slots = declared_groupware_slots(Path(state_root))
    return tuple(
        PlannedReobservation(
            slot,
            build_groupware_reobservation_manifest(slot, bucket),
        )
        for slot in slots
    )


def submit_groupware_reobservations(
    state_root: Path,
    *,
    now: datetime,
    client: RootActionBrokerClient | None = None,
) -> ReobservationCycle:
    bucket = observation_bucket(now)
    plans = plan_groupware_reobservations(state_root, now=now)
    broker = client or RootActionBrokerClient()
    handles: list[RootActionRequestHandle] = []
    for plan in plans:
        try:
            handle, _projection = broker.submit(plan.manifest)
        except Exception as exc:
            raise GroupwareReobservationError("broker_submission_failed") from exc
        handles.append(handle)
    return ReobservationCycle(
        _bucket_timestamp(bucket),
        tuple(plan.slot for plan in plans),
        tuple(handles),
    )


def _state_root() -> Path:
    value = Path(os.environ.get("AGENT_RUNTIME_STATE_ROOT", str(DEFAULT_STATE_ROOT)))
    if not value.is_absolute():
        raise GroupwareReobservationError("state_root_not_absolute")
    return value


def main() -> int:
    if len(sys.argv) != 1:
        print(
            "groupware_reobservation=failed reason=arguments_not_supported",
            file=sys.stderr,
        )
        return 2
    try:
        cycle = submit_groupware_reobservations(
            _state_root(),
            now=datetime.now(timezone.utc),
        )
    except GroupwareReobservationError as exc:
        print(
            f"groupware_reobservation=failed reason={exc.reason_code}",
            file=sys.stderr,
        )
        return 1
    except Exception:
        print(
            "groupware_reobservation=failed reason=internal_error",
            file=sys.stderr,
        )
        return 1
    print("groupware_reobservation=submitted")
    print(f"bucket={cycle.bucket}")
    print(f"slot_count={len(cycle.slots)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
