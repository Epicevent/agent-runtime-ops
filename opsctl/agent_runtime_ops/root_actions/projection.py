from __future__ import annotations

import json
from typing import Any

from .admission import LineageSummary
from .contracts import SealedJob
from .receipts import ReceiptArtifact, ReceiptValidationError, seal_receipt
from .state import (
    JobRecord,
    JobState,
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
    apply_transition,
    initial_record,
    validate_record,
)
from .storage import LedgerEntry


STATUS_SCHEMA = "agent-runtime-root-action-status/v1"
HISTORY_SCHEMA = "agent-runtime-root-action-history/v1"


class ProjectionError(ValueError):
    """Sealed job, ledger state, and receipt cannot form one read-only view."""


def status_projection(
    job: SealedJob,
    record: JobRecord,
    receipt: ReceiptArtifact | None = None,
    lineage_summary: LineageSummary | None = None,
) -> dict[str, Any]:
    validate_record(record)
    if record.job_id != job.job_id or record.job_digest != job.job_digest:
        raise ProjectionError("ledger record job identity mismatch")
    if receipt is not None:
        try:
            verified_receipt = seal_receipt(receipt.canonical_receipt)
        except ReceiptValidationError as exc:
            raise ProjectionError("receipt bytes are invalid") from exc
        if verified_receipt != receipt:
            raise ProjectionError("receipt metadata does not match canonical bytes")
        if (
            receipt.job_id != job.job_id
            or receipt.job_digest != job.job_digest
            or receipt.operation_id != job.operation_id
            or receipt.request_id != job.request_id
            or receipt.reply_target != job.reply_target
        ):
            raise ProjectionError("receipt job identity mismatch")
        if record.state not in {JobState.TERMINAL, JobState.UNKNOWN}:
            raise ProjectionError("non-final state cannot expose a receipt")
        if record.state is JobState.UNKNOWN and receipt.kind != "unknown":
            raise ProjectionError("unknown state requires an unknown receipt")
        if record.state is JobState.TERMINAL and receipt.kind == "unknown":
            raise ProjectionError("terminal state cannot expose an unknown receipt")
        receipt_value = receipt.receipt_copy()
        expected_outcome = (
            record.terminal_outcome.value
            if record.terminal_outcome is not None
            else None
        )
        if receipt_value["terminal_outcome"] != expected_outcome:
            raise ProjectionError("receipt terminal outcome mismatch")
        if receipt.kind in {"unknown", "terminal_notice"} and (
            receipt_value["reason_code"] != record.reason_code
        ):
            raise ProjectionError("receipt reason_code mismatch")

    manifest = job.manifest_copy()
    return {
        "schema": STATUS_SCHEMA,
        "job": {
            "job_id": job.job_id,
            "job_digest": job.job_digest,
            "operation_id": job.operation_id,
            "operation_version": job.operation_version,
            "request_id": job.request_id,
            "lineage_id": job.lineage_id,
            "reply_target": job.reply_target,
            "submitted_at": job.submitted_at,
            "parameters": manifest["parameters"],
            "expected_pre_state": manifest["expected_pre_state"],
            "review": manifest["review"],
        },
        "state": {
            "name": record.state.value,
            "revision": record.revision,
            "execution_count": record.execution_count,
            "terminal_outcome": (
                record.terminal_outcome.value if record.terminal_outcome else None
            ),
            "reason_code": record.reason_code,
            "last_changed_at": record.last_changed_at,
        },
        "lineage_24h": (
            {
                "availability": "measured",
                **lineage_summary.projection(),
            }
            if lineage_summary is not None
            else {
                "availability": "unavailable",
                "reason": "root_owned_ledger_summary_not_supplied",
            }
        ),
        "receipt": (
            {
                "kind": receipt.kind,
                "receipt_digest": receipt.receipt_digest,
            }
            if receipt is not None
            else None
        ),
    }


def canonical_status_bytes(value: dict[str, Any]) -> bytes:
    if value.get("schema") != STATUS_SCHEMA:
        raise ProjectionError("status projection schema mismatch")
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def canonical_history_bytes(value: dict[str, Any]) -> bytes:
    if value.get("schema") != HISTORY_SCHEMA:
        raise ProjectionError("history projection schema mismatch")
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def history_projection(
    job: SealedJob, entries: tuple[LedgerEntry, ...]
) -> dict[str, Any]:
    if not entries:
        raise ProjectionError("history cannot be empty")
    prior_sequence = 0
    prior_record: JobRecord | None = None
    projected: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if entry.job_id != job.job_id or entry.job_digest != job.job_digest:
            raise ProjectionError("history job identity mismatch")
        if entry.sequence <= prior_sequence:
            raise ProjectionError("history sequence is not increasing")
        if index == 0:
            if (
                entry.action != "sealed_pending"
                or entry.prior_state is not None
                or entry.next_state != "pending"
                or entry.record_revision != 0
                or entry.terminal_outcome is not None
                or entry.reason_code is not None
            ):
                raise ProjectionError(
                    "history does not begin with sealed pending state"
                )
            try:
                prior_record = initial_record(
                    job, event_id=entry.event_id, occurred_at=entry.occurred_at
                )
            except ValueError as exc:
                raise ProjectionError("history initial event is invalid") from exc
        else:
            assert prior_record is not None
            try:
                kind = TransitionKind(entry.action)
                outcome = (
                    TerminalOutcome(entry.terminal_outcome)
                    if entry.terminal_outcome is not None
                    else None
                )
                event = TransitionEvent(
                    event_id=entry.event_id,
                    job_id=entry.job_id,
                    job_digest=entry.job_digest,
                    expected_revision=prior_record.revision,
                    kind=kind,
                    occurred_at=entry.occurred_at,
                    outcome=outcome,
                    reason_code=entry.reason_code,
                )
                next_record = apply_transition(prior_record, event)
            except (ValueError, KeyError) as exc:
                raise ProjectionError("history transition is invalid") from exc
            if (
                entry.prior_state != prior_record.state.value
                or entry.next_state != next_record.state.value
                or entry.record_revision != next_record.revision
                or entry.terminal_outcome
                != (
                    next_record.terminal_outcome.value
                    if next_record.terminal_outcome is not None
                    else None
                )
                or entry.reason_code != next_record.reason_code
            ):
                raise ProjectionError("history transition projection mismatch")
            prior_record = next_record
        projected.append(
            {
                "sequence": entry.sequence,
                "action": entry.action,
                "prior_state": entry.prior_state,
                "next_state": entry.next_state,
                "record_revision": entry.record_revision,
                "event_id": entry.event_id,
                "occurred_at": entry.occurred_at,
                "terminal_outcome": entry.terminal_outcome,
                "reason_code": entry.reason_code,
            }
        )
        prior_sequence = entry.sequence
    return {
        "schema": HISTORY_SCHEMA,
        "job_id": job.job_id,
        "job_digest": job.job_digest,
        "events": projected,
    }
