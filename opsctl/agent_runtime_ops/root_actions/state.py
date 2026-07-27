from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import re

from .contracts import SealedJob


_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


class TransitionKind(str, Enum):
    CLAIM_EXECUTION = "claim_execution"
    CLOSE_PENDING = "close_pending"
    COMPLETE_EXECUTION = "complete_execution"
    MARK_UNKNOWN = "mark_unknown"
    RECONCILE_UNKNOWN = "reconcile_unknown"


class TerminalOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELED = "canceled"
    PRESTART_FAILED = "prestart_failed"


class StateTransitionError(ValueError):
    """The requested pure state transition violates the root-action contract."""


class ReplayBlocked(StateTransitionError):
    """An execution claim was attempted after the one-shot boundary was consumed."""


class StaleRevision(StateTransitionError):
    """The caller attempted a transition from an obsolete ledger revision."""


@dataclass(frozen=True)
class JobRecord:
    job_id: str
    job_digest: str
    state: JobState
    revision: int
    execution_count: int
    terminal_outcome: TerminalOutcome | None
    reason_code: str | None
    last_event_id: str
    last_changed_at: str


@dataclass(frozen=True)
class TransitionEvent:
    event_id: str
    job_id: str
    job_digest: str
    expected_revision: int
    kind: TransitionKind
    occurred_at: str
    outcome: TerminalOutcome | None = None
    reason_code: str | None = None


def initial_record(job: SealedJob, *, event_id: str, occurred_at: str) -> JobRecord:
    _validate_event_fields(event_id, occurred_at)
    record = JobRecord(
        job_id=job.job_id,
        job_digest=job.job_digest,
        state=JobState.PENDING,
        revision=0,
        execution_count=0,
        terminal_outcome=None,
        reason_code=None,
        last_event_id=event_id,
        last_changed_at=occurred_at,
    )
    validate_record(record)
    return record


def _validate_event_fields(event_id: str, occurred_at: str) -> None:
    if not isinstance(event_id, str) or _SAFE_ID_RE.fullmatch(event_id) is None:
        raise StateTransitionError("event_id must be a safe identifier")
    if not isinstance(occurred_at, str) or _TIMESTAMP_RE.fullmatch(occurred_at) is None:
        raise StateTransitionError("occurred_at must be an RFC3339 UTC second timestamp")
    try:
        datetime.strptime(occurred_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise StateTransitionError(
            "occurred_at must be a real RFC3339 UTC second timestamp"
        ) from exc


def _require_reason(event: TransitionEvent) -> str:
    reason = event.reason_code
    if not isinstance(reason, str) or _SAFE_ID_RE.fullmatch(reason) is None:
        raise StateTransitionError("transition requires a safe reason_code")
    return reason


def _next(
    record: JobRecord,
    event: TransitionEvent,
    *,
    state: JobState,
    execution_count: int,
    outcome: TerminalOutcome | None,
    reason_code: str | None,
) -> JobRecord:
    if execution_count not in {0, 1}:
        raise AssertionError("execution_count must remain one-shot")
    updated = replace(
        record,
        state=state,
        revision=record.revision + 1,
        execution_count=execution_count,
        terminal_outcome=outcome,
        reason_code=reason_code,
        last_event_id=event.event_id,
        last_changed_at=event.occurred_at,
    )
    validate_record(updated)
    return updated


def validate_record(record: JobRecord) -> None:
    if not isinstance(record.state, JobState):
        raise StateTransitionError("job record state must be a JobState")
    if record.terminal_outcome is not None and not isinstance(
        record.terminal_outcome, TerminalOutcome
    ):
        raise StateTransitionError(
            "job record terminal_outcome must be a TerminalOutcome"
        )
    if (
        not isinstance(record.job_id, str)
        or _SAFE_ID_RE.fullmatch(record.job_id) is None
        or not isinstance(record.job_digest, str)
        or _DIGEST_RE.fullmatch(record.job_digest) is None
    ):
        raise StateTransitionError("job record identity invariant failed")
    if (
        isinstance(record.revision, bool)
        or not isinstance(record.revision, int)
        or record.revision < 0
        or isinstance(record.execution_count, bool)
        or not isinstance(record.execution_count, int)
        or record.execution_count not in {0, 1}
    ):
        raise StateTransitionError("job record counter invariant failed")
    _validate_event_fields(record.last_event_id, record.last_changed_at)
    if record.state is JobState.PENDING:
        valid = (
            record.execution_count == 0
            and record.terminal_outcome is None
            and record.reason_code is None
        )
    elif record.state is JobState.RUNNING:
        valid = (
            record.execution_count == 1
            and record.terminal_outcome is None
            and record.reason_code is None
        )
    elif record.state is JobState.UNKNOWN:
        valid = (
            record.execution_count == 1
            and record.terminal_outcome is None
            and record.reason_code is not None
        )
    else:
        if record.terminal_outcome in {
            TerminalOutcome.SUCCEEDED,
            TerminalOutcome.FAILED,
        }:
            expected_execution_count = 1
        else:
            expected_execution_count = 0
        valid = (
            record.terminal_outcome is not None
            and record.reason_code is not None
            and record.execution_count == expected_execution_count
        )
    if not valid:
        raise StateTransitionError("job record state invariant failed")
    if record.reason_code is not None and (
        not isinstance(record.reason_code, str)
        or _SAFE_ID_RE.fullmatch(record.reason_code) is None
    ):
        raise StateTransitionError("job record reason_code is invalid")


def apply_transition(record: JobRecord, event: TransitionEvent) -> JobRecord:
    validate_record(record)
    _validate_event_fields(event.event_id, event.occurred_at)
    if not isinstance(event.kind, TransitionKind):
        raise StateTransitionError("transition kind must be a TransitionKind")
    if event.outcome is not None and not isinstance(event.outcome, TerminalOutcome):
        raise StateTransitionError("transition outcome must be a TerminalOutcome")
    if isinstance(event.expected_revision, bool) or not isinstance(
        event.expected_revision, int
    ) or event.expected_revision < 0:
        raise StateTransitionError("expected_revision must be a non-negative integer")
    if event.job_id != record.job_id or event.job_digest != record.job_digest:
        raise StateTransitionError("transition job identity mismatch")
    if event.expected_revision != record.revision:
        raise StaleRevision(
            f"stale revision expected={event.expected_revision} actual={record.revision}"
        )
    if event.occurred_at < record.last_changed_at:
        raise StateTransitionError("transition timestamp precedes the current record")
    if event.event_id == record.last_event_id:
        raise ReplayBlocked("event replay is blocked")

    if event.kind is TransitionKind.CLAIM_EXECUTION:
        if record.state is not JobState.PENDING or record.execution_count != 0:
            raise ReplayBlocked("execution has already been claimed or the job is closed")
        if event.outcome is not None or event.reason_code is not None:
            raise StateTransitionError("execution claim cannot carry an outcome or reason")
        return _next(
            record,
            event,
            state=JobState.RUNNING,
            execution_count=1,
            outcome=None,
            reason_code=None,
        )

    if event.kind is TransitionKind.CLOSE_PENDING:
        if record.state is not JobState.PENDING:
            raise StateTransitionError("only a pending job can close without execution")
        if event.outcome not in {
            TerminalOutcome.REJECTED,
            TerminalOutcome.EXPIRED,
            TerminalOutcome.CANCELED,
            TerminalOutcome.PRESTART_FAILED,
        }:
            raise StateTransitionError("pending close has an invalid terminal outcome")
        return _next(
            record,
            event,
            state=JobState.TERMINAL,
            execution_count=0,
            outcome=event.outcome,
            reason_code=_require_reason(event),
        )

    if event.kind is TransitionKind.COMPLETE_EXECUTION:
        if record.state is not JobState.RUNNING or record.execution_count != 1:
            raise StateTransitionError("only a running claimed job can complete")
        if event.outcome not in {TerminalOutcome.SUCCEEDED, TerminalOutcome.FAILED}:
            raise StateTransitionError("execution completion has an invalid outcome")
        return _next(
            record,
            event,
            state=JobState.TERMINAL,
            execution_count=1,
            outcome=event.outcome,
            reason_code=_require_reason(event),
        )

    if event.kind is TransitionKind.MARK_UNKNOWN:
        if record.state is not JobState.RUNNING or record.execution_count != 1:
            raise StateTransitionError("only a running claimed job can become unknown")
        if event.outcome is not None:
            raise StateTransitionError("unknown outcome cannot claim a terminal result")
        return _next(
            record,
            event,
            state=JobState.UNKNOWN,
            execution_count=1,
            outcome=None,
            reason_code=_require_reason(event),
        )

    if event.kind is TransitionKind.RECONCILE_UNKNOWN:
        if record.state is not JobState.UNKNOWN or record.execution_count != 1:
            raise StateTransitionError("only an unknown claimed job can be reconciled")
        if event.outcome not in {TerminalOutcome.SUCCEEDED, TerminalOutcome.FAILED}:
            raise StateTransitionError("unknown reconciliation has an invalid outcome")
        return _next(
            record,
            event,
            state=JobState.TERMINAL,
            execution_count=1,
            outcome=event.outcome,
            reason_code=_require_reason(event),
        )

    raise AssertionError(f"unsupported transition kind: {event.kind}")
