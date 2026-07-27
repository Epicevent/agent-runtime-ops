from __future__ import annotations

from threading import RLock
from datetime import datetime, timedelta, timezone

from .admission import (
    LineageFailurePolicy,
    LineageSummary,
    SubmissionAdmission,
)
from .contracts import ManifestValidationError, SealedJob, seal_typed_manifest
from .receipts import (
    QuarantineRecord,
    RawReceiptArtifact,
    ReceiptArtifact,
    ReceiptValidationError,
    seal_receipt,
)
from .state import (
    JobRecord,
    JobState,
    TransitionEvent,
    apply_transition,
    initial_record,
    validate_record,
)
from .storage import (
    LedgerEntry,
    StorageConflict,
    StorageNotFound,
    SubmissionLimits,
    SubmissionMetadata,
)


class LocalRootActionFixture:
    """Thread-safe in-memory contract fixture; it makes no root-ownership claim."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._jobs: dict[str, SealedJob] = {}
        self._records: dict[str, JobRecord] = {}
        self._submissions: dict[str, SubmissionMetadata] = {}
        self._ledger: dict[str, list[LedgerEntry]] = {}
        self._raw_receipts: dict[str, RawReceiptArtifact] = {}
        self._receipts: dict[str, ReceiptArtifact] = {}
        self._receipt_history: dict[str, list[ReceiptArtifact]] = {}
        self._quarantine: dict[str, QuarantineRecord] = {}
        self._sequence = 0

    def put_if_absent(self, job: SealedJob) -> None:
        with self._lock:
            self._verify_job(job)
            if job.job_id in self._jobs:
                raise StorageConflict("job_id is already sealed")
            self._jobs[job.job_id] = job

    def create_pending(self, record: JobRecord) -> None:
        with self._lock:
            validate_record(record)
            if record.state is not JobState.PENDING or record.revision != 0:
                raise StorageConflict(
                    "create_pending requires an initial pending record"
                )
            job = self._jobs.get(record.job_id)
            if job is None or job.job_digest != record.job_digest:
                raise StorageConflict("pending record has no matching sealed job")
            if record.job_id in self._records:
                raise StorageConflict("pending record already exists")
            self._records[record.job_id] = record
            self._sequence += 1
            self._ledger[record.job_id] = [
                LedgerEntry(
                    sequence=self._sequence,
                    action="sealed_pending",
                    prior_state=None,
                    next_state=record.state.value,
                    record_revision=record.revision,
                    event_id=record.last_event_id,
                    occurred_at=record.last_changed_at,
                    job_id=record.job_id,
                    job_digest=record.job_digest,
                    terminal_outcome=None,
                    reason_code=None,
                )
            ]

    def seal_pending(
        self,
        job: SealedJob,
        *,
        event_id: str,
        occurred_at: str,
        submission: SubmissionMetadata | None = None,
        limits: SubmissionLimits = SubmissionLimits(),
    ) -> JobRecord:
        self._verify_job(job)
        record = initial_record(job, event_id=event_id, occurred_at=occurred_at)
        submission = submission or SubmissionMetadata(0, 0, 0, occurred_at)
        self._validate_submission(submission, limits)
        with self._lock:
            if job.job_id in self._jobs or job.job_id in self._records:
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(job, submission, limits)
            self._jobs[job.job_id] = job
            self._submissions[job.job_id] = submission
            self._records[job.job_id] = record
            self._sequence += 1
            self._ledger[job.job_id] = [
                LedgerEntry(
                    sequence=self._sequence,
                    action="sealed_pending",
                    prior_state=None,
                    next_state=record.state.value,
                    record_revision=record.revision,
                    event_id=record.last_event_id,
                    occurred_at=record.last_changed_at,
                    job_id=record.job_id,
                    job_digest=record.job_digest,
                    terminal_outcome=None,
                    reason_code=None,
                )
            ]
            return record

    def seal_rejected(
        self,
        job: SealedJob,
        *,
        pending_event_id: str,
        pending_occurred_at: str,
        close_event: TransitionEvent,
        notice: ReceiptArtifact,
        submission: SubmissionMetadata,
        limits: SubmissionLimits = SubmissionLimits(),
    ) -> JobRecord:
        self._verify_job(job)
        self._verify_receipt(notice)
        pending = initial_record(
            job, event_id=pending_event_id, occurred_at=pending_occurred_at
        )
        self._validate_submission(submission, limits)
        if (
            close_event.job_id != job.job_id
            or close_event.job_digest != job.job_digest
            or close_event.expected_revision != 0
            or close_event.kind.value != "close_pending"
            or close_event.outcome is None
            or close_event.outcome.value != "rejected"
        ):
            raise StorageConflict("atomic rejected submission transition is invalid")
        with self._lock:
            if job.job_id in self._jobs or job.job_id in self._records:
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(job, submission, limits)
            rejected = apply_transition(pending, close_event)
            receipt = notice.receipt_copy()
            if (
                notice.job_id != job.job_id
                or notice.job_digest != job.job_digest
                or notice.operation_id != job.operation_id
                or notice.kind != "terminal_notice"
                or receipt["terminal_outcome"] != "rejected"
                or receipt.get("reason_code") != rejected.reason_code
            ):
                raise StorageConflict("atomic rejected submission notice is invalid")
            self._jobs[job.job_id] = job
            self._submissions[job.job_id] = submission
            self._records[job.job_id] = rejected
            self._sequence += 1
            pending_entry = LedgerEntry(
                sequence=self._sequence,
                action="sealed_pending",
                prior_state=None,
                next_state="pending",
                record_revision=0,
                event_id=pending.last_event_id,
                occurred_at=pending.last_changed_at,
                job_id=job.job_id,
                job_digest=job.job_digest,
                terminal_outcome=None,
                reason_code=None,
            )
            self._sequence += 1
            close_entry = LedgerEntry(
                sequence=self._sequence,
                action=close_event.kind.value,
                prior_state="pending",
                next_state=rejected.state.value,
                record_revision=rejected.revision,
                event_id=close_event.event_id,
                occurred_at=close_event.occurred_at,
                job_id=job.job_id,
                job_digest=job.job_digest,
                terminal_outcome="rejected",
                reason_code=rejected.reason_code,
            )
            self._ledger[job.job_id] = [pending_entry, close_entry]
            self._receipts[job.job_id] = notice
            self._receipt_history[job.job_id] = [notice]
            return rejected

    @staticmethod
    def _validate_submission(
        submission: SubmissionMetadata, limits: SubmissionLimits
    ) -> None:
        for value in (submission.peer_uid, submission.peer_gid, submission.peer_pid):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StorageConflict("submission peer identity is invalid")
        try:
            datetime.strptime(submission.broker_received_at, "%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError) as exc:
            raise StorageConflict("submission broker timestamp is invalid") from exc
        for value in (
            limits.max_open_per_uid,
            limits.max_open_per_lineage,
            limits.max_jobs_per_uid_window,
            limits.window_seconds,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StorageConflict("submission limit is invalid")

    def _enforce_submission_limits(
        self,
        job: SealedJob,
        submission: SubmissionMetadata,
        limits: SubmissionLimits,
    ) -> None:
        now = datetime.strptime(
            submission.broker_received_at, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        cutoff = now - timedelta(seconds=limits.window_seconds)
        open_states = {JobState.PENDING, JobState.RUNNING, JobState.UNKNOWN}
        open_for_uid = sum(
            metadata.peer_uid == submission.peer_uid
            and self._records[job_id].state in open_states
            for job_id, metadata in self._submissions.items()
        )
        if open_for_uid >= limits.max_open_per_uid:
            raise StorageConflict("submission uid open-job circuit breaker")
        open_lineage = sum(
            self._jobs[job_id].lineage_id == job.lineage_id
            and self._records[job_id].state in open_states
            for job_id in self._submissions
        )
        if open_lineage >= limits.max_open_per_lineage:
            raise StorageConflict("submission lineage circuit breaker")
        recent_for_uid = sum(
            metadata.peer_uid == submission.peer_uid
            and datetime.strptime(
                metadata.broker_received_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            >= cutoff
            for metadata in self._submissions.values()
        )
        if recent_for_uid >= limits.max_jobs_per_uid_window:
            raise StorageConflict("submission uid rate circuit breaker")

    def read_sealed(self, job_id: str) -> SealedJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def list_job_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._jobs))

    def catalog_job_ids(self, *, limit: int) -> tuple[tuple[str, ...], int]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("catalog job limit must be a positive integer")
        with self._lock:
            ordered = sorted(
                self._records,
                key=lambda job_id: (
                    self._records[job_id].last_changed_at,
                    job_id,
                ),
                reverse=True,
            )
            return tuple(ordered[:limit]), len(ordered)

    def submission_metadata(self, job_id: str) -> SubmissionMetadata:
        with self._lock:
            try:
                return self._submissions[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def lineage_summary(
        self,
        lineage_id: str,
        *,
        measured_at: str,
        policy: LineageFailurePolicy = LineageFailurePolicy(),
    ) -> LineageSummary:
        with self._lock:
            return self._lineage_summary_locked(
                lineage_id,
                measured_at=measured_at,
                policy=policy,
            )

    def _lineage_summary_locked(
        self,
        lineage_id: str,
        *,
        measured_at: str,
        policy: LineageFailurePolicy,
    ) -> LineageSummary:
        now = datetime.strptime(measured_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        cutoff = now - timedelta(seconds=policy.window_seconds)
        terminal_counts = {
            "succeeded": 0,
            "failed": 0,
            "rejected": 0,
            "expired": 0,
            "canceled": 0,
            "prestart_failed": 0,
        }
        submission_count = 0
        technical_failure_count = 0
        for job_id, job in self._jobs.items():
            metadata = self._submissions[job_id]
            received = datetime.strptime(
                metadata.broker_received_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if job.lineage_id != lineage_id or received < cutoff or received > now:
                continue
            submission_count += 1
            record = self._records[job_id]
            if record.terminal_outcome is None:
                continue
            outcome = record.terminal_outcome.value
            terminal_counts[outcome] += 1
            if (
                outcome in {"failed", "prestart_failed"}
                and record.reason_code in policy.technical_reason_codes
            ):
                technical_failure_count += 1
        return LineageSummary(
            lineage_id=lineage_id,
            measured_at=measured_at,
            window_seconds=policy.window_seconds,
            submission_count=submission_count,
            terminal_counts=terminal_counts,
            technical_failure_count=technical_failure_count,
        )

    def seal_with_lineage_admission(
        self,
        job: SealedJob,
        *,
        pending_event_id: str,
        pending_occurred_at: str,
        circuit_event: TransitionEvent,
        circuit_notice: ReceiptArtifact,
        submission: SubmissionMetadata,
        limits: SubmissionLimits = SubmissionLimits(),
        failure_policy: LineageFailurePolicy = LineageFailurePolicy(),
    ) -> tuple[JobRecord, SubmissionAdmission]:
        self._verify_job(job)
        self._verify_receipt(circuit_notice)
        pending = initial_record(
            job,
            event_id=pending_event_id,
            occurred_at=pending_occurred_at,
        )
        self._validate_submission(submission, limits)
        with self._lock:
            if job.job_id in self._jobs or job.job_id in self._records:
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(job, submission, limits)
            summary = self._lineage_summary_locked(
                job.lineage_id,
                measured_at=submission.broker_received_at,
                policy=failure_policy,
            )
            blocked = (
                summary.technical_failure_count
                >= failure_policy.maximum_technical_failures
            )
            if blocked:
                if (
                    circuit_event.job_id != job.job_id
                    or circuit_event.job_digest != job.job_digest
                    or circuit_event.expected_revision != 0
                    or circuit_event.kind.value != "close_pending"
                    or circuit_event.outcome is None
                    or circuit_event.outcome.value != "prestart_failed"
                    or circuit_event.reason_code != failure_policy.circuit_reason_code
                ):
                    raise StorageConflict("lineage circuit transition is invalid")
                value = circuit_notice.receipt_copy()
                if (
                    circuit_notice.job_id != job.job_id
                    or circuit_notice.job_digest != job.job_digest
                    or circuit_notice.operation_id != job.operation_id
                    or circuit_notice.request_id != job.request_id
                    or circuit_notice.reply_target != job.reply_target
                    or circuit_notice.kind != "terminal_notice"
                    or value["terminal_outcome"] != "prestart_failed"
                    or value["reason_code"] != failure_policy.circuit_reason_code
                ):
                    raise StorageConflict("lineage circuit notice is invalid")
            self._jobs[job.job_id] = job
            self._submissions[job.job_id] = submission
            self._records[job.job_id] = pending
            self._sequence += 1
            entries = [
                LedgerEntry(
                    sequence=self._sequence,
                    action="sealed_pending",
                    prior_state=None,
                    next_state="pending",
                    record_revision=0,
                    event_id=pending.last_event_id,
                    occurred_at=pending.last_changed_at,
                    job_id=job.job_id,
                    job_digest=job.job_digest,
                    terminal_outcome=None,
                    reason_code=None,
                )
            ]
            record = pending
            reason_code: str | None = None
            if blocked:
                record = apply_transition(pending, circuit_event)
                self._records[job.job_id] = record
                self._sequence += 1
                entries.append(
                    LedgerEntry(
                        sequence=self._sequence,
                        action=circuit_event.kind.value,
                        prior_state="pending",
                        next_state="terminal",
                        record_revision=record.revision,
                        event_id=circuit_event.event_id,
                        occurred_at=circuit_event.occurred_at,
                        job_id=job.job_id,
                        job_digest=job.job_digest,
                        terminal_outcome="prestart_failed",
                        reason_code=record.reason_code,
                    )
                )
                self._receipts[job.job_id] = circuit_notice
                self._receipt_history[job.job_id] = [circuit_notice]
                reason_code = failure_policy.circuit_reason_code
            self._ledger[job.job_id] = entries
            return record, SubmissionAdmission(
                allowed=not blocked,
                reason_code=reason_code,
                summary=summary,
            )

    def read_record(self, job_id: str) -> JobRecord:
        with self._lock:
            try:
                return self._records[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def compare_and_append(self, event: TransitionEvent) -> JobRecord:
        with self._lock:
            current = self.read_record(event.job_id)
            if any(
                entry.event_id == event.event_id for entry in self._ledger[event.job_id]
            ):
                raise StorageConflict("ledger event_id replay is blocked")
            updated = apply_transition(current, event)
            self._records[event.job_id] = updated
            self._sequence += 1
            self._ledger[event.job_id].append(
                LedgerEntry(
                    sequence=self._sequence,
                    action=event.kind.value,
                    prior_state=current.state.value,
                    next_state=updated.state.value,
                    record_revision=updated.revision,
                    event_id=event.event_id,
                    occurred_at=event.occurred_at,
                    job_id=event.job_id,
                    job_digest=event.job_digest,
                    terminal_outcome=(
                        updated.terminal_outcome.value
                        if updated.terminal_outcome is not None
                        else None
                    ),
                    reason_code=updated.reason_code,
                )
            )
            return updated

    def read_ledger(self, job_id: str) -> tuple[LedgerEntry, ...]:
        with self._lock:
            try:
                return tuple(self._ledger[job_id])
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def put_raw_if_absent(self, artifact: RawReceiptArtifact) -> None:
        with self._lock:
            reference = artifact.reference
            if reference.job_id in self._raw_receipts:
                raise StorageConflict("raw receipt already exists")
            job = self.read_sealed(reference.job_id)
            if job.job_digest != reference.job_digest:
                raise StorageConflict("raw receipt job identity mismatch")
            self._raw_receipts[reference.job_id] = artifact

    def read_raw_root_only(self, job_id: str) -> RawReceiptArtifact:
        with self._lock:
            try:
                return self._raw_receipts[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def publish_if_absent(self, artifact: ReceiptArtifact) -> None:
        with self._lock:
            self._verify_receipt(artifact)
            current_receipt = self._receipts.get(artifact.job_id)
            if current_receipt is not None and not (
                current_receipt.kind == "unknown" and artifact.kind != "unknown"
            ):
                raise StorageConflict("public receipt or notice already exists")
            job = self.read_sealed(artifact.job_id)
            record = self.read_record(artifact.job_id)
            if (
                job.job_digest != artifact.job_digest
                or job.operation_id != artifact.operation_id
                or job.request_id != artifact.request_id
                or job.reply_target != artifact.reply_target
            ):
                raise StorageConflict("receipt job identity mismatch")
            if record.state.value not in {"terminal", "unknown"}:
                raise StorageConflict(
                    "receipt cannot publish before a final or unknown state"
                )
            receipt = artifact.receipt_copy()
            if artifact.kind != "terminal_notice":
                raw_artifact = self._raw_receipts.get(artifact.job_id)
                raw_reference = (
                    raw_artifact.reference if raw_artifact is not None else None
                )
                if (
                    raw_reference is None
                    or raw_reference.job_digest != artifact.job_digest
                    or raw_reference.raw_receipt_digest != receipt["raw_receipt_digest"]
                ):
                    raise StorageConflict(
                        "receipt has no matching root-only raw receipt"
                    )
            if record.state.value == "unknown":
                if (
                    artifact.kind != "unknown"
                    or receipt["terminal_outcome"] is not None
                ):
                    raise StorageConflict("unknown state requires an unknown receipt")
            else:
                if artifact.kind == "unknown":
                    raise StorageConflict(
                        "terminal state cannot publish an unknown receipt"
                    )
                expected_outcome = (
                    record.terminal_outcome.value if record.terminal_outcome else None
                )
                if receipt["terminal_outcome"] != expected_outcome:
                    raise StorageConflict("receipt terminal outcome mismatch")
            self._receipts[artifact.job_id] = artifact
            self._receipt_history.setdefault(artifact.job_id, []).append(artifact)

    def retrieve(self, job_id: str, job_digest: str) -> ReceiptArtifact:
        with self._lock:
            try:
                artifact = self._receipts[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc
            if artifact.job_digest != job_digest:
                raise StorageNotFound(job_id)
            return artifact

    def quarantine_if_absent(self, record: QuarantineRecord) -> None:
        artifact = record.notice
        with self._lock:
            if artifact.job_id in self._quarantine:
                raise StorageConflict("quarantine entry already exists")
            self.publish_if_absent(artifact)
            self._quarantine[artifact.job_id] = record

    def read_quarantine_notice(self, job_id: str) -> ReceiptArtifact:
        with self._lock:
            try:
                return self._quarantine[job_id].notice
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    @staticmethod
    def _verify_job(job: SealedJob) -> None:
        try:
            verified = seal_typed_manifest(job.canonical_manifest)
        except ManifestValidationError as exc:
            raise StorageConflict("sealed job bytes are invalid") from exc
        if verified != job:
            raise StorageConflict("sealed job metadata does not match canonical bytes")

    @staticmethod
    def _verify_receipt(artifact: ReceiptArtifact) -> None:
        try:
            verified = seal_receipt(artifact.canonical_receipt)
        except ReceiptValidationError as exc:
            raise StorageConflict("receipt bytes are invalid") from exc
        if verified != artifact:
            raise StorageConflict("receipt metadata does not match canonical bytes")
