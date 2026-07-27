from __future__ import annotations

from threading import RLock

from .contracts import ManifestValidationError, SealedJob, seal_typed_manifest
from .receipts import (
    QuarantineRecord,
    RawReceiptReference,
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
from .storage import LedgerEntry, StorageConflict, StorageNotFound


class LocalRootActionFixture:
    """Thread-safe in-memory contract fixture; it makes no root-ownership claim."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._jobs: dict[str, SealedJob] = {}
        self._records: dict[str, JobRecord] = {}
        self._ledger: dict[str, list[LedgerEntry]] = {}
        self._raw_receipts: dict[str, RawReceiptReference] = {}
        self._receipts: dict[str, ReceiptArtifact] = {}
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
                raise StorageConflict("create_pending requires an initial pending record")
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
        self, job: SealedJob, *, event_id: str, occurred_at: str
    ) -> JobRecord:
        self._verify_job(job)
        record = initial_record(job, event_id=event_id, occurred_at=occurred_at)
        with self._lock:
            if job.job_id in self._jobs or job.job_id in self._records:
                raise StorageConflict("job_id is already sealed")
            self._jobs[job.job_id] = job
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

    def read_sealed(self, job_id: str) -> SealedJob:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def read_record(self, job_id: str) -> JobRecord:
        with self._lock:
            try:
                return self._records[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def compare_and_append(self, event: TransitionEvent) -> JobRecord:
        with self._lock:
            current = self.read_record(event.job_id)
            if any(entry.event_id == event.event_id for entry in self._ledger[event.job_id]):
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

    def put_raw_if_absent(self, reference: RawReceiptReference) -> None:
        with self._lock:
            if reference.job_id in self._raw_receipts:
                raise StorageConflict("raw receipt already exists")
            job = self.read_sealed(reference.job_id)
            if job.job_digest != reference.job_digest:
                raise StorageConflict("raw receipt job identity mismatch")
            self._raw_receipts[reference.job_id] = reference

    def read_raw_root_only(self, job_id: str) -> RawReceiptReference:
        with self._lock:
            try:
                return self._raw_receipts[job_id]
            except KeyError as exc:
                raise StorageNotFound(job_id) from exc

    def publish_if_absent(self, artifact: ReceiptArtifact) -> None:
        with self._lock:
            self._verify_receipt(artifact)
            if artifact.job_id in self._receipts:
                raise StorageConflict("public receipt or notice already exists")
            job = self.read_sealed(artifact.job_id)
            record = self.read_record(artifact.job_id)
            if job.job_digest != artifact.job_digest or job.operation_id != artifact.operation_id:
                raise StorageConflict("receipt job identity mismatch")
            if record.state.value not in {"terminal", "unknown"}:
                raise StorageConflict("receipt cannot publish before a final or unknown state")
            receipt = artifact.receipt_copy()
            raw_reference = self._raw_receipts.get(artifact.job_id)
            if (
                raw_reference is None
                or raw_reference.job_digest != artifact.job_digest
                or raw_reference.raw_receipt_digest != receipt["raw_receipt_digest"]
            ):
                raise StorageConflict("receipt has no matching root-only raw receipt")
            if record.state.value == "unknown":
                if artifact.kind != "unknown" or receipt["terminal_outcome"] is not None:
                    raise StorageConflict("unknown state requires an unknown receipt")
            else:
                if artifact.kind == "unknown":
                    raise StorageConflict("terminal state cannot publish an unknown receipt")
                expected_outcome = (
                    record.terminal_outcome.value if record.terminal_outcome else None
                )
                if receipt["terminal_outcome"] != expected_outcome:
                    raise StorageConflict("receipt terminal outcome mismatch")
            self._receipts[artifact.job_id] = artifact

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
