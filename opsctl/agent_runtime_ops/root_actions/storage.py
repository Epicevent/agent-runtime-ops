from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .admission import (
    LineageFailurePolicy,
    LineageSummary,
    SubmissionAdmission,
)
from .contracts import SealedJob
from .receipts import QuarantineRecord, RawReceiptArtifact, ReceiptArtifact
from .state import JobRecord, TransitionEvent


class StorageConflict(RuntimeError):
    """A write-once or compare-and-swap storage invariant was violated."""


class StorageNotFound(KeyError):
    """The requested immutable job, state, or receipt is absent."""


@dataclass(frozen=True)
class SubmissionMetadata:
    peer_uid: int
    peer_gid: int
    peer_pid: int
    broker_received_at: str


@dataclass(frozen=True)
class SubmissionLimits:
    max_open_per_uid: int = 8
    max_open_per_lineage: int = 1
    max_jobs_per_uid_window: int = 32
    window_seconds: int = 3600


@dataclass(frozen=True)
class StorageContract:
    area: str
    required_owner: str
    mutation_semantics: str
    link_policy: str
    public_read_surface: str


ROOT_OWNED_STORAGE_CONTRACTS = (
    StorageContract(
        area="spool",
        required_owner="root",
        mutation_semantics="canonical-bytes-create-once",
        link_policy="no-follow-single-object",
        public_read_surface="status-projection-only",
    ),
    StorageContract(
        area="ledger",
        required_owner="root",
        mutation_semantics="append-only-state-cas",
        link_policy="no-follow-single-object",
        public_read_surface="status-and-history-projection-only",
    ),
    StorageContract(
        area="raw_receipt",
        required_owner="root",
        mutation_semantics="complete-bytes-create-once",
        link_policy="no-follow-single-object",
        public_read_surface="none",
    ),
    StorageContract(
        area="quarantine",
        required_owner="root",
        mutation_semantics="whole-artifact-create-once",
        link_policy="no-follow-single-object",
        public_read_surface="quarantine-notice-only",
    ),
)


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    action: str
    prior_state: str | None
    next_state: str
    record_revision: int
    event_id: str
    occurred_at: str
    job_id: str
    job_digest: str
    terminal_outcome: str | None
    reason_code: str | None


@runtime_checkable
class RootOwnedSpool(Protocol):
    """Write-once canonical job bytes; production implementations must be root-owned."""

    def put_if_absent(self, job: SealedJob) -> None: ...

    def read_sealed(self, job_id: str) -> SealedJob: ...

    def list_job_ids(self) -> tuple[str, ...]: ...

    def catalog_job_ids(self, *, limit: int) -> tuple[tuple[str, ...], int]:
        """Newest state-change IDs plus the full root-authority count."""
        ...

    def submission_metadata(self, job_id: str) -> SubmissionMetadata: ...

    def lineage_summary(
        self,
        lineage_id: str,
        *,
        measured_at: str,
        policy: LineageFailurePolicy = LineageFailurePolicy(),
    ) -> LineageSummary: ...


@runtime_checkable
class AppendOnlyLedger(Protocol):
    """Atomic state CAS plus append-only transition lineage."""

    def create_pending(self, record: JobRecord) -> None: ...

    def read_record(self, job_id: str) -> JobRecord: ...

    def compare_and_append(self, event: TransitionEvent) -> JobRecord: ...

    def read_ledger(self, job_id: str) -> tuple[LedgerEntry, ...]: ...


@runtime_checkable
class RootOwnedRawReceiptStore(Protocol):
    """Root-only full forensic receipt references; never a status projection source."""

    def put_raw_if_absent(self, artifact: RawReceiptArtifact) -> None: ...

    def read_raw_root_only(self, job_id: str) -> RawReceiptArtifact: ...


@runtime_checkable
class ReadOnlyReceiptStore(Protocol):
    """Full typed public receipt or whole quarantine/unknown notice retrieval."""

    def publish_if_absent(self, artifact: ReceiptArtifact) -> None: ...

    def retrieve(self, job_id: str, job_digest: str) -> ReceiptArtifact: ...


@runtime_checkable
class RootOwnedQuarantineStore(Protocol):
    """Root-owned raw quarantine index; public callers receive only its notice."""

    def quarantine_if_absent(self, record: QuarantineRecord) -> None: ...

    def read_quarantine_notice(self, job_id: str) -> ReceiptArtifact: ...


@runtime_checkable
class RootActionStore(
    RootOwnedSpool,
    AppendOnlyLedger,
    RootOwnedRawReceiptStore,
    ReadOnlyReceiptStore,
    RootOwnedQuarantineStore,
    Protocol,
):
    """Atomic composition boundary for a future root-owned backend."""

    def seal_pending(
        self,
        job: SealedJob,
        *,
        event_id: str,
        occurred_at: str,
        submission: SubmissionMetadata | None = None,
        limits: SubmissionLimits = SubmissionLimits(),
    ) -> JobRecord: ...

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
        """Atomically seal a disabled request, rejection, and terminal notice."""
        ...

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
        """Atomically admit pending work or close it at the lineage circuit."""
        ...
