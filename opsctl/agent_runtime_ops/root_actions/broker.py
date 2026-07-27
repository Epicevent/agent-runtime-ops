from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .contracts import SealedJob, seal_typed_manifest
from .projection import (
    canonical_history_bytes,
    canonical_status_bytes,
    history_projection,
    status_projection,
)
from .receipts import ReceiptArtifact
from .state import JobRecord
from .storage import RootActionStore, StorageNotFound


class BrokerContractError(ValueError):
    """A caller attempted to cross the typed broker boundary incorrectly."""


@dataclass(frozen=True)
class SubmittedJob:
    job_id: str
    job_digest: str
    status: dict[str, Any]


@dataclass(frozen=True)
class PublicProjectionBundle:
    """Canonical public bytes; never includes raw execution output or secrets."""

    job_id: str
    job_digest: str
    status_bytes: bytes
    history_bytes: bytes


@runtime_checkable
class PublicRootActionReader(Protocol):
    """The only surface the ordinary OPS web process is allowed to consume."""

    def status(self, job_id: str) -> dict[str, Any]: ...

    def history(self, job_id: str) -> dict[str, Any]: ...

    def receipt(self, job_id: str, job_digest: str) -> ReceiptArtifact: ...


class TypedRootActionBroker:
    """Decision-independent typed submission and read projection.

    This class deliberately has no authentication or execution method.  Those
    edges must be supplied only after the user has selected the authentication
    and approval/dispatch design.  It is still useful production code: it owns
    canonical submission, immutable identity, pending creation, and the exact
    public read model shared by the broker and OPS web.
    """

    def __init__(self, store: RootActionStore) -> None:
        self._store = store

    def submit(
        self,
        raw_manifest: bytes,
        *,
        event_id: str,
        occurred_at: str,
    ) -> SubmittedJob:
        job = seal_typed_manifest(raw_manifest)
        record = self._store.seal_pending(
            job,
            event_id=event_id,
            occurred_at=occurred_at,
        )
        return SubmittedJob(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status=status_projection(job, record),
        )

    def status(self, job_id: str) -> dict[str, Any]:
        job, record = self._read_job_and_record(job_id)
        receipt = self._read_optional_receipt(job)
        return status_projection(job, record, receipt)

    def history(self, job_id: str) -> dict[str, Any]:
        job = self._store.read_sealed(job_id)
        return history_projection(job, self._store.read_ledger(job_id))

    def public_projection(self, job_id: str) -> PublicProjectionBundle:
        job = self._store.read_sealed(job_id)
        return PublicProjectionBundle(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status_bytes=canonical_status_bytes(self.status(job_id)),
            history_bytes=canonical_history_bytes(self.history(job_id)),
        )

    def receipt(self, job_id: str, job_digest: str) -> ReceiptArtifact:
        if not isinstance(job_digest, str):
            raise BrokerContractError("job_digest must be a string")
        job = self._store.read_sealed(job_id)
        if job.job_digest != job_digest:
            raise StorageNotFound(job_id)
        return self._store.retrieve(job_id, job_digest)

    def _read_job_and_record(self, job_id: str) -> tuple[SealedJob, JobRecord]:
        job = self._store.read_sealed(job_id)
        record = self._store.read_record(job_id)
        return job, record

    def _read_optional_receipt(self, job: SealedJob) -> ReceiptArtifact | None:
        try:
            return self._store.retrieve(job.job_id, job.job_digest)
        except StorageNotFound:
            return None
