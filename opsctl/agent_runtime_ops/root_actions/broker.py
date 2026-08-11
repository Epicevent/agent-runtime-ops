from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import secrets
import json
import threading
from typing import Any, Callable, Protocol, runtime_checkable

from .admission import LineageFailurePolicy
from .contracts import SealedJob, seal_typed_manifest
from .execution import (
    DEFAULT_EXECUTION_POLICIES,
    ExecutionPolicyRegistry,
    OperationAvailability,
)
from .projection import (
    canonical_history_bytes,
    canonical_status_bytes,
    history_projection,
    status_projection,
)
from .receipts import RECEIPT_SCHEMA, ReceiptArtifact, seal_receipt
from .public_projection import build_public_projection
from .state import JobRecord, TerminalOutcome, TransitionEvent, TransitionKind
from .storage import RootActionStore, StorageConflict, StorageNotFound
from .submission import BrokerPeerIdentity, SubmissionPolicy


PUBLIC_CATALOG_JOB_LIMIT = 2048


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
    projection_digest: str
    projection_bytes: bytes


@runtime_checkable
class BrokerEventSource(Protocol):
    """Trusted broker-owned source of audit event identity and time."""

    def next_event(self) -> tuple[str, str]: ...


class SystemBrokerEventSource:
    def next_event(self) -> tuple[str, str]:
        event_id = "event-" + secrets.token_hex(16)
        occurred_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return event_id, occurred_at


@runtime_checkable
class PublicProjectionSink(Protocol):
    def publish(self, bundle: PublicProjectionBundle) -> None: ...

    def publish_catalog(
        self,
        bundles: tuple[PublicProjectionBundle, ...],
        *,
        authority_job_count: int | None = None,
    ) -> None: ...


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

    def __init__(
        self,
        store: RootActionStore,
        *,
        events: BrokerEventSource | None = None,
        public_sink: PublicProjectionSink | None = None,
        policies: ExecutionPolicyRegistry = DEFAULT_EXECUTION_POLICIES,
        submission_policy: SubmissionPolicy,
        lineage_failure_policy: LineageFailurePolicy = LineageFailurePolicy(),
        dispatch: Callable[[str, str], None] | None = None,
    ) -> None:
        self._store = store
        self._events = events or SystemBrokerEventSource()
        self._public_sink = public_sink
        self._policies = policies
        self._submission_policy = submission_policy
        self._lineage_failure_policy = lineage_failure_policy
        self._dispatch = dispatch
        self._last_publication_error: str | None = None
        self._publication_lock = threading.RLock()
        self._published_projection_digests: dict[str, str] = {}
        self._published_projection_revisions: dict[str, int] = {}

    def submit(
        self,
        raw_manifest: bytes,
        *,
        peer: BrokerPeerIdentity,
    ) -> SubmittedJob:
        job = seal_typed_manifest(raw_manifest)
        try:
            existing = self._store.read_sealed(job.job_id)
        except StorageNotFound:
            existing = None
        if existing is not None:
            return self._recover_idempotent(job, peer=peer)
        event_id, occurred_at = self._events.next_event()
        submission = self._submission_policy.authorize(
            job,
            peer=peer,
            broker_received_at=occurred_at,
        )
        policy = self._policies.policy(job.operation_id)
        if policy.operation_version != job.operation_version:
            raise BrokerContractError("execution policy version mismatch")
        admission = None
        if policy.availability is not OperationAvailability.ENABLED:
            close_event_id, close_time = self._events.next_event()
            close_event = TransitionEvent(
                event_id=close_event_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLOSE_PENDING,
                occurred_at=close_time,
                outcome=TerminalOutcome.REJECTED,
                reason_code=policy.reason_code,
            )
            notice = seal_receipt(
                json.dumps(
                    {
                        "schema": RECEIPT_SCHEMA,
                        "kind": "terminal_notice",
                        "job_id": job.job_id,
                        "job_digest": job.job_digest,
                        "operation_id": job.operation_id,
                        "request_id": job.request_id,
                        "reply_target": job.reply_target,
                        "terminal_outcome": "rejected",
                        "reason_code": policy.reason_code,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            try:
                record = self._store.seal_rejected(
                    job,
                    pending_event_id=event_id,
                    pending_occurred_at=occurred_at,
                    close_event=close_event,
                    notice=notice,
                    submission=submission,
                    limits=self._submission_policy.limits,
                )
            except StorageConflict as exc:
                try:
                    return self._recover_idempotent(job, peer=peer)
                except StorageNotFound:
                    raise exc
        else:
            circuit_event_id, circuit_time = self._events.next_event()
            circuit_event = TransitionEvent(
                event_id=circuit_event_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLOSE_PENDING,
                occurred_at=circuit_time,
                outcome=TerminalOutcome.PRESTART_FAILED,
                reason_code=self._lineage_failure_policy.circuit_reason_code,
            )
            circuit_notice = seal_receipt(
                json.dumps(
                    {
                        "schema": RECEIPT_SCHEMA,
                        "kind": "terminal_notice",
                        "job_id": job.job_id,
                        "job_digest": job.job_digest,
                        "operation_id": job.operation_id,
                        "request_id": job.request_id,
                        "reply_target": job.reply_target,
                        "terminal_outcome": "prestart_failed",
                        "reason_code": self._lineage_failure_policy.circuit_reason_code,
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            try:
                record, admission = self._store.seal_with_lineage_admission(
                    job,
                    pending_event_id=event_id,
                    pending_occurred_at=occurred_at,
                    circuit_event=circuit_event,
                    circuit_notice=circuit_notice,
                    submission=submission,
                    limits=self._submission_policy.limits,
                    failure_policy=self._lineage_failure_policy,
                )
            except StorageConflict as exc:
                try:
                    return self._recover_idempotent(job, peer=peer)
                except StorageNotFound:
                    raise exc
        if policy.auto_dispatch and admission is not None and admission.allowed:
            record = self._auto_claim_and_dispatch(job, record)
        submitted = SubmittedJob(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status=self._status_projection(
                job, record, self._read_optional_receipt(job)
            ),
        )
        self._repair_public_best_effort(job.job_id)
        return submitted

    def set_dispatch(self, dispatch: Callable[[str, str], None]) -> None:
        if not callable(dispatch):
            raise TypeError("dispatch must be callable")
        self._dispatch = dispatch

    def _auto_claim_and_dispatch(self, job: SealedJob, record: JobRecord) -> JobRecord:
        if self._dispatch is None:
            raise BrokerContractError("automatic read-only dispatch is unavailable")
        event_id, claimed_at = self._events.next_event()
        claimed = self._store.compare_and_append(
            TransitionEvent(
                event_id=event_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=record.revision,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at=claimed_at,
            )
        )
        try:
            self._dispatch(claimed.job_id, claimed.job_digest)
        except Exception:
            try:
                return self._store.read_record(job.job_id)
            except Exception:
                return claimed
        return claimed

    def status(self, job_id: str) -> dict[str, Any]:
        job, record = self._read_job_and_record(job_id)
        receipt = self._read_optional_receipt(job)
        return self._status_projection(job, record, receipt)

    def history(self, job_id: str) -> dict[str, Any]:
        job = self._store.read_sealed(job_id)
        return history_projection(job, self._store.read_ledger(job_id))

    def public_projection(self, job_id: str) -> PublicProjectionBundle:
        job = self._store.read_sealed(job_id)
        receipt = self._read_optional_receipt(job)
        status_bytes = canonical_status_bytes(
            self._status_projection(job, self._store.read_record(job_id), receipt)
        )
        history_bytes = canonical_history_bytes(
            history_projection(job, self._store.read_ledger(job_id))
        )
        artifact = build_public_projection(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status_bytes=status_bytes,
            history_bytes=history_bytes,
            receipt=receipt,
        )
        return PublicProjectionBundle(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status_bytes=status_bytes,
            history_bytes=history_bytes,
            projection_digest=artifact.projection_digest,
            projection_bytes=artifact.canonical_bytes,
        )

    def requester_projection(
        self,
        *,
        peer: BrokerPeerIdentity,
        job_id: str,
        job_digest: str,
        request_id: str,
        reply_target: str,
    ) -> PublicProjectionBundle:
        """Return only the submitting identity's exactly bound public result."""

        metadata = self._store.submission_metadata(job_id)
        if metadata.peer_uid != peer.uid or metadata.peer_gid != peer.gid:
            raise StorageNotFound(job_id)
        job = self._store.read_sealed(job_id)
        if (
            job.job_digest != job_digest
            or job.request_id != request_id
            or job.reply_target != reply_target
        ):
            raise StorageNotFound(job_id)
        bundle = self.public_projection(job_id)
        return self._repair_public_best_effort(job_id, bundle=bundle)

    def publish_public(self, job_id: str) -> PublicProjectionBundle:
        with self._publication_lock:
            bundle = self.public_projection(job_id)
            if self._public_sink is not None:
                self._public_sink.publish(bundle)
            self._remember_publication(bundle)
            return bundle

    def repair_public_best_effort(self, job_id: str) -> PublicProjectionBundle:
        """Build the authoritative projection and repair its derived copy.

        Persistence and execution authority never depend on the public sink;
        callers still receive the root-built bundle when a derived-file repair
        fails, and startup reconciliation can retry publication.
        """

        bundle = self.public_projection(job_id)
        return self._repair_public_best_effort(job_id, bundle=bundle)

    def reconcile_public(self) -> tuple[PublicProjectionBundle, ...]:
        """Rebuild every derived public file from root-owned authority.

        This is startup/crash recovery, not an execution or approval action.
        """

        with self._publication_lock:
            bundles = tuple(
                self.public_projection(job_id) for job_id in self._store.list_job_ids()
            )
            if self._public_sink is not None:
                for bundle in bundles:
                    self._public_sink.publish(bundle)
            self._publish_catalog()
            for bundle in bundles:
                self._remember_publication(bundle)
            return bundles

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

    def _status_projection(
        self,
        job: SealedJob,
        record: JobRecord,
        receipt: ReceiptArtifact | None,
    ) -> dict[str, Any]:
        summary = self._store.lineage_summary(
            job.lineage_id,
            measured_at=record.last_changed_at,
            policy=self._lineage_failure_policy,
        )
        return status_projection(job, record, receipt, summary)

    def _publish_catalog(self) -> None:
        if self._public_sink is None or not hasattr(
            self._public_sink, "publish_catalog"
        ):
            return
        job_ids, authority_count = self._store.catalog_job_ids(
            limit=PUBLIC_CATALOG_JOB_LIMIT
        )
        bundles = tuple(self.public_projection(job_id) for job_id in job_ids)
        self._public_sink.publish_catalog(
            bundles,
            authority_job_count=authority_count,
        )

    def _repair_public_best_effort(
        self,
        job_id: str,
        *,
        bundle: PublicProjectionBundle | None = None,
    ) -> PublicProjectionBundle:
        with self._publication_lock:
            current_revision = self._store.read_record(job_id).revision
            if bundle is None or self._bundle_revision(bundle) != current_revision:
                bundle = self.public_projection(job_id)
            revision = self._bundle_revision(bundle)
            published_revision = self._published_projection_revisions.get(job_id, -1)
            if revision < published_revision:
                return self.public_projection(job_id)
            if (
                revision == published_revision
                and self._published_projection_digests.get(job_id)
                == bundle.projection_digest
            ):
                return bundle
            try:
                if self._public_sink is not None:
                    self._public_sink.publish(bundle)
                self._publish_catalog()
            except Exception as exc:
                self._last_publication_error = type(exc).__name__
            else:
                self._last_publication_error = None
                self._remember_publication(bundle)
            return bundle

    @staticmethod
    def _bundle_revision(bundle: PublicProjectionBundle) -> int:
        try:
            revision = json.loads(bundle.status_bytes)["state"]["revision"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise BrokerContractError("public projection revision is invalid") from exc
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise BrokerContractError("public projection revision is invalid")
        return revision

    def _remember_publication(self, bundle: PublicProjectionBundle) -> None:
        revision = self._bundle_revision(bundle)
        self._published_projection_digests.pop(bundle.job_id, None)
        self._published_projection_revisions.pop(bundle.job_id, None)
        self._published_projection_digests[bundle.job_id] = bundle.projection_digest
        self._published_projection_revisions[bundle.job_id] = revision
        while len(self._published_projection_digests) > PUBLIC_CATALOG_JOB_LIMIT:
            oldest = next(iter(self._published_projection_digests))
            del self._published_projection_digests[oldest]
            self._published_projection_revisions.pop(oldest, None)

    def _recover_idempotent(
        self,
        job: SealedJob,
        *,
        peer: BrokerPeerIdentity,
    ) -> SubmittedJob:
        existing = self._store.read_sealed(job.job_id)
        metadata = self._store.submission_metadata(job.job_id)
        if (
            existing != job
            or metadata.peer_uid != peer.uid
            or metadata.peer_gid != peer.gid
        ):
            raise BrokerContractError("conflicting job retry is blocked")
        record = self._store.read_record(job.job_id)
        submitted = SubmittedJob(
            job_id=job.job_id,
            job_digest=job.job_digest,
            status=self._status_projection(
                job,
                record,
                self._read_optional_receipt(job),
            ),
        )
        self._repair_public_best_effort(job.job_id)
        return submitted
