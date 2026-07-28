from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterator

from .admission import (
    LineageFailurePolicy,
    LineageSummary,
    SubmissionAdmission,
)
from .authorization import (
    ApprovalRecord,
    BootstrapSession,
    BootstrapState,
    CeremonyPurpose,
    CeremonyState,
    CredentialRole,
    PendingCeremony,
    RegisteredCredential,
    VerifiedAssertion,
)
from .contracts import ManifestValidationError, SealedJob, seal_typed_manifest
from .receipts import (
    QuarantineRecord,
    RawReceiptArtifact,
    RawReceiptReference,
    ReceiptArtifact,
    ReceiptValidationError,
    seal_receipt,
)
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
from .storage import (
    LedgerEntry,
    StorageConflict,
    StorageNotFound,
    SubmissionLimits,
    SubmissionMetadata,
)


_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS root_action_jobs (
    job_id TEXT PRIMARY KEY,
    job_digest TEXT NOT NULL UNIQUE,
    operation_id TEXT NOT NULL,
    operation_version INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    lineage_id TEXT NOT NULL,
    reply_target TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    peer_uid INTEGER NOT NULL,
    peer_gid INTEGER NOT NULL,
    peer_pid INTEGER NOT NULL,
    broker_received_at TEXT NOT NULL,
    canonical_manifest BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS root_action_records (
    job_id TEXT PRIMARY KEY REFERENCES root_action_jobs(job_id),
    job_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    revision INTEGER NOT NULL,
    execution_count INTEGER NOT NULL,
    terminal_outcome TEXT,
    reason_code TEXT,
    last_event_id TEXT NOT NULL,
    last_changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS root_action_ledger (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    prior_state TEXT,
    next_state TEXT NOT NULL,
    record_revision INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    job_id TEXT NOT NULL REFERENCES root_action_jobs(job_id),
    job_digest TEXT NOT NULL,
    terminal_outcome TEXT,
    reason_code TEXT,
    UNIQUE(job_id, event_id)
);
CREATE INDEX IF NOT EXISTS root_action_ledger_job_sequence
ON root_action_ledger(job_id, sequence);
CREATE TABLE IF NOT EXISTS root_action_raw_receipts (
    job_id TEXT PRIMARY KEY REFERENCES root_action_jobs(job_id),
    job_digest TEXT NOT NULL,
    raw_receipt_digest TEXT NOT NULL,
    root_storage_id TEXT NOT NULL UNIQUE,
    raw_receipt BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS root_action_receipts (
    receipt_digest TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES root_action_jobs(job_id),
    job_digest TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    canonical_receipt BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS root_action_receipt_current (
    job_id TEXT PRIMARY KEY REFERENCES root_action_jobs(job_id),
    receipt_digest TEXT NOT NULL REFERENCES root_action_receipts(receipt_digest)
);
CREATE TABLE IF NOT EXISTS root_action_quarantine (
    job_id TEXT PRIMARY KEY REFERENCES root_action_jobs(job_id),
    receipt_digest TEXT NOT NULL REFERENCES root_action_receipts(receipt_digest),
    root_storage_id TEXT NOT NULL
);
"""
_AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS root_action_auth_bootstrap (
    bootstrap_id TEXT PRIMARY KEY,
    token_digest TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    remaining_registrations INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS root_action_auth_credentials (
    credential_id BLOB PRIMARY KEY,
    credential_fingerprint TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL,
    role TEXT NOT NULL,
    label TEXT NOT NULL,
    aaguid TEXT NOT NULL,
    device_type TEXT NOT NULL,
    backed_up INTEGER NOT NULL,
    registered_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS root_action_auth_active_label
ON root_action_auth_credentials(label) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS root_action_auth_ceremonies (
    ceremony_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    challenge BLOB NOT NULL,
    binding_nonce BLOB NOT NULL,
    challenge_digest TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    job_id TEXT REFERENCES root_action_jobs(job_id),
    job_digest TEXT,
    bootstrap_id TEXT REFERENCES root_action_auth_bootstrap(bootstrap_id),
    role TEXT,
    label TEXT,
    state TEXT NOT NULL,
    consumed_at TEXT,
    credential_fingerprint TEXT REFERENCES root_action_auth_credentials(credential_fingerprint)
);
CREATE INDEX IF NOT EXISTS root_action_auth_ceremony_job
ON root_action_auth_ceremonies(job_id, issued_at);
CREATE TABLE IF NOT EXISTS root_action_auth_approvals (
    approval_id TEXT PRIMARY KEY,
    ceremony_id TEXT NOT NULL UNIQUE REFERENCES root_action_auth_ceremonies(ceremony_id),
    job_id TEXT NOT NULL REFERENCES root_action_jobs(job_id),
    job_digest TEXT NOT NULL,
    credential_fingerprint TEXT NOT NULL REFERENCES root_action_auth_credentials(credential_fingerprint),
    verified_at TEXT NOT NULL,
    origin TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    user_verified INTEGER NOT NULL,
    sign_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS root_action_auth_approval_job
ON root_action_auth_approvals(job_id, verified_at);
"""
_SCHEMA = _BASE_SCHEMA + _AUTH_SCHEMA
_SCHEMA_VERSION = 3
_SCHEMA_VERSION_2_TABLES = {
    "root_action_jobs",
    "root_action_records",
    "root_action_ledger",
    "root_action_raw_receipts",
    "root_action_receipts",
    "root_action_receipt_current",
    "root_action_quarantine",
}
_REQUIRED_TABLES = {
    *_SCHEMA_VERSION_2_TABLES,
    "root_action_auth_bootstrap",
    "root_action_auth_credentials",
    "root_action_auth_ceremonies",
    "root_action_auth_approvals",
}


class PosixStoreSecurityError(RuntimeError):
    """The production store path is not a trusted root-owned object."""


class PosixRootActionStore:
    """SQLite-backed root-owned store with transactional CAS and append ledger.

    The database is the root-only authority. Public status files are a separate
    derived projection and are never read back as execution truth.
    """

    def __init__(
        self,
        root: Path,
        *,
        create: bool = False,
        required_uid: int | None = 0,
        required_gid: int | None = 0,
        require_posix: bool = True,
    ) -> None:
        self.root = Path(root)
        self.database = self.root / "root-actions.sqlite3"
        self._required_uid = required_uid
        self._required_gid = required_gid
        self._enforce_posix_identity = os.name == "posix"
        if require_posix and os.name != "posix":
            raise PosixStoreSecurityError("production root-action store requires POSIX")
        self._prepare_root(create=create)
        self._prepare_database(create=create)
        with self._connect(check_schema=False) as connection:
            self._initialize_schema(connection)

    def put_if_absent(self, job: SealedJob) -> None:
        self._verify_job(job)
        with self._transaction() as connection:
            self._insert_job(
                connection,
                job,
                SubmissionMetadata(0, 0, 0, job.submitted_at),
            )

    def read_sealed(self, job_id: str) -> SealedJob:
        with self._connect() as connection:
            return self._read_job(connection, job_id)

    def list_job_ids(self) -> tuple[str, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT job_id FROM root_action_jobs ORDER BY job_id"
            ).fetchall()
            return tuple(row["job_id"] for row in rows)

    def catalog_job_ids(self, *, limit: int) -> tuple[tuple[str, ...], int]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("catalog job limit must be a positive integer")
        with self._connect() as connection:
            authority_count = connection.execute(
                "SELECT COUNT(*) FROM root_action_records"
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT job_id FROM root_action_records
                ORDER BY last_changed_at DESC, job_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(row["job_id"] for row in rows), authority_count

    def submission_metadata(self, job_id: str) -> SubmissionMetadata:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT peer_uid, peer_gid, peer_pid, broker_received_at
                FROM root_action_jobs WHERE job_id=?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            raise StorageNotFound(job_id)
        return SubmissionMetadata(**dict(row))

    def lineage_summary(
        self,
        lineage_id: str,
        *,
        measured_at: str,
        policy: LineageFailurePolicy = LineageFailurePolicy(),
    ) -> LineageSummary:
        with self._connect() as connection:
            return self._lineage_summary(
                connection,
                lineage_id,
                measured_at=measured_at,
                policy=policy,
            )

    @staticmethod
    def _lineage_summary(
        connection: sqlite3.Connection,
        lineage_id: str,
        *,
        measured_at: str,
        policy: LineageFailurePolicy,
    ) -> LineageSummary:
        now = datetime.strptime(measured_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        cutoff = (now - timedelta(seconds=policy.window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        rows = connection.execute(
            """
            SELECT r.terminal_outcome, r.reason_code
            FROM root_action_jobs j
            JOIN root_action_records r ON r.job_id=j.job_id
            WHERE j.lineage_id=?
              AND j.broker_received_at>=?
              AND j.broker_received_at<=?
            """,
            (lineage_id, cutoff, measured_at),
        ).fetchall()
        terminal_counts = {
            "succeeded": 0,
            "failed": 0,
            "rejected": 0,
            "expired": 0,
            "canceled": 0,
            "prestart_failed": 0,
        }
        technical_failure_count = 0
        for row in rows:
            outcome = row["terminal_outcome"]
            if outcome is None:
                continue
            terminal_counts[outcome] += 1
            if (
                outcome in {"failed", "prestart_failed"}
                and row["reason_code"] in policy.technical_reason_codes
            ):
                technical_failure_count += 1
        return LineageSummary(
            lineage_id=lineage_id,
            measured_at=measured_at,
            window_seconds=policy.window_seconds,
            submission_count=len(rows),
            terminal_counts=terminal_counts,
            technical_failure_count=technical_failure_count,
        )

    def create_pending(self, record: JobRecord) -> None:
        validate_record(record)
        if record.state is not JobState.PENDING or record.revision != 0:
            raise StorageConflict("create_pending requires an initial pending record")
        with self._transaction() as connection:
            job = self._read_job(connection, record.job_id)
            if job.job_digest != record.job_digest:
                raise StorageConflict("pending record has no matching sealed job")
            self._insert_record_and_initial_ledger(connection, record)

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
        with self._transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM root_action_jobs WHERE job_id=?", (job.job_id,)
                ).fetchone()
                is not None
            ):
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(connection, job, submission, limits)
            self._insert_job(connection, job, submission)
            self._insert_record_and_initial_ledger(connection, record)
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
        with self._transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM root_action_jobs WHERE job_id=?", (job.job_id,)
                ).fetchone()
                is not None
            ):
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(connection, job, submission, limits)
            self._insert_job(connection, job, submission)
            self._insert_record_and_initial_ledger(connection, pending)
            self._compare_and_append(connection, close_event)
            self._validate_receipt_publication(connection, notice)
            self._insert_receipt(connection, notice)
        return rejected

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
        with self._transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM root_action_jobs WHERE job_id=?",
                    (job.job_id,),
                ).fetchone()
                is not None
            ):
                raise StorageConflict("job_id is already sealed")
            self._enforce_submission_limits(connection, job, submission, limits)
            summary = self._lineage_summary(
                connection,
                job.lineage_id,
                measured_at=submission.broker_received_at,
                policy=failure_policy,
            )
            blocked = (
                summary.technical_failure_count
                >= failure_policy.maximum_technical_failures
            )
            if blocked:
                value = circuit_notice.receipt_copy()
                if (
                    circuit_event.job_id != job.job_id
                    or circuit_event.job_digest != job.job_digest
                    or circuit_event.expected_revision != 0
                    or circuit_event.kind.value != "close_pending"
                    or circuit_event.outcome is None
                    or circuit_event.outcome.value != "prestart_failed"
                    or circuit_event.reason_code != failure_policy.circuit_reason_code
                    or circuit_notice.job_id != job.job_id
                    or circuit_notice.job_digest != job.job_digest
                    or circuit_notice.operation_id != job.operation_id
                    or circuit_notice.request_id != job.request_id
                    or circuit_notice.reply_target != job.reply_target
                    or circuit_notice.kind != "terminal_notice"
                    or value["terminal_outcome"] != "prestart_failed"
                    or value["reason_code"] != failure_policy.circuit_reason_code
                ):
                    raise StorageConflict("lineage circuit notice is invalid")
            self._insert_job(connection, job, submission)
            self._insert_record_and_initial_ledger(connection, pending)
            record = pending
            reason_code: str | None = None
            if blocked:
                record = self._compare_and_append(connection, circuit_event)
                self._validate_receipt_publication(connection, circuit_notice)
                self._insert_receipt(connection, circuit_notice)
                reason_code = failure_policy.circuit_reason_code
        return record, SubmissionAdmission(
            allowed=not blocked,
            reason_code=reason_code,
            summary=summary,
        )

    def read_record(self, job_id: str) -> JobRecord:
        with self._connect() as connection:
            return self._read_record(connection, job_id)

    def running_job_ids(self) -> tuple[str, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT job_id FROM root_action_records
                WHERE state='running' ORDER BY last_changed_at, job_id
                """
            ).fetchall()
        return tuple(row["job_id"] for row in rows)

    def compare_and_append(self, event: TransitionEvent) -> JobRecord:
        with self._transaction() as connection:
            return self._compare_and_append(connection, event)

    def _compare_and_append(
        self, connection: sqlite3.Connection, event: TransitionEvent
    ) -> JobRecord:
        current = self._read_record(connection, event.job_id)
        replay = connection.execute(
            "SELECT 1 FROM root_action_ledger WHERE job_id=? AND event_id=?",
            (event.job_id, event.event_id),
        ).fetchone()
        if replay is not None:
            raise StorageConflict("ledger event_id replay is blocked")
        updated = apply_transition(current, event)
        cursor = connection.execute(
            """
            UPDATE root_action_records
            SET state=?, revision=?, execution_count=?, terminal_outcome=?,
                reason_code=?, last_event_id=?, last_changed_at=?
            WHERE job_id=? AND job_digest=? AND revision=?
            """,
            (
                updated.state.value,
                updated.revision,
                updated.execution_count,
                updated.terminal_outcome.value if updated.terminal_outcome else None,
                updated.reason_code,
                updated.last_event_id,
                updated.last_changed_at,
                updated.job_id,
                updated.job_digest,
                current.revision,
            ),
        )
        if cursor.rowcount != 1:
            raise StorageConflict("state compare-and-swap lost a concurrent race")
        self._insert_ledger(connection, current, updated, event)
        return updated

    def read_ledger(self, job_id: str) -> tuple[LedgerEntry, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, action, prior_state, next_state, record_revision,
                       event_id, occurred_at, job_id, job_digest,
                       terminal_outcome, reason_code
                FROM root_action_ledger WHERE job_id=? ORDER BY sequence
                """,
                (job_id,),
            ).fetchall()
        if not rows:
            raise StorageNotFound(job_id)
        return tuple(LedgerEntry(**dict(row)) for row in rows)

    def put_raw_if_absent(self, artifact: RawReceiptArtifact) -> None:
        reference = artifact.reference
        with self._transaction() as connection:
            job = self._read_job(connection, reference.job_id)
            if job.job_digest != reference.job_digest:
                raise StorageConflict("raw receipt job identity mismatch")
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_raw_receipts
                (job_id, job_digest, raw_receipt_digest, root_storage_id, raw_receipt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    reference.job_id,
                    reference.job_digest,
                    reference.raw_receipt_digest,
                    reference.root_storage_id,
                    artifact.raw_bytes,
                ),
                "raw receipt already exists",
            )

    def read_raw_root_only(self, job_id: str) -> RawReceiptArtifact:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT job_id, job_digest, raw_receipt_digest, root_storage_id,
                       raw_receipt
                FROM root_action_raw_receipts WHERE job_id=?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            raise StorageNotFound(job_id)
        values = dict(row)
        raw_bytes = values.pop("raw_receipt")
        return RawReceiptArtifact(
            reference=RawReceiptReference(**values),
            raw_bytes=raw_bytes,
        )

    def complete_claimed_execution(
        self,
        *,
        event: TransitionEvent,
        raw: RawReceiptArtifact,
        receipt: ReceiptArtifact,
    ) -> JobRecord:
        if event.kind is not TransitionKind.COMPLETE_EXECUTION:
            raise StorageConflict("execution completion requires a complete event")
        return self._finalize_claimed_execution(
            event=event,
            raw=raw,
            receipt=receipt,
        )

    def mark_claimed_execution_unknown(
        self,
        *,
        event: TransitionEvent,
        raw: RawReceiptArtifact,
        receipt: ReceiptArtifact,
    ) -> JobRecord:
        if event.kind is not TransitionKind.MARK_UNKNOWN:
            raise StorageConflict("unknown completion requires a mark-unknown event")
        return self._finalize_claimed_execution(
            event=event,
            raw=raw,
            receipt=receipt,
        )

    def _finalize_claimed_execution(
        self,
        *,
        event: TransitionEvent,
        raw: RawReceiptArtifact,
        receipt: ReceiptArtifact,
    ) -> JobRecord:
        self._verify_receipt(receipt)
        reference = raw.reference
        value = receipt.receipt_copy()
        if (
            event.job_id != reference.job_id
            or event.job_digest != reference.job_digest
            or receipt.job_id != reference.job_id
            or receipt.job_digest != reference.job_digest
            or value.get("raw_receipt_digest") != reference.raw_receipt_digest
        ):
            raise StorageConflict("execution receipt identity mismatch")
        with self._transaction() as connection:
            job = self._read_job(connection, event.job_id)
            if job.job_digest != event.job_digest:
                raise StorageConflict("execution event job identity mismatch")
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_raw_receipts
                (job_id, job_digest, raw_receipt_digest, root_storage_id, raw_receipt)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    reference.job_id,
                    reference.job_digest,
                    reference.raw_receipt_digest,
                    reference.root_storage_id,
                    raw.raw_bytes,
                ),
                "raw receipt already exists",
            )
            record = self._compare_and_append(connection, event)
            self._validate_receipt_publication(connection, receipt)
            self._insert_receipt(connection, receipt)
            return record

    def publish_if_absent(self, artifact: ReceiptArtifact) -> None:
        self._verify_receipt(artifact)
        with self._transaction() as connection:
            self._validate_receipt_publication(connection, artifact)
            self._insert_receipt(connection, artifact)

    def retrieve(self, job_id: str, job_digest: str) -> ReceiptArtifact:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT r.kind, r.job_id, r.job_digest, r.operation_id,
                       r.receipt_digest, r.canonical_receipt
                FROM root_action_receipt_current c
                JOIN root_action_receipts r
                  ON r.receipt_digest=c.receipt_digest
                WHERE c.job_id=? AND r.job_digest=?
                """,
                (job_id, job_digest),
            ).fetchone()
        if row is None:
            raise StorageNotFound(job_id)
        values = dict(row)
        artifact = seal_receipt(values["canonical_receipt"])
        if any(
            values[field] != getattr(artifact, field)
            for field in (
                "kind",
                "job_id",
                "job_digest",
                "operation_id",
                "receipt_digest",
            )
        ):
            raise StorageConflict("receipt index metadata mismatch")
        self._verify_receipt(artifact)
        return artifact

    def quarantine_if_absent(self, record: QuarantineRecord) -> None:
        artifact = record.notice
        self._verify_receipt(artifact)
        with self._transaction() as connection:
            raw = connection.execute(
                """
                SELECT job_id, job_digest, raw_receipt_digest, root_storage_id
                FROM root_action_raw_receipts WHERE job_id=?
                """,
                (record.raw_reference.job_id,),
            ).fetchone()
            if raw is None or RawReceiptReference(**dict(raw)) != record.raw_reference:
                raise StorageConflict("quarantine raw receipt reference mismatch")
            self._validate_receipt_publication(connection, artifact)
            self._insert_receipt(connection, artifact)
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_quarantine
                (job_id, receipt_digest, root_storage_id) VALUES (?, ?, ?)
                """,
                (
                    artifact.job_id,
                    artifact.receipt_digest,
                    record.raw_reference.root_storage_id,
                ),
                "quarantine entry already exists",
            )

    def read_quarantine_notice(self, job_id: str) -> ReceiptArtifact:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT receipt_digest FROM root_action_quarantine WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise StorageNotFound(job_id)
            receipt = connection.execute(
                """
                SELECT kind, job_id, job_digest, operation_id, receipt_digest,
                       canonical_receipt
                FROM root_action_receipts WHERE receipt_digest=?
                """,
                (row["receipt_digest"],),
            ).fetchone()
        if receipt is None:
            raise StorageConflict("quarantine notice points to a missing receipt")
        values = dict(receipt)
        artifact = seal_receipt(values["canonical_receipt"])
        if any(
            values[field] != getattr(artifact, field)
            for field in (
                "kind",
                "job_id",
                "job_digest",
                "operation_id",
                "receipt_digest",
            )
        ):
            raise StorageConflict("quarantine receipt index metadata mismatch")
        self._verify_receipt(artifact)
        return artifact

    def create_auth_bootstrap(self, session: BootstrapSession) -> None:
        if session.state is not BootstrapState.ISSUED:
            raise StorageConflict("new bootstrap session must be issued")
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE root_action_auth_bootstrap
                SET state='expired'
                WHERE state='issued' AND expires_at<=?
                """,
                (session.issued_at,),
            )
            if connection.execute(
                "SELECT 1 FROM root_action_auth_bootstrap WHERE state='issued'"
            ).fetchone() is not None:
                raise StorageConflict("an unexpired bootstrap session already exists")
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_auth_bootstrap
                (bootstrap_id, token_digest, issued_at, expires_at,
                 remaining_registrations, state)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session.bootstrap_id,
                    session.token_digest,
                    session.issued_at,
                    session.expires_at,
                    session.remaining_registrations,
                    session.state.value,
                ),
                "bootstrap identity already exists",
            )

    def read_auth_bootstrap(self, bootstrap_id: str) -> BootstrapSession:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT bootstrap_id, token_digest, issued_at, expires_at,
                       remaining_registrations, state
                FROM root_action_auth_bootstrap WHERE bootstrap_id=?
                """,
                (bootstrap_id,),
            ).fetchone()
        if row is None:
            raise StorageNotFound(bootstrap_id)
        return self._bootstrap_from_row(row)

    def read_auth_bootstrap_by_token(self, token_digest: str) -> BootstrapSession:
        with self._connect() as connection:
            return self._bootstrap_by_token(connection, token_digest)

    def issue_registration_ceremony(
        self, *, token_digest: str, ceremony: PendingCeremony
    ) -> None:
        if (
            ceremony.purpose is not CeremonyPurpose.REGISTRATION
            or ceremony.state is not CeremonyState.ISSUED
        ):
            raise StorageConflict("registration ceremony is invalid")
        with self._transaction() as connection:
            bootstrap = self._bootstrap_by_token(connection, token_digest)
            if (
                bootstrap.bootstrap_id != ceremony.bootstrap_id
                or bootstrap.state is not BootstrapState.ISSUED
                or bootstrap.remaining_registrations < 1
                or bootstrap.expires_at <= ceremony.issued_at
                or ceremony.expires_at > bootstrap.expires_at
            ):
                raise StorageConflict("bootstrap does not authorize this registration")
            outstanding = connection.execute(
                """
                SELECT 1 FROM root_action_auth_ceremonies
                WHERE bootstrap_id=? AND state='issued' AND expires_at>=?
                """,
                (bootstrap.bootstrap_id, ceremony.issued_at),
            ).fetchone()
            if outstanding is not None:
                raise StorageConflict("bootstrap already has an issued ceremony")
            self._insert_ceremony(connection, ceremony)

    def complete_registration(
        self,
        *,
        token_digest: str,
        ceremony_id: str,
        credential: RegisteredCredential,
        consumed_at: str,
    ) -> RegisteredCredential:
        with self._transaction() as connection:
            ceremony = self._read_ceremony(connection, ceremony_id)
            if (
                ceremony.purpose is not CeremonyPurpose.REGISTRATION
                or ceremony.state is not CeremonyState.ISSUED
                or ceremony.expires_at <= consumed_at
                or ceremony.bootstrap_id is None
                or ceremony.role is not credential.role
                or ceremony.label != credential.label
            ):
                raise StorageConflict("registration ceremony cannot be consumed")
            bootstrap = self._bootstrap_by_token(connection, token_digest)
            if (
                bootstrap.bootstrap_id != ceremony.bootstrap_id
                or bootstrap.state is not BootstrapState.ISSUED
                or bootstrap.remaining_registrations < 1
                or bootstrap.expires_at <= consumed_at
            ):
                raise StorageConflict("bootstrap is not active for registration")
            self._insert_credential(connection, credential)
            cursor = connection.execute(
                """
                UPDATE root_action_auth_ceremonies
                SET state='consumed', consumed_at=?, credential_fingerprint=?
                WHERE ceremony_id=? AND state='issued'
                """,
                (consumed_at, credential.fingerprint, ceremony.ceremony_id),
            )
            if cursor.rowcount != 1:
                raise StorageConflict("registration ceremony consumption race")
            remaining = bootstrap.remaining_registrations - 1
            state = "consumed" if remaining == 0 else "issued"
            cursor = connection.execute(
                """
                UPDATE root_action_auth_bootstrap
                SET remaining_registrations=?, state=?
                WHERE bootstrap_id=? AND state='issued'
                  AND remaining_registrations=?
                """,
                (
                    remaining,
                    state,
                    bootstrap.bootstrap_id,
                    bootstrap.remaining_registrations,
                ),
            )
            if cursor.rowcount != 1:
                raise StorageConflict("bootstrap registration counter race")
        return credential

    def active_credentials(
        self, role: CredentialRole
    ) -> tuple[RegisteredCredential, ...]:
        if not isinstance(role, CredentialRole):
            raise ValueError("credential role is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT credential_id, credential_fingerprint, public_key,
                       sign_count, role, label, aaguid,
                       device_type, backed_up, registered_at, revoked_at
                FROM root_action_auth_credentials
                WHERE role=? AND revoked_at IS NULL
                ORDER BY registered_at, credential_fingerprint
                """,
                (role.value,),
            ).fetchall()
        return tuple(self._credential_from_row(row) for row in rows)

    def read_credential(self, credential_id: bytes) -> RegisteredCredential:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT credential_id, credential_fingerprint, public_key,
                       sign_count, role, label, aaguid,
                       device_type, backed_up, registered_at, revoked_at
                FROM root_action_auth_credentials WHERE credential_id=?
                """,
                (credential_id,),
            ).fetchone()
        if row is None:
            raise StorageNotFound("credential")
        return self._credential_from_row(row)

    def issue_approval_ceremony(self, ceremony: PendingCeremony) -> None:
        if (
            ceremony.purpose is not CeremonyPurpose.APPROVAL
            or ceremony.state is not CeremonyState.ISSUED
            or ceremony.job_id is None
            or ceremony.job_digest is None
        ):
            raise StorageConflict("approval ceremony is invalid")
        with self._transaction() as connection:
            record = self._read_record(connection, ceremony.job_id)
            if (
                record.job_digest != ceremony.job_digest
                or record.state is not JobState.PENDING
                or record.execution_count != 0
            ):
                raise StorageConflict("only the exact pending job can request approval")
            if connection.execute(
                """
                SELECT 1 FROM root_action_auth_credentials
                WHERE role='approval' AND revoked_at IS NULL LIMIT 1
                """
            ).fetchone() is None:
                raise StorageConflict("no active approval credential is enrolled")
            connection.execute(
                """
                UPDATE root_action_auth_ceremonies
                SET state='expired', consumed_at=?
                WHERE purpose='approval' AND state='issued' AND expires_at<=?
                """,
                (ceremony.issued_at, ceremony.issued_at),
            )
            self._insert_ceremony(connection, ceremony)

    def read_ceremony(self, ceremony_id: str) -> PendingCeremony:
        with self._connect() as connection:
            return self._read_ceremony(connection, ceremony_id)

    def claim_with_approval(
        self,
        *,
        ceremony: PendingCeremony,
        credential: RegisteredCredential,
        verified: VerifiedAssertion,
        approval: ApprovalRecord,
        claim_event: TransitionEvent,
    ) -> JobRecord:
        if (
            ceremony.purpose is not CeremonyPurpose.APPROVAL
            or ceremony.state is not CeremonyState.ISSUED
            or credential.role is not CredentialRole.APPROVAL
            or credential.revoked_at is not None
            or verified.credential_id != credential.credential_id
            or verified.user_verified is not True
            or verified.device_type != credential.device_type
            or approval.origin != verified.origin
            or approval.rp_id != verified.rp_id
            or approval.ceremony_id != ceremony.ceremony_id
            or approval.job_id != ceremony.job_id
            or approval.job_digest != ceremony.job_digest
            or approval.credential_fingerprint != credential.fingerprint
            or approval.sign_count != verified.new_sign_count
            or approval.user_verified is not True
            or claim_event.kind.value != "claim_execution"
            or claim_event.job_id != ceremony.job_id
            or claim_event.job_digest != ceremony.job_digest
        ):
            raise StorageConflict("approval claim contract is invalid")
        with self._transaction() as connection:
            stored_ceremony = self._read_ceremony(connection, ceremony.ceremony_id)
            if stored_ceremony != ceremony or ceremony.expires_at <= approval.verified_at:
                raise StorageConflict("approval ceremony is stale, consumed, or expired")
            stored_credential = self._read_credential(connection, credential.credential_id)
            if stored_credential != credential:
                raise StorageConflict("approval credential changed during verification")
            cursor = connection.execute(
                """
                UPDATE root_action_auth_credentials
                SET sign_count=?, backed_up=?
                WHERE credential_id=? AND sign_count=? AND revoked_at IS NULL
                """,
                (
                    verified.new_sign_count,
                    1 if verified.backed_up else 0,
                    credential.credential_id,
                    credential.sign_count,
                ),
            )
            if cursor.rowcount != 1:
                raise StorageConflict("credential counter compare-and-swap failed")
            cursor = connection.execute(
                """
                UPDATE root_action_auth_ceremonies
                SET state='consumed', consumed_at=?, credential_fingerprint=?
                WHERE ceremony_id=? AND state='issued'
                """,
                (
                    approval.verified_at,
                    credential.fingerprint,
                    ceremony.ceremony_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StorageConflict("approval ceremony consumption race")
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_auth_approvals
                (approval_id, ceremony_id, job_id, job_digest,
                 credential_fingerprint, verified_at, origin, rp_id,
                 user_verified, sign_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.approval_id,
                    approval.ceremony_id,
                    approval.job_id,
                    approval.job_digest,
                    approval.credential_fingerprint,
                    approval.verified_at,
                    approval.origin,
                    approval.rp_id,
                    1,
                    approval.sign_count,
                ),
                "approval identity already exists",
            )
            return self._compare_and_append(connection, claim_event)

    def approvals(self, job_id: str) -> tuple[ApprovalRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT approval_id, ceremony_id, job_id, job_digest,
                       credential_fingerprint, verified_at, origin, rp_id,
                       user_verified, sign_count
                FROM root_action_auth_approvals
                WHERE job_id=? ORDER BY verified_at, approval_id
                """,
                (job_id,),
            ).fetchall()
        return tuple(
            ApprovalRecord(
                **{
                    **dict(row),
                    "user_verified": bool(row["user_verified"]),
                }
            )
            for row in rows
        )

    def _prepare_root(self, *, create: bool) -> None:
        if create:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.chmod(self.root, 0o700)
            except OSError as exc:
                raise PosixStoreSecurityError(
                    "cannot set root-action store mode"
                ) from exc
        try:
            info = self.root.lstat()
        except OSError as exc:
            raise PosixStoreSecurityError(
                "root-action store root is unavailable"
            ) from exc
        if not stat.S_ISDIR(info.st_mode) or self.root.is_symlink():
            raise PosixStoreSecurityError(
                "root-action store root is not a real directory"
            )
        if self._enforce_posix_identity and stat.S_IMODE(info.st_mode) != 0o700:
            raise PosixStoreSecurityError("root-action store root mode is invalid")
        self._verify_identity(info, "root-action store root", allow_public_read=False)
        self._root_identity = (info.st_dev, info.st_ino)

    def _prepare_database(self, *, create: bool) -> None:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if create:
            flags |= os.O_CREAT
        try:
            fd = os.open(self.database, flags, 0o600)
        except OSError as exc:
            raise PosixStoreSecurityError(
                "root-action database cannot be opened safely"
            ) from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PosixStoreSecurityError(
                    "root-action database is not a single-link file"
                )
            if stat.S_IMODE(info.st_mode) != 0o600:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                else:
                    os.chmod(self.database, 0o600)
                info = os.fstat(fd)
            self._verify_identity(info, "root-action database", allow_public_read=False)
            self._database_identity = (info.st_dev, info.st_ino)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_directory(self.root)

    def _verify_database_path(self) -> None:
        try:
            info = self.database.lstat()
        except OSError as exc:
            raise PosixStoreSecurityError("root-action database disappeared") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or self.database.is_symlink()
            or info.st_nlink != 1
        ):
            raise PosixStoreSecurityError("root-action database identity is unsafe")
        if (info.st_dev, info.st_ino) != self._database_identity:
            raise PosixStoreSecurityError("root-action database identity changed")
        self._verify_identity(info, "root-action database", allow_public_read=False)

    def _verify_root_path(self) -> None:
        try:
            info = self.root.lstat()
        except OSError as exc:
            raise PosixStoreSecurityError("root-action store root disappeared") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or self.root.is_symlink()
            or (info.st_dev, info.st_ino) != self._root_identity
        ):
            raise PosixStoreSecurityError("root-action store root identity changed")
        if self._enforce_posix_identity and stat.S_IMODE(info.st_mode) != 0o700:
            raise PosixStoreSecurityError("root-action store root mode is invalid")
        self._verify_identity(info, "root-action store root", allow_public_read=False)

    def _verify_identity(
        self, info: os.stat_result, field: str, *, allow_public_read: bool
    ) -> None:
        if not self._enforce_posix_identity:
            return
        if self._required_uid is not None and info.st_uid != self._required_uid:
            raise PosixStoreSecurityError(f"{field} uid is not trusted")
        if self._required_gid is not None and info.st_gid != self._required_gid:
            raise PosixStoreSecurityError(f"{field} gid is not trusted")
        mode = stat.S_IMODE(info.st_mode)
        # Private paths may use the owner's read/write/execute bits.  The
        # security boundary is that group/other receive no access at all.
        forbidden = 0o022 if allow_public_read else 0o077
        if mode & forbidden:
            raise PosixStoreSecurityError(f"{field} mode is too permissive")

    @contextmanager
    def _connect(self, *, check_schema: bool = True) -> Iterator[sqlite3.Connection]:
        self._verify_root_path()
        self._verify_database_path()
        connection = sqlite3.connect(
            self.database,
            isolation_level=None,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            if check_schema:
                self._verify_schema(connection)
            yield connection
        finally:
            connection.close()
            self._verify_database_path()

    @staticmethod
    def _schema_tables(connection: sqlite3.Connection) -> set[str]:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if isinstance(row[0], str) and row[0].startswith("root_action_")
        }

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = self._schema_tables(connection)
        if version == 0:
            if tables:
                raise PosixStoreSecurityError(
                    "unversioned root-action database is not accepted"
                )
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + _SCHEMA
                    + f"\nPRAGMA user_version={_SCHEMA_VERSION};\nCOMMIT;"
                )
            except Exception:
                connection.rollback()
                raise
        elif version == 2:
            if tables != _SCHEMA_VERSION_2_TABLES:
                raise PosixStoreSecurityError(
                    "root-action v2 database table set is invalid"
                )
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + _AUTH_SCHEMA
                    + f"\nPRAGMA user_version={_SCHEMA_VERSION};\nCOMMIT;"
                )
            except Exception:
                connection.rollback()
                raise
        elif version != _SCHEMA_VERSION:
            raise PosixStoreSecurityError("root-action database schema is unsupported")
        self._verify_schema(connection)

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != _SCHEMA_VERSION:
            raise PosixStoreSecurityError("root-action database schema is unsupported")
        if self._schema_tables(connection) != _REQUIRED_TABLES:
            raise PosixStoreSecurityError("root-action database table set is invalid")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    @staticmethod
    def _execute_insert(
        connection: sqlite3.Connection,
        statement: str,
        values: tuple[object, ...],
        message: str,
    ) -> None:
        try:
            connection.execute(statement, values)
        except sqlite3.IntegrityError as exc:
            raise StorageConflict(message) from exc

    def _insert_job(
        self,
        connection: sqlite3.Connection,
        job: SealedJob,
        submission: SubmissionMetadata,
    ) -> None:
        self._execute_insert(
            connection,
            """
            INSERT INTO root_action_jobs
            (job_id, job_digest, operation_id, operation_version, request_id,
             lineage_id, reply_target, submitted_at, peer_uid, peer_gid, peer_pid,
             broker_received_at, canonical_manifest)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job.job_id,
                job.job_digest,
                job.operation_id,
                job.operation_version,
                job.request_id,
                job.lineage_id,
                job.reply_target,
                job.submitted_at,
                submission.peer_uid,
                submission.peer_gid,
                submission.peer_pid,
                submission.broker_received_at,
                job.canonical_manifest,
            ),
            "job_id is already sealed",
        )

    @staticmethod
    def _bootstrap_from_row(row: sqlite3.Row) -> BootstrapSession:
        values = dict(row)
        values["state"] = BootstrapState(values["state"])
        return BootstrapSession(**values)

    def _bootstrap_by_token(
        self, connection: sqlite3.Connection, token_digest: str
    ) -> BootstrapSession:
        row = connection.execute(
            """
            SELECT bootstrap_id, token_digest, issued_at, expires_at,
                   remaining_registrations, state
            FROM root_action_auth_bootstrap WHERE token_digest=?
            """,
            (token_digest,),
        ).fetchone()
        if row is None:
            raise StorageNotFound("bootstrap")
        return self._bootstrap_from_row(row)

    @staticmethod
    def _credential_from_row(row: sqlite3.Row) -> RegisteredCredential:
        values = dict(row)
        stored_fingerprint = values.pop("credential_fingerprint")
        values["credential_id"] = bytes(values["credential_id"])
        values["public_key"] = bytes(values["public_key"])
        values["role"] = CredentialRole(values["role"])
        values["backed_up"] = bool(values["backed_up"])
        credential = RegisteredCredential(**values)
        if credential.fingerprint != stored_fingerprint:
            raise StorageConflict("credential fingerprint metadata mismatch")
        return credential

    def _read_credential(
        self, connection: sqlite3.Connection, credential_id: bytes
    ) -> RegisteredCredential:
        row = connection.execute(
            """
            SELECT credential_id, credential_fingerprint, public_key,
                   sign_count, role, label, aaguid,
                   device_type, backed_up, registered_at, revoked_at
            FROM root_action_auth_credentials WHERE credential_id=?
            """,
            (credential_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFound("credential")
        return self._credential_from_row(row)

    def _insert_credential(
        self, connection: sqlite3.Connection, credential: RegisteredCredential
    ) -> None:
        self._execute_insert(
            connection,
            """
            INSERT INTO root_action_auth_credentials
            (credential_id, credential_fingerprint, public_key, sign_count,
             role, label, aaguid, device_type, backed_up, registered_at,
             revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                credential.credential_id,
                credential.fingerprint,
                credential.public_key,
                credential.sign_count,
                credential.role.value,
                credential.label,
                credential.aaguid,
                credential.device_type,
                1 if credential.backed_up else 0,
                credential.registered_at,
                credential.revoked_at,
            ),
            "credential or active label already exists",
        )

    @staticmethod
    def _ceremony_from_row(row: sqlite3.Row) -> PendingCeremony:
        values = dict(row)
        values["challenge"] = bytes(values["challenge"])
        values["binding_nonce"] = bytes(values["binding_nonce"])
        values["purpose"] = CeremonyPurpose(values["purpose"])
        values["state"] = CeremonyState(values["state"])
        if values["role"] is not None:
            values["role"] = CredentialRole(values["role"])
        return PendingCeremony(**values)

    def _read_ceremony(
        self, connection: sqlite3.Connection, ceremony_id: str
    ) -> PendingCeremony:
        row = connection.execute(
            """
            SELECT ceremony_id, purpose, challenge, binding_nonce,
                   challenge_digest, issued_at,
                   expires_at, job_id, job_digest, bootstrap_id, role, label,
                   state, consumed_at, credential_fingerprint
            FROM root_action_auth_ceremonies WHERE ceremony_id=?
            """,
            (ceremony_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFound(ceremony_id)
        return self._ceremony_from_row(row)

    def _insert_ceremony(
        self, connection: sqlite3.Connection, ceremony: PendingCeremony
    ) -> None:
        self._execute_insert(
            connection,
            """
            INSERT INTO root_action_auth_ceremonies
            (ceremony_id, purpose, challenge, binding_nonce, challenge_digest, issued_at,
             expires_at, job_id, job_digest, bootstrap_id, role, label, state,
             consumed_at, credential_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ceremony.ceremony_id,
                ceremony.purpose.value,
                ceremony.challenge,
                ceremony.binding_nonce,
                ceremony.challenge_digest,
                ceremony.issued_at,
                ceremony.expires_at,
                ceremony.job_id,
                ceremony.job_digest,
                ceremony.bootstrap_id,
                ceremony.role.value if ceremony.role else None,
                ceremony.label,
                ceremony.state.value,
                ceremony.consumed_at,
                ceremony.credential_fingerprint,
            ),
            "ceremony identity already exists",
        )

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

    @staticmethod
    def _enforce_submission_limits(
        connection: sqlite3.Connection,
        job: SealedJob,
        submission: SubmissionMetadata,
        limits: SubmissionLimits,
    ) -> None:
        open_states = ("pending", "running", "unknown")
        open_for_uid = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM root_action_jobs j
            JOIN root_action_records r ON r.job_id=j.job_id
            WHERE j.peer_uid=? AND r.state IN (?, ?, ?)
            """,
            (submission.peer_uid, *open_states),
        ).fetchone()["count"]
        if open_for_uid >= limits.max_open_per_uid:
            raise StorageConflict("submission uid open-job circuit breaker")
        open_lineage = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM root_action_jobs j
            JOIN root_action_records r ON r.job_id=j.job_id
            WHERE j.lineage_id=? AND r.state IN (?, ?, ?)
            """,
            (job.lineage_id, *open_states),
        ).fetchone()["count"]
        if open_lineage >= limits.max_open_per_lineage:
            raise StorageConflict("submission lineage circuit breaker")
        now = datetime.strptime(
            submission.broker_received_at, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        cutoff = (now - timedelta(seconds=limits.window_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        recent_for_uid = connection.execute(
            """
            SELECT COUNT(*) AS count FROM root_action_jobs
            WHERE peer_uid=? AND broker_received_at>=?
            """,
            (submission.peer_uid, cutoff),
        ).fetchone()["count"]
        if recent_for_uid >= limits.max_jobs_per_uid_window:
            raise StorageConflict("submission uid rate circuit breaker")

    def _insert_record_and_initial_ledger(
        self, connection: sqlite3.Connection, record: JobRecord
    ) -> None:
        self._execute_insert(
            connection,
            """
            INSERT INTO root_action_records
            (job_id, job_digest, state, revision, execution_count,
             terminal_outcome, reason_code, last_event_id, last_changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.job_id,
                record.job_digest,
                record.state.value,
                record.revision,
                record.execution_count,
                None,
                None,
                record.last_event_id,
                record.last_changed_at,
            ),
            "pending record already exists",
        )
        try:
            connection.execute(
                """
                INSERT INTO root_action_ledger
                (action, prior_state, next_state, record_revision, event_id,
                 occurred_at, job_id, job_digest, terminal_outcome, reason_code)
                VALUES ('sealed_pending', NULL, 'pending', 0, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    record.last_event_id,
                    record.last_changed_at,
                    record.job_id,
                    record.job_digest,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StorageConflict("initial ledger event already exists") from exc

    @staticmethod
    def _insert_ledger(
        connection: sqlite3.Connection,
        prior: JobRecord,
        updated: JobRecord,
        event: TransitionEvent,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO root_action_ledger
                (action, prior_state, next_state, record_revision, event_id,
                 occurred_at, job_id, job_digest, terminal_outcome, reason_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.kind.value,
                    prior.state.value,
                    updated.state.value,
                    updated.revision,
                    event.event_id,
                    event.occurred_at,
                    updated.job_id,
                    updated.job_digest,
                    updated.terminal_outcome.value
                    if updated.terminal_outcome
                    else None,
                    updated.reason_code,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StorageConflict("ledger event insert failed") from exc

    def _read_job(self, connection: sqlite3.Connection, job_id: str) -> SealedJob:
        row = connection.execute(
            """
            SELECT job_id, job_digest, operation_id, operation_version, request_id,
                   lineage_id, reply_target, submitted_at, canonical_manifest
            FROM root_action_jobs WHERE job_id=?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFound(job_id)
        job = SealedJob(**dict(row))
        self._verify_job(job)
        return job

    @staticmethod
    def _read_record(connection: sqlite3.Connection, job_id: str) -> JobRecord:
        row = connection.execute(
            """
            SELECT job_id, job_digest, state, revision, execution_count,
                   terminal_outcome, reason_code, last_event_id, last_changed_at
            FROM root_action_records WHERE job_id=?
            """,
            (job_id,),
        ).fetchone()
        if row is None:
            raise StorageNotFound(job_id)
        values = dict(row)
        values["state"] = JobState(values["state"])
        values["terminal_outcome"] = (
            TerminalOutcome(values["terminal_outcome"])
            if values["terminal_outcome"] is not None
            else None
        )
        record = JobRecord(**values)
        validate_record(record)
        return record

    def _validate_receipt_publication(
        self, connection: sqlite3.Connection, artifact: ReceiptArtifact
    ) -> None:
        job = self._read_job(connection, artifact.job_id)
        record = self._read_record(connection, artifact.job_id)
        if (
            job.job_digest != artifact.job_digest
            or job.operation_id != artifact.operation_id
            or job.request_id != artifact.request_id
            or job.reply_target != artifact.reply_target
        ):
            raise StorageConflict("receipt job identity mismatch")
        if record.state not in {JobState.TERMINAL, JobState.UNKNOWN}:
            raise StorageConflict(
                "receipt cannot publish before a final or unknown state"
            )
        value = artifact.receipt_copy()
        if artifact.kind != "terminal_notice":
            raw = connection.execute(
                """
                SELECT raw_receipt_digest FROM root_action_raw_receipts WHERE job_id=?
                """,
                (artifact.job_id,),
            ).fetchone()
            if raw is None or raw["raw_receipt_digest"] != value["raw_receipt_digest"]:
                raise StorageConflict("receipt has no matching root-only raw receipt")
        if record.state is JobState.UNKNOWN:
            if artifact.kind != "unknown" or value["terminal_outcome"] is not None:
                raise StorageConflict("unknown state requires an unknown receipt")
        else:
            if artifact.kind == "unknown":
                raise StorageConflict(
                    "terminal state cannot publish an unknown receipt"
                )
            expected = (
                record.terminal_outcome.value if record.terminal_outcome else None
            )
            if value["terminal_outcome"] != expected:
                raise StorageConflict("receipt terminal outcome mismatch")
            if artifact.kind in {"unknown", "terminal_notice"} and (
                value.get("reason_code") != record.reason_code
            ):
                raise StorageConflict("receipt reason_code mismatch")

    def _insert_receipt(
        self, connection: sqlite3.Connection, artifact: ReceiptArtifact
    ) -> None:
        current = connection.execute(
            """
            SELECT r.kind
            FROM root_action_receipt_current c
            JOIN root_action_receipts r
              ON r.receipt_digest=c.receipt_digest
            WHERE c.job_id=?
            """,
            (artifact.job_id,),
        ).fetchone()
        if current is not None and not (
            current["kind"] == "unknown" and artifact.kind != "unknown"
        ):
            raise StorageConflict("public receipt or notice already exists")
        self._execute_insert(
            connection,
            """
            INSERT INTO root_action_receipts
            (receipt_digest, job_id, job_digest, operation_id, kind, canonical_receipt)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.receipt_digest,
                artifact.job_id,
                artifact.job_digest,
                artifact.operation_id,
                artifact.kind,
                artifact.canonical_receipt,
            ),
            "receipt digest already exists",
        )
        if current is None:
            self._execute_insert(
                connection,
                """
                INSERT INTO root_action_receipt_current (job_id, receipt_digest)
                VALUES (?, ?)
                """,
                (artifact.job_id, artifact.receipt_digest),
                "public receipt pointer already exists",
            )
        else:
            cursor = connection.execute(
                """
                UPDATE root_action_receipt_current
                SET receipt_digest=?
                WHERE job_id=?
                """,
                (artifact.receipt_digest, artifact.job_id),
            )
            if cursor.rowcount != 1:
                raise StorageConflict("public receipt pointer update failed")

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

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
