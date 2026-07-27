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


_SCHEMA = """
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
_SCHEMA_VERSION = 2
_REQUIRED_TABLES = {
    "root_action_jobs",
    "root_action_records",
    "root_action_ledger",
    "root_action_raw_receipts",
    "root_action_receipts",
    "root_action_receipt_current",
    "root_action_quarantine",
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
        forbidden = 0o022 if allow_public_read else 0o177
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
