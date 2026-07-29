from __future__ import annotations

from datetime import datetime
import hashlib
import json
from queue import Empty, Full, Queue
import threading
from typing import Callable

from .broker import BrokerEventSource, SystemBrokerEventSource
from .execution import DEFAULT_OPERATION_HANDLERS, OperationHandlerRegistry
from .posix_store import PosixRootActionStore
from .receipts import RECEIPT_SCHEMA, seal_raw_receipt, seal_receipt
from .state import JobState, TerminalOutcome, TransitionEvent, TransitionKind


class RootActionWorkerError(RuntimeError):
    """A claimed execution could not reach a trustworthy worker boundary."""


ProjectionRepair = Callable[[str], object]


class RootActionExecutionWorker:
    """One-shot background executor for already approved, claimed typed jobs."""

    def __init__(
        self,
        store: PosixRootActionStore,
        *,
        handlers: OperationHandlerRegistry = DEFAULT_OPERATION_HANDLERS,
        events: BrokerEventSource | None = None,
        repair_public: ProjectionRepair | None = None,
        queue_capacity: int = 32,
    ) -> None:
        if queue_capacity < 1 or queue_capacity > 1024:
            raise ValueError("worker queue capacity is invalid")
        self._store = store
        self._handlers = handlers
        self._events = events or SystemBrokerEventSource()
        self._repair_public = repair_public
        self._queue: Queue[tuple[str, str] | None] = Queue(maxsize=queue_capacity)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            raise RootActionWorkerError("root-action worker is already started")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="root-action-execution-worker",
            daemon=True,
        )
        self._thread.start()

    def close(self, *, timeout_seconds: float = 5.0) -> None:
        thread = self._thread
        self._thread = None
        if thread is None:
            return
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except Full:
            pass
        thread.join(timeout_seconds)

    def recover_orphaned_claims(self) -> tuple[str, ...]:
        recovered: list[str] = []
        for job_id in self._store.running_job_ids():
            record = self._store.read_record(job_id)
            self._mark_unknown(
                job_id,
                record.job_digest,
                reason_code="broker_restarted_with_running_job",
                failure_type="BrokerRestart",
            )
            recovered.append(job_id)
            self._repair(job_id)
        return tuple(recovered)

    def enqueue(self, job_id: str, job_digest: str) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._mark_unknown(
                job_id,
                job_digest,
                reason_code="worker_unavailable_after_claim",
                failure_type="WorkerUnavailable",
            )
            self._repair(job_id)
            raise RootActionWorkerError("root-action worker is unavailable")
        record = self._store.read_record(job_id)
        if (
            record.job_digest != job_digest
            or record.state is not JobState.RUNNING
            or record.execution_count != 1
        ):
            raise RootActionWorkerError("only the exact claimed job can be enqueued")
        try:
            self._queue.put_nowait((job_id, job_digest))
        except Full as exc:
            self._mark_unknown(
                job_id,
                job_digest,
                reason_code="worker_queue_unavailable",
                failure_type="WorkerQueueFull",
            )
            self._repair(job_id)
            raise RootActionWorkerError("root-action worker queue is full") from exc

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                if item is None:
                    return
                self._execute(*item)
            finally:
                self._queue.task_done()

    def _execute(self, job_id: str, job_digest: str) -> None:
        try:
            job = self._store.read_sealed(job_id)
            record = self._store.read_record(job_id)
            if (
                job.job_digest != job_digest
                or record.job_digest != job_digest
                or record.state is not JobState.RUNNING
                or record.execution_count != 1
            ):
                raise RootActionWorkerError("queued job is not the exact running claim")
            handler = self._handlers.handler(job.operation_id)
            result = handler.run(job)
            event_id, ended_at = self._events.next_event()
            raw = seal_raw_receipt(
                job_id=job.job_id,
                job_digest=job.job_digest,
                root_storage_id=_raw_storage_id(job.job_id, event_id),
                raw_bytes=result.raw_bytes,
            )
            receipt = seal_receipt(
                json.dumps(
                    {
                        "schema": RECEIPT_SCHEMA,
                        "kind": "public",
                        "job_id": job.job_id,
                        "job_digest": job.job_digest,
                        "operation_id": job.operation_id,
                        "request_id": job.request_id,
                        "reply_target": job.reply_target,
                        "terminal_outcome": result.terminal_outcome,
                        "raw_receipt_digest": raw.reference.raw_receipt_digest,
                        "started_at": record.last_changed_at,
                        "ended_at": ended_at,
                        "exit_code": result.exit_code,
                        "removed_lines": 0,
                        "result": {
                            "status": result.public_status,
                            "facts": [
                                {"name": name, "value": value}
                                for name, value in result.public_facts
                            ],
                        },
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            self._store.complete_claimed_execution(
                event=TransitionEvent(
                    event_id=event_id,
                    job_id=job.job_id,
                    job_digest=job.job_digest,
                    expected_revision=record.revision,
                    kind=TransitionKind.COMPLETE_EXECUTION,
                    occurred_at=ended_at,
                    outcome=TerminalOutcome(result.terminal_outcome),
                    reason_code=result.reason_code,
                ),
                raw=raw,
                receipt=receipt,
            )
        except Exception as exc:
            try:
                current = self._store.read_record(job_id)
                if current.state is JobState.RUNNING:
                    self._mark_unknown(
                        job_id,
                        job_digest,
                        reason_code="worker_outcome_uncertain",
                        failure_type=type(exc).__name__,
                    )
            except Exception:
                # Startup recovery retries any record that remains RUNNING.
                pass
        finally:
            self._repair(job_id)

    def _mark_unknown(
        self,
        job_id: str,
        job_digest: str,
        *,
        reason_code: str,
        failure_type: str,
    ) -> None:
        job = self._store.read_sealed(job_id)
        record = self._store.read_record(job_id)
        if (
            job.job_digest != job_digest
            or record.job_digest != job_digest
            or record.state is not JobState.RUNNING
        ):
            raise RootActionWorkerError("only a running exact claim can become unknown")
        event_id, occurred_at = self._events.next_event()
        raw = seal_raw_receipt(
            job_id=job.job_id,
            job_digest=job.job_digest,
            root_storage_id=_raw_storage_id(job.job_id, event_id),
            raw_bytes=(
                json.dumps(
                    {
                        "failure_type": failure_type,
                        "phase": "claimed_execution",
                        "reason_code": reason_code,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        notice = seal_receipt(
            json.dumps(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "unknown",
                    "job_id": job.job_id,
                    "job_digest": job.job_digest,
                    "operation_id": job.operation_id,
                    "request_id": job.request_id,
                    "reply_target": job.reply_target,
                    "terminal_outcome": None,
                    "raw_receipt_digest": raw.reference.raw_receipt_digest,
                    "last_known_at": occurred_at,
                    "reason_code": reason_code,
                }
            ).encode("utf-8")
        )
        self._store.mark_claimed_execution_unknown(
            event=TransitionEvent(
                event_id=event_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=record.revision,
                kind=TransitionKind.MARK_UNKNOWN,
                occurred_at=occurred_at,
                reason_code=reason_code,
            ),
            raw=raw,
            receipt=notice,
        )

    def _repair(self, job_id: str) -> None:
        if self._repair_public is None:
            return
        try:
            self._repair_public(job_id)
        except Exception:
            pass


def _raw_storage_id(job_id: str, event_id: str) -> str:
    digest = hashlib.sha256(
        b"agent-runtime-root-action-raw-storage/v1\x00"
        + job_id.encode("ascii")
        + b"\x00"
        + event_id.encode("ascii")
    ).hexdigest()
    return "raw-" + digest[:48]
