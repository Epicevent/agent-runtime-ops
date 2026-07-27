from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import struct
from typing import Protocol

from .contracts import MAX_MANIFEST_BYTES, SealedJob
from .storage import SubmissionLimits, SubmissionMetadata


SUBMISSION_RESPONSE_SCHEMA = "agent-runtime-root-action-submission-response/v1"
MAX_SUBMISSION_RESPONSE_BYTES = 4096


class SubmissionRejected(ValueError):
    """The broker cannot accept this peer or submission window."""


@dataclass(frozen=True)
class BrokerPeerIdentity:
    uid: int
    gid: int
    pid: int

    def __post_init__(self) -> None:
        for value in (self.uid, self.gid, self.pid):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SubmissionRejected("broker peer identity is invalid")


@dataclass(frozen=True)
class SubmissionPolicy:
    allowed_uids: frozenset[int]
    allowed_gids: frozenset[int]
    maximum_age_seconds: int = 900
    maximum_future_skew_seconds: int = 30
    limits: SubmissionLimits = SubmissionLimits()

    def __post_init__(self) -> None:
        if not self.allowed_uids and not self.allowed_gids:
            raise SubmissionRejected(
                "submission policy requires an explicit peer allowlist"
            )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (*self.allowed_uids, *self.allowed_gids)
        ):
            raise SubmissionRejected("submission policy peer allowlist is invalid")
        for value in (self.maximum_age_seconds, self.maximum_future_skew_seconds):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SubmissionRejected("submission policy time bound is invalid")

    def authorize(
        self,
        job: SealedJob,
        *,
        peer: BrokerPeerIdentity,
        broker_received_at: str,
    ) -> SubmissionMetadata:
        if peer.uid not in self.allowed_uids and peer.gid not in self.allowed_gids:
            raise SubmissionRejected("submission peer is not allowlisted")
        try:
            submitted = datetime.strptime(
                job.submitted_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            received = datetime.strptime(
                broker_received_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise SubmissionRejected("submission timestamp is invalid") from exc
        age = (received - submitted).total_seconds()
        if age > self.maximum_age_seconds:
            raise SubmissionRejected("submission manifest is stale")
        if age < -self.maximum_future_skew_seconds:
            raise SubmissionRejected("submission manifest is from the future")
        return SubmissionMetadata(
            peer_uid=peer.uid,
            peer_gid=peer.gid,
            peer_pid=peer.pid,
            broker_received_at=broker_received_at,
        )


def encode_submission_frame(manifest: bytes) -> bytes:
    if (
        not isinstance(manifest, bytes)
        or not manifest
        or len(manifest) > MAX_MANIFEST_BYTES
    ):
        raise SubmissionRejected("submission manifest byte length is invalid")
    return struct.pack("!I", len(manifest)) + manifest


def decode_submission_frame(frame: bytes) -> bytes:
    if not isinstance(frame, bytes) or len(frame) < 4:
        raise SubmissionRejected("submission frame is truncated")
    (length,) = struct.unpack("!I", frame[:4])
    if length < 1 or length > MAX_MANIFEST_BYTES:
        raise SubmissionRejected("submission frame length is invalid")
    if len(frame) != 4 + length:
        raise SubmissionRejected("submission frame length does not match its bytes")
    return frame[4:]


class SubmissionBroker(Protocol):
    def submit(self, raw_manifest: bytes, *, peer: BrokerPeerIdentity): ...

    def public_projection(self, job_id: str): ...


class RootActionSubmissionEndpoint:
    """Transport-neutral framed submission endpoint.

    A future root-owned listener supplies peer identity from its operating-system
    connection credentials.  The request has no method, path, shell, environment,
    authentication, approval, or dispatch field.
    """

    def __init__(self, broker: SubmissionBroker) -> None:
        self._broker = broker

    def handle(self, frame: bytes, *, peer: BrokerPeerIdentity) -> bytes:
        manifest = decode_submission_frame(frame)
        submitted = self._broker.submit(manifest, peer=peer)
        projection = self._broker.public_projection(submitted.job_id)
        state = submitted.status["state"]
        value = {
            "schema": SUBMISSION_RESPONSE_SCHEMA,
            "job_id": submitted.job_id,
            "job_digest": submitted.job_digest,
            "state": state["name"],
            "terminal_outcome": state["terminal_outcome"],
            "reason_code": state["reason_code"],
            "projection_digest": projection.projection_digest,
        }
        encoded = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_SUBMISSION_RESPONSE_BYTES:
            raise SubmissionRejected("submission response exceeds its byte limit")
        return encoded
