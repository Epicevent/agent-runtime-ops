from __future__ import annotations

from dataclasses import dataclass
import json
import math
import re
import socket
import struct
import time
from pathlib import Path
from typing import Any, Callable

from .contracts import SealedJob, seal_typed_manifest
from .protocol import (
    BROKER_RESPONSE_SCHEMA,
    MAX_BROKER_RESPONSE_BYTES,
    BrokerProtocolError,
    parse_response_frame,
    retrieve_request,
    submit_request,
    auth_request,
)
from .public_projection import validate_public_projection
from .receipts import ReceiptArtifact, seal_receipt


DEFAULT_BROKER_SOCKET = Path(
    "/run/agent-runtime-ops/root-action-broker.sock"
)
MAX_BROKER_TIMEOUT_SECONDS = 60.0
MAX_POLL_INTERVAL_SECONDS = 60.0
MAX_WAIT_TIMEOUT_SECONDS = 24.0 * 60.0 * 60.0
_RESPONSE_FIELDS = {
    "schema",
    "method",
    "job_id",
    "job_digest",
    "request_id",
    "reply_target",
    "projection_digest",
    "state",
    "terminal_outcome",
    "reason_code",
    "projection",
}
_HANDLE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_HANDLE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


class RootActionClientError(RuntimeError):
    """The requester could not prove its bound broker result."""


@dataclass(frozen=True)
class RootActionRequestHandle:
    job_id: str
    job_digest: str
    request_id: str
    reply_target: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or _HANDLE_ID_RE.fullmatch(value) is None
            for value in (self.job_id, self.request_id, self.reply_target)
        ) or (
            not isinstance(self.job_digest, str)
            or _HANDLE_DIGEST_RE.fullmatch(self.job_digest) is None
        ):
            raise RootActionClientError("root action request handle is invalid")


Transport = Callable[[bytes, float], bytes]


class RootActionBrokerClient:
    def __init__(
        self,
        *,
        socket_path: Path = DEFAULT_BROKER_SOCKET,
        transport: Transport | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        self._transport = transport or self._unix_exchange

    def submit(
        self,
        raw_manifest: bytes,
        *,
        timeout_seconds: float = 5.0,
    ) -> tuple[RootActionRequestHandle, dict[str, Any]]:
        job = seal_typed_manifest(raw_manifest)
        response = self._exchange(
            submit_request(job.canonical_manifest),
            timeout_seconds=timeout_seconds,
        )
        projection = self._validate_response(
            response,
            expected_method="submit",
            expected_job=job,
        )
        handle = RootActionRequestHandle(
            job_id=job.job_id,
            job_digest=job.job_digest,
            request_id=job.request_id,
            reply_target=job.reply_target,
        )
        return handle, projection

    def retrieve(
        self,
        handle: RootActionRequestHandle,
        *,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        response = self._exchange(
            retrieve_request(
                job_id=handle.job_id,
                job_digest=handle.job_digest,
                request_id=handle.request_id,
                reply_target=handle.reply_target,
            ),
            timeout_seconds=timeout_seconds,
        )
        return self._validate_response(
            response,
            expected_method="retrieve",
            expected_handle=handle,
        )

    def create_auth_bootstrap(
        self,
        *,
        timeout_seconds: float = 5.0,
    ) -> dict[str, Any]:
        response = self._exchange(
            auth_request("auth_bootstrap_create"),
            timeout_seconds=timeout_seconds,
        )
        expected = {
            "schema",
            "method",
            "bootstrap_id",
            "bootstrap_token",
            "expires_at",
            "remaining_registrations",
        }
        if (
            set(response) != expected
            or response["schema"] != BROKER_RESPONSE_SCHEMA
            or response["method"] != "auth_bootstrap_create"
            or not isinstance(response["bootstrap_token"], str)
            or len(response["bootstrap_token"]) != 43
            or response["remaining_registrations"] != 3
        ):
            raise RootActionClientError("authorization bootstrap response is invalid")
        return {key: response[key] for key in expected - {"schema", "method"}}

    def poll_terminal(
        self,
        handle: RootActionRequestHandle,
        *,
        timeout_seconds: float,
        interval_seconds: float = 0.25,
    ) -> tuple[dict[str, Any], ReceiptArtifact]:
        if (
            not math.isfinite(timeout_seconds)
            or not math.isfinite(interval_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > MAX_WAIT_TIMEOUT_SECONDS
            or interval_seconds <= 0
            or interval_seconds > MAX_POLL_INTERVAL_SECONDS
        ):
            raise RootActionClientError("poll bounds must be positive")
        deadline = time.monotonic() + timeout_seconds
        observed_unknown = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = (
                    "outcome_unknown_recovery_needed"
                    if observed_unknown
                    else "terminal_receipt_polling_timed_out"
                )
                raise RootActionClientError(reason)
            projection = self.retrieve(
                handle,
                timeout_seconds=min(remaining, 5.0),
            )
            state = projection["status"]["state"]["name"]
            if state in {"terminal", "unknown"}:
                receipt_value = projection["receipt"]
                if not isinstance(receipt_value, dict):
                    raise RootActionClientError(
                        "terminal projection has no immutable receipt or notice"
                    )
                artifact = seal_receipt(
                    (
                        json.dumps(
                            receipt_value,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                )
                if (
                    artifact.job_id != handle.job_id
                    or artifact.job_digest != handle.job_digest
                    or artifact.request_id != handle.request_id
                    or artifact.reply_target != handle.reply_target
                ):
                    raise RootActionClientError(
                        "terminal receipt request binding mismatch"
                    )
                if state == "terminal":
                    return projection, artifact
                observed_unknown = True
            time.sleep(min(interval_seconds, max(0.0, remaining)))

    def _exchange(self, frame: bytes, *, timeout_seconds: float) -> dict[str, Any]:
        if (
            not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > MAX_BROKER_TIMEOUT_SECONDS
        ):
            raise RootActionClientError("broker timeout must be positive")
        try:
            response_frame = self._transport(frame, timeout_seconds)
            return parse_response_frame(response_frame)
        except (OSError, BrokerProtocolError, ValueError, KeyError, RuntimeError) as exc:
            raise RootActionClientError("broker response failed closed") from exc

    def _unix_exchange(self, frame: bytes, timeout_seconds: float) -> bytes:
        if not self.socket_path.is_absolute():
            raise RootActionClientError("broker socket path must be absolute")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds)
            client.connect(str(self.socket_path))
            client.sendall(frame)
            client.shutdown(socket.SHUT_WR)
            header = self._recv_exact(client, 4)
            (length,) = struct.unpack("!I", header)
            if length < 1 or length > MAX_BROKER_RESPONSE_BYTES:
                raise RootActionClientError("broker response length is invalid")
            payload = self._recv_exact(client, length)
            if client.recv(1) != b"":
                raise RootActionClientError("broker sent more than one response frame")
            return header + payload

    @staticmethod
    def _recv_exact(connection: socket.socket, size: int) -> bytes:
        value = bytearray()
        while len(value) < size:
            chunk = connection.recv(size - len(value))
            if not chunk:
                raise RootActionClientError("broker response was truncated")
            value.extend(chunk)
        return bytes(value)

    @staticmethod
    def _validate_response(
        response: dict[str, Any],
        *,
        expected_method: str,
        expected_job: SealedJob | None = None,
        expected_handle: RootActionRequestHandle | None = None,
    ) -> dict[str, Any]:
        if (
            set(response) != _RESPONSE_FIELDS
            or response["schema"] != BROKER_RESPONSE_SCHEMA
            or response["method"] != expected_method
        ):
            raise RootActionClientError("broker response field set is invalid")
        projection = response["projection"]
        if not isinstance(projection, dict):
            raise RootActionClientError("broker projection is not an object")
        raw = (
            json.dumps(
                projection,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        try:
            artifact = validate_public_projection(raw)
        except (ValueError, RuntimeError) as exc:
            raise RootActionClientError(
                "broker projection validation failed closed"
            ) from exc
        expected = expected_job or expected_handle
        assert expected is not None
        if (
            response["job_id"] != expected.job_id
            or response["job_digest"] != expected.job_digest
            or response["request_id"] != expected.request_id
            or response["reply_target"] != expected.reply_target
            or response["projection_digest"] != artifact.projection_digest
            or artifact.job_id != expected.job_id
            or artifact.job_digest != expected.job_digest
        ):
            raise RootActionClientError("broker response request binding mismatch")
        status = projection.get("status", {})
        job = status.get("job", {}) if isinstance(status, dict) else {}
        state = status.get("state", {}) if isinstance(status, dict) else {}
        if (
            job.get("request_id") != expected.request_id
            or job.get("reply_target") != expected.reply_target
            or response["state"] != state.get("name")
            or response["terminal_outcome"] != state.get("terminal_outcome")
            or response["reason_code"] != state.get("reason_code")
        ):
            raise RootActionClientError("broker response status binding mismatch")
        return projection
