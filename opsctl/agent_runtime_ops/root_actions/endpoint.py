from __future__ import annotations

import json
from typing import Any

from .broker import PublicProjectionBundle, TypedRootActionBroker
from .protocol import (
    BROKER_RESPONSE_SCHEMA,
    encode_response,
    parse_request_frame,
)
from .public_projection import validate_public_projection
from .submission import BrokerPeerIdentity


class RootActionBrokerEndpoint:
    """Submit and identity-bound read-only retrieval only."""

    ALLOWED_METHODS = frozenset({"submit", "retrieve"})

    def __init__(self, broker: TypedRootActionBroker) -> None:
        self._broker = broker

    def handle(self, frame: bytes, *, peer: BrokerPeerIdentity) -> bytes:
        method, values = parse_request_frame(frame)
        if method == "submit":
            submitted = self._broker.submit(values["raw_manifest"], peer=peer)
            projection = self._broker.requester_projection(
                peer=peer,
                job_id=submitted.job_id,
                job_digest=submitted.job_digest,
                request_id=submitted.status["job"]["request_id"],
                reply_target=submitted.status["job"]["reply_target"],
            )
        elif method == "retrieve":
            projection = self._broker.requester_projection(peer=peer, **values)
        else:
            raise AssertionError("unsupported parsed broker method")
        return encode_response(self._response_value(method, projection))

    @staticmethod
    def _response_value(
        method: str,
        projection: PublicProjectionBundle,
    ) -> dict[str, Any]:
        verified = validate_public_projection(projection.projection_bytes)
        if verified.projection_digest != projection.projection_digest:
            raise ValueError("broker projection metadata mismatch")
        value = json.loads(projection.projection_bytes.decode("utf-8"))
        status = value["status"]
        job = status["job"]
        state = status["state"]
        return {
            "schema": BROKER_RESPONSE_SCHEMA,
            "method": method,
            "job_id": projection.job_id,
            "job_digest": projection.job_digest,
            "request_id": job["request_id"],
            "reply_target": job["reply_target"],
            "projection_digest": projection.projection_digest,
            "state": state["name"],
            "terminal_outcome": state["terminal_outcome"],
            "reason_code": state["reason_code"],
            "projection": value,
        }
