from __future__ import annotations

import json
from typing import Any

from .auth_service import RootActionAuthorizationService
from .authorization import CredentialRole, public_credential_summary
from .broker import PublicProjectionBundle, TypedRootActionBroker
from .protocol import (
    BROKER_RESPONSE_SCHEMA,
    encode_response,
    parse_request_frame,
)
from .public_projection import validate_public_projection
from .submission import BrokerPeerIdentity


class RootActionBrokerEndpoint:
    """Typed job and root-owned WebAuthn boundary over one trusted socket."""

    ALLOWED_METHODS = frozenset(
        {
            "submit",
            "retrieve",
            "auth_status",
            "auth_bootstrap_create",
            "auth_registration_begin",
            "auth_registration_finish",
            "auth_approval_begin",
            "auth_approval_finish",
        }
    )

    def __init__(
        self,
        broker: TypedRootActionBroker,
        *,
        authorization: RootActionAuthorizationService | None = None,
    ) -> None:
        self._broker = broker
        self._authorization = authorization

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
        elif method.startswith("auth_"):
            return self._handle_authorization(method, values, peer=peer)
        else:
            raise AssertionError("unsupported parsed broker method")
        return encode_response(self._response_value(method, projection))

    def _handle_authorization(
        self,
        method: str,
        values: dict[str, Any],
        *,
        peer: BrokerPeerIdentity,
    ) -> bytes:
        authorization = self._authorization
        if authorization is None:
            raise ValueError("root-action authorization is not configured")
        if method == "auth_status":
            response = authorization.status()
        elif method == "auth_bootstrap_create":
            if peer.uid != 0:
                raise ValueError("only a kernel-authenticated root peer can bootstrap")
            session, token = authorization.create_initial_bootstrap()
            response = {
                "bootstrap_id": session.bootstrap_id,
                "bootstrap_token": token,
                "expires_at": session.expires_at,
                "remaining_registrations": session.remaining_registrations,
            }
        elif method == "auth_registration_begin":
            options = authorization.begin_registration(
                encoded_token=values["bootstrap_token"],
                role=CredentialRole(values["role"]),
                label=values["label"],
            )
            response = {
                "ceremony_id": options.ceremony_id,
                "expires_at": options.expires_at,
                "public_key": options.public_key,
            }
        elif method == "auth_registration_finish":
            result = authorization.finish_registration(
                encoded_token=values["bootstrap_token"],
                ceremony_id=values["ceremony_id"],
                browser_credential=values["browser_credential"],
            )
            response = {
                "credential": public_credential_summary(result.credential),
                "remaining_registrations": result.remaining_registrations,
            }
        elif method == "auth_approval_begin":
            options = authorization.begin_approval(**values)
            response = {
                "ceremony_id": options.ceremony_id,
                "job_id": options.job_id,
                "job_digest": options.job_digest,
                "expires_at": options.expires_at,
                "public_key": options.public_key,
            }
        elif method == "auth_approval_finish":
            record = authorization.finish_approval(**values)
            projection = self._broker.repair_public_best_effort(record.job_id)
            response = {
                "job_id": record.job_id,
                "job_digest": record.job_digest,
                "state": record.state.value,
                "projection": json.loads(projection.projection_bytes.decode("utf-8")),
                "projection_digest": projection.projection_digest,
            }
        else:
            raise AssertionError("unsupported parsed authorization method")
        return encode_response(
            {
                "schema": BROKER_RESPONSE_SCHEMA,
                "method": method,
                **response,
            }
        )

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
