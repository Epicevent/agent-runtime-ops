from __future__ import annotations

import json
import re
import struct
from typing import Any

from .contracts import MAX_MANIFEST_BYTES, seal_typed_manifest


BROKER_REQUEST_SCHEMA = "agent-runtime-root-action-broker-request/v1"
BROKER_RESPONSE_SCHEMA = "agent-runtime-root-action-broker-response/v1"
MAX_BROKER_REQUEST_BYTES = 512 * 1024
MAX_BROKER_RESPONSE_BYTES = 4 * 1024 * 1024
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_BOOTSTRAP_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_CREDENTIAL_ROLES = {"approval", "recovery"}
_CREDENTIAL_LABELS = {
    "office_windows_hello",
    "remote_phone_passkey",
    "recovery_fido2",
}


class BrokerProtocolError(ValueError):
    """A local client frame is not an exact supported broker message."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BrokerProtocolError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def encode_frame(payload: bytes, *, maximum: int) -> bytes:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise BrokerProtocolError("frame payload byte length is invalid")
    return struct.pack("!I", len(payload)) + payload


def decode_frame(frame: bytes, *, maximum: int) -> bytes:
    if not isinstance(frame, bytes) or len(frame) < 4:
        raise BrokerProtocolError("frame is truncated")
    (length,) = struct.unpack("!I", frame[:4])
    if length < 1 or length > maximum or len(frame) != length + 4:
        raise BrokerProtocolError("frame length does not match one bounded payload")
    return frame[4:]


def submit_request(raw_manifest: bytes) -> bytes:
    job = seal_typed_manifest(raw_manifest)
    return encode_frame(
        canonical_json(
            {
                "schema": BROKER_REQUEST_SCHEMA,
                "method": "submit",
                "manifest": job.manifest_copy(),
            }
        ),
        maximum=MAX_BROKER_REQUEST_BYTES,
    )


def retrieve_request(
    *,
    job_id: str,
    job_digest: str,
    request_id: str,
    reply_target: str,
) -> bytes:
    return encode_frame(
        canonical_json(
            {
                "schema": BROKER_REQUEST_SCHEMA,
                "method": "retrieve",
                "job_id": job_id,
                "job_digest": job_digest,
                "request_id": request_id,
                "reply_target": reply_target,
            }
        ),
        maximum=MAX_BROKER_REQUEST_BYTES,
    )


def auth_request(method: str, **values: Any) -> bytes:
    if not isinstance(method, str) or not method.startswith("auth_"):
        raise BrokerProtocolError("authorization method is invalid")
    return encode_frame(
        canonical_json(
            {
                "schema": BROKER_REQUEST_SCHEMA,
                "method": method,
                **values,
            }
        ),
        maximum=MAX_BROKER_REQUEST_BYTES,
    )


def parse_request_frame(frame: bytes) -> tuple[str, dict[str, Any]]:
    payload = decode_frame(frame, maximum=MAX_BROKER_REQUEST_BYTES)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except BrokerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BrokerProtocolError("broker request is not UTF-8 JSON") from exc
    if not isinstance(value, dict) or payload != canonical_json(value):
        raise BrokerProtocolError("broker request must be canonical JSON")
    if value.get("schema") != BROKER_REQUEST_SCHEMA:
        raise BrokerProtocolError("broker request schema is unsupported")
    method = value.get("method")
    if method == "submit":
        if set(value) != {"schema", "method", "manifest"}:
            raise BrokerProtocolError("submit request field set is invalid")
        manifest = value["manifest"]
        if not isinstance(manifest, dict):
            raise BrokerProtocolError("submit manifest must be an object")
        canonical_manifest = canonical_json(manifest)
        seal_typed_manifest(canonical_manifest)
        return method, {"raw_manifest": canonical_manifest}
    if method == "retrieve":
        expected = {
            "schema",
            "method",
            "job_id",
            "job_digest",
            "request_id",
            "reply_target",
        }
        if set(value) != expected:
            raise BrokerProtocolError("retrieve request field set is invalid")
        if any(
            not isinstance(value[field], str)
            or _SAFE_ID_RE.fullmatch(value[field]) is None
            for field in ("job_id", "request_id", "reply_target")
        ) or (
            not isinstance(value["job_digest"], str)
            or _DIGEST_RE.fullmatch(value["job_digest"]) is None
        ):
            raise BrokerProtocolError("retrieve request identity is invalid")
        return method, {key: value[key] for key in expected - {"schema", "method"}}
    if method in {"auth_status", "auth_bootstrap_create"}:
        if set(value) != {"schema", "method"}:
            raise BrokerProtocolError("authorization request field set is invalid")
        return method, {}
    if method == "auth_registration_begin":
        expected = {"schema", "method", "bootstrap_token", "role", "label"}
        if set(value) != expected:
            raise BrokerProtocolError("registration begin field set is invalid")
        if (
            not isinstance(value["bootstrap_token"], str)
            or _BOOTSTRAP_TOKEN_RE.fullmatch(value["bootstrap_token"]) is None
            or not isinstance(value["role"], str)
            or value["role"] not in _CREDENTIAL_ROLES
            or not isinstance(value["label"], str)
            or value["label"] not in _CREDENTIAL_LABELS
        ):
            raise BrokerProtocolError("registration begin fields are invalid")
        return method, {
            key: value[key] for key in ("bootstrap_token", "role", "label")
        }
    if method == "auth_registration_finish":
        expected = {
            "schema",
            "method",
            "bootstrap_token",
            "ceremony_id",
            "credential",
        }
        if set(value) != expected:
            raise BrokerProtocolError("registration finish field set is invalid")
        if (
            not isinstance(value["bootstrap_token"], str)
            or _BOOTSTRAP_TOKEN_RE.fullmatch(value["bootstrap_token"]) is None
            or not isinstance(value["ceremony_id"], str)
            or _SAFE_ID_RE.fullmatch(value["ceremony_id"]) is None
            or not isinstance(value["credential"], dict)
        ):
            raise BrokerProtocolError("registration finish fields are invalid")
        return method, {
            "bootstrap_token": value["bootstrap_token"],
            "ceremony_id": value["ceremony_id"],
            "browser_credential": value["credential"],
        }
    if method == "auth_approval_begin":
        expected = {"schema", "method", "job_id", "job_digest"}
        if set(value) != expected:
            raise BrokerProtocolError("approval begin field set is invalid")
        if (
            not isinstance(value["job_id"], str)
            or _SAFE_ID_RE.fullmatch(value["job_id"]) is None
            or not isinstance(value["job_digest"], str)
            or _DIGEST_RE.fullmatch(value["job_digest"]) is None
        ):
            raise BrokerProtocolError("approval begin identity is invalid")
        return method, {
            "job_id": value["job_id"],
            "job_digest": value["job_digest"],
        }
    if method == "auth_approval_finish":
        expected = {"schema", "method", "ceremony_id", "credential"}
        if set(value) != expected:
            raise BrokerProtocolError("approval finish field set is invalid")
        if (
            not isinstance(value["ceremony_id"], str)
            or _SAFE_ID_RE.fullmatch(value["ceremony_id"]) is None
            or not isinstance(value["credential"], dict)
        ):
            raise BrokerProtocolError("approval finish fields are invalid")
        return method, {
            "ceremony_id": value["ceremony_id"],
            "browser_credential": value["credential"],
        }
    raise BrokerProtocolError("broker request method is unsupported")


def encode_response(value: dict[str, Any]) -> bytes:
    if value.get("schema") != BROKER_RESPONSE_SCHEMA:
        raise BrokerProtocolError("broker response schema is invalid")
    return encode_frame(
        canonical_json(value),
        maximum=MAX_BROKER_RESPONSE_BYTES,
    )


def parse_response_frame(frame: bytes) -> dict[str, Any]:
    payload = decode_frame(frame, maximum=MAX_BROKER_RESPONSE_BYTES)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except BrokerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BrokerProtocolError("broker response is not UTF-8 JSON") from exc
    if (
        not isinstance(value, dict)
        or payload != canonical_json(value)
        or value.get("schema") != BROKER_RESPONSE_SCHEMA
    ):
        raise BrokerProtocolError("broker response is not canonical or supported")
    return value
