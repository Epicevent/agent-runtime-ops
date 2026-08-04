from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import unicodedata
from typing import Any

from .observation import (
    ObservationValidationError,
    validate_public_observation_facts,
)


RECEIPT_SCHEMA = "agent-runtime-root-action-receipt/v1"
MAX_RECEIPT_BYTES = 512 * 1024
MAX_RAW_RECEIPT_BYTES = 8 * 1024 * 1024
_COMMON_KEYS = {
    "schema",
    "kind",
    "job_id",
    "job_digest",
    "operation_id",
    "request_id",
    "reply_target",
    "terminal_outcome",
}
_RAW_BASE_KEYS = _COMMON_KEYS | {
    "raw_receipt_digest",
}
_PUBLIC_KEYS = _RAW_BASE_KEYS | {
    "started_at",
    "ended_at",
    "exit_code",
    "removed_lines",
    "result",
}
_QUARANTINE_KEYS = _RAW_BASE_KEYS | {"quarantine_id", "reason_code"}
_UNKNOWN_KEYS = _RAW_BASE_KEYS | {"last_known_at", "reason_code"}
_TERMINAL_NOTICE_KEYS = _COMMON_KEYS | {"reason_code"}
_RESULT_KEYS = {"status", "facts"}
_FACT_KEYS = {"name", "value"}
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)


class ReceiptValidationError(ValueError):
    """A receipt violates the public/full-or-quarantine contract."""


@dataclass(frozen=True)
class ReceiptArtifact:
    kind: str
    job_id: str
    job_digest: str
    operation_id: str
    request_id: str
    reply_target: str
    receipt_digest: str
    canonical_receipt: bytes

    def receipt_copy(self) -> dict[str, Any]:
        return json.loads(self.canonical_receipt.decode("utf-8"))


@dataclass(frozen=True)
class RawReceiptReference:
    job_id: str
    job_digest: str
    raw_receipt_digest: str
    root_storage_id: str

    def __post_init__(self) -> None:
        _safe_id(self.job_id, "raw_reference.job_id")
        _digest(self.job_digest, "raw_reference.job_digest")
        _digest(self.raw_receipt_digest, "raw_reference.raw_receipt_digest")
        _safe_id(self.root_storage_id, "raw_reference.root_storage_id")


@dataclass(frozen=True)
class RawReceiptArtifact:
    reference: RawReceiptReference
    raw_bytes: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.raw_bytes, bytes)
            or not self.raw_bytes
            or len(self.raw_bytes) > MAX_RAW_RECEIPT_BYTES
        ):
            raise ReceiptValidationError(
                "raw receipt byte length is outside the allowed range"
            )
        digest = "sha256:" + hashlib.sha256(self.raw_bytes).hexdigest()
        if self.reference.raw_receipt_digest != digest:
            raise ReceiptValidationError("raw receipt digest mismatch")


@dataclass(frozen=True)
class QuarantineRecord:
    raw_reference: RawReceiptReference
    notice: ReceiptArtifact

    def __post_init__(self) -> None:
        if self.notice.kind != "quarantined":
            raise ReceiptValidationError(
                "quarantine record requires a quarantine notice"
            )
        value = self.notice.receipt_copy()
        if (
            self.raw_reference.job_id != self.notice.job_id
            or self.raw_reference.job_digest != self.notice.job_digest
            or self.raw_reference.raw_receipt_digest != value["raw_receipt_digest"]
        ):
            raise ReceiptValidationError("quarantine raw/public identity mismatch")


def seal_raw_receipt(
    *,
    job_id: str,
    job_digest: str,
    root_storage_id: str,
    raw_bytes: bytes,
) -> RawReceiptArtifact:
    if (
        not isinstance(raw_bytes, bytes)
        or not raw_bytes
        or len(raw_bytes) > MAX_RAW_RECEIPT_BYTES
    ):
        raise ReceiptValidationError(
            "raw receipt byte length is outside the allowed range"
        )
    reference = RawReceiptReference(
        job_id=job_id,
        job_digest=job_digest,
        raw_receipt_digest="sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
        root_storage_id=root_storage_id,
    )
    return RawReceiptArtifact(reference=reference, raw_bytes=raw_bytes)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = set(value) if isinstance(value, dict) else set()
        raise ReceiptValidationError(
            f"{field} field set mismatch missing={sorted(keys - actual)} "
            f"extra={sorted(actual - keys)}"
        )
    return value


def _safe_text(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ReceiptValidationError(f"{field} must be a bounded non-empty string")
    if unicodedata.normalize("NFC", value) != value:
        raise ReceiptValidationError(f"{field} must use NFC-normalized Unicode")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise ReceiptValidationError(f"{field} contains a control character")
    return value


def _safe_id(value: Any, field: str) -> str:
    text = _safe_text(value, field, 128)
    if _SAFE_ID_RE.fullmatch(text) is None:
        raise ReceiptValidationError(f"{field} must be a safe identifier")
    return text


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ReceiptValidationError(f"{field} must be a sha256 digest")
    return value


def _timestamp(value: Any, field: str) -> str:
    text = _safe_text(value, field, 20)
    if _TIMESTAMP_RE.fullmatch(text) is None:
        raise ReceiptValidationError(f"{field} must be an RFC3339 UTC second timestamp")
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReceiptValidationError(
            f"{field} must be a real RFC3339 UTC second timestamp"
        ) from exc
    return text


def _validate_common(value: dict[str, Any], *, raw_receipt: bool = True) -> None:
    if value["schema"] != RECEIPT_SCHEMA:
        raise ReceiptValidationError("receipt.schema is not supported")
    _safe_id(value["job_id"], "job_id")
    _digest(value["job_digest"], "job_digest")
    _safe_id(value["operation_id"], "operation_id")
    _safe_id(value["request_id"], "request_id")
    _safe_id(value["reply_target"], "reply_target")
    if raw_receipt:
        _digest(value["raw_receipt_digest"], "raw_receipt_digest")


def _validate_public(value: dict[str, Any]) -> None:
    _exact(value, _PUBLIC_KEYS, "public receipt")
    _validate_common(value)
    if value["terminal_outcome"] not in {"succeeded", "failed", "timed_out"}:
        raise ReceiptValidationError("public receipt has an invalid terminal_outcome")
    started_at = _timestamp(value["started_at"], "started_at")
    ended_at = _timestamp(value["ended_at"], "ended_at")
    if ended_at < started_at:
        raise ReceiptValidationError("ended_at cannot precede started_at")
    if isinstance(value["exit_code"], bool) or not isinstance(value["exit_code"], int):
        raise ReceiptValidationError("exit_code must be an integer")
    if value["removed_lines"] != 0:
        raise ReceiptValidationError("public receipt cannot contain removed lines")
    result = _exact(value["result"], _RESULT_KEYS, "result")
    _safe_id(result["status"], "result.status")
    facts = result["facts"]
    if not isinstance(facts, list) or len(facts) > 128:
        raise ReceiptValidationError(
            "result.facts must be a list with at most 128 items"
        )
    names: list[str] = []
    fact_pairs: list[tuple[str, str]] = []
    for index, raw_fact in enumerate(facts):
        fact = _exact(raw_fact, _FACT_KEYS, f"result.facts[{index}]")
        name = _safe_id(fact["name"], f"result.facts[{index}].name")
        value = _safe_text(fact["value"], f"result.facts[{index}].value", 4096)
        names.append(name)
        fact_pairs.append((name, value))
    if len(set(names)) != len(names):
        raise ReceiptValidationError("result.facts names must be unique")
    try:
        validate_public_observation_facts(tuple(fact_pairs))
    except ObservationValidationError as exc:
        raise ReceiptValidationError(
            "result.facts violates the execution observation contract"
        ) from exc


def _validate_quarantine(value: dict[str, Any]) -> None:
    _exact(value, _QUARANTINE_KEYS, "quarantine receipt")
    _validate_common(value)
    if value["terminal_outcome"] not in {"succeeded", "failed", "timed_out"}:
        raise ReceiptValidationError(
            "quarantine receipt has an invalid terminal_outcome"
        )
    _safe_id(value["quarantine_id"], "quarantine_id")
    _safe_id(value["reason_code"], "reason_code")


def _validate_unknown(value: dict[str, Any]) -> None:
    _exact(value, _UNKNOWN_KEYS, "unknown receipt")
    _validate_common(value)
    if value["terminal_outcome"] is not None:
        raise ReceiptValidationError("unknown receipt cannot claim a terminal outcome")
    _timestamp(value["last_known_at"], "last_known_at")
    _safe_id(value["reason_code"], "reason_code")


def _validate_terminal_notice(value: dict[str, Any]) -> None:
    _exact(value, _TERMINAL_NOTICE_KEYS, "terminal notice")
    _validate_common(value, raw_receipt=False)
    if value["terminal_outcome"] not in {
        "rejected",
        "expired",
        "canceled",
        "prestart_failed",
    }:
        raise ReceiptValidationError("terminal notice has an invalid terminal_outcome")
    _safe_id(value["reason_code"], "reason_code")


def seal_receipt(raw: bytes) -> ReceiptArtifact:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptValidationError("receipt byte length is outside the allowed range")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except ReceiptValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReceiptValidationError("receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReceiptValidationError("receipt must be an object")
    kind = value.get("kind")
    if kind == "public":
        _validate_public(value)
    elif kind == "quarantined":
        _validate_quarantine(value)
    elif kind == "unknown":
        _validate_unknown(value)
    elif kind == "terminal_notice":
        _validate_terminal_notice(value)
    else:
        raise ReceiptValidationError("receipt.kind is not supported")
    canonical = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    receipt_digest = (
        "sha256:"
        + hashlib.sha256(
            b"agent-runtime-root-action-receipt/v1\x00" + canonical
        ).hexdigest()
    )
    return ReceiptArtifact(
        kind=kind,
        job_id=value["job_id"],
        job_digest=value["job_digest"],
        operation_id=value["operation_id"],
        request_id=value["request_id"],
        reply_target=value["reply_target"],
        receipt_digest=receipt_digest,
        canonical_receipt=canonical,
    )
