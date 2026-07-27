from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
import unicodedata
from typing import Any

from .registry import (
    DEFAULT_REGISTRY,
    REGISTRY_VERSION,
    OperationRegistry,
    RegistryValidationError,
)


MANIFEST_SCHEMA = "agent-runtime-root-action-manifest/v1"
MAX_MANIFEST_BYTES = 128 * 1024
_TOP_LEVEL_KEYS = {
    "schema",
    "registry_version",
    "job_id",
    "operation_id",
    "operation_version",
    "request",
    "parameters",
    "expected_pre_state",
    "review",
}
_REQUEST_KEYS = {"request_id", "lineage_id", "reply_target", "submitted_at"}
_PRE_STATE_KEYS = {"kind", "digest"}
_REVIEW_KEYS = {
    "purpose",
    "premises",
    "targets",
    "changes",
    "recovery",
    "risk_delta",
}
_RISK_DELTA_KEYS = {"baseline", "added", "removed", "maximum_consequence"}
_PREMISE_KEYS = {"claim", "basis", "anchor", "falsifier"}
_ANCHOR_KEYS = {"source", "quote"}
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
_BASIS_VALUES = {"user_authority", "direct_observation", "inference", "unknown"}


class ManifestValidationError(ValueError):
    """The manifest cannot enter the typed root-action core."""


@dataclass(frozen=True)
class SealedJob:
    job_id: str
    job_digest: str
    operation_id: str
    operation_version: int
    request_id: str
    lineage_id: str
    reply_target: str
    submitted_at: str
    canonical_manifest: bytes

    @property
    def identity(self) -> str:
        return f"{self.job_id}@{self.job_digest}"

    def manifest_copy(self) -> dict[str, Any]:
        return json.loads(self.canonical_manifest.decode("utf-8"))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestValidationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise ManifestValidationError("manifest input must be bytes")
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestValidationError(
            "manifest byte length is outside the allowed range"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError("manifest must be UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except ManifestValidationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ManifestValidationError("manifest is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ManifestValidationError("manifest must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestValidationError(f"{field} must be an object")
    actual = set(value)
    if actual != expected:
        raise ManifestValidationError(
            f"{field} field set mismatch missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _safe_text(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ManifestValidationError(f"{field} must be a bounded non-empty string")
    if unicodedata.normalize("NFC", value) != value:
        raise ManifestValidationError(f"{field} must use NFC-normalized Unicode")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise ManifestValidationError(f"{field} contains a control character")
    return value


def _safe_id(value: Any, field: str) -> str:
    text = _safe_text(value, field, maximum=128)
    if _SAFE_ID_RE.fullmatch(text) is None:
        raise ManifestValidationError(f"{field} must be a safe identifier")
    return text


def _safe_timestamp(value: Any, field: str) -> str:
    text = _safe_text(value, field, maximum=20)
    if _TIMESTAMP_RE.fullmatch(text) is None:
        raise ManifestValidationError(
            f"{field} must be an RFC3339 UTC second timestamp"
        )
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ManifestValidationError(
            f"{field} must be a real RFC3339 UTC second timestamp"
        ) from exc
    return text


def _text_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ManifestValidationError(f"{field} must contain 1 to 32 items")
    result = [_safe_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(set(result)) != len(result):
        raise ManifestValidationError(f"{field} must not contain duplicates")
    return result


def _optional_text_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ManifestValidationError(f"{field} must contain 0 to 32 items")
    result = [_safe_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(set(result)) != len(result):
        raise ManifestValidationError(f"{field} must not contain duplicates")
    return result


def _validate_premises(value: Any) -> None:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ManifestValidationError("review.premises must contain 1 to 8 items")
    for index, raw_premise in enumerate(value):
        premise = _exact_keys(raw_premise, _PREMISE_KEYS, f"review.premises[{index}]")
        _safe_text(premise["claim"], f"review.premises[{index}].claim")
        basis = premise["basis"]
        if basis not in _BASIS_VALUES:
            raise ManifestValidationError(
                f"review.premises[{index}].basis has an invalid value"
            )
        _safe_text(premise["falsifier"], f"review.premises[{index}].falsifier")
        anchor = premise["anchor"]
        if basis in {"user_authority", "direct_observation"}:
            anchor_value = _exact_keys(
                anchor, _ANCHOR_KEYS, f"review.premises[{index}].anchor"
            )
            _safe_text(
                anchor_value["source"], f"review.premises[{index}].anchor.source"
            )
            _safe_text(anchor_value["quote"], f"review.premises[{index}].anchor.quote")
        elif basis == "unknown":
            if anchor is not None:
                raise ManifestValidationError(
                    f"review.premises[{index}].anchor must be null when basis is unknown"
                )
        elif anchor is not None:
            anchor_value = _exact_keys(
                anchor, _ANCHOR_KEYS, f"review.premises[{index}].anchor"
            )
            _safe_text(
                anchor_value["source"], f"review.premises[{index}].anchor.source"
            )
            _safe_text(anchor_value["quote"], f"review.premises[{index}].anchor.quote")


def _validate_expected_pre_state(value: Any) -> None:
    pre_state = _exact_keys(value, _PRE_STATE_KEYS, "expected_pre_state")
    kind = pre_state["kind"]
    digest = pre_state["digest"]
    if kind == "required":
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise ManifestValidationError(
                "expected_pre_state.digest must be a sha256 digest when kind is required"
            )
    elif kind == "none":
        if digest is not None:
            raise ManifestValidationError(
                "expected_pre_state.digest must be null when kind is none"
            )
    else:
        raise ManifestValidationError("expected_pre_state.kind has an invalid value")


def _validate_manifest(value: dict[str, Any], registry: OperationRegistry) -> None:
    manifest = _exact_keys(value, _TOP_LEVEL_KEYS, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ManifestValidationError("manifest.schema is not supported")
    if manifest["registry_version"] != REGISTRY_VERSION:
        raise ManifestValidationError("manifest.registry_version is not supported")
    _safe_id(manifest["job_id"], "job_id")
    operation_id = _safe_id(manifest["operation_id"], "operation_id")

    request = _exact_keys(manifest["request"], _REQUEST_KEYS, "request")
    _safe_id(request["request_id"], "request.request_id")
    _safe_id(request["lineage_id"], "request.lineage_id")
    _safe_id(request["reply_target"], "request.reply_target")
    _safe_timestamp(request["submitted_at"], "request.submitted_at")

    _validate_expected_pre_state(manifest["expected_pre_state"])
    review = _exact_keys(manifest["review"], _REVIEW_KEYS, "review")
    _safe_text(review["purpose"], "review.purpose")
    _validate_premises(review["premises"])
    _text_list(review["targets"], "review.targets")
    _text_list(review["changes"], "review.changes")
    _text_list(review["recovery"], "review.recovery")
    risk = _exact_keys(review["risk_delta"], _RISK_DELTA_KEYS, "review.risk_delta")
    _safe_text(risk["baseline"], "review.risk_delta.baseline")
    _optional_text_list(risk["added"], "review.risk_delta.added")
    _optional_text_list(risk["removed"], "review.risk_delta.removed")
    _safe_text(
        risk["maximum_consequence"],
        "review.risk_delta.maximum_consequence",
    )

    try:
        registry.validate(
            operation_id,
            manifest["operation_version"],
            manifest["parameters"],
        )
    except RegistryValidationError as exc:
        raise ManifestValidationError(str(exc)) from exc


def canonical_manifest_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def seal_typed_manifest(
    raw: bytes, *, registry: OperationRegistry = DEFAULT_REGISTRY
) -> SealedJob:
    value = _parse_manifest(raw)
    _validate_manifest(value, registry)
    canonical = canonical_manifest_bytes(value)
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"agent-runtime-root-action-job/v1\x00" + canonical
        ).hexdigest()
    )
    request = value["request"]
    return SealedJob(
        job_id=value["job_id"],
        job_digest=digest,
        operation_id=value["operation_id"],
        operation_version=value["operation_version"],
        request_id=request["request_id"],
        lineage_id=request["lineage_id"],
        reply_target=request["reply_target"],
        submitted_at=request["submitted_at"],
        canonical_manifest=canonical,
    )
