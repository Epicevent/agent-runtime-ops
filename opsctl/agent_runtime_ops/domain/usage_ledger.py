from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping

from ..routing import RuntimeBinding


CALL_SCHEMA = "jitech-provider-usage-call/v1"
EXPORT_SCHEMA = "jitech-provider-usage-export/v1"
COVERAGE_SCHEMA = "jitech-provider-usage-coverage/v1"

CALL_KEYS = {
    "schema",
    "ledgerSeq",
    "receiptDigest",
    "producerCoverageDigest",
    "callId",
    "runId",
    "turnId",
    "requestId",
    "sessionId",
    "trigger",
    "attempt",
    "retryOf",
    "fallbackParent",
    "fallbackIndex",
    "startedAt",
    "completedAt",
    "status",
    "configured",
    "requested",
    "actual",
    "usage",
    "usageCoverage",
    "missingUsageFields",
    "receiptCoverage",
    "missingReceiptFields",
    "finishReason",
    "errorCategory",
}
EXPORT_KEYS = {
    "schema",
    "after",
    "nextCursor",
    "highWatermark",
    "count",
    "hasMore",
    "receipts",
    "coverageManifests",
}
COVERAGE_KEYS = {
    "schema",
    "productFamily",
    "manifestDigest",
    "coverageStatus",
    "surfaces",
}
COVERAGE_SURFACE_KEYS = {
    "surfaceCode",
    "observationKind",
    "meterFamily",
    "modelEvidence",
    "retryObservation",
    "usageObservation",
    "status",
    "gapCode",
}
MODEL_KEYS = {"provider", "model"}
ACTUAL_KEYS = {"provider", "model", "responseId", "evidenceSource"}
USAGE_FIELD_ORDER = (
    "inputTotal",
    "inputNonCached",
    "cacheRead",
    "cacheWrite",
    "outputCandidates",
    "reasoningThinking",
    "toolUsePrompt",
    "providerReportedTotal",
    "serviceTier",
    "rawProviderUsage",
)
USAGE_KEYS = set(USAGE_FIELD_ORDER)
COUNT_KEYS = USAGE_KEYS - {"serviceTier", "rawProviderUsage"}
RECEIPT_IDENTITY_FIELDS = ("runId", "turnId", "requestId", "sessionId")
SUCCEEDED_EVIDENCE_FIELDS = (
    "actual.provider",
    "actual.model",
    "actual.responseId",
    "actual.evidenceSource",
    "finishReason",
)

TRIGGERS = {"user", "cron", "heartbeat", "manual", "memory", "overflow", "unknown"}
STATUSES = {"succeeded", "failed", "interrupted", "cancelled"}
COVERAGES = {"complete", "partial", "unavailable"}
PRODUCT_FAMILIES = {"hermes", "openclaw"}
SURFACE_OBSERVATION_KINDS = {"per_call", "turn_aggregate", "request_only"}
SURFACE_METER_FAMILIES = {"tokens", "image", "audio", "characters", "search", "other"}
SURFACE_MODEL_EVIDENCE = {"provider_response", "requested_only", "unavailable"}
SURFACE_RETRY_OBSERVATION = {"physical_attempt", "logical_call_only", "unavailable"}
SURFACE_USAGE_OBSERVATION = {"provider_reported", "request_observed", "unavailable"}
SURFACE_STATUSES = {"implemented", "partial", "gap"}
HEX_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_RAW_USAGE_BYTES = 64 * 1024
RAW_USAGE_COUNT_KEYS = {
    "promptTokenCount",
    "cachedContentTokenCount",
    "candidatesTokenCount",
    "thoughtsTokenCount",
    "toolUsePromptTokenCount",
    "totalTokenCount",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "inputTokens",
    "outputTokens",
    "totalTokens",
    "cacheReadInputTokens",
    "cacheWriteInputTokens",
}
RAW_USAGE_ENUM_KEYS = {"serviceTier", "trafficType", "service_tier"}
RAW_USAGE_DETAIL_KEYS = {
    "promptTokensDetails",
    "cacheTokensDetails",
    "candidatesTokensDetails",
    "toolUsePromptTokensDetails",
    "prompt_tokens_details",
    "completion_tokens_details",
    "input_tokens_details",
    "output_tokens_details",
}
RAW_USAGE_DETAIL_COUNT_KEYS = {
    "tokenCount",
    "cached_tokens",
    "cache_creation_tokens",
    "cache_write_tokens",
    "audio_tokens",
    "reasoning_tokens",
    "accepted_prediction_tokens",
    "rejected_prediction_tokens",
}
RAW_USAGE_DETAIL_KEYS_ALLOWED = RAW_USAGE_DETAIL_COUNT_KEYS | {"modality"}
RAW_USAGE_KEYS = RAW_USAGE_COUNT_KEYS | RAW_USAGE_ENUM_KEYS | RAW_USAGE_DETAIL_KEYS


class UsageContractError(ValueError):
    pass


class UsageLedgerConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedExport:
    after: int
    next_cursor: int
    high_watermark: int
    has_more: bool
    receipts: tuple[dict[str, Any], ...]
    coverage_manifests: tuple[ValidatedCoverage, ...]


@dataclass(frozen=True)
class ValidatedCoverage:
    family: str
    manifest_digest: str
    status: str
    surfaces: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class RuntimeUsageStamp:
    instance_id: str
    linux_account: str
    public_host: str
    family: str
    runtime_class: str
    binding_digest: str
    container_id: str
    wrapper_image: str
    product_image: str
    ops_repo_commit: str
    collected_at: str


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise UsageContractError(f"value is not canonical JSON: {exc}") from exc


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return sha256_digest(
        {
            key: value
            for key, value in receipt.items()
            if key not in {"ledgerSeq", "receiptDigest"}
        }
    )


def runtime_binding_digest(binding: RuntimeBinding) -> str:
    return sha256_digest(binding.to_json())


def _exact_keys(value: object, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UsageContractError(f"{path} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise UsageContractError(
            f"{path} keys mismatch: missing={missing} extra={extra}"
        )
    return value


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise UsageContractError(f"{path} must be an integer >= {minimum}")
    return value


def _nullable_string(value: object, path: str, *, max_length: int = 512) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise UsageContractError(f"{path} must be null or a non-empty string")
    if len(value) > max_length:
        raise UsageContractError(f"{path} exceeds {max_length} characters")
    return value


def _required_string(value: object, path: str, *, max_length: int = 512) -> str:
    result = _nullable_string(value, path, max_length=max_length)
    if result is None:
        raise UsageContractError(f"{path} must be a non-empty string")
    return result


def _timestamp(value: object, path: str) -> datetime:
    text = _required_string(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageContractError(f"{path} must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise UsageContractError(f"{path} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _string_list(value: object, path: str) -> list[str]:
    if not isinstance(value, list):
        raise UsageContractError(f"{path} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_required_string(item, f"{path}[{index}]"))
    if len(set(result)) != len(result):
        raise UsageContractError(f"{path} must not contain duplicates")
    return result


def _coverage_from_missing(missing: list[str], expected_count: int) -> str:
    if not missing:
        return "complete"
    return "unavailable" if len(missing) == expected_count else "partial"


def _validate_accounting_json(
    value: object, path: str = "usage.rawProviderUsage"
) -> None:
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_RAW_USAGE_BYTES:
        raise UsageContractError(f"{path} exceeds {MAX_RAW_USAGE_BYTES} bytes")
    if not isinstance(value, dict):
        raise UsageContractError(f"{path} must be an accounting object")
    unknown = set(value) - RAW_USAGE_KEYS
    if unknown:
        raise UsageContractError(f"{path} has non-accounting fields: {sorted(unknown)}")
    for key in RAW_USAGE_COUNT_KEYS:
        if key in value and value[key] is not None:
            _integer(value[key], f"{path}.{key}")
    for key in RAW_USAGE_ENUM_KEYS:
        if key in value and value[key] is not None:
            _required_string(value[key], f"{path}.{key}", max_length=64)
    for key in RAW_USAGE_DETAIL_KEYS:
        if key not in value or value[key] is None:
            continue
        details = value[key]
        detail_items = details if isinstance(details, list) else [details]
        if not isinstance(details, (dict, list)):
            raise UsageContractError(f"{path}.{key} must be an object or array")
        for index, item in enumerate(detail_items):
            item_path = f"{path}.{key}[{index}]"
            if not isinstance(item, dict):
                raise UsageContractError(f"{item_path} must be an object")
            unknown_detail = set(item) - RAW_USAGE_DETAIL_KEYS_ALLOWED
            if unknown_detail:
                raise UsageContractError(
                    f"{item_path} has non-accounting fields: {sorted(unknown_detail)}"
                )
            if "modality" in item:
                _required_string(
                    item["modality"], f"{item_path}.modality", max_length=64
                )
            for detail_key in RAW_USAGE_DETAIL_COUNT_KEYS:
                if detail_key in item:
                    _integer(item[detail_key], f"{item_path}.{detail_key}")


def validate_call_receipt(value: object) -> dict[str, Any]:
    receipt = _exact_keys(value, CALL_KEYS, "receipt")
    if receipt["schema"] != CALL_SCHEMA:
        raise UsageContractError(f"receipt.schema must be {CALL_SCHEMA}")
    _integer(receipt["ledgerSeq"], "receipt.ledgerSeq", minimum=1)
    digest = _required_string(receipt["receiptDigest"], "receipt.receiptDigest")
    if not HEX_DIGEST_RE.fullmatch(digest):
        raise UsageContractError(
            "receipt.receiptDigest must be sha256:<64 lower-case hex>"
        )
    if digest != receipt_digest(receipt):
        raise UsageContractError(
            "receipt.receiptDigest does not match canonical receipt bytes"
        )
    producer_coverage_digest = _required_string(
        receipt["producerCoverageDigest"], "receipt.producerCoverageDigest"
    )
    if not HEX_DIGEST_RE.fullmatch(producer_coverage_digest):
        raise UsageContractError(
            "receipt.producerCoverageDigest must be sha256:<64 lower-case hex>"
        )

    _required_string(receipt["callId"], "receipt.callId", max_length=128)
    for key in (
        "runId",
        "turnId",
        "requestId",
        "sessionId",
        "retryOf",
        "fallbackParent",
        "finishReason",
        "errorCategory",
    ):
        _nullable_string(receipt[key], f"receipt.{key}", max_length=128)
    if receipt["trigger"] not in TRIGGERS:
        raise UsageContractError(f"receipt.trigger must be one of {sorted(TRIGGERS)}")
    _integer(receipt["attempt"], "receipt.attempt", minimum=1)
    fallback_index = _integer(receipt["fallbackIndex"], "receipt.fallbackIndex")
    if receipt["fallbackParent"] is None and fallback_index != 0:
        raise UsageContractError(
            "receipt.fallbackIndex must be 0 when fallbackParent is null"
        )
    if receipt["fallbackParent"] is not None and fallback_index == 0:
        raise UsageContractError(
            "receipt.fallbackIndex must be positive when fallbackParent is set"
        )
    started = _timestamp(receipt["startedAt"], "receipt.startedAt")
    completed = _timestamp(receipt["completedAt"], "receipt.completedAt")
    if completed < started:
        raise UsageContractError("receipt.completedAt precedes startedAt")
    if receipt["status"] not in STATUSES:
        raise UsageContractError(f"receipt.status must be one of {sorted(STATUSES)}")

    for key in ("configured", "requested"):
        model = _exact_keys(receipt[key], MODEL_KEYS, f"receipt.{key}")
        _required_string(model["provider"], f"receipt.{key}.provider", max_length=64)
        _required_string(model["model"], f"receipt.{key}.model", max_length=191)
    actual = _exact_keys(receipt["actual"], ACTUAL_KEYS, "receipt.actual")
    for key in ACTUAL_KEYS:
        _nullable_string(actual[key], f"receipt.actual.{key}", max_length=191)

    usage = _exact_keys(receipt["usage"], USAGE_KEYS, "receipt.usage")
    for key in COUNT_KEYS:
        if usage[key] is not None:
            _integer(usage[key], f"receipt.usage.{key}")
    _nullable_string(usage["serviceTier"], "receipt.usage.serviceTier", max_length=64)
    if usage["rawProviderUsage"] is not None:
        _validate_accounting_json(usage["rawProviderUsage"])

    missing_usage = _string_list(
        receipt["missingUsageFields"], "receipt.missingUsageFields"
    )
    missing_receipt = _string_list(
        receipt["missingReceiptFields"], "receipt.missingReceiptFields"
    )
    expected_missing_usage = [key for key in USAGE_FIELD_ORDER if usage[key] is None]
    if missing_usage != expected_missing_usage:
        raise UsageContractError(
            "receipt.missingUsageFields must exactly name null usage fields: "
            f"expected={expected_missing_usage} actual={missing_usage}"
        )
    expected_usage_coverage = _coverage_from_missing(
        missing_usage, len(USAGE_FIELD_ORDER)
    )
    if receipt["usageCoverage"] != expected_usage_coverage:
        raise UsageContractError(
            f"receipt.usageCoverage must be {expected_usage_coverage} for missingUsageFields"
        )

    expected_missing_receipt = [
        key for key in RECEIPT_IDENTITY_FIELDS if receipt[key] is None
    ]
    expected_receipt_field_count = (
        len(RECEIPT_IDENTITY_FIELDS) + 1 + len(USAGE_FIELD_ORDER)
    )
    if receipt["trigger"] == "unknown":
        expected_missing_receipt.append("trigger")
    if receipt["status"] == "succeeded":
        expected_receipt_field_count += len(SUCCEEDED_EVIDENCE_FIELDS)
        evidence_values = {
            "actual.provider": actual["provider"],
            "actual.model": actual["model"],
            "actual.responseId": actual["responseId"],
            "actual.evidenceSource": actual["evidenceSource"],
            "finishReason": receipt["finishReason"],
        }
        expected_missing_receipt.extend(
            path for path in SUCCEEDED_EVIDENCE_FIELDS if evidence_values[path] is None
        )
    else:
        expected_receipt_field_count += 1
        if receipt["errorCategory"] is None:
            expected_missing_receipt.append("errorCategory")
    expected_missing_receipt.extend(f"usage.{key}" for key in expected_missing_usage)
    if missing_receipt != expected_missing_receipt:
        raise UsageContractError(
            "receipt.missingReceiptFields is inconsistent with applicable null evidence: "
            f"expected={expected_missing_receipt} actual={missing_receipt}"
        )
    expected_receipt_coverage = _coverage_from_missing(
        expected_missing_receipt, expected_receipt_field_count
    )
    if receipt["receiptCoverage"] != expected_receipt_coverage:
        raise UsageContractError(
            f"receipt.receiptCoverage must be {expected_receipt_coverage} for missingReceiptFields"
        )
    return receipt


def validate_export(
    value: object, *, expected_after: int, expected_family: str
) -> ValidatedExport:
    payload = _exact_keys(value, EXPORT_KEYS, "export")
    if payload["schema"] != EXPORT_SCHEMA:
        raise UsageContractError(f"export.schema must be {EXPORT_SCHEMA}")
    after = _integer(payload["after"], "export.after")
    if after != expected_after:
        raise UsageContractError(
            f"export.after mismatch: expected={expected_after} actual={after}"
        )
    next_cursor = _integer(payload["nextCursor"], "export.nextCursor")
    high_watermark = _integer(payload["highWatermark"], "export.highWatermark")
    count = _integer(payload["count"], "export.count")
    if not isinstance(payload["hasMore"], bool):
        raise UsageContractError("export.hasMore must be boolean")
    if high_watermark < after:
        raise UsageContractError(
            f"product ledger moved backwards: after={after} highWatermark={high_watermark}"
        )
    raw_receipts = payload["receipts"]
    if not isinstance(raw_receipts, list):
        raise UsageContractError("export.receipts must be an array")
    if count != len(raw_receipts):
        raise UsageContractError(
            f"export.count mismatch: count={count} receipts={len(raw_receipts)}"
        )
    receipts = tuple(validate_call_receipt(item) for item in raw_receipts)
    raw_manifests = payload["coverageManifests"]
    if not isinstance(raw_manifests, list):
        raise UsageContractError("export.coverageManifests must be an array")
    coverage_manifests = tuple(
        validate_coverage(item, expected_family=expected_family)
        for item in raw_manifests
    )
    manifest_digests = [item.manifest_digest for item in coverage_manifests]
    if manifest_digests != sorted(set(manifest_digests)):
        raise UsageContractError(
            "export.coverageManifests manifestDigest must be unique and ascending"
        )
    referenced_digests = sorted(
        {str(item["producerCoverageDigest"]) for item in receipts}
    )
    if manifest_digests != referenced_digests:
        raise UsageContractError(
            "export.coverageManifests must exactly match receipt producerCoverageDigest values"
        )
    sequences = [int(item["ledgerSeq"]) for item in receipts]
    if sequences != sorted(set(sequences)):
        raise UsageContractError(
            "export.receipts ledgerSeq must be unique and ascending"
        )
    if sequences and sequences[0] <= after:
        raise UsageContractError(
            "export.receipts contains a sequence at or before export.after"
        )
    if sequences and sequences[-1] > high_watermark:
        raise UsageContractError(
            "export.receipts contains a sequence above highWatermark"
        )
    expected_next = sequences[-1] if sequences else after
    if next_cursor != expected_next:
        raise UsageContractError(
            f"export.nextCursor mismatch: expected={expected_next} actual={next_cursor}"
        )
    expected_has_more = next_cursor < high_watermark
    if payload["hasMore"] != expected_has_more:
        raise UsageContractError(
            f"export.hasMore mismatch: expected={expected_has_more} actual={payload['hasMore']}"
        )
    if expected_has_more and not sequences:
        raise UsageContractError("export made no cursor progress while hasMore=true")
    return ValidatedExport(
        after=after,
        next_cursor=next_cursor,
        high_watermark=high_watermark,
        has_more=expected_has_more,
        receipts=receipts,
        coverage_manifests=coverage_manifests,
    )


def coverage_manifest_digest(value: Mapping[str, Any]) -> str:
    return sha256_digest(
        {key: item for key, item in value.items() if key != "manifestDigest"}
    )


def validate_coverage(value: object, *, expected_family: str) -> ValidatedCoverage:
    payload = _exact_keys(value, COVERAGE_KEYS, "coverage")
    if payload["schema"] != COVERAGE_SCHEMA:
        raise UsageContractError(f"coverage.schema must be {COVERAGE_SCHEMA}")
    family = _required_string(
        payload["productFamily"], "coverage.productFamily", max_length=32
    )
    if family not in PRODUCT_FAMILIES:
        raise UsageContractError(
            f"coverage.productFamily must be one of {sorted(PRODUCT_FAMILIES)}"
        )
    if family != expected_family:
        raise UsageContractError(
            f"coverage.productFamily mismatch: expected={expected_family} actual={family}"
        )
    manifest_digest = _required_string(
        payload["manifestDigest"], "coverage.manifestDigest"
    )
    if not HEX_DIGEST_RE.fullmatch(manifest_digest):
        raise UsageContractError(
            "coverage.manifestDigest must be sha256:<64 lower-case hex>"
        )
    expected_digest = coverage_manifest_digest(payload)
    if manifest_digest != expected_digest:
        raise UsageContractError(
            "coverage.manifestDigest does not match canonical manifest bytes"
        )
    status = _required_string(
        payload["coverageStatus"], "coverage.coverageStatus", max_length=16
    )
    if status not in {"complete", "partial"}:
        raise UsageContractError("coverage.coverageStatus must be complete or partial")
    raw_surfaces = payload["surfaces"]
    if not isinstance(raw_surfaces, list) or not raw_surfaces:
        raise UsageContractError("coverage.surfaces must be a non-empty array")
    surfaces: list[dict[str, Any]] = []
    codes: list[str] = []
    for index, raw_surface in enumerate(raw_surfaces):
        path = f"coverage.surfaces[{index}]"
        surface = _exact_keys(raw_surface, COVERAGE_SURFACE_KEYS, path)
        code = _required_string(
            surface["surfaceCode"], f"{path}.surfaceCode", max_length=128
        )
        codes.append(code)
        enum_fields = {
            "observationKind": SURFACE_OBSERVATION_KINDS,
            "meterFamily": SURFACE_METER_FAMILIES,
            "modelEvidence": SURFACE_MODEL_EVIDENCE,
            "retryObservation": SURFACE_RETRY_OBSERVATION,
            "usageObservation": SURFACE_USAGE_OBSERVATION,
            "status": SURFACE_STATUSES,
        }
        for field, allowed in enum_fields.items():
            item = _required_string(surface[field], f"{path}.{field}", max_length=32)
            if item not in allowed:
                raise UsageContractError(
                    f"{path}.{field} must be one of {sorted(allowed)}"
                )
        gap_code = _nullable_string(
            surface["gapCode"], f"{path}.gapCode", max_length=128
        )
        if surface["status"] == "implemented" and gap_code is not None:
            raise UsageContractError(
                f"{path}.gapCode must be null when status=implemented"
            )
        if surface["status"] != "implemented" and gap_code is None:
            raise UsageContractError(
                f"{path}.gapCode is required when status is not implemented"
            )
        surfaces.append(surface)
    if codes != sorted(set(codes)):
        raise UsageContractError(
            "coverage.surfaces surfaceCode must be unique and ascending"
        )
    expected_status = (
        "complete"
        if all(item["status"] == "implemented" for item in surfaces)
        else "partial"
    )
    if status != expected_status:
        raise UsageContractError(
            f"coverage.coverageStatus must be {expected_status} for surface statuses"
        )
    return ValidatedCoverage(
        family=family,
        manifest_digest=manifest_digest,
        status=status,
        surfaces=tuple(surfaces),
    )


def export_command(family: str, *, after: int, limit: int) -> list[str]:
    _integer(after, "after")
    _integer(limit, "limit", minimum=1)
    if family == "hermes":
        entry = "hermes"
    elif family == "openclaw":
        entry = "openclaw"
    else:
        raise UsageContractError(f"unsupported usage export family: {family}")
    return [
        entry,
        "usage-receipts",
        "export",
        "--after",
        str(after),
        "--limit",
        str(limit),
    ]


def coverage_command(family: str) -> list[str]:
    if family not in PRODUCT_FAMILIES:
        raise UsageContractError(f"unsupported usage coverage family: {family}")
    return [family, "usage-receipts", "coverage", "--json"]


def parse_export_stdout(
    stdout: str, *, expected_after: int, expected_family: str
) -> ValidatedExport:
    text = stdout.strip()
    if not text:
        raise UsageContractError("product usage export returned empty stdout")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageContractError(
            "product usage export stdout is not exactly one JSON document"
        ) from exc
    return validate_export(
        payload, expected_after=expected_after, expected_family=expected_family
    )


def parse_coverage_stdout(stdout: str, *, expected_family: str) -> ValidatedCoverage:
    text = stdout.strip()
    if not text:
        raise UsageContractError("product usage coverage returned empty stdout")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageContractError(
            "product usage coverage stdout is not exactly one JSON document"
        ) from exc
    return validate_coverage(payload, expected_family=expected_family)


def now_rfc3339() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def redact_error(text: object, *, limit: int = 512) -> str:
    value = str(text or "").replace("\r", " ").replace("\n", " ").strip()
    value = re.sub(
        r"(?i)(authorization|bearer|password|api[_-]?key|token)\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        value,
    )
    return value[:limit]


def build_runtime_stamp(
    *,
    binding: RuntimeBinding,
    container_id: str,
    truth: Mapping[str, object],
    collected_at: str | None = None,
) -> RuntimeUsageStamp:
    if truth.get("truth_status") != "ok":
        raise UsageContractError(
            f"live runtime truth is not ok: {truth.get('truth_status')}"
        )
    if str(truth.get("instance_id") or "") != binding.instance_id:
        raise UsageContractError("live runtime instance_id does not match binding")
    if str(truth.get("family") or "") != binding.family:
        raise UsageContractError("live runtime family does not match binding")
    wrapper = _required_string(truth.get("wrapper_image"), "truth.wrapper_image")
    product = _required_string(truth.get("product_image"), "truth.product_image")
    return RuntimeUsageStamp(
        instance_id=binding.instance_id,
        linux_account=binding.linux_account,
        public_host=binding.public_host,
        family=binding.family,
        runtime_class=binding.runtime_class,
        binding_digest=runtime_binding_digest(binding),
        container_id=_required_string(container_id, "container_id"),
        wrapper_image=wrapper,
        product_image=product,
        ops_repo_commit=str(truth.get("ops_repo_commit") or ""),
        collected_at=collected_at or now_rfc3339(),
    )


def ensure_binding_unchanged(before: RuntimeBinding, after: RuntimeBinding) -> None:
    if runtime_binding_digest(before) != runtime_binding_digest(after):
        raise UsageContractError("runtime binding changed during usage export")


def receipts_contain_no_content(receipts: Iterable[Mapping[str, Any]]) -> None:
    for receipt in receipts:
        raw = receipt.get("usage")
        if isinstance(raw, dict) and raw.get("rawProviderUsage") is not None:
            _validate_accounting_json(raw["rawProviderUsage"])


ConnectionFactory = Callable[[], Any]


def load_mysql_defaults(path: Path) -> dict[str, object]:
    import configparser
    import os
    import stat

    parser = configparser.ConfigParser(interpolation=None)
    if os.name == "posix":
        if not hasattr(os, "O_NOFOLLOW"):
            raise UsageContractError("usage DB defaults loader requires O_NOFOLLOW")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise UsageContractError(
                f"cannot safely open usage DB defaults file: {path}"
            ) from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise UsageContractError(
                    f"usage DB defaults file must be root:root 0600 regular nlink=1: {path}"
                )
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                parser.read_file(handle)
        finally:
            if fd >= 0:
                os.close(fd)
    else:
        if path.is_symlink() or not path.is_file():
            raise UsageContractError(
                f"usage DB defaults file must be a regular file: {path}"
            )
        parser.read(path, encoding="utf-8")
    if not parser.has_section("client"):
        raise UsageContractError("usage DB defaults file is missing [client]")
    client = parser["client"]
    database = client.get("database", "nas_ops").strip()
    if database != "nas_ops":
        raise UsageContractError("usage DB credential must target database=nas_ops")
    user = client.get("user", "").strip()
    password = client.get("password", "")
    if not user or not password:
        raise UsageContractError("usage DB defaults file is missing user/password")
    try:
        port = int(client.get("port", "3306"))
    except ValueError as exc:
        raise UsageContractError("usage DB port must be an integer") from exc
    return {
        "host": client.get("host", "127.0.0.1").strip() or "127.0.0.1",
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "charset": "utf8mb4",
        "autocommit": False,
    }


def mysql_connection_factory(defaults_path: Path) -> ConnectionFactory:
    config = load_mysql_defaults(defaults_path)

    def connect():
        try:
            import pymysql
            from pymysql.cursors import DictCursor
        except ImportError as exc:  # pragma: no cover - install contract
            raise UsageContractError(
                "PyMySQL is required for the central usage ledger"
            ) from exc
        return pymysql.connect(**config, cursorclass=DictCursor)

    return connect
