from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Mapping

from .usage_ledger import (
    RuntimeUsageStamp,
    UsageContractError,
    UsageLedgerConflict,
    ValidatedCoverage,
    ValidatedExport,
    canonical_json_bytes,
    redact_error,
)


class UsageCollectionBusy(UsageContractError):
    """Another collector owns this runtime instance's DB connection lock."""


def _sql_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageContractError(f"invalid receipt timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise UsageContractError(f"receipt timestamp must include a timezone: {value}")
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _json_text(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _fetchone_dict(cursor) -> dict[str, Any] | None:
    row = cursor.fetchone()
    if row is None:
        return None
    if isinstance(row, dict):
        return dict(row)
    raise UsageContractError("usage DB cursor must return dictionary rows")


def ensure_schema(connection) -> None:
    required = {
        "provider_usage_call",
        "provider_usage_coverage_manifest",
        "usage_collection_cursor",
        "usage_collection_conflict",
        "slot_assignment_interval",
    }
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name IN (%s,%s,%s,%s,%s)",
            tuple(sorted(required)),
        )
        found = {str(row["table_name"]) for row in cursor.fetchall()}
    if found != required:
        raise UsageContractError(
            f"usage DB schema incomplete: missing={sorted(required - found)}"
        )


def acquire_collection_lock(connection, instance_id: str) -> None:
    lock_name = f"jitech-usage:{instance_id}"
    if len(lock_name.encode("utf-8")) > 64:
        raise UsageContractError("usage collection lock name exceeds MySQL limit")
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK(%s, 0) AS acquired", (lock_name,))
        row = _fetchone_dict(cursor)
    if row is None or int(row.get("acquired") or 0) != 1:
        raise UsageCollectionBusy(
            f"usage collection already running: instance={instance_id}"
        )


def read_cursor(connection, stamp: RuntimeUsageStamp) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT last_ledger_seq, product_family, last_status FROM usage_collection_cursor "
            "WHERE runtime_instance_id=%s",
            (stamp.instance_id,),
        )
        row = _fetchone_dict(cursor)
    if row is None:
        return 0
    if str(row["product_family"]) != stamp.family:
        raise UsageContractError(
            f"usage cursor family mismatch: stored={row['product_family']} live={stamp.family}"
        )
    if str(row.get("last_status") or "") == "conflict":
        raise UsageLedgerConflict(
            f"usage cursor is stopped on an unresolved conflict: instance={stamp.instance_id}"
        )
    return int(row["last_ledger_seq"])


def _ensure_cursor_locked(
    cursor, stamp: RuntimeUsageStamp, expected_after: int
) -> None:
    cursor.execute(
        "INSERT IGNORE INTO usage_collection_cursor "
        "(runtime_instance_id, linux_account, public_host, product_family, runtime_class, "
        "runtime_binding_digest, last_ledger_seq, last_status) "
        "VALUES (%s,%s,%s,%s,%s,%s,0,'never')",
        (
            stamp.instance_id,
            stamp.linux_account,
            stamp.public_host,
            stamp.family,
            stamp.runtime_class,
            stamp.binding_digest,
        ),
    )
    cursor.execute(
        "SELECT last_ledger_seq, product_family FROM usage_collection_cursor "
        "WHERE runtime_instance_id=%s FOR UPDATE",
        (stamp.instance_id,),
    )
    row = _fetchone_dict(cursor)
    if row is None:
        raise UsageContractError("usage cursor disappeared during collection")
    if str(row["product_family"]) != stamp.family:
        raise UsageContractError("usage cursor product family changed")
    actual = int(row["last_ledger_seq"])
    if actual != expected_after:
        raise UsageContractError(
            f"usage cursor raced: expected={expected_after} actual={actual}"
        )


def _assignment_for_call(
    cursor, linux_account: str, started_at: datetime
) -> tuple[int | None, str | None, str]:
    cursor.execute(
        "SELECT id, mb_id FROM slot_assignment_interval "
        "WHERE agent_id=%s AND effective_from<=%s "
        "AND (effective_to IS NULL OR effective_to>%s) "
        "ORDER BY effective_from DESC LIMIT 2",
        (linux_account, started_at, started_at),
    )
    rows = list(cursor.fetchall())
    if not rows:
        return None, None, "unavailable"
    if len(rows) != 1:
        raise UsageContractError(
            f"overlapping assignment intervals for {linux_account} at {started_at.isoformat()}"
        )
    row = rows[0]
    if not isinstance(row, dict):
        raise UsageContractError("usage DB cursor must return dictionary rows")
    return int(row["id"]), str(row["mb_id"]), "matched"


def _record_conflict(
    cursor,
    *,
    stamp: RuntimeUsageStamp,
    receipt: Mapping[str, Any],
    conflict_kind: str,
    existing_digest: str,
) -> None:
    cursor.execute(
        "INSERT INTO usage_collection_conflict "
        "(runtime_instance_id, product_family, call_id, product_ledger_seq, conflict_kind, "
        "existing_receipt_digest, observed_receipt_digest, observed_receipt_json, detected_at) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            stamp.instance_id,
            stamp.family,
            receipt["callId"],
            receipt["ledgerSeq"],
            conflict_kind,
            existing_digest,
            receipt["receiptDigest"],
            _json_text(receipt),
            _sql_timestamp(stamp.collected_at),
        ),
    )
    cursor.execute(
        "UPDATE usage_collection_cursor SET last_status='conflict', last_attempt_at=%s, "
        "last_error_code=%s, last_error_detail=%s WHERE runtime_instance_id=%s",
        (
            _sql_timestamp(stamp.collected_at),
            conflict_kind,
            f"call={receipt['callId']} seq={receipt['ledgerSeq']}",
            stamp.instance_id,
        ),
    )


def _coverage_payload(coverage: ValidatedCoverage) -> dict[str, Any]:
    return {
        "schema": "jitech-provider-usage-coverage/v1",
        "productFamily": coverage.family,
        "manifestDigest": coverage.manifest_digest,
        "coverageStatus": coverage.status,
        "surfaces": list(coverage.surfaces),
    }


def _store_coverage_manifest(
    cursor,
    *,
    stamp: RuntimeUsageStamp,
    coverage: ValidatedCoverage,
) -> None:
    payload = _coverage_payload(coverage)
    payload_text = _json_text(payload)
    cursor.execute(
        "SELECT product_family, coverage_status, manifest_json "
        "FROM provider_usage_coverage_manifest WHERE manifest_digest=%s FOR UPDATE",
        (coverage.manifest_digest,),
    )
    existing = _fetchone_dict(cursor)
    if existing is None:
        cursor.execute(
            "INSERT INTO provider_usage_coverage_manifest "
            "(manifest_digest, product_family, coverage_status, manifest_json, "
            "first_collected_at, last_collected_at) VALUES (%s,%s,%s,%s,%s,%s)",
            (
                coverage.manifest_digest,
                coverage.family,
                coverage.status,
                payload_text,
                _sql_timestamp(stamp.collected_at),
                _sql_timestamp(stamp.collected_at),
            ),
        )
        return
    raw_manifest = existing.get("manifest_json")
    try:
        stored_payload = (
            json.loads(raw_manifest) if isinstance(raw_manifest, str) else raw_manifest
        )
        stored_text = _json_text(stored_payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise UsageContractError(
            "stored producer coverage manifest is invalid"
        ) from exc
    if (
        str(existing.get("product_family") or "") != coverage.family
        or str(existing.get("coverage_status") or "") != coverage.status
        or stored_text != payload_text
    ):
        raise UsageContractError(
            f"producer coverage digest is bound to different bytes: {coverage.manifest_digest}"
        )
    cursor.execute(
        "UPDATE provider_usage_coverage_manifest SET last_collected_at=%s "
        "WHERE manifest_digest=%s",
        (_sql_timestamp(stamp.collected_at), coverage.manifest_digest),
    )


def _insert_receipt(
    cursor,
    *,
    stamp: RuntimeUsageStamp,
    coverage: ValidatedCoverage,
    receipt: Mapping[str, Any],
) -> bool:
    cursor.execute(
        "SELECT receipt_digest, product_ledger_seq FROM provider_usage_call "
        "WHERE runtime_instance_id=%s AND call_id=%s FOR UPDATE",
        (stamp.instance_id, receipt["callId"]),
    )
    existing = _fetchone_dict(cursor)
    if existing is not None:
        existing_digest = str(existing["receipt_digest"])
        existing_sequence = int(existing["product_ledger_seq"])
        if existing_digest == receipt["receiptDigest"] and existing_sequence == int(
            receipt["ledgerSeq"]
        ):
            return False
        conflict_kind = (
            "call_id_sequence_mismatch"
            if existing_digest == receipt["receiptDigest"]
            else "call_id_digest_mismatch"
        )
        _record_conflict(
            cursor,
            stamp=stamp,
            receipt=receipt,
            conflict_kind=conflict_kind,
            existing_digest=existing_digest,
        )
        raise UsageLedgerConflict(
            f"same callId has different digest: instance={stamp.instance_id} call={receipt['callId']}"
        )

    cursor.execute(
        "SELECT receipt_digest, call_id FROM provider_usage_call "
        "WHERE runtime_instance_id=%s AND product_family=%s AND product_ledger_seq=%s FOR UPDATE",
        (stamp.instance_id, stamp.family, receipt["ledgerSeq"]),
    )
    by_sequence = _fetchone_dict(cursor)
    if by_sequence is not None:
        _record_conflict(
            cursor,
            stamp=stamp,
            receipt=receipt,
            conflict_kind="ledger_sequence_reused",
            existing_digest=str(by_sequence["receipt_digest"]),
        )
        raise UsageLedgerConflict(
            f"product ledger sequence reused: instance={stamp.instance_id} seq={receipt['ledgerSeq']}"
        )

    started_at = _sql_timestamp(str(receipt["startedAt"]))
    completed_at = _sql_timestamp(str(receipt["completedAt"]))
    interval_id, mb_id, assignment_status = _assignment_for_call(
        cursor, stamp.linux_account, started_at
    )
    usage = receipt["usage"]
    actual = receipt["actual"]
    cursor.execute(
        "INSERT INTO provider_usage_call "
        "(runtime_instance_id, linux_account, public_host, product_family, runtime_class, "
        "runtime_binding_digest, wrapper_image, product_image, ops_repo_commit, container_id, "
        "product_ledger_seq, receipt_digest, producer_coverage_status, producer_coverage_digest, "
        "call_id, run_id, turn_id, request_id, session_id, "
        "trigger_kind, attempt, retry_of, fallback_parent, fallback_index, started_at, completed_at, "
        "call_status, configured_provider, configured_model, requested_provider, requested_model, "
        "actual_provider, actual_model, response_id, evidence_source, input_total, input_non_cached, "
        "cache_read, cache_write, output_candidates, reasoning_thinking, tool_use_prompt, "
        "provider_reported_total, service_tier, usage_coverage, receipt_coverage, finish_reason, "
        "error_category, assignment_interval_id, assigned_mb_id, assignment_status, receipt_json, collected_at) "
        "VALUES (" + ",".join(["%s"] * 53) + ")",
        (
            stamp.instance_id,
            stamp.linux_account,
            stamp.public_host,
            stamp.family,
            stamp.runtime_class,
            stamp.binding_digest,
            stamp.wrapper_image,
            stamp.product_image,
            stamp.ops_repo_commit or None,
            stamp.container_id,
            receipt["ledgerSeq"],
            receipt["receiptDigest"],
            coverage.status,
            coverage.manifest_digest,
            receipt["callId"],
            receipt["runId"],
            receipt["turnId"],
            receipt["requestId"],
            receipt["sessionId"],
            receipt["trigger"],
            receipt["attempt"],
            receipt["retryOf"],
            receipt["fallbackParent"],
            receipt["fallbackIndex"],
            started_at,
            completed_at,
            receipt["status"],
            receipt["configured"]["provider"],
            receipt["configured"]["model"],
            receipt["requested"]["provider"],
            receipt["requested"]["model"],
            actual["provider"],
            actual["model"],
            actual["responseId"],
            actual["evidenceSource"],
            usage["inputTotal"],
            usage["inputNonCached"],
            usage["cacheRead"],
            usage["cacheWrite"],
            usage["outputCandidates"],
            usage["reasoningThinking"],
            usage["toolUsePrompt"],
            usage["providerReportedTotal"],
            usage["serviceTier"],
            receipt["usageCoverage"],
            receipt["receiptCoverage"],
            receipt["finishReason"],
            receipt["errorCategory"],
            interval_id,
            mb_id,
            assignment_status,
            _json_text(receipt),
            _sql_timestamp(stamp.collected_at),
        ),
    )
    return True


def store_export_page(
    connection,
    *,
    stamp: RuntimeUsageStamp,
    coverage: ValidatedCoverage,
    page: ValidatedExport,
) -> dict[str, int]:
    inserted = 0
    idempotent = 0
    pending_conflict: UsageLedgerConflict | None = None
    try:
        connection.begin()
        with connection.cursor() as cursor:
            _ensure_cursor_locked(cursor, stamp, page.after)
            _store_coverage_manifest(cursor, stamp=stamp, coverage=coverage)
            for receipt in page.receipts:
                try:
                    was_inserted = _insert_receipt(
                        cursor,
                        stamp=stamp,
                        coverage=coverage,
                        receipt=receipt,
                    )
                except UsageLedgerConflict as exc:
                    pending_conflict = exc
                    break
                if was_inserted:
                    inserted += 1
                else:
                    idempotent += 1
            if pending_conflict is None:
                cursor.execute(
                    "UPDATE usage_collection_cursor SET linux_account=%s, public_host=%s, "
                    "runtime_class=%s, runtime_binding_digest=%s, last_ledger_seq=%s, "
                    "last_high_watermark=%s, last_success_at=%s, last_attempt_at=%s, "
                    "last_status='ok', last_error_code=NULL, last_error_detail=NULL, "
                    "producer_coverage_status=%s, producer_coverage_digest=%s, "
                    "producer_coverage_manifest=%s, "
                    "wrapper_image=%s, product_image=%s, container_id=%s "
                    "WHERE runtime_instance_id=%s",
                    (
                        stamp.linux_account,
                        stamp.public_host,
                        stamp.runtime_class,
                        stamp.binding_digest,
                        page.next_cursor,
                        page.high_watermark,
                        _sql_timestamp(stamp.collected_at),
                        _sql_timestamp(stamp.collected_at),
                        coverage.status,
                        coverage.manifest_digest,
                        _json_text(_coverage_payload(coverage)),
                        stamp.wrapper_image,
                        stamp.product_image,
                        stamp.container_id,
                        stamp.instance_id,
                    ),
                )
        connection.commit()
    except Exception:
        if pending_conflict is None:
            connection.rollback()
        raise
    if pending_conflict is not None:
        raise pending_conflict
    return {
        "inserted": inserted,
        "idempotent": idempotent,
        "nextCursor": page.next_cursor,
    }


def record_collection_failure(
    connection,
    *,
    stamp: RuntimeUsageStamp,
    error_code: str,
    detail: str,
) -> None:
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO usage_collection_cursor "
                "(runtime_instance_id, linux_account, public_host, product_family, runtime_class, "
                "runtime_binding_digest, last_ledger_seq, last_status, last_attempt_at, "
                "last_error_code, last_error_detail, wrapper_image, product_image, container_id) "
                "VALUES (%s,%s,%s,%s,%s,%s,0,'failed',%s,%s,%s,%s,%s,%s) "
                "ON DUPLICATE KEY UPDATE linux_account=VALUES(linux_account), public_host=VALUES(public_host), "
                "runtime_class=VALUES(runtime_class), runtime_binding_digest=VALUES(runtime_binding_digest), "
                "last_status='failed', last_attempt_at=VALUES(last_attempt_at), "
                "last_error_code=VALUES(last_error_code), last_error_detail=VALUES(last_error_detail), "
                "wrapper_image=VALUES(wrapper_image), product_image=VALUES(product_image), container_id=VALUES(container_id)",
                (
                    stamp.instance_id,
                    stamp.linux_account,
                    stamp.public_host,
                    stamp.family,
                    stamp.runtime_class,
                    stamp.binding_digest,
                    _sql_timestamp(stamp.collected_at),
                    error_code,
                    redact_error(detail),
                    stamp.wrapper_image,
                    stamp.product_image,
                    stamp.container_id,
                ),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def list_collection_status(
    connection, *, linux_account: str | None = None
) -> list[dict[str, Any]]:
    sql = (
        "SELECT runtime_instance_id, linux_account, public_host, product_family, runtime_class, "
        "last_ledger_seq, last_high_watermark, last_success_at, last_attempt_at, last_status, "
        "last_error_code, last_error_detail, wrapper_image, product_image "
        "FROM usage_collection_cursor"
    )
    params: tuple[object, ...] = ()
    if linux_account:
        sql += " WHERE linux_account=%s"
        params = (linux_account,)
    sql += " ORDER BY linux_account"
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
