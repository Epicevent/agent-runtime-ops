from __future__ import annotations

from datetime import datetime, timezone
import json

from .usage_cost import DailyReferenceFxLedger, PricingCatalog, project_call_cost
from .usage_ledger import UsageContractError, canonical_json_bytes


def _json_text(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ensure_cost_schema(connection) -> None:
    required = {
        "usage_pricing_catalog_revision",
        "usage_reference_fx_ledger_revision",
        "provider_usage_cost_estimate",
    }
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name IN (%s,%s,%s)",
            tuple(sorted(required)),
        )
        found = {str(row["table_name"]) for row in cursor.fetchall()}
    if found != required:
        raise UsageContractError(
            f"usage cost DB schema incomplete: missing={sorted(required - found)}"
        )


def _store_revision(
    cursor,
    *,
    table: str,
    digest: str,
    schema: str,
    revision: str,
    payload: object,
    published_at: str,
    now: datetime,
) -> None:
    if table not in {
        "usage_pricing_catalog_revision",
        "usage_reference_fx_ledger_revision",
    }:
        raise UsageContractError("invalid revision table")
    payload_text = _json_text(payload)
    cursor.execute(
        f"SELECT artifact_json FROM {table} WHERE artifact_digest=%s FOR UPDATE",
        (digest,),
    )
    existing = cursor.fetchone()
    if existing is not None:
        raw = existing["artifact_json"]
        stored = json.loads(raw) if isinstance(raw, str) else raw
        if _json_text(stored) != payload_text:
            raise UsageContractError(f"{table} digest is bound to different bytes")
        return
    cursor.execute(
        f"INSERT INTO {table} "
        "(artifact_digest, artifact_schema, revision, published_at, artifact_json, recorded_at) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (digest, schema, revision, published_at, payload_text, now),
    )


def project_costs(
    connection,
    *,
    catalog: PricingCatalog,
    fx: DailyReferenceFxLedger,
    api_product: str,
    price_scenario: str,
    linux_account: str | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    ensure_cost_schema(connection)
    projected_at = now or _utc_now()
    inserted = 0
    idempotent = 0
    settled_skipped = 0
    connection.begin()
    try:
        with connection.cursor() as cursor:
            _store_revision(
                cursor,
                table="usage_pricing_catalog_revision",
                digest=catalog.digest,
                schema=str(catalog.payload["schema"]),
                revision=str(catalog.payload["revision"]),
                payload=catalog.payload,
                published_at=str(catalog.payload["publishedAt"]),
                now=projected_at,
            )
            _store_revision(
                cursor,
                table="usage_reference_fx_ledger_revision",
                digest=fx.digest,
                schema=str(fx.payload["schema"]),
                revision=str(fx.payload["revision"]),
                payload=fx.payload,
                published_at=str(fx.payload["publishedAt"]),
                now=projected_at,
            )
            sql = (
                "SELECT id, runtime_instance_id, linux_account, receipt_digest, receipt_json "
                "FROM provider_usage_call c"
            )
            params: list[object] = []
            if linux_account:
                sql += " WHERE c.linux_account=%s"
                params.append(linux_account)
            sql += " ORDER BY c.id"
            cursor.execute(sql, tuple(params))
            calls = [dict(row) for row in cursor.fetchall()]
            for row in calls:
                raw_receipt = row["receipt_json"]
                receipt = (
                    json.loads(raw_receipt)
                    if isinstance(raw_receipt, str)
                    else raw_receipt
                )
                if not isinstance(receipt, dict):
                    raise UsageContractError("stored usage receipt must be an object")
                if receipt.get("receiptDigest") != row["receipt_digest"]:
                    raise UsageContractError(
                        "stored usage receipt digest disagrees with its row"
                    )
                projection = project_call_cost(
                    receipt,
                    catalog,
                    fx,
                    api_product=api_product,
                    price_scenario=price_scenario,
                )
                cursor.execute(
                    "SELECT estimate_digest, estimate_json FROM provider_usage_cost_estimate "
                    "WHERE provider_usage_call_id=%s AND pricing_catalog_digest=%s "
                    "AND reference_fx_ledger_digest=%s AND api_product=%s "
                    "AND price_scenario=%s FOR UPDATE",
                    (
                        row["id"],
                        catalog.digest,
                        fx.digest,
                        api_product,
                        price_scenario,
                    ),
                )
                existing = cursor.fetchone()
                if existing is not None:
                    raw_existing = existing["estimate_json"]
                    existing_payload = (
                        json.loads(raw_existing)
                        if isinstance(raw_existing, str)
                        else raw_existing
                    )
                    if existing["estimate_digest"] != projection[
                        "projectionDigest"
                    ] or _json_text(existing_payload) != _json_text(projection):
                        raise UsageContractError(
                            "cost estimate identity is bound to different bytes"
                        )
                    idempotent += 1
                    continue
                # A complete or partial estimate is an immutable historical
                # valuation of this call at its usage-date FX rate.  A newly
                # downloaded daily FX artifact must not create another row for
                # every old call.  Unavailable calls are intentionally retried
                # so a later pricing or FX artifact can make them estimable.
                cursor.execute(
                    "SELECT id FROM provider_usage_cost_estimate "
                    "WHERE provider_usage_call_id=%s AND api_product=%s "
                    "AND price_scenario=%s "
                    "AND estimate_status IN ('complete','partial') LIMIT 1",
                    (row["id"], api_product, price_scenario),
                )
                if cursor.fetchone() is not None:
                    settled_skipped += 1
                    continue
                cursor.execute(
                    "INSERT INTO provider_usage_cost_estimate "
                    "(provider_usage_call_id, runtime_instance_id, linux_account, usage_receipt_digest, "
                    "estimate_schema, estimate_digest, estimate_status, api_product, price_scenario, "
                    "estimated_amount_usd, estimated_amount_krw, pricing_entry_id, pricing_catalog_digest, "
                    "reference_fx_ledger_digest, reference_fx_rate_date, reference_usd_per_eur, "
                    "reference_krw_per_eur, reference_krw_per_usd, components_json, "
                    "missing_components_json, estimate_json, estimated_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        row["id"],
                        row["runtime_instance_id"],
                        row["linux_account"],
                        row["receipt_digest"],
                        projection["schema"],
                        projection["projectionDigest"],
                        projection["estimateStatus"],
                        projection["apiProduct"],
                        projection["priceScenario"],
                        projection["estimatedAmountUsd"],
                        projection["estimatedAmountKrw"],
                        projection["pricingEntryId"],
                        projection["pricingCatalogDigest"],
                        projection["referenceFxLedgerDigest"],
                        projection["referenceFxRateDate"],
                        projection["referenceUsdPerEur"],
                        projection["referenceKrwPerEur"],
                        projection["referenceKrwPerUsd"],
                        _json_text(projection["components"]),
                        _json_text(projection["missingComponents"]),
                        _json_text(projection),
                        projected_at,
                    ),
                )
                inserted += 1
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "inserted": inserted,
        "idempotent": idempotent,
        "settledSkipped": settled_skipped,
    }
