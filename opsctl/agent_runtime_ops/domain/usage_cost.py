from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping
from zoneinfo import ZoneInfo

from .usage_ledger import UsageContractError, canonical_json_bytes


PRICING_SCHEMA = "jitech-provider-pricing-catalog/v1"
FX_SCHEMA = "jitech-daily-reference-fx/v1"
COST_SCHEMA = "jitech-provider-operational-cost-estimate/v1"
METERING_PROFILE = "gemini-generate-content-v1"
KST = ZoneInfo("Asia/Seoul")


@dataclass(frozen=True)
class PricingCatalog:
    payload: Mapping[str, Any]
    digest: str


@dataclass(frozen=True)
class DailyReferenceFxLedger:
    payload: Mapping[str, Any]
    digest: str


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _record(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise UsageContractError(f"{path} must be an object")
    return value


def _exact_fields(value: Mapping[str, Any], fields: set[str], path: str) -> None:
    actual = set(value)
    if actual != fields:
        raise UsageContractError(
            f"{path} fields mismatch: missing={sorted(fields - actual)} extra={sorted(actual - fields)}"
        )


def _text(value: object, path: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise UsageContractError(f"{path} must be a nonempty string")
    return value


def _timestamp(value: object, path: str) -> datetime:
    raw = _text(value, path)
    assert raw is not None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageContractError(f"{path} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise UsageContractError(f"{path} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _day(value: object, path: str) -> date:
    raw = _text(value, path)
    assert raw is not None
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise UsageContractError(f"{path} must be an ISO date") from exc


def _decimal(value: object, path: str, *, positive: bool = False) -> Decimal:
    if not isinstance(value, str):
        raise UsageContractError(f"{path} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise UsageContractError(f"{path} must be a decimal string") from exc
    if not parsed.is_finite() or parsed < 0 or (positive and parsed <= 0):
        raise UsageContractError(
            f"{path} must be {'positive' if positive else 'nonnegative'}"
        )
    return parsed


def _load_json(path: Path) -> Mapping[str, Any]:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UsageContractError(f"duplicate JSON key in artifact: {key}")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        parsed = json.loads(raw, object_pairs_hook=strict_object)
    except UsageContractError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise UsageContractError(f"cannot read JSON artifact: {path}") from exc
    payload = _record(parsed, str(path))
    return payload


def validate_pricing_catalog(payload: object) -> PricingCatalog:
    catalog = _record(payload, "pricing")
    _exact_fields(catalog, {"schema", "revision", "publishedAt", "entries"}, "pricing")
    if catalog["schema"] != PRICING_SCHEMA:
        raise UsageContractError(f"pricing.schema must be {PRICING_SCHEMA}")
    _text(catalog["revision"], "pricing.revision")
    _timestamp(catalog["publishedAt"], "pricing.publishedAt")
    entries = catalog["entries"]
    if not isinstance(entries, list):
        raise UsageContractError("pricing.entries must be an array")
    identities: list[tuple[str, str, str, str, str]] = []
    entry_ids: list[str] = []
    for index, item in enumerate(entries):
        path = f"pricing.entries[{index}]"
        entry = _record(item, path)
        _exact_fields(
            entry,
            {
                "entryId",
                "provider",
                "apiProduct",
                "actualModel",
                "serviceTier",
                "priceScenario",
                "currency",
                "meteringProfile",
                "effectiveFrom",
                "effectiveUntil",
                "ratesPerMillion",
                "unpricedComponents",
                "source",
            },
            path,
        )
        entry_id = _text(entry["entryId"], f"{path}.entryId")
        assert entry_id is not None
        provider = _text(entry["provider"], f"{path}.provider")
        api_product = _text(entry["apiProduct"], f"{path}.apiProduct")
        model = _text(entry["actualModel"], f"{path}.actualModel")
        tier = _text(entry["serviceTier"], f"{path}.serviceTier")
        scenario = _text(entry["priceScenario"], f"{path}.priceScenario")
        if entry["currency"] != "USD":
            raise UsageContractError(f"{path}.currency must be USD")
        if entry["meteringProfile"] != METERING_PROFILE:
            raise UsageContractError(f"{path}.meteringProfile is unsupported")
        start = _timestamp(entry["effectiveFrom"], f"{path}.effectiveFrom")
        end_raw = _text(
            entry["effectiveUntil"], f"{path}.effectiveUntil", nullable=True
        )
        if (
            end_raw is not None
            and _timestamp(end_raw, f"{path}.effectiveUntil") <= start
        ):
            raise UsageContractError(
                f"{path}.effectiveUntil must be after effectiveFrom"
            )
        rates = _record(entry["ratesPerMillion"], f"{path}.ratesPerMillion")
        _exact_fields(
            rates,
            {"inputNonCached", "cacheRead", "outputIncludingThinking"},
            f"{path}.ratesPerMillion",
        )
        for name, raw in rates.items():
            _decimal(raw, f"{path}.ratesPerMillion.{name}")
        missing = entry["unpricedComponents"]
        if not isinstance(missing, list) or any(
            not isinstance(item, str) or not item for item in missing
        ):
            raise UsageContractError(
                f"{path}.unpricedComponents must be a string array"
            )
        if missing != sorted(set(missing)):
            raise UsageContractError(
                f"{path}.unpricedComponents must be sorted and unique"
            )
        source = _record(entry["source"], f"{path}.source")
        _exact_fields(source, {"url", "checkedAt", "checkedBy"}, f"{path}.source")
        _text(source["url"], f"{path}.source.url")
        _timestamp(source["checkedAt"], f"{path}.source.checkedAt")
        _text(source["checkedBy"], f"{path}.source.checkedBy")
        identities.append(
            (str(provider), str(api_product), str(model), str(tier), str(scenario))
        )
        entry_ids.append(entry_id)
    if entry_ids != sorted(set(entry_ids)):
        raise UsageContractError(
            "pricing entries must be unique and ordered by entryId"
        )
    if len(identities) != len(set(identities)):
        raise UsageContractError("pricing entries contain an ambiguous exact selector")
    return PricingCatalog(payload=catalog, digest=_digest(catalog))


def load_pricing_catalog(path: Path) -> PricingCatalog:
    return validate_pricing_catalog(_load_json(path))


def validate_fx_ledger(payload: object) -> DailyReferenceFxLedger:
    ledger = _record(payload, "fx")
    _exact_fields(
        ledger,
        {
            "schema",
            "revision",
            "publishedAt",
            "baseCurrency",
            "quoteCurrency",
            "maxCarryDays",
            "rates",
        },
        "fx",
    )
    if ledger["schema"] != FX_SCHEMA:
        raise UsageContractError(f"fx.schema must be {FX_SCHEMA}")
    _text(ledger["revision"], "fx.revision")
    _timestamp(ledger["publishedAt"], "fx.publishedAt")
    if ledger["baseCurrency"] != "USD" or ledger["quoteCurrency"] != "KRW":
        raise UsageContractError("fx currencies must be USD/KRW")
    max_carry = ledger["maxCarryDays"]
    if (
        not isinstance(max_carry, int)
        or isinstance(max_carry, bool)
        or not 0 <= max_carry <= 14
    ):
        raise UsageContractError("fx.maxCarryDays must be an integer between 0 and 14")
    rates = ledger["rates"]
    if not isinstance(rates, list):
        raise UsageContractError("fx.rates must be an array")
    days: list[str] = []
    for index, item in enumerate(rates):
        path = f"fx.rates[{index}]"
        rate = _record(item, path)
        _exact_fields(
            rate,
            {"rateDate", "usdPerEur", "krwPerEur", "krwPerUsd", "source"},
            path,
        )
        rate_day = _day(rate["rateDate"], f"{path}.rateDate")
        usd_per_eur = _decimal(rate["usdPerEur"], f"{path}.usdPerEur", positive=True)
        krw_per_eur = _decimal(rate["krwPerEur"], f"{path}.krwPerEur", positive=True)
        krw_per_usd = _decimal(rate["krwPerUsd"], f"{path}.krwPerUsd", positive=True)
        expected_cross = (krw_per_eur / usd_per_eur).quantize(
            Decimal("0.000000000001"), rounding=ROUND_HALF_UP
        )
        if krw_per_usd != expected_cross:
            raise UsageContractError(
                f"{path}.krwPerUsd must equal krwPerEur / usdPerEur at 12 decimals"
            )
        source = _record(rate["source"], f"{path}.source")
        _exact_fields(
            source,
            {"url", "retrievedAt", "documentSha256", "derivation"},
            f"{path}.source",
        )
        _text(source["url"], f"{path}.source.url")
        _timestamp(source["retrievedAt"], f"{path}.source.retrievedAt")
        document_digest = _text(
            source["documentSha256"], f"{path}.source.documentSha256"
        )
        if document_digest is None or not document_digest.startswith("sha256:"):
            raise UsageContractError(
                f"{path}.source.documentSha256 must be a sha256 digest"
            )
        if source["derivation"] != "KRW_per_EUR / USD_per_EUR":
            raise UsageContractError(f"{path}.source.derivation is unsupported")
        days.append(rate_day.isoformat())
    if days != sorted(set(days)):
        raise UsageContractError("fx rates must be unique and ordered by rateDate")
    return DailyReferenceFxLedger(payload=ledger, digest=_digest(ledger))


def load_fx_ledger(path: Path) -> DailyReferenceFxLedger:
    return validate_fx_ledger(_load_json(path))


def _unavailable(
    receipt: Mapping[str, Any],
    catalog: PricingCatalog,
    fx: DailyReferenceFxLedger,
    reason: str,
    *,
    api_product: str,
    price_scenario: str,
) -> dict[str, Any]:
    payload = {
        "schema": COST_SCHEMA,
        "callId": receipt.get("callId"),
        "usageReceiptDigest": receipt.get("receiptDigest"),
        "valuationKind": "operational_estimate",
        "estimateStatus": "unavailable",
        "billingReconciliationStatus": "not_applicable",
        "apiProduct": api_product,
        "priceScenario": price_scenario,
        "estimatedAmountUsd": None,
        "estimatedAmountKrw": None,
        "pricingEntryId": None,
        "pricingCatalogDigest": catalog.digest,
        "referenceFxLedgerDigest": fx.digest,
        "referenceFxRateDate": None,
        "referenceUsdPerEur": None,
        "referenceKrwPerEur": None,
        "referenceKrwPerUsd": None,
        "referenceFxBasis": "daily_reference_not_billing",
        "components": [],
        "missingComponents": [reason],
    }
    return {**payload, "projectionDigest": _digest(payload)}


def project_call_cost(
    receipt: Mapping[str, Any],
    catalog: PricingCatalog,
    fx: DailyReferenceFxLedger,
    *,
    api_product: str = "gemini_developer_api",
    price_scenario: str = "paid_standard_list",
) -> dict[str, Any]:
    actual = receipt.get("actual")
    usage = receipt.get("usage")
    if not isinstance(actual, dict) or not isinstance(usage, dict):
        return _unavailable(
            receipt,
            catalog,
            fx,
            "usage_receipt_invalid",
            api_product=api_product,
            price_scenario=price_scenario,
        )
    provider = actual.get("provider")
    model = actual.get("model")
    tier = usage.get("serviceTier")
    if not all(isinstance(value, str) and value for value in (provider, model, tier)):
        return _unavailable(
            receipt,
            catalog,
            fx,
            "actual_model_or_tier_unavailable",
            api_product=api_product,
            price_scenario=price_scenario,
        )
    started_at = _timestamp(receipt.get("startedAt"), "receipt.startedAt")
    entries = []
    for entry in catalog.payload["entries"]:
        if (
            entry["provider"] == provider
            and entry["apiProduct"] == api_product
            and entry["actualModel"] == model
            and entry["serviceTier"] == tier
            and entry["priceScenario"] == price_scenario
            and _timestamp(entry["effectiveFrom"], "entry.effectiveFrom") <= started_at
            and (
                entry["effectiveUntil"] is None
                or started_at
                < _timestamp(entry["effectiveUntil"], "entry.effectiveUntil")
            )
        ):
            entries.append(entry)
    if len(entries) != 1:
        return _unavailable(
            receipt,
            catalog,
            fx,
            "pricing_entry_missing" if not entries else "pricing_entry_ambiguous",
            api_product=api_product,
            price_scenario=price_scenario,
        )
    entry = entries[0]
    usage_day = started_at.astimezone(KST).date()
    fx_rows = [
        row
        for row in fx.payload["rates"]
        if _day(row["rateDate"], "fx.rateDate") <= usage_day
    ]
    if not fx_rows:
        return _unavailable(
            receipt,
            catalog,
            fx,
            "daily_fx_missing",
            api_product=api_product,
            price_scenario=price_scenario,
        )
    fx_row = fx_rows[-1]
    fx_day = _day(fx_row["rateDate"], "fx.rateDate")
    carry_days = (usage_day - fx_day).days
    if carry_days > int(fx.payload["maxCarryDays"]):
        return _unavailable(
            receipt,
            catalog,
            fx,
            "daily_fx_stale",
            api_product=api_product,
            price_scenario=price_scenario,
        )
    quantity_fields = {
        "inputNonCached": "inputNonCached",
        "cacheRead": "cacheRead",
        "outputCandidates": "outputCandidates",
        "reasoningThinking": "reasoningThinking",
    }
    missing = [
        name for name, field in quantity_fields.items() if usage.get(field) is None
    ]
    if missing:
        return _unavailable(
            receipt,
            catalog,
            fx,
            "usage_fields_missing:" + ",".join(sorted(missing)),
            api_product=api_product,
            price_scenario=price_scenario,
        )
    quantities = {
        name: Decimal(int(usage[field])) for name, field in quantity_fields.items()
    }
    rates = entry["ratesPerMillion"]
    components = [
        (
            "input_non_cached",
            quantities["inputNonCached"],
            _decimal(rates["inputNonCached"], "rate.input"),
        ),
        (
            "cache_read",
            quantities["cacheRead"],
            _decimal(rates["cacheRead"], "rate.cache"),
        ),
        (
            "output_including_thinking",
            quantities["outputCandidates"] + quantities["reasoningThinking"],
            _decimal(rates["outputIncludingThinking"], "rate.output"),
        ),
    ]
    component_rows: list[dict[str, Any]] = []
    amount_usd = Decimal("0")
    for kind, quantity, rate in components:
        component_amount = quantity * rate / Decimal(1_000_000)
        amount_usd += component_amount
        component_rows.append(
            {
                "kind": kind,
                "quantity": int(quantity),
                "unit": "tokens",
                "rateUsdPerMillion": format(rate, "f"),
                "amountUsd": format(
                    component_amount.quantize(
                        Decimal("0.000000000001"), rounding=ROUND_HALF_UP
                    ),
                    "f",
                ),
            }
        )
    krw_per_usd = _decimal(fx_row["krwPerUsd"], "fx.krwPerUsd", positive=True)
    amount_usd = amount_usd.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_UP)
    amount_krw = (amount_usd * krw_per_usd).quantize(
        Decimal("0.0001"), rounding=ROUND_HALF_UP
    )
    missing_components = sorted(set(str(item) for item in entry["unpricedComponents"]))
    if receipt.get("usageCoverage") != "complete":
        missing_components.append("usage_coverage_incomplete")
        missing_components = sorted(set(missing_components))
    estimate_status = "partial" if missing_components else "complete"
    payload = {
        "schema": COST_SCHEMA,
        "callId": receipt.get("callId"),
        "usageReceiptDigest": receipt.get("receiptDigest"),
        "valuationKind": "operational_estimate",
        "estimateStatus": estimate_status,
        "billingReconciliationStatus": "not_applicable",
        "apiProduct": api_product,
        "priceScenario": price_scenario,
        "estimatedAmountUsd": format(amount_usd, "f"),
        "estimatedAmountKrw": format(amount_krw, "f"),
        "pricingEntryId": entry["entryId"],
        "pricingCatalogDigest": catalog.digest,
        "referenceFxLedgerDigest": fx.digest,
        "referenceFxRateDate": fx_day.isoformat(),
        "referenceUsdPerEur": fx_row["usdPerEur"],
        "referenceKrwPerEur": fx_row["krwPerEur"],
        "referenceKrwPerUsd": format(krw_per_usd, "f"),
        "referenceFxBasis": "daily_reference_not_billing",
        "components": component_rows,
        "missingComponents": missing_components,
    }
    return {**payload, "projectionDigest": _digest(payload)}
