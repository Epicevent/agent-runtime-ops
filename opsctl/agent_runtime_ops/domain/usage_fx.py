from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import os
from pathlib import Path
import stat
from typing import Any
import urllib.request
from xml.etree import ElementTree

from .usage_cost import FX_SCHEMA, load_fx_ledger, validate_fx_ledger
from .usage_ledger import UsageContractError, canonical_json_bytes


ECB_90_DAY_XML_URL = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-hist-90d.xml"
MAX_ECB_DOCUMENT_BYTES = 4 * 1024 * 1024


def _iso_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise UsageContractError("FX retrieval timestamp must include a timezone")
    return value.isoformat()


def build_ecb_reference_fx_ledger(
    xml_bytes: bytes,
    *,
    revision: str,
    published_at: datetime,
    retrieved_at: datetime,
    max_carry_days: int = 7,
) -> dict[str, Any]:
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError as exc:
        raise UsageContractError("ECB FX document is not valid XML") from exc
    document_digest = "sha256:" + hashlib.sha256(xml_bytes).hexdigest()
    rates: list[dict[str, Any]] = []
    seen_days: set[str] = set()
    for day_node in root.iter():
        rate_day = day_node.attrib.get("time")
        if rate_day is None:
            continue
        if rate_day in seen_days:
            raise UsageContractError(f"ECB FX document repeats rate date: {rate_day}")
        seen_days.add(rate_day)
        by_currency: dict[str, str] = {}
        for child in day_node:
            currency = child.attrib.get("currency")
            rate = child.attrib.get("rate")
            if currency is None or rate is None:
                continue
            if currency in by_currency:
                raise UsageContractError(
                    f"ECB FX document repeats currency {currency} on {rate_day}"
                )
            by_currency[currency] = rate
        if "USD" not in by_currency or "KRW" not in by_currency:
            raise UsageContractError(f"ECB FX document lacks USD or KRW on {rate_day}")
        try:
            usd_per_eur = Decimal(by_currency["USD"])
            krw_per_eur = Decimal(by_currency["KRW"])
        except Exception as exc:
            raise UsageContractError(
                f"ECB FX document has invalid rates on {rate_day}"
            ) from exc
        if usd_per_eur <= 0 or krw_per_eur <= 0:
            raise UsageContractError(
                f"ECB FX document has nonpositive rates on {rate_day}"
            )
        cross = (krw_per_eur / usd_per_eur).quantize(
            Decimal("0.000000000001"), rounding=ROUND_HALF_UP
        )
        rates.append(
            {
                "rateDate": rate_day,
                "usdPerEur": format(usd_per_eur, "f"),
                "krwPerEur": format(krw_per_eur, "f"),
                "krwPerUsd": format(cross, "f"),
                "source": {
                    "url": ECB_90_DAY_XML_URL,
                    "retrievedAt": _iso_timestamp(retrieved_at),
                    "documentSha256": document_digest,
                    "derivation": "KRW_per_EUR / USD_per_EUR",
                },
            }
        )
    rates.sort(key=lambda item: item["rateDate"])
    if not rates:
        raise UsageContractError("ECB FX document contains no daily rates")
    payload = {
        "schema": FX_SCHEMA,
        "revision": revision,
        "publishedAt": _iso_timestamp(published_at),
        "baseCurrency": "USD",
        "quoteCurrency": "KRW",
        "maxCarryDays": max_carry_days,
        "rates": rates,
    }
    return dict(validate_fx_ledger(payload).payload)


def fetch_ecb_90_day_xml(*, timeout: int = 30) -> tuple[bytes, datetime]:
    request = urllib.request.Request(
        ECB_90_DAY_XML_URL,
        headers={
            "Accept": "application/xml,text/xml;q=0.9",
            "User-Agent": "agent-runtime-ops/usage-fx",
        },
    )
    retrieved_at = datetime.now(timezone.utc)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = int(getattr(response, "status", 200) or 200)
            if status_code != 200:
                raise UsageContractError(f"ECB FX download returned HTTP {status_code}")
            content_type = str(response.headers.get("Content-Type") or "").lower()
            if "xml" not in content_type:
                raise UsageContractError("ECB FX download did not return XML")
            raw = response.read(MAX_ECB_DOCUMENT_BYTES + 1)
    except UsageContractError:
        raise
    except Exception as exc:
        raise UsageContractError("ECB FX download failed") from exc
    if not raw or len(raw) > MAX_ECB_DOCUMENT_BYTES:
        raise UsageContractError("ECB FX document size is invalid")
    return raw, retrieved_at


def _safe_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UsageContractError(f"FX artifact parent is not a real directory: {path}")


def _existing_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UsageContractError(f"FX artifact target is not a regular file: {path}")
    return True


def _write_all(fd: int, payload: bytes) -> None:
    written = 0
    while written < len(payload):
        count = os.write(fd, payload[written:])
        if count <= 0:
            raise UsageContractError("short write while publishing FX artifact")
        written += count


def _publish_atomic(path: Path, payload: bytes, *, mode: int = 0o640) -> str:
    _safe_directory(path.parent)
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise UsageContractError(
                f"FX artifact target is not a regular file: {path}"
            )
        if path.read_bytes() == payload:
            return "unchanged"
    temp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp, flags, 0o600)
    try:
        _write_all(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, mode) if hasattr(os, "fchmod") else None
    finally:
        os.close(fd)
    try:
        os.replace(temp, path)
        if not hasattr(os, "fchmod"):
            os.chmod(path, mode)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()
    return "published"


def refresh_ecb_reference_fx(
    *,
    output_path: Path,
    evidence_dir: Path,
    timeout: int = 30,
) -> dict[str, Any]:
    xml_bytes, retrieved_at = fetch_ecb_90_day_xml(timeout=timeout)
    document_hex = hashlib.sha256(xml_bytes).hexdigest()
    revision = f"{retrieved_at.date().isoformat()}.ecb.{document_hex[:12]}"
    ledger = build_ecb_reference_fx_ledger(
        xml_bytes,
        revision=revision,
        published_at=retrieved_at,
        retrieved_at=retrieved_at,
    )
    # The ECB endpoint is a rolling 90-day window.  Replacing the ledger with
    # only that window would eventually erase the exact daily rate needed to
    # reproduce an older slot estimate.  Preserve already validated history
    # and let the newest official document replace overlapping dates.
    if _existing_regular_file(output_path):
        previous = load_fx_ledger(output_path)
        by_day = {
            str(row["rateDate"]): dict(row) for row in previous.payload["rates"]
        }
        by_day.update({str(row["rateDate"]): dict(row) for row in ledger["rates"]})
        ledger = dict(
            validate_fx_ledger(
                {
                    **ledger,
                    "rates": [by_day[day] for day in sorted(by_day)],
                }
            ).payload
        )
    evidence_path = evidence_dir / f"ecb-eurofxref-hist-90d-{document_hex}.xml"
    _safe_directory(evidence_dir)
    evidence_status = _publish_atomic(evidence_path, xml_bytes, mode=0o640)
    ledger_status = _publish_atomic(
        output_path,
        canonical_json_bytes(ledger),
        mode=0o640,
    )
    latest_rate_date = str(ledger["rates"][-1]["rateDate"])
    return {
        "schema": "jitech-daily-reference-fx-refresh/v1",
        "status": "ok",
        "ledgerStatus": ledger_status,
        "evidenceStatus": evidence_status,
        "revision": revision,
        "rateCount": len(ledger["rates"]),
        "latestRateDate": latest_rate_date,
        "documentSha256": "sha256:" + document_hex,
        "outputPath": str(output_path),
        "evidencePath": str(evidence_path),
    }
