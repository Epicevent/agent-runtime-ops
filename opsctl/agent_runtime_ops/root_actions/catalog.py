from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Iterable

from .public_projection import PublicProjectionError, validate_public_projection


PUBLIC_CATALOG_SCHEMA = "agent-runtime-root-action-public-catalog/v1"
PUBLIC_CATALOG_PAGE_SCHEMA = "agent-runtime-root-action-public-catalog-page/v1"
PUBLIC_CATALOG_PAGE_SIZE = 128
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_TIMESTAMP_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
_GENERATION_RE = re.compile(r"generation-[0-9a-f]{32}")
_ENTRY_KEYS = {
    "job_id",
    "job_digest",
    "projection_digest",
    "request_id",
    "reply_target",
    "operation_id",
    "state",
    "terminal_outcome",
    "reason_code",
    "last_changed_at",
    "path",
}
_STATE_VALUES = {"pending", "running", "terminal", "unknown"}
_TERMINAL_OUTCOMES = {
    "succeeded",
    "failed",
    "rejected",
    "expired",
    "canceled",
    "prestart_failed",
}


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _digest(domain: bytes, value: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _is_safe_id(value: Any) -> bool:
    return isinstance(value, str) and _SAFE_ID_RE.fullmatch(value) is not None


def _is_real_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _validate_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
        raise PublicProjectionError("public catalog entry field set is invalid")
    if (
        not _is_safe_id(entry["job_id"])
        or not _is_safe_id(entry["request_id"])
        or not _is_safe_id(entry["reply_target"])
        or not _is_safe_id(entry["operation_id"])
        or not isinstance(entry["job_digest"], str)
        or _DIGEST_RE.fullmatch(entry["job_digest"]) is None
        or not isinstance(entry["projection_digest"], str)
        or _DIGEST_RE.fullmatch(entry["projection_digest"]) is None
        or entry["state"] not in _STATE_VALUES
        or not _is_real_timestamp(entry["last_changed_at"])
        or entry["path"] != f'{entry["job_id"]}/projection.json'
    ):
        raise PublicProjectionError("public catalog entry value is invalid")
    outcome = entry["terminal_outcome"]
    reason = entry["reason_code"]
    if outcome is not None and outcome not in _TERMINAL_OUTCOMES:
        raise PublicProjectionError("public catalog terminal outcome is invalid")
    if reason is not None and not _is_safe_id(reason):
        raise PublicProjectionError("public catalog reason code is invalid")
    if entry["state"] in {"pending", "running"}:
        valid_state = outcome is None and reason is None
    elif entry["state"] == "unknown":
        valid_state = outcome is None and reason is not None
    else:
        valid_state = outcome is not None and reason is not None
    if not valid_state:
        raise PublicProjectionError("public catalog entry state is inconsistent")
    return entry


@dataclass(frozen=True)
class PublicCatalogArtifact:
    generation: str
    catalog_digest: str
    catalog_bytes: bytes
    pages: tuple[tuple[str, str, bytes], ...]


def build_public_catalog(
    bundles: Iterable[Any],
    *,
    page_size: int = PUBLIC_CATALOG_PAGE_SIZE,
    authority_job_count: int | None = None,
) -> PublicCatalogArtifact:
    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 256:
        raise PublicProjectionError("public catalog page size is invalid")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for bundle in bundles:
        projection = validate_public_projection(bundle.projection_bytes)
        if projection.job_id in seen:
            raise PublicProjectionError("public catalog job id is duplicated")
        seen.add(projection.job_id)
        value = json.loads(projection.canonical_bytes.decode("utf-8"))
        status = value["status"]
        job = status["job"]
        state = status["state"]
        entries.append(
            {
                "job_id": projection.job_id,
                "job_digest": projection.job_digest,
                "projection_digest": projection.projection_digest,
                "request_id": job["request_id"],
                "reply_target": job["reply_target"],
                "operation_id": job["operation_id"],
                "state": state["name"],
                "terminal_outcome": state["terminal_outcome"],
                "reason_code": state["reason_code"],
                "last_changed_at": state["last_changed_at"],
                "path": f"{projection.job_id}/projection.json",
            }
        )
    entries.sort(key=lambda item: (item["last_changed_at"], item["job_id"]), reverse=True)
    entries_bytes = _canonical({"entries": entries, "page_size": page_size})
    generation_digest = _digest(
        b"agent-runtime-root-action-public-catalog-generation/v1",
        entries_bytes,
    )
    generation = "generation-" + generation_digest.removeprefix("sha256:")[:32]
    total_jobs = len(entries)
    if authority_job_count is None:
        authority_job_count = total_jobs
    if (
        isinstance(authority_job_count, bool)
        or not isinstance(authority_job_count, int)
        or authority_job_count < total_jobs
    ):
        raise PublicProjectionError("public catalog authority count is invalid")
    total_pages = (total_jobs + page_size - 1) // page_size
    pages: list[tuple[str, str, bytes]] = []
    page_refs: list[dict[str, Any]] = []
    for page_index in range(total_pages):
        number = page_index + 1
        page_entries = entries[page_index * page_size : (page_index + 1) * page_size]
        page_payload = {
            "schema": PUBLIC_CATALOG_PAGE_SCHEMA,
            "generation": generation,
            "page": number,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_jobs": total_jobs,
            "entries": page_entries,
        }
        payload_bytes = _canonical(page_payload)
        page_digest = _digest(
            b"agent-runtime-root-action-public-catalog-page/v1",
            payload_bytes,
        )
        page_bytes = _canonical({**page_payload, "page_digest": page_digest})
        path = f"catalog-generations/{generation}/page-{number:08d}.json"
        pages.append((path, page_digest, page_bytes))
        page_refs.append(
            {
                "page": number,
                "path": path,
                "page_digest": page_digest,
                "entry_count": len(page_entries),
            }
        )
    payload = {
        "schema": PUBLIC_CATALOG_SCHEMA,
        "generation": generation,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_jobs": total_jobs,
        "authority_job_count": authority_job_count,
        "listed_job_count": total_jobs,
        "truncated": authority_job_count > total_jobs,
        "pages": page_refs,
        "retention": {
            "root_authority": "permanent",
            "public_job_projection": "permanent",
            "catalog_generation": "current_plus_one_prior_validated",
        },
    }
    payload_bytes = _canonical(payload)
    catalog_digest = _digest(
        b"agent-runtime-root-action-public-catalog/v1",
        payload_bytes,
    )
    return PublicCatalogArtifact(
        generation=generation,
        catalog_digest=catalog_digest,
        catalog_bytes=_canonical({**payload, "catalog_digest": catalog_digest}),
        pages=tuple(pages),
    )


def validate_public_catalog(
    catalog_raw: bytes,
    page_values: dict[str, bytes],
) -> PublicCatalogArtifact:
    try:
        catalog = json.loads(catalog_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicProjectionError("public catalog is not UTF-8 JSON") from exc
    if not isinstance(catalog, dict) or catalog_raw != _canonical(catalog):
        raise PublicProjectionError("public catalog is not canonical")
    expected = {
        "schema",
        "generation",
        "page_size",
        "total_pages",
        "total_jobs",
        "authority_job_count",
        "listed_job_count",
        "truncated",
        "pages",
        "retention",
        "catalog_digest",
    }
    if set(catalog) != expected or catalog["schema"] != PUBLIC_CATALOG_SCHEMA:
        raise PublicProjectionError("public catalog field set is invalid")
    payload = {key: catalog[key] for key in catalog if key != "catalog_digest"}
    catalog_digest = _digest(
        b"agent-runtime-root-action-public-catalog/v1",
        _canonical(payload),
    )
    if catalog["catalog_digest"] != catalog_digest:
        raise PublicProjectionError("public catalog digest mismatch")
    if (
        catalog["retention"]
        != {
            "root_authority": "permanent",
            "public_job_projection": "permanent",
            "catalog_generation": "current_plus_one_prior_validated",
        }
        or isinstance(catalog["page_size"], bool)
        or not isinstance(catalog["page_size"], int)
        or not 1 <= catalog["page_size"] <= 256
        or isinstance(catalog["total_pages"], bool)
        or not isinstance(catalog["total_pages"], int)
        or catalog["total_pages"] < 0
        or isinstance(catalog["total_jobs"], bool)
        or not isinstance(catalog["total_jobs"], int)
        or catalog["total_jobs"] < 0
        or isinstance(catalog["authority_job_count"], bool)
        or not isinstance(catalog["authority_job_count"], int)
        or catalog["authority_job_count"] < catalog["total_jobs"]
        or isinstance(catalog["listed_job_count"], bool)
        or catalog["listed_job_count"] != catalog["total_jobs"]
        or not isinstance(catalog["truncated"], bool)
        or catalog["truncated"] != (
            catalog["authority_job_count"] > catalog["listed_job_count"]
        )
        or not isinstance(catalog["pages"], list)
        or len(catalog["pages"]) != catalog["total_pages"]
        or not isinstance(catalog["generation"], str)
        or _GENERATION_RE.fullmatch(catalog["generation"]) is None
    ):
        raise PublicProjectionError("public catalog counters or retention are invalid")
    expected_total_pages = (
        catalog["total_jobs"] + catalog["page_size"] - 1
    ) // catalog["page_size"]
    if catalog["total_pages"] != expected_total_pages:
        raise PublicProjectionError("public catalog page count formula is invalid")
    pages: list[tuple[str, str, bytes]] = []
    counted = 0
    all_entries: list[dict[str, Any]] = []
    seen_jobs: set[str] = set()
    for expected_number, reference in enumerate(catalog["pages"], start=1):
        expected_path = (
            f'catalog-generations/{catalog["generation"]}/'
            f"page-{expected_number:08d}.json"
        )
        if (
            not isinstance(reference, dict)
            or set(reference) != {"page", "path", "page_digest", "entry_count"}
            or isinstance(reference["page"], bool)
            or not isinstance(reference["page"], int)
            or reference["page"] != expected_number
            or reference["path"] != expected_path
            or not isinstance(reference["page_digest"], str)
            or _DIGEST_RE.fullmatch(reference["page_digest"]) is None
            or isinstance(reference["entry_count"], bool)
            or not isinstance(reference["entry_count"], int)
            or not 1 <= reference["entry_count"] <= catalog["page_size"]
        ):
            raise PublicProjectionError("public catalog page reference is invalid")
        try:
            raw = page_values[reference["path"]]
            page = json.loads(raw.decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicProjectionError("public catalog page is unavailable") from exc
        if not isinstance(page, dict) or raw != _canonical(page):
            raise PublicProjectionError("public catalog page is not canonical")
        page_expected = {
            "schema",
            "generation",
            "page",
            "page_size",
            "total_pages",
            "total_jobs",
            "entries",
            "page_digest",
        }
        if (
            set(page) != page_expected
            or page["schema"] != PUBLIC_CATALOG_PAGE_SCHEMA
            or page["generation"] != catalog["generation"]
            or isinstance(page["page"], bool)
            or not isinstance(page["page"], int)
            or page["page"] != expected_number
            or isinstance(page["page_size"], bool)
            or not isinstance(page["page_size"], int)
            or page["page_size"] != catalog["page_size"]
            or isinstance(page["total_pages"], bool)
            or not isinstance(page["total_pages"], int)
            or page["total_pages"] != catalog["total_pages"]
            or isinstance(page["total_jobs"], bool)
            or not isinstance(page["total_jobs"], int)
            or page["total_jobs"] != catalog["total_jobs"]
            or not isinstance(page["entries"], list)
            or len(page["entries"]) != reference["entry_count"]
        ):
            raise PublicProjectionError("public catalog page contract mismatch")
        page_payload = {key: page[key] for key in page if key != "page_digest"}
        digest = _digest(
            b"agent-runtime-root-action-public-catalog-page/v1",
            _canonical(page_payload),
        )
        if page["page_digest"] != digest or digest != reference["page_digest"]:
            raise PublicProjectionError("public catalog page digest mismatch")
        expected_count = catalog["page_size"]
        if expected_number == catalog["total_pages"]:
            expected_count = catalog["total_jobs"] - (
                (catalog["total_pages"] - 1) * catalog["page_size"]
            )
        if reference["entry_count"] != expected_count:
            raise PublicProjectionError("public catalog page size formula is invalid")
        for raw_entry in page["entries"]:
            entry = _validate_entry(raw_entry)
            if entry["job_id"] in seen_jobs:
                raise PublicProjectionError("public catalog job id is duplicated")
            seen_jobs.add(entry["job_id"])
            all_entries.append(entry)
        counted += len(page["entries"])
        pages.append((reference["path"], digest, raw))
    if counted != catalog["total_jobs"]:
        raise PublicProjectionError("public catalog job count mismatch")
    if all_entries != sorted(
        all_entries,
        key=lambda item: (item["last_changed_at"], item["job_id"]),
        reverse=True,
    ):
        raise PublicProjectionError("public catalog entry ordering is invalid")
    generation_digest = _digest(
        b"agent-runtime-root-action-public-catalog-generation/v1",
        _canonical({"entries": all_entries, "page_size": catalog["page_size"]}),
    )
    expected_generation = "generation-" + generation_digest.removeprefix("sha256:")[:32]
    if catalog["generation"] != expected_generation:
        raise PublicProjectionError("public catalog generation mismatch")
    return PublicCatalogArtifact(
        generation=catalog["generation"],
        catalog_digest=catalog_digest,
        catalog_bytes=catalog_raw,
        pages=tuple(pages),
    )
