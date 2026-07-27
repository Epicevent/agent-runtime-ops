from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_runtime_ops.root_actions import BrokerPeerIdentity, SubmissionPolicy, TypedRootActionBroker
from agent_runtime_ops.root_actions.catalog import (
    PUBLIC_CATALOG_PAGE_SIZE,
    build_public_catalog,
    validate_public_catalog,
)
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.public_projection import (
    AtomicPublicProjectionPublisher,
    PublicProjectionError,
)
from agent_runtime_ops.root_actions.storage import SubmissionLimits
from tests.test_root_action_admission import manifest


PEER = BrokerPeerIdentity(uid=1027, gid=1048, pid=401)


class CounterEvents:
    def __init__(self) -> None:
        self.index = 0

    def next_event(self) -> tuple[str, str]:
        self.index += 1
        return f"catalog-event-{self.index}", "2026-07-27T12:00:00Z"


def manifest_for(index: int) -> bytes:
    value = json.loads(manifest(f"job-catalog-{index:04d}"))
    value["request"]["lineage_id"] = f"lineage-catalog-{index:04d}"
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def bundles(count: int):
    store = LocalRootActionFixture()
    broker = TypedRootActionBroker(
        store,
        events=CounterEvents(),
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({PEER.uid}),
            allowed_gids=frozenset({PEER.gid}),
            limits=SubmissionLimits(
                max_open_per_uid=count + 2,
                max_open_per_lineage=1,
                max_jobs_per_uid_window=count + 2,
                window_seconds=3600,
            ),
        ),
    )
    for index in range(count):
        broker.submit(manifest_for(index), peer=PEER)
    return tuple(
        broker.public_projection(job_id)
        for job_id in store.list_job_ids()
    )


def page_map(artifact) -> dict[str, bytes]:
    return {path: raw for path, _digest, raw in artifact.pages}


def canonical(value: dict) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def digest(domain: bytes, raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\x00" + raw).hexdigest()


def resign_catalog(catalog: dict) -> bytes:
    payload = {key: value for key, value in catalog.items() if key != "catalog_digest"}
    catalog["catalog_digest"] = digest(
        b"agent-runtime-root-action-public-catalog/v1", canonical(payload)
    )
    return canonical(catalog)


def resign_page(page: dict) -> bytes:
    payload = {key: value for key, value in page.items() if key != "page_digest"}
    page["page_digest"] = digest(
        b"agent-runtime-root-action-public-catalog-page/v1", canonical(payload)
    )
    return canonical(page)


def test_513th_projection_is_paginated_not_global_unavailable() -> None:
    values = bundles(513)
    artifact = build_public_catalog(values)
    validated = validate_public_catalog(artifact.catalog_bytes, page_map(artifact))
    catalog = json.loads(validated.catalog_bytes)
    assert catalog["total_jobs"] == 513
    assert catalog["total_pages"] == 5
    assert catalog["page_size"] == PUBLIC_CATALOG_PAGE_SIZE
    fifth = json.loads(validated.pages[4][2])
    assert len(fifth["entries"]) == 1
    assert fifth["entries"][0]["job_id"]
    assert catalog["retention"] == {
        "root_authority": "permanent",
        "public_job_projection": "permanent",
        "catalog_generation": "current_plus_one_prior_validated",
    }


def test_catalog_atomic_replace_keeps_prior_complete_generation_on_crash(
    tmp_path: Path,
) -> None:
    publisher = AtomicPublicProjectionPublisher(
        tmp_path,
        create=True,
        required_uid=None,
        required_gid=None,
        require_posix=False,
    )
    first = bundles(2)
    publisher.publish_catalog(first)
    prior = (tmp_path / "catalog.json").read_bytes()
    prior_value = json.loads(prior)
    prior_pages = {
        reference["path"]: (tmp_path / reference["path"]).read_bytes()
        for reference in prior_value["pages"]
    }
    validate_public_catalog(prior, prior_pages)
    real_replace = __import__("os").replace

    def fail_catalog_replace(source, destination, *args, **kwargs):
        if Path(destination).name == "catalog.json":
            raise OSError("simulated catalog switch crash")
        return real_replace(source, destination, *args, **kwargs)

    with patch(
        "agent_runtime_ops.root_actions.public_projection.os.replace",
        side_effect=fail_catalog_replace,
    ):
        with pytest.raises(OSError):
            publisher.publish_catalog(bundles(3))

    assert (tmp_path / "catalog.json").read_bytes() == prior
    validate_public_catalog(prior, prior_pages)


def test_catalog_retention_is_bounded_to_current_plus_prior_and_linear(
    tmp_path: Path,
) -> None:
    publisher = AtomicPublicProjectionPublisher(
        tmp_path,
        create=True,
        required_uid=None,
        required_gid=None,
        require_posix=False,
    )
    latest = None
    for count in (513, 514, 515, 516):
        latest = bundles(count)
        publisher.publish_catalog(latest)
        generations = list((tmp_path / "catalog-generations").iterdir())
        assert len(generations) <= 2
    assert latest is not None
    current = build_public_catalog(latest)
    catalog_bytes = sum(
        path.stat().st_size
        for generation in (tmp_path / "catalog-generations").iterdir()
        for path in generation.iterdir()
    )
    one_generation = sum(len(raw) for _path, _digest, raw in current.pages)
    assert catalog_bytes <= one_generation * 3


def test_catalog_wrong_page_digest_fails_closed() -> None:
    artifact = build_public_catalog(bundles(3))
    pages = page_map(artifact)
    first_path = next(iter(pages))
    value = json.loads(pages[first_path])
    value["entries"][0]["job_id"] = "job-swapped"
    pages[first_path] = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(PublicProjectionError):
        validate_public_catalog(artifact.catalog_bytes, pages)


@pytest.mark.parametrize(
    "malicious_path",
    ["../projection.json", "/etc/shadow", "catalog-generations/../page.json"],
)
def test_catalog_rejects_page_reference_traversal_even_with_valid_digest(
    malicious_path: str,
) -> None:
    artifact = build_public_catalog(bundles(3))
    catalog = json.loads(artifact.catalog_bytes)
    original_path = catalog["pages"][0]["path"]
    catalog["pages"][0]["path"] = malicious_path
    pages = {malicious_path: page_map(artifact)[original_path]}
    with pytest.raises(PublicProjectionError, match="page reference"):
        validate_public_catalog(resign_catalog(catalog), pages)


def test_catalog_rejects_duplicate_job_ids_even_with_valid_page_digests() -> None:
    artifact = build_public_catalog(bundles(3), page_size=2)
    catalog = json.loads(artifact.catalog_bytes)
    pages = page_map(artifact)
    first_path = catalog["pages"][0]["path"]
    second_path = catalog["pages"][1]["path"]
    first = json.loads(pages[first_path])
    second = json.loads(pages[second_path])
    second["entries"][0]["job_id"] = first["entries"][0]["job_id"]
    second["entries"][0]["path"] = first["entries"][0]["path"]
    pages[second_path] = resign_page(second)
    catalog["pages"][1]["page_digest"] = second["page_digest"]
    with pytest.raises(PublicProjectionError, match="duplicated"):
        validate_public_catalog(resign_catalog(catalog), pages)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job_digest", "sha256:bad"),
        ("last_changed_at", "2026-02-31T12:00:00Z"),
        ("state", "approved"),
        ("path", "../projection.json"),
    ],
)
def test_catalog_rejects_bad_entry_values_even_with_valid_page_digest(
    field: str,
    value: object,
) -> None:
    artifact = build_public_catalog(bundles(2))
    catalog = json.loads(artifact.catalog_bytes)
    pages = page_map(artifact)
    first_path = catalog["pages"][0]["path"]
    page = json.loads(pages[first_path])
    page["entries"][0][field] = value
    pages[first_path] = resign_page(page)
    catalog["pages"][0]["page_digest"] = page["page_digest"]
    with pytest.raises(PublicProjectionError, match="entry"):
        validate_public_catalog(resign_catalog(catalog), pages)


def test_catalog_rejects_arbitrary_entry_key_and_boolean_count() -> None:
    artifact = build_public_catalog(bundles(2))
    catalog = json.loads(artifact.catalog_bytes)
    pages = page_map(artifact)
    first_path = catalog["pages"][0]["path"]
    page = json.loads(pages[first_path])
    page["entries"][0]["raw_stdout"] = "must never enter public catalog"
    pages[first_path] = resign_page(page)
    catalog["pages"][0]["page_digest"] = page["page_digest"]
    with pytest.raises(PublicProjectionError, match="field set"):
        validate_public_catalog(resign_catalog(catalog), pages)

    clean = json.loads(artifact.catalog_bytes)
    clean["pages"][0]["entry_count"] = True
    with pytest.raises(PublicProjectionError, match="page reference"):
        validate_public_catalog(resign_catalog(clean), page_map(artifact))
