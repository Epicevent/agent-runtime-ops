from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest

from agent_runtime_ops.domain import kwrag_runtime_capsule as runtime_capsule
from agent_runtime_ops.domain.kwrag_runtime_capsule import (
    load_runtime_capsule,
    publish_runtime_capsule_inputs,
    run_openclaw_runtime_capsule_probe,
    stage_dev_runtime_capsule,
)
from agent_runtime_ops.domain.retrieval_contract import (
    P1_IDENTITY_FIXED,
    canonical_digest,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture(
    slot: str = "oc14", *, status: str = "published_ready"
) -> dict[str, object]:
    family = "openclaw" if slot in {"oc14", "dev-oc-img"} else "hermes"
    root = "/home/node/nas_docs" if family == "openclaw" else "/workspace/nas_docs"
    release = "sha256:" + "1" * 64
    manifest = "sha256:" + "2" * 64
    authority = {
        "schema": "kwrag-read-only-authority-receipt/v1",
        "status": "observed",
        "slot": slot,
        "family": family,
        "containerNasRoot": root,
        "releaseRelativeRoot": f"kw/package/.kwrag/releases/{release.replace(':', '-')}",
        "indexManifestDigest": manifest,
        "mountReadOnly": True,
        "allBoundFilesReadOnly": True,
    }
    engine = {
        "status": "research_selected_p1_attachment_probe_candidate",
        "backend_id": "slot-local-fts5-trigram-or-attachment-v1",
        "factory_source_digest": "sha256:104276b46fa427d741fcf63db87b70d9a6d8a2ad32e63c4a43e87692041ed43e",
        "contract_source_digest": "sha256:46dbce894e5987fb47598b26d0c29bf3c13c297f705a17c313d550cc6dbc844a",
        "research_decision_source_digest": "sha256:2245278aa9ad4e16ad8502287a0e10340c90a83fa93a2e26210c8f43c6f8f5e1",
        "pipeline_factory_digest": P1_IDENTITY_FIXED["pipelineFactoryDigest"],
        "pipeline_fingerprint": P1_IDENTITY_FIXED["pipelineFingerprint"],
        "research_decision_digest": P1_IDENTITY_FIXED["researchDecisionDigest"],
    }
    prefix = f"kw/package/.kwrag/releases/{release.replace(':', '-')}"
    receipt_root = (
        "/home/node/.openclaw/kwrag"
        if family == "openclaw"
        else "/opt/data/kwrag-p1-attachment"
    )

    def fixed(enabled: bool) -> dict[str, object]:
        return {
            "schema_version": "kwrag-fixed-producer-binding-v1",
            "enabled": enabled,
            "mount_root": root,
            "index_manifest_relative": f"{prefix}/index-manifest.json",
            "index_manifest_digest": manifest,
            "operation_receipt_path": f"{receipt_root}/operation-receipts.jsonl",
            "producer_receipt_path": f"{receipt_root}/producer-receipts.jsonl",
            "max_concurrent": 1,
            "selected_engine": engine,
            "corpora": {
                "room": {
                    "database_relative": f"{prefix}/room.sqlite3",
                    "database_sha256": "sha256:" + "3" * 64,
                    "source_snapshot_relative": f"{prefix}/room-source.json",
                    "source_snapshot_digest": "sha256:" + "4" * 64,
                    "authority_receipt_digest": canonical_digest(authority),
                }
            },
        }

    enabled = fixed(True)
    runtime = None
    runtime_digest = canonical_digest(enabled)
    if family == "hermes":
        runtime = {
            "schema_version": "kwrag-slot-runtime-binding-v1",
            "mount_root": root,
            "index_manifest_relative": f"{prefix}/index-manifest.json",
            "index_manifest_digest": manifest,
            "receipt_path": f"{receipt_root}/operation-receipts.jsonl",
            "pipeline_fingerprint": P1_IDENTITY_FIXED["pipelineFingerprint"],
            "max_concurrent": 1,
        }
        runtime_digest = canonical_digest(runtime)
    return {
        "schema": "kwrag-two-canary-runtime-capsule/v1",
        "status": status,
        "slot": slot,
        "family": family,
        "publicationReceiptDigest": "sha256:" + "5" * 64,
        "userIdDigest": "sha256:" + "6" * 64,
        "packageIdentityDigest": "sha256:" + "7" * 64,
        "releaseId": release,
        "indexManifestDigest": manifest,
        "authorityReceipt": authority,
        "authorityReceiptState": "expected_not_observed",
        "attachmentData": {
            "databaseSha256": "sha256:" + "3" * 64,
            "indexManifestDigest": manifest,
            "sourceSnapshotDigest": "sha256:" + "8" * 64,
            "readOnlyAuthorityReceiptDigest": canonical_digest(authority),
            "slotRuntimeBindingDigest": runtime_digest,
        },
        "fixedProducerBindings": {"disabled": fixed(False), "enabled": enabled},
        "productRuntimeBinding": runtime,
        "privateProofRequests": {
            "positive": {
                "schema": "kwrag-two-canary-private-proof-request/v1",
                "corpus": "room",
                "query": "private fixture query",
            },
            "negative": {
                "schema": "kwrag-two-canary-private-proof-request/v1",
                "corpus": "room",
                "query": "private absent query",
            },
        },
        "contentPolicy": {
            "privateMode": "capsule-0600/runtime-0640-root-runtime-group",
            "queryInArgv": False,
            "rawQueryInReceipt": False,
            "rawResultInReceipt": False,
        },
    }


def publish(root: Path, value: dict[str, object]) -> str:
    payload = canonical(value)
    digest = sha(payload)
    path = (
        root / "kw/package/.kwrag/runtime-capsules" / f"{digest.replace(':', '-')}.json"
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(payload)
    path.chmod(0o444)
    return digest


def dev_archive(
    root: Path, *, extra: bool = False, tamper: bool = False
) -> tuple[Path, str]:
    value = fixture("dev-oc-img")
    release = str(value["releaseId"]).replace(":", "-")
    prefix = f"kw/package/.kwrag/releases/{release}"
    manifest = b'{"schema":"synthetic-index/v1"}'
    database = b"SQLite format 3\x00synthetic"
    source = b'{"schema":"synthetic-source/v1"}'
    manifest_digest = sha(manifest)
    database_digest = sha(database)
    source_digest = sha(source)
    value["indexManifestDigest"] = manifest_digest
    value["authorityReceipt"]["indexManifestDigest"] = manifest_digest
    authority_digest = canonical_digest(value["authorityReceipt"])
    value["attachmentData"].update(
        {
            "databaseSha256": database_digest,
            "indexManifestDigest": manifest_digest,
            "sourceSnapshotDigest": source_digest,
            "readOnlyAuthorityReceiptDigest": authority_digest,
        }
    )
    for binding in value["fixedProducerBindings"].values():
        binding["index_manifest_digest"] = manifest_digest
        binding["index_manifest_relative"] = f"{prefix}/index-manifest.json"
        corpus = binding["corpora"]["room"]
        corpus.update(
            {
                "authority_receipt_digest": authority_digest,
                "database_relative": f"{prefix}/room.sqlite3",
                "database_sha256": database_digest,
                "source_snapshot_relative": f"{prefix}/room-source.json",
                "source_snapshot_digest": source_digest,
            }
        )
    value["attachmentData"]["slotRuntimeBindingDigest"] = canonical_digest(
        value["fixedProducerBindings"]["enabled"]
    )
    capsule = canonical(value)
    digest = sha(capsule)
    files = {
        f"kw/package/.kwrag/runtime-capsules/{digest.replace(':', '-')}.json": capsule,
        f"{prefix}/index-manifest.json": manifest,
        f"{prefix}/room.sqlite3": database + (b"tamper" if tamper else b""),
        f"{prefix}/room-source.json": source,
    }
    if extra:
        files[f"{prefix}/unexpected.txt"] = b"unexpected"
    directories = runtime_capsule._expected_directories(
        {name: sha(payload) for name, payload in files.items()}
    )
    archive_path = root / "capsule.tar"
    with tarfile.open(archive_path, "w") as archive:
        for name in sorted(directories, key=lambda item: (item.count("/"), item)):
            member = tarfile.TarInfo(name + "/")
            member.type = tarfile.DIRTYPE
            member.mode = 0o750
            archive.addfile(member)
        for name, payload in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o440
            archive.addfile(member, io.BytesIO(payload))
    archive_path.chmod(0o400)
    return archive_path, digest


@pytest.mark.parametrize("slot", ["oc14", "oc20", "dev-oc-img"])
def test_loads_exact_published_capsule(slot: str, tmp_path: Path) -> None:
    value = fixture(slot)
    digest = publish(tmp_path, value)
    loaded = load_runtime_capsule(slot, digest, nas_root=tmp_path)
    assert loaded.family == value["family"]
    assert loaded.positive_request["corpus"] == "room"
    assert loaded.attachment_data["slotRuntimeBindingDigest"]


def test_prepared_capsule_is_not_runtime_input(tmp_path: Path) -> None:
    digest = publish(tmp_path, fixture(status="prepared_not_published"))
    with pytest.raises(ValueError, match="publication state"):
        load_runtime_capsule("oc14", digest, nas_root=tmp_path)


def test_digest_and_binding_drift_fail_closed(tmp_path: Path) -> None:
    value = fixture()
    value["attachmentData"]["slotRuntimeBindingDigest"] = "sha256:" + "9" * 64
    digest = publish(tmp_path, value)
    with pytest.raises(ValueError, match="execution boundary"):
        load_runtime_capsule("oc14", digest, nas_root=tmp_path)
    path = (
        tmp_path
        / "kw/package/.kwrag/runtime-capsules"
        / f"{digest.replace(':', '-')}.json"
    )
    path.chmod(0o666)
    with pytest.raises(ValueError, match="unsafe"):
        load_runtime_capsule("oc14", digest, nas_root=tmp_path)


@pytest.mark.parametrize(
    "field", ["publicationReceiptDigest", "userIdDigest", "packageIdentityDigest"]
)
def test_publication_identity_digests_are_required(field: str, tmp_path: Path) -> None:
    value = fixture()
    value[field] = "not-a-digest"
    digest = publish(tmp_path, value)
    with pytest.raises(ValueError, match=field):
        load_runtime_capsule("oc14", digest, nas_root=tmp_path)


@pytest.mark.parametrize(
    ("slot", "private_names"),
    [
        ("oc14", ("proof-request.json", "negative-proof-request.json")),
        ("dev-oc-img", ("proof-request.json", "negative-proof-request.json")),
        ("oc20", ("request.json", "conversation-message.txt")),
    ],
)
def test_disabled_publication_removes_private_proof_inputs(
    slot: str,
    private_names: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capsule_root = tmp_path / "capsule"
    digest = publish(capsule_root, fixture(slot))
    capsule = load_runtime_capsule(slot, digest, nas_root=capsule_root)
    state_root = tmp_path / "state"
    state_root.mkdir()
    for name in private_names:
        (state_root / name).write_text("private", encoding="utf-8")
    writes: list[tuple[str, int]] = []
    chowns: list[tuple[Path, int, int]] = []

    def write_json(path: Path, value: object, mode: int = 0o600) -> None:
        writes.append((Path(path).name, mode))
        Path(path).write_bytes(canonical(value))

    monkeypatch.setattr(
        runtime_capsule, "retrieval_state_host_path", lambda desired: state_root
    )
    monkeypatch.setattr(
        runtime_capsule,
        "_ensure_directory",
        lambda path, mode: Path(path).mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(
        runtime_capsule,
        "_write_json",
        write_json,
    )
    monkeypatch.setattr(runtime_capsule, "runtime_ids", lambda slot: (1000, 1000, 1001))
    monkeypatch.setattr(
        runtime_capsule.os,
        "chown",
        lambda path, uid, gid: chowns.append((Path(path), uid, gid)),
        raising=False,
    )
    desired = SimpleNamespace(
        slot=slot,
        family=capsule.family,
        image_spec={"retrieval_binding": {"enabled": False, "attachmentData": None}},
    )
    publish_runtime_capsule_inputs(desired, capsule)
    assert all(not (state_root / name).exists() for name in private_names)
    assert writes and {mode for _, mode in writes} == {0o640}
    assert chowns == [(state_root, 0, 1000)]


def test_enabled_openclaw_publication_projects_distinct_private_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule_root = tmp_path / "capsule"
    digest = publish(capsule_root, fixture())
    capsule = load_runtime_capsule("oc14", digest, nas_root=capsule_root)
    state_root = tmp_path / "state"
    state_root.mkdir()
    writes: dict[str, object] = {}

    def write_json(path: Path, value: object, mode: int = 0o600) -> None:
        assert mode == 0o640
        writes[Path(path).name] = value

    monkeypatch.setattr(
        runtime_capsule, "retrieval_state_host_path", lambda desired: state_root
    )
    monkeypatch.setattr(
        runtime_capsule,
        "_ensure_directory",
        lambda path, mode: Path(path).mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(runtime_capsule, "_write_json", write_json)
    monkeypatch.setattr(runtime_capsule, "runtime_ids", lambda slot: (1000, 1000, 1001))
    monkeypatch.setattr(runtime_capsule.os, "chown", lambda *args: None, raising=False)
    desired = SimpleNamespace(
        slot="oc14",
        family="openclaw",
        image_spec={
            "retrieval_binding": {
                "enabled": True,
                "attachmentData": capsule.attachment_data,
            }
        },
    )
    publish_runtime_capsule_inputs(desired, capsule)
    assert writes["proof-request.json"] != writes["negative-proof-request.json"]
    assert writes["proof-request.json"]["query"] == capsule.positive_request["query"]
    assert (
        writes["negative-proof-request.json"]["query"]
        == capsule.negative_request["query"]
    )


def test_dev_capsule_archive_is_validated_and_published_without_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, digest = dev_archive(tmp_path)
    nas_root = tmp_path / "nas"
    nas_root.mkdir()
    monkeypatch.setattr(runtime_capsule, "runtime_ids", lambda slot: (1000, 1000, 0))
    monkeypatch.setattr(runtime_capsule.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(runtime_capsule.os, "fchown", lambda *args: None, raising=False)
    monkeypatch.setattr(runtime_capsule.os, "fchmod", lambda *args: None, raising=False)

    loaded = stage_dev_runtime_capsule(
        "dev-oc-img", digest, archive_path=archive, nas_root=nas_root
    )
    assert loaded.slot == "dev-oc-img"
    assert load_runtime_capsule("dev-oc-img", digest, nas_root=nas_root) == loaded

    # Exact replay is idempotent; an existing content-addressed file is not rewritten.
    capsule_path = (
        nas_root
        / "kw/package/.kwrag/runtime-capsules"
        / f"{digest.replace(':', '-')}.json"
    )
    before = capsule_path.stat().st_mtime_ns
    assert (
        stage_dev_runtime_capsule(
            "dev-oc-img", digest, archive_path=archive, nas_root=nas_root
        )
        == loaded
    )
    assert capsule_path.stat().st_mtime_ns == before


@pytest.mark.parametrize(
    ("extra", "tamper", "message"),
    [
        (True, False, "member set"),
        (False, True, "digest mismatch"),
    ],
)
def test_dev_capsule_archive_fails_before_publication(
    extra: bool,
    tamper: bool,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive, digest = dev_archive(tmp_path, extra=extra, tamper=tamper)
    nas_root = tmp_path / "nas"
    nas_root.mkdir()
    monkeypatch.setattr(runtime_capsule, "runtime_ids", lambda slot: (1000, 1000, 0))
    monkeypatch.setattr(runtime_capsule.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(runtime_capsule.os, "fchown", lambda *args: None, raising=False)
    monkeypatch.setattr(runtime_capsule.os, "fchmod", lambda *args: None, raising=False)
    with pytest.raises(ValueError, match=message):
        stage_dev_runtime_capsule(
            "dev-oc-img", digest, archive_path=archive, nas_root=nas_root
        )
    assert list(nas_root.iterdir()) == []


def test_capsule_staging_rejects_customer_target_before_archive_read() -> None:
    with pytest.raises(ValueError, match="dev-target-only"):
        stage_dev_runtime_capsule(
            "oc14",
            "sha256:" + "1" * 64,
            archive_path=Path("/does/not/exist"),
        )


def test_openclaw_probe_requires_zero_hit_control_and_full_receipt_chain() -> None:
    digest = "sha256:" + "8" * 64
    proof = {
        "schema": "jitech-openclaw-kwrag-user-turn-proof/v1",
        "enabled": True,
        "retrievalCount": 1,
        "projectionCount": 1,
        "dispatchCount": 1,
        "responseObservedCount": 1,
        "negativeControl": {
            "resultStatus": "zero_hits",
            "retrievalCount": 1,
            "projectionCount": 0,
            "dispatchCount": 0,
            "responseObservedCount": 0,
            "operationReceiptDigest": digest,
            "resultReceiptDigest": digest,
            "sourceExchangeDigest": digest,
        },
        "receipts": [
            {"stage": "evidence_dispatch_handoff_committed"},
            {"stage": "response_observed"},
        ],
    }

    def runner(argv, timeout):
        return SimpleNamespace(
            returncode=0, stdout=canonical(proof).decode(), stderr=""
        )

    assert run_openclaw_runtime_capsule_probe("oc14-container", runner=runner) == proof

    proof["negativeControl"]["dispatchCount"] = 1
    with pytest.raises(ValueError, match="negative control"):
        run_openclaw_runtime_capsule_probe("oc14-container", runner=runner)


def test_openclaw_probe_failure_preserves_redacted_machine_receipt() -> None:
    def runner(argv, timeout):
        if argv[3] == "stat":
            return SimpleNamespace(
                returncode=0,
                stdout="/run/kwrag/attachment-binding-v2.json|regular file|0|959|640|1|42\n",
                stderr="",
            )
        return SimpleNamespace(
            returncode=17,
            stdout="proof_status=failed\nrequest_id=req-1\n",
            stderr="password=do-not-print\nexact failure detail\n",
        )

    with pytest.raises(ValueError) as error:
        run_openclaw_runtime_capsule_probe("oc14-container", runner=runner)

    message = str(error.value)
    assert '"returncode":17' in message
    assert '"bindingMetadata":{"returncode":0' in message
    assert "attachment-binding-v2.json|regular file|0|959|640|1|42\\n" in message
    assert "proof_status=failed\\nrequest_id=req-1\\n" in message
    assert "password=<redacted>\\nexact failure detail\\n" in message
    assert "do-not-print" not in message
