from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable
import uuid

from ..host.files import fsync_parent
from ..routing import validate_linux_account
from .common import run_text
from .retrieval_contract import canonical_digest, parse_retrieval_status_output
from .retrieval_resources import measure_retrieval_promotion_headroom


CANARY_CORPUS = "jitech-hermes-p1-canary"
CANARY_DIR_NAME = ".jitech-kwrag-canary"
CONTAINER_NAS_ROOT = "/workspace/nas_docs"
CONTAINER_STATE_ROOT = "/opt/data/kwrag-p1-attachment"
P1_PIPELINE_FINGERPRINT = (
    "sha256:53e14752cc9d147dfb4129e00234d1c7fb9f6558df00da7c03189db8da8e4606"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROOF_KEYS = set(
    "schema operationReceiptDigest resultReceiptDigest consumptionReceiptDigest "
    "resultStatus resultCount".split()
)
_ATTESTATION_KEYS = set(
    "schema componentDigest runtimeBindingDigest indexManifestDigest resultStatus "
    "operationReceiptDigest resultReceiptDigest consumptionReceiptDigest "
    "providerAttemptId providerCallId providerAttemptBindingDigest "
    "providerAttemptOutcomeReceiptDigest evidenceProjectionStatus "
    "dispatchHandoffStatus transportOutcomeStatus providerAttestationStatus "
    "billingStatus".split()
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _database_bytes() -> bytes:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            "CREATE TABLE turns(turn_id INTEGER PRIMARY KEY, text TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE turn_mids(turn_id INTEGER NOT NULL, mid TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE VIRTUAL TABLE turns_fts USING fts5("
            "turn_id UNINDEXED, text, tokenize='trigram')"
        )
        text = "Jitech Hermes canary marker cobalt orchard reached verified storage."
        connection.execute("INSERT INTO turns VALUES (1, ?)", (text,))
        connection.execute(
            "INSERT INTO turn_mids VALUES (1, 'jitech-hermes-canary-message-1')"
        )
        connection.execute("INSERT INTO turns_fts VALUES (1, ?)", (text,))
        connection.commit()
        return connection.serialize()
    finally:
        connection.close()


@dataclass(frozen=True)
class HermesP1CanaryInputs:
    attachment_data: dict[str, object]
    database: bytes
    index_manifest: dict[str, object]
    read_only_authority: dict[str, object]
    runtime_binding: dict[str, object]
    negative_request: dict[str, object]
    positive_request: dict[str, object]
    conversation_message: bytes


def build_hermes_p1_canary_inputs(
    *,
    slot: str,
    instance_id: str,
) -> HermesP1CanaryInputs:
    validate_linux_account(slot)
    if not isinstance(instance_id, str) or not instance_id:
        raise ValueError("Hermes P1 canary instance identity is unavailable")
    database = _database_bytes()
    database_digest = "sha256:" + hashlib.sha256(database).hexdigest()
    request_identity = uuid.uuid4().hex
    source_snapshot = canonical_digest(
        {
            "schema": "jitech-hermes-p1-canary-snapshot/v1",
            "corpus": CANARY_CORPUS,
            "canaryRunId": request_identity,
            "recordCount": 1,
            "databaseSha256": database_digest,
        }
    )
    manifest = {
        "version": 1,
        "release_id": "jitech-hermes-p1-canary-v1",
        "corpus_snapshot": source_snapshot,
        "embedding_fingerprint": P1_PIPELINE_FINGERPRINT,
        "rooms": {
            CANARY_CORPUS: {
                "conversation_id": CANARY_CORPUS,
                "files": [{"path": "room.meta.sqlite", "sha256": database_digest}],
            }
        },
    }
    manifest_digest = canonical_digest(manifest)
    authority = {
        "schema": "jitech-hermes-p1-read-only-authority/v1",
        "instanceId": instance_id,
        "hostPath": f"/home/{slot}/nas_docs",
        "containerPath": CONTAINER_NAS_ROOT,
        "requiredReadOnly": True,
    }
    runtime_binding = {
        "schema_version": "kwrag-slot-runtime-binding-v1",
        "mount_root": CONTAINER_NAS_ROOT,
        "index_manifest_relative": (
            f"{CANARY_DIR_NAME}/{source_snapshot.removeprefix('sha256:')}/manifest.json"
        ),
        "index_manifest_digest": manifest_digest,
        "receipt_path": f"{CONTAINER_STATE_ROOT}/operation-receipts.jsonl",
        "pipeline_fingerprint": P1_PIPELINE_FINGERPRINT,
        "max_concurrent": 1,
    }
    runtime_digest = canonical_digest(runtime_binding)

    def request(query: str, suffix: str) -> dict[str, object]:
        return {
            "schema_version": "kwrag-slot-search-request-v1",
            "query": query,
            "request_id": f"hermes-p1-{suffix}-{request_identity}",
            "operation_id": f"hermes-p1-{suffix}-{request_identity}",
            "run_id": f"hermes-p1-{suffix}-{request_identity}",
            "attempt": 1,
            "max_results": 5,
            "corpus": CANARY_CORPUS,
        }

    return HermesP1CanaryInputs(
        attachment_data={
            "databaseSha256": database_digest,
            "indexManifestDigest": manifest_digest,
            "sourceSnapshotDigest": source_snapshot,
            "readOnlyAuthorityReceiptDigest": canonical_digest(authority),
            "slotRuntimeBindingDigest": runtime_digest,
        },
        database=database,
        index_manifest=manifest,
        read_only_authority=authority,
        runtime_binding=runtime_binding,
        negative_request=request("violet glacier token is absent", "negative"),
        positive_request=request("cobalt orchard verified storage", "positive"),
        conversation_message=(
            b"Using only the attached verified evidence, confirm the Hermes canary marker."
        ),
    )


def _require_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"Hermes P1 managed directory is unavailable: {path}")


def _ensure_directory(path: Path, *, mode: int) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ValueError(f"Hermes P1 managed directory is unsafe: {path}")
    path.mkdir(mode=mode, exist_ok=True)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def _host_state_root(desired) -> Path:
    digest = str(desired.image_spec.get("retrieval_binding_digest") or "")
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Hermes P1 binding digest is invalid")
    return Path(
        f"/home/{validate_linux_account(desired.slot)}/.hermes/agent-runtime/"
        f"kwrag-p1-state/{digest}"
    )


def _atomic_write_bytes(path: Path, payload: bytes, *, mode: int) -> None:
    _require_directory(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Hermes P1 managed file is unsafe: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        fsync_parent(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _write_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    _atomic_write_bytes(path, _canonical_bytes(value), mode=mode)


def publish_hermes_p1_runtime_inputs(
    desired,
    prepared: HermesP1CanaryInputs | None,
) -> None:
    if os.name != "posix":
        raise ValueError("Hermes P1 runtime input publication requires POSIX")
    binding = desired.image_spec.get("retrieval_binding")
    if not isinstance(binding, dict) or binding.get("family") != "hermes":
        raise ValueError("Hermes P1 binding-v2 is unavailable")
    enabled = binding.get("enabled") is True
    if enabled != (prepared is not None):
        raise ValueError("Hermes P1 prepared input does not match enabled intent")
    if (
        prepared is not None
        and binding.get("attachmentData") != prepared.attachment_data
    ):
        raise ValueError("Hermes P1 attachment data changed before publication")
    slot = validate_linux_account(desired.slot)
    home = Path("/home") / slot
    hermes_home = home / ".hermes"
    nas_root = home / "nas_docs"
    _require_directory(home)
    _require_directory(hermes_home)
    _require_directory(nas_root)
    state_parent = hermes_home / "agent-runtime" / "kwrag-p1-state"
    _require_directory(state_parent.parent)
    _ensure_directory(state_parent, mode=0o700)
    state_root = _host_state_root(desired)
    _ensure_directory(state_root, mode=0o700)
    _write_json(state_root / "binding-v2.json", binding)
    if prepared is None:
        return
    source_snapshot = str(prepared.attachment_data["sourceSnapshotDigest"])
    if not _DIGEST.fullmatch(source_snapshot):
        raise ValueError("Hermes P1 source snapshot digest is invalid")
    canary_parent = nas_root / CANARY_DIR_NAME
    _ensure_directory(canary_parent, mode=0o755)
    canary_root = canary_parent / source_snapshot.removeprefix("sha256:")
    _ensure_directory(canary_root, mode=0o755)
    _atomic_write_bytes(canary_root / "room.meta.sqlite", prepared.database, mode=0o444)
    _write_json(canary_root / "manifest.json", prepared.index_manifest, mode=0o444)
    _write_json(state_root / "runtime-binding.json", prepared.runtime_binding)
    _write_json(state_root / "read-only-authority.json", prepared.read_only_authority)
    _write_json(state_root / "request.json", prepared.negative_request)
    _atomic_write_bytes(
        state_root / "conversation-message.txt",
        prepared.conversation_message,
        mode=0o600,
    )


def _container_runtime_identity(
    container: str,
    *,
    runner: Callable[..., object] = run_text,
) -> dict[str, str]:
    script = (
        "import hashlib,json,pathlib,socket;"
        "c=pathlib.Path('/proc/self/cgroup').read_bytes();"
        "v={'cgroupIdentityDigest':'sha256:'+hashlib.sha256(c).hexdigest(),"
        "'containerIdentityDigest':'sha256:'+hashlib.sha256(socket.gethostname().encode()).hexdigest()};"
        "print(json.dumps(v,sort_keys=True,separators=(',',':')))"
    )
    result = runner(["docker", "exec", container, "python", "-c", script], timeout=15)
    if result.returncode != 0:
        raise ValueError("Hermes P1 container identity observation failed")
    value = parse_retrieval_status_output(result.stdout)
    if (
        not isinstance(value, dict)
        or set(value) != {"containerIdentityDigest", "cgroupIdentityDigest"}
        or any(not _DIGEST.fullmatch(str(item)) for item in value.values())
    ):
        raise ValueError("Hermes P1 container identity observation is invalid")
    return {key: str(item) for key, item in value.items()}


def _write_resource_observation(
    container: str,
    desired,
    *,
    runner: Callable[..., object] = run_text,
    headroom_observer: Callable[
        ..., dict[str, object]
    ] = measure_retrieval_promotion_headroom,
) -> dict[str, object]:
    observation = dict(headroom_observer(container, desired.image_spec, runner=runner))
    observation.pop("observationDigest", None)
    observation.update(
        _container_runtime_identity(container, runner=runner),
        observedAt=datetime.now(timezone.utc).isoformat(),
        targetInstanceId=desired.route.instance_id,
        ttlSeconds=300,
    )
    observation["observationDigest"] = canonical_digest(observation)
    _write_json(
        _host_state_root(desired) / "resource-observation.json",
        observation,
    )
    return observation


def _run_product_probe(
    container: str,
    *,
    conversation: bool,
    runner: Callable[..., object] = run_text,
) -> dict[str, object]:
    command = [
        "docker",
        "exec",
        container,
        "hermes",
        "kwrag-slot",
        "p1-attachment-probe",
        "--runtime-binding",
        f"{CONTAINER_STATE_ROOT}/runtime-binding.json",
        "--p1-binding",
        f"{CONTAINER_STATE_ROOT}/binding-v2.json",
        "--resource-observation",
        f"{CONTAINER_STATE_ROOT}/resource-observation.json",
        "--request",
        f"{CONTAINER_STATE_ROOT}/request.json",
    ]
    if conversation:
        command.extend(
            [
                "--conversation-message-file",
                f"{CONTAINER_STATE_ROOT}/conversation-message.txt",
            ]
        )
    command.append("--json")
    result = runner(command, timeout=240)
    if result.returncode != 0:
        raise ValueError("Hermes P1 product probe failed")
    value = parse_retrieval_status_output(result.stdout)
    expected_keys = _PROOF_KEYS | (
        {"conversationAttestation"} if conversation else set()
    )
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("Hermes P1 product probe shape is invalid")
    return value


def _validate_positive_proof(
    value: dict[str, object],
    *,
    desired,
    prepared: HermesP1CanaryInputs,
) -> None:
    attestation = value.get("conversationAttestation")
    expected = {
        "schema": "jitech-hermes-kwrag-consumption-attestation/v1",
        "componentDigest": desired.image_spec["retrieval_binding"]["componentDigest"],
        "runtimeBindingDigest": prepared.attachment_data["slotRuntimeBindingDigest"],
        "indexManifestDigest": prepared.attachment_data["indexManifestDigest"],
        "resultStatus": "hits",
        "operationReceiptDigest": value.get("operationReceiptDigest"),
        "resultReceiptDigest": value.get("resultReceiptDigest"),
        "providerAttemptId": 1,
        "evidenceProjectionStatus": "verified_hits",
        "dispatchHandoffStatus": "evidence_dispatch_handoff_committed",
        "transportOutcomeStatus": "response_observed",
        "providerAttestationStatus": "unavailable",
        "billingStatus": "unavailable",
    }
    if (
        value.get("schema") != "jitech-hermes-kwrag-p1-attachment-proof/v1"
        or value.get("resultStatus") != "hits"
        or not isinstance(value.get("resultCount"), int)
        or isinstance(value.get("resultCount"), bool)
        or int(value["resultCount"]) < 1
        or not isinstance(attestation, dict)
        or set(attestation) != _ATTESTATION_KEYS
        or any(attestation.get(key) != item for key, item in expected.items())
        or not isinstance(attestation.get("providerCallId"), str)
        or not attestation.get("providerCallId")
    ):
        raise ValueError("Hermes P1 conversation attestation is invalid")
    for field in (
        "operationReceiptDigest",
        "resultReceiptDigest",
        "consumptionReceiptDigest",
        "providerAttemptBindingDigest",
        "providerAttemptOutcomeReceiptDigest",
    ):
        candidate = (
            attestation.get(field) if field.startswith("provider") else value.get(field)
        )
        if not _DIGEST.fullmatch(str(candidate or "")):
            raise ValueError(f"Hermes P1 {field} is invalid")
    if not _DIGEST.fullmatch(str(attestation.get("consumptionReceiptDigest") or "")):
        raise ValueError("Hermes P1 conversation consumption receipt is invalid")


def _tamper_control(
    container: str,
    desired,
    *,
    runner: Callable[..., object] = run_text,
) -> None:
    binding_path = _host_state_root(desired) / "binding-v2.json"
    binding = desired.image_spec["retrieval_binding"]
    original = _canonical_bytes(binding)
    tampered = dict(binding)
    tampered["componentDigest"] = "sha256:" + "0" * 64
    try:
        _atomic_write_bytes(binding_path, _canonical_bytes(tampered), mode=0o600)
        result = runner(
            [
                "docker",
                "exec",
                container,
                "hermes",
                "kwrag-slot",
                "p1-attachment-status",
                "--json",
            ],
            timeout=30,
        )
        if result.returncode == 0:
            raise ValueError("Hermes P1 tampered binding was accepted")
    finally:
        _atomic_write_bytes(binding_path, original, mode=0o600)


def run_hermes_p1_canary_probe(
    container: str,
    desired,
    prepared: HermesP1CanaryInputs,
    *,
    runner: Callable[..., object] = run_text,
    headroom_observer: Callable[
        ..., dict[str, object]
    ] = measure_retrieval_promotion_headroom,
) -> dict[str, object]:
    if desired.image_spec.get("retrieval_enabled") is not True:
        raise ValueError("Hermes P1 canary probe requires enabled intent")
    _write_resource_observation(
        container,
        desired,
        runner=runner,
        headroom_observer=headroom_observer,
    )
    state_root = _host_state_root(desired)
    _write_json(state_root / "request.json", prepared.negative_request)
    negative = _run_product_probe(container, conversation=False, runner=runner)
    if negative.get("resultStatus") != "zero_hits" or negative.get("resultCount") != 0:
        raise ValueError("Hermes P1 negative control did not remain zero-hit")
    _write_json(state_root / "request.json", prepared.positive_request)
    positive = _run_product_probe(container, conversation=True, runner=runner)
    _validate_positive_proof(positive, desired=desired, prepared=prepared)
    _tamper_control(container, desired, runner=runner)
    proof = {
        "schema": "agent-runtime-hermes-p1-canary-proof/v1",
        "negative": {
            key: negative[key]
            for key in (
                "operationReceiptDigest",
                "resultReceiptDigest",
                "consumptionReceiptDigest",
                "resultStatus",
                "resultCount",
            )
        },
        "positive": positive,
        "tamperStatus": "rejected",
    }
    _write_json(state_root / "canary-proof.json", proof)
    return proof
