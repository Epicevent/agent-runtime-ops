from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import stat
import tarfile
import tempfile
from typing import Any

from ..host.account_files import runtime_ids
from ..redaction import redact
from ..routing import validate_linux_account
from .common import run_text
from .hermes_p1_canary import (
    HermesP1CanaryInputs,
    _atomic_write_bytes,
    _ensure_directory,
    _write_json,
)
from .retrieval_contract import (
    P1_IDENTITY_FIXED,
    _canonical_bytes,
    _digest,
    canonical_digest,
    digest_path_component,
    parse_retrieval_status_output,
)


CAPSULE_SCHEMA = "kwrag-two-canary-runtime-capsule/v1"
_ROOTS = {"openclaw": "/home/node/nas_docs", "hermes": "/workspace/nas_docs"}
_FAMILIES = {
    "oc14": "openclaw",
    "oc20": "hermes",
    "dev-oc-img": "openclaw",
}
_ENGINE = {
    "status": "research_selected_p1_attachment_probe_candidate",
    "backend_id": "slot-local-fts5-trigram-or-attachment-v1",
    "factory_source_digest": "sha256:104276b46fa427d741fcf63db87b70d9a6d8a2ad32e63c4a43e87692041ed43e",
    "contract_source_digest": "sha256:46dbce894e5987fb47598b26d0c29bf3c13c297f705a17c313d550cc6dbc844a",
    "research_decision_source_digest": "sha256:2245278aa9ad4e16ad8502287a0e10340c90a83fa93a2e26210c8f43c6f8f5e1",
    "pipeline_factory_digest": P1_IDENTITY_FIXED["pipelineFactoryDigest"],
    "pipeline_fingerprint": P1_IDENTITY_FIXED["pipelineFingerprint"],
    "research_decision_digest": P1_IDENTITY_FIXED["researchDecisionDigest"],
}
_TOP = frozenset(
    "schema status slot family publicationReceiptDigest userIdDigest packageIdentityDigest releaseId indexManifestDigest authorityReceipt authorityReceiptState attachmentData fixedProducerBindings productRuntimeBinding privateProofRequests contentPolicy".split()
)
_ATTACHMENT = frozenset(
    "databaseSha256 indexManifestDigest sourceSnapshotDigest readOnlyAuthorityReceiptDigest slotRuntimeBindingDigest".split()
)
_DEV_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024
_DEV_ARCHIVE_MAX_MEMBERS = 32
_DEV_ARCHIVE_MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class KwragRuntimeCapsule:
    digest: str
    slot: str
    family: str
    attachment_data: dict[str, object]
    authority_receipt: dict[str, object]
    disabled_binding: dict[str, object]
    enabled_binding: dict[str, object]
    product_runtime_binding: dict[str, object] | None
    positive_request: dict[str, str]
    negative_request: dict[str, str]


@dataclass(frozen=True)
class PreparedDevRuntimeCapsule:
    capsule: KwragRuntimeCapsule
    files: dict[str, bytes]
    expected: dict[str, str]


def _object(
    value: object, keys: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"runtime capsule {label} has unexpected fields")
    return value


def _match(value: dict[str, Any], expected: dict[str, object], label: str) -> None:
    if any(value.get(key) != item for key, item in expected.items()):
        raise ValueError(f"runtime capsule {label} is invalid")


def _read_exact(path: Path, digest: str) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 256 * 1024
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise ValueError("runtime capsule file identity is unsafe")
        chunks, remaining = [], before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("runtime capsule changed while reading")
    finally:
        os.close(descriptor)
    if "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("runtime capsule digest mismatch")
    return payload


def _strict_json(payload: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("runtime capsule has duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode(),
            object_pairs_hook=pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime capsule JSON is invalid") from exc
    if _canonical_bytes(value) != payload:
        raise ValueError("runtime capsule JSON is not canonical")
    return _object(value, _TOP, "root")


def _fixed_binding(
    value: object, *, enabled: bool, family: str, manifest: str
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("runtime capsule fixed producer binding is invalid")
    binding = value
    _match(
        binding,
        {
            "schema_version": "kwrag-fixed-producer-binding-v1",
            "enabled": enabled,
            "mount_root": _ROOTS[family],
            "index_manifest_digest": manifest,
            "selected_engine": _ENGINE,
            "max_concurrent": 1,
        },
        "fixed producer binding",
    )
    corpora = binding.get("corpora")
    if not isinstance(corpora, dict) or not 1 <= len(corpora) <= 512:
        raise ValueError("runtime capsule corpus set is invalid")
    return dict(binding)


def load_runtime_capsule(
    slot: str, digest: str, *, nas_root: Path | None = None
) -> KwragRuntimeCapsule:
    root = nas_root or Path("/home") / validate_linux_account(slot) / "nas_docs"
    name = f"{_digest(digest, 'digest').replace(':', '-')}.json"
    value = _strict_json(
        _read_exact(root / "kw/package/.kwrag/runtime-capsules" / name, digest)
    )
    family = _FAMILIES.get(slot)
    _match(
        value,
        {
            "schema": CAPSULE_SCHEMA,
            "status": "published_ready",
            "slot": slot,
            "family": family,
        },
        "target or publication state",
    )
    for field in "publicationReceiptDigest userIdDigest packageIdentityDigest releaseId indexManifestDigest".split():
        _digest(value.get(field), field)
    release, manifest = str(value["releaseId"]), str(value["indexManifestDigest"])
    authority = value.get("authorityReceipt")
    expected_authority = {
        "schema": "kwrag-read-only-authority-receipt/v1",
        "status": "observed",
        "slot": slot,
        "family": family,
        "containerNasRoot": _ROOTS[family],
        "releaseRelativeRoot": f"kw/package/.kwrag/releases/{release.replace(':', '-')}",
        "indexManifestDigest": manifest,
        "mountReadOnly": True,
        "allBoundFilesReadOnly": True,
    }
    if value.get("authorityReceiptState") != "expected_not_observed":
        raise ValueError("runtime capsule authority expectation is invalid")
    if authority != expected_authority:
        raise ValueError("runtime capsule authority expectation is invalid")
    assert isinstance(authority, dict)
    authority_digest = canonical_digest(authority)
    attachment = _object(value.get("attachmentData"), _ATTACHMENT, "attachment data")
    for field in _ATTACHMENT:
        _digest(attachment.get(field), field)
    if (
        attachment.get("indexManifestDigest") != manifest
        or attachment.get("readOnlyAuthorityReceiptDigest") != authority_digest
    ):
        raise ValueError("runtime capsule attachment identity mismatch")
    binding_set = _object(
        value.get("fixedProducerBindings"), {"disabled", "enabled"}, "binding set"
    )
    enabled = _fixed_binding(
        binding_set["enabled"], enabled=True, family=family, manifest=manifest
    )
    disabled = binding_set["disabled"]
    if disabled != {**enabled, "enabled": False}:
        raise ValueError("runtime capsule disabled producer binding drifted")
    requests = _object(
        value.get("privateProofRequests"), {"negative", "positive"}, "proof requests"
    )
    parsed: dict[str, dict[str, str]] = {}
    for name in ("positive", "negative"):
        request = _object(
            requests[name], {"corpus", "query", "schema"}, f"{name} proof request"
        )
        if (
            request.get("schema") != "kwrag-two-canary-private-proof-request/v1"
            or request.get("corpus") not in enabled["corpora"]
            or not isinstance(request.get("query"), str)
            or not request["query"].strip()
            or len(request["query"]) > 4_000
        ):
            raise ValueError("runtime capsule proof request is invalid")
        parsed[name] = {
            "corpus": str(request["corpus"]),
            "query": str(request["query"]),
        }
    if parsed["positive"] == parsed["negative"]:
        raise ValueError("runtime capsule proof controls are not distinct")
    runtime = value.get("productRuntimeBinding")
    expected_binding_digest = canonical_digest(enabled)
    if family == "hermes":
        if not isinstance(runtime, dict):
            raise ValueError("runtime capsule product runtime binding is invalid")
        _match(
            runtime,
            {
                "schema_version": "kwrag-slot-runtime-binding-v1",
                "mount_root": _ROOTS[family],
                "index_manifest_digest": manifest,
                "pipeline_fingerprint": P1_IDENTITY_FIXED["pipelineFingerprint"],
                "max_concurrent": 1,
            },
            "product runtime binding",
        )
        expected_binding_digest = canonical_digest(runtime)
    elif runtime is not None:
        raise ValueError("OpenClaw capsule must use the fixed producer binding")
    policy = {
        "privateMode": "capsule-0600/runtime-0640-root-runtime-group",
        "queryInArgv": False,
        "rawQueryInReceipt": False,
        "rawResultInReceipt": False,
    }
    if (
        attachment.get("slotRuntimeBindingDigest") != expected_binding_digest
        or value.get("contentPolicy") != policy
    ):
        raise ValueError("runtime capsule execution boundary is invalid")
    return KwragRuntimeCapsule(
        digest,
        slot,
        family,
        dict(attachment),
        dict(authority),
        disabled,
        enabled,
        dict(runtime) if isinstance(runtime, dict) else None,
        parsed["positive"],
        parsed["negative"],
    )


def dev_runtime_capsule_archive_path(digest: str) -> Path:
    component = _digest(digest, "digest").replace(":", "-")
    return Path("/tmp") / f"kwrag-runtime-capsule-{component}.tar"


def _safe_archive_member(name: str) -> str:
    if not name or "\\" in name or name.startswith("/"):
        raise ValueError("runtime capsule archive member path is unsafe")
    normalized = name.removesuffix("/")
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("runtime capsule archive member path is unsafe")
    return normalized


def _read_dev_capsule_archive(path: Path) -> tuple[dict[str, bytes], set[str]]:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        identity = os.fstat(descriptor)
        sudo_uid = int(os.environ.get("SUDO_UID", "0") or "0")
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_nlink != 1
            or identity.st_uid not in {0, sudo_uid}
            or identity.st_size <= 0
            or identity.st_size > _DEV_ARCHIVE_MAX_BYTES
            or (os.name != "nt" and stat.S_IMODE(identity.st_mode) & 0o077)
        ):
            raise ValueError("runtime capsule archive identity is unsafe")
        files: dict[str, bytes] = {}
        directories: set[str] = set()
        total = 0
        with (
            os.fdopen(os.dup(descriptor), "rb") as source,
            tarfile.open(fileobj=source, mode="r:") as archive,
        ):
            for index, member in enumerate(archive, start=1):
                if index > _DEV_ARCHIVE_MAX_MEMBERS:
                    raise ValueError("runtime capsule archive has too many members")
                name = _safe_archive_member(member.name)
                if name in files or name in directories:
                    raise ValueError("runtime capsule archive has duplicate members")
                if member.isdir():
                    directories.add(name)
                    continue
                if (
                    not member.isreg()
                    or member.size < 0
                    or member.size > _DEV_ARCHIVE_MAX_FILE_BYTES
                ):
                    raise ValueError(
                        "runtime capsule archive member type or size is unsafe"
                    )
                total += member.size
                if total > _DEV_ARCHIVE_MAX_BYTES:
                    raise ValueError("runtime capsule archive payload is too large")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("runtime capsule archive member is unreadable")
                payload = stream.read(member.size + 1)
                if len(payload) != member.size:
                    raise ValueError(
                        "runtime capsule archive member changed while reading"
                    )
                files[name] = payload
        after = os.fstat(descriptor)
        if (
            identity.st_dev,
            identity.st_ino,
            identity.st_size,
            identity.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("runtime capsule archive changed while reading")
        return files, directories
    finally:
        os.close(descriptor)


def _archive_expected_files(
    capsule: KwragRuntimeCapsule,
) -> dict[str, str]:
    capsule_path = (
        f"kw/package/.kwrag/runtime-capsules/{capsule.digest.replace(':', '-')}.json"
    )
    release_root = str(capsule.authority_receipt["releaseRelativeRoot"])
    binding = capsule.enabled_binding
    expected = {
        capsule_path: capsule.digest,
        str(binding["index_manifest_relative"]): str(binding["index_manifest_digest"]),
    }
    corpora = binding["corpora"]
    assert isinstance(corpora, dict)
    for corpus in corpora.values():
        assert isinstance(corpus, dict)
        expected[str(corpus["database_relative"])] = str(corpus["database_sha256"])
        expected[str(corpus["source_snapshot_relative"])] = str(
            corpus["source_snapshot_digest"]
        )
    for name in expected:
        if name != capsule_path and not name.startswith(release_root + "/"):
            raise ValueError("runtime capsule archive file escaped its release root")
        _safe_archive_member(name)
    return expected


def _expected_directories(files: dict[str, str]) -> set[str]:
    result: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _write_archive_fixture_root(
    root: Path, files: dict[str, bytes], directories: set[str]
) -> None:
    for name in sorted(directories, key=lambda item: (item.count("/"), item)):
        path = root.joinpath(*PurePosixPath(name).parts)
        path.mkdir(mode=0o750)
    for name, payload in files.items():
        path = root.joinpath(*PurePosixPath(name).parts)
        path.write_bytes(payload)
        path.chmod(0o440)


def _verify_file_set(root: Path, expected: dict[str, str]) -> None:
    for name, digest in expected.items():
        _read_exact(root.joinpath(*PurePosixPath(name).parts), digest)


def _publish_dev_capsule_files(
    slot: str,
    files: dict[str, bytes],
    expected: dict[str, str],
    *,
    nas_root: Path | None = None,
) -> None:
    root = nas_root or Path("/home") / validate_linux_account(slot) / "nas_docs"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("runtime capsule NAS root is unsafe")
    _, _, data_gid = runtime_ids(slot)
    capsule_name = next(name for name in expected if "/runtime-capsules/" in name)
    release_name = str(
        PurePosixPath(next(name for name in expected if name != capsule_name)).parts[4]
    )
    release_parent = root / "kw/package/.kwrag/releases"
    release_target = release_parent / release_name
    capsule_parent = root / "kw/package/.kwrag/runtime-capsules"
    capsule_target = root.joinpath(*PurePosixPath(capsule_name).parts)

    for directory in (
        root / "kw",
        root / "kw/package",
        root / "kw/package/.kwrag",
        release_parent,
        capsule_parent,
    ):
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("runtime capsule publication path is unsafe")
            identity = directory.stat()
            if (
                identity.st_uid != 0
                or identity.st_gid != data_gid
                or (os.name != "nt" and stat.S_IMODE(identity.st_mode) != 0o750)
            ):
                raise ValueError("runtime capsule publication ownership drifted")
        else:
            directory.mkdir(mode=0o750)
            os.chown(directory, 0, data_gid)
            directory.chmod(0o750)

    release_expected = {
        name: digest
        for name, digest in expected.items()
        if name.startswith(f"kw/package/.kwrag/releases/{release_name}/")
    }
    if release_target.exists():
        if release_target.is_symlink() or not release_target.is_dir():
            raise ValueError("runtime capsule release target is unsafe")
        _verify_file_set(root, release_expected)
        names = []
        with os.scandir(release_target) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > len(release_expected):
                    raise ValueError("runtime capsule release has unexpected files")
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError("runtime capsule release member is unsafe")
        if set(names) != {PurePosixPath(name).name for name in release_expected}:
            raise ValueError("runtime capsule release member set drifted")
    else:
        stage = Path(
            tempfile.mkdtemp(prefix=f".staging-{release_name}-", dir=release_parent)
        )
        created_release = False
        try:
            os.chown(stage, 0, data_gid)
            stage.chmod(0o750)
            prefix = f"kw/package/.kwrag/releases/{release_name}/"
            for name in sorted(release_expected):
                relative = name.removeprefix(prefix)
                if "/" in relative:
                    raise ValueError("runtime capsule release nesting is unsupported")
                target = stage / relative
                target.write_bytes(files[name])
                os.chown(target, 0, data_gid)
                target.chmod(0o440)
            os.rename(stage, release_target)
            created_release = True
            _verify_file_set(root, release_expected)
        except Exception:
            if stage.exists():
                shutil.rmtree(stage)
            if (
                created_release
                and release_target.exists()
                and not capsule_target.exists()
            ):
                shutil.rmtree(release_target)
            raise

    if capsule_target.exists():
        _verify_file_set(root, {capsule_name: expected[capsule_name]})
        return
    temporary = capsule_parent / f".{capsule_target.name}.{os.getpid()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o640,
        )
        try:
            payload = memoryview(files[capsule_name])
            while payload:
                written = os.write(descriptor, payload)
                if written <= 0:
                    raise ValueError("runtime capsule publication write failed")
                payload = payload[written:]
            os.fsync(descriptor)
            os.fchown(descriptor, 0, data_gid)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o440)
        finally:
            os.close(descriptor)
        temporary.chmod(0o440)
        if os.name == "nt":
            os.rename(temporary, capsule_target)
        else:
            os.link(temporary, capsule_target)
    finally:
        temporary.unlink(missing_ok=True)
    _verify_file_set(root, expected)


def prepare_dev_runtime_capsule(
    slot: str,
    digest: str,
    *,
    archive_path: Path | None = None,
) -> PreparedDevRuntimeCapsule:
    if not slot.startswith("dev-"):
        raise ValueError("runtime capsule staging is dev-target-only")
    archive = archive_path or dev_runtime_capsule_archive_path(digest)
    files, directories = _read_dev_capsule_archive(archive)
    with tempfile.TemporaryDirectory(
        prefix="agent-runtime-kwrag-capsule-"
    ) as temporary:
        root = Path(temporary)
        _write_archive_fixture_root(root, files, directories)
        capsule = load_runtime_capsule(slot, digest, nas_root=root)
        expected = _archive_expected_files(capsule)
        if set(files) != set(expected) or directories != _expected_directories(
            expected
        ):
            raise ValueError("runtime capsule archive member set is invalid")
        _verify_file_set(root, expected)
    return PreparedDevRuntimeCapsule(capsule, files, expected)


def publish_prepared_dev_runtime_capsule(
    slot: str,
    prepared: PreparedDevRuntimeCapsule,
    *,
    nas_root: Path | None = None,
) -> KwragRuntimeCapsule:
    if prepared.capsule.slot != slot or not slot.startswith("dev-"):
        raise ValueError("prepared runtime capsule target drifted")
    _publish_dev_capsule_files(
        slot, prepared.files, prepared.expected, nas_root=nas_root
    )
    return load_runtime_capsule(slot, prepared.capsule.digest, nas_root=nas_root)


def stage_dev_runtime_capsule(
    slot: str,
    digest: str,
    *,
    archive_path: Path | None = None,
    nas_root: Path | None = None,
) -> KwragRuntimeCapsule:
    prepared = prepare_dev_runtime_capsule(slot, digest, archive_path=archive_path)
    return publish_prepared_dev_runtime_capsule(slot, prepared, nas_root=nas_root)


def retrieval_state_host_path(desired) -> Path:
    hidden = {"openclaw": ".openclaw", "hermes": ".hermes"}.get(
        str(desired.family or "")
    )
    if hidden is None:
        raise ValueError("runtime capsule family is unsupported")
    digest = digest_path_component(desired.image_spec.get("retrieval_binding_digest"))
    return (
        Path("/home")
        / validate_linux_account(desired.slot)
        / hidden
        / "agent-runtime/kwrag-p1-state"
        / digest
    )


def _slot_request(capsule: KwragRuntimeCapsule, positive: bool) -> dict[str, object]:
    kind = "positive" if positive else "negative"
    source = capsule.positive_request if positive else capsule.negative_request
    identity = capsule.digest.removeprefix("sha256:")[:20]
    return {
        "schema_version": "kwrag-slot-search-request-v1",
        "query": source["query"],
        "request_id": f"{capsule.slot}-p1-{kind}-{identity}",
        "operation_id": f"{capsule.slot}-p1-{kind}-{identity}",
        "run_id": f"{capsule.slot}-p1-{kind}-{identity}",
        "attempt": 1,
        "max_results": 5,
        "corpus": source["corpus"],
    }


def publish_runtime_capsule_inputs(desired, capsule: KwragRuntimeCapsule) -> Path:
    binding = desired.image_spec.get("retrieval_binding")
    if (
        not isinstance(binding, dict)
        or desired.slot != capsule.slot
        or desired.family != capsule.family
    ):
        raise ValueError("runtime capsule does not match the desired target")
    enabled = binding.get("enabled") is True
    if binding.get("attachmentData") != (capsule.attachment_data if enabled else None):
        raise ValueError("runtime capsule attachment data changed before publication")
    root = retrieval_state_host_path(desired)
    for path in (root.parent.parent, root.parent, root):
        _ensure_directory(path, mode=0o700)
    _, runtime_gid, _ = runtime_ids(desired.slot)
    os.chown(root, 0, runtime_gid)
    os.chmod(root, 0o750)
    _write_json(root / "binding-v2.json", binding, mode=0o640)
    if capsule.family == "openclaw":
        _write_json(
            root / "fixed-producer-binding.json",
            capsule.enabled_binding if enabled else capsule.disabled_binding,
            mode=0o640,
        )
        if enabled:
            for name, request in (
                ("proof-request.json", capsule.positive_request),
                ("negative-proof-request.json", capsule.negative_request),
            ):
                _write_json(
                    root / name,
                    {"schema": "kwrag-two-canary-private-proof-request/v1", **request},
                    mode=0o640,
                )
        else:
            for name in ("proof-request.json", "negative-proof-request.json"):
                (root / name).unlink(missing_ok=True)
    else:
        if capsule.product_runtime_binding is None:
            raise ValueError("Hermes runtime capsule is missing its product binding")
        _write_json(
            root / "runtime-binding.json", capsule.product_runtime_binding, mode=0o640
        )
        if enabled:
            _write_json(
                root / "request.json", _slot_request(capsule, False), mode=0o640
            )
            _atomic_write_bytes(
                root / "conversation-message.txt",
                b"Use only the attached verified evidence for this bounded canary turn.",
                mode=0o640,
            )
        else:
            for name in ("request.json", "conversation-message.txt"):
                (root / name).unlink(missing_ok=True)
    return root


def publish_runtime_capsule_authority(desired, capsule: KwragRuntimeCapsule) -> None:
    _write_json(
        retrieval_state_host_path(desired) / "read-only-authority.json",
        capsule.authority_receipt,
        mode=0o640,
    )


def run_openclaw_runtime_capsule_probe(
    container: str, *, runner=run_text
) -> dict[str, object]:
    result = runner(
        [
            "docker",
            "exec",
            container,
            "openclaw",
            "kwrag-p0",
            "p1-user-turn-proof",
            "--json",
        ],
        timeout=300,
    )
    if result.returncode != 0:
        receipt = json.dumps(
            {
                "returncode": result.returncode,
                "stderr": redact(result.stderr or ""),
                "stdout": redact(result.stdout or ""),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        raise ValueError(f"OpenClaw runtime capsule proof failed: {receipt}")
    value = parse_retrieval_status_output(result.stdout)
    keys = frozenset(
        "schema enabled retrievalCount projectionCount dispatchCount responseObservedCount negativeControl receipts".split()
    )
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("OpenClaw runtime capsule proof is incomplete")
    _match(
        value,
        {
            "schema": "jitech-openclaw-kwrag-user-turn-proof/v1",
            "enabled": True,
            "retrievalCount": 1,
            "projectionCount": 1,
            "dispatchCount": 1,
            "responseObservedCount": 1,
        },
        "OpenClaw proof",
    )
    receipts = value.get("receipts")
    if not isinstance(receipts, list) or [
        item.get("stage") if isinstance(item, dict) else None for item in receipts
    ] != ["evidence_dispatch_handoff_committed", "response_observed"]:
        raise ValueError("OpenClaw runtime capsule receipt chain is incomplete")
    negative = _object(
        value.get("negativeControl"),
        frozenset(
            "resultStatus retrievalCount projectionCount dispatchCount responseObservedCount operationReceiptDigest resultReceiptDigest sourceExchangeDigest".split()
        ),
        "OpenClaw negative control",
    )
    fact_keys = "resultStatus retrievalCount projectionCount dispatchCount responseObservedCount".split()
    if tuple(negative[key] for key in fact_keys) != ("zero_hits", 1, 0, 0, 0):
        raise ValueError("OpenClaw negative control is invalid")
    for (
        field
    ) in "operationReceiptDigest resultReceiptDigest sourceExchangeDigest".split():
        _digest(negative[field], field)
    return value


def hermes_capsule_inputs(capsule: KwragRuntimeCapsule):
    if capsule.family != "hermes" or capsule.product_runtime_binding is None:
        raise ValueError("Hermes runtime capsule is unavailable")
    return HermesP1CanaryInputs(
        capsule.attachment_data,
        b"",
        {},
        capsule.authority_receipt,
        capsule.product_runtime_binding,
        _slot_request(capsule, False),
        _slot_request(capsule, True),
        b"Use only the attached verified evidence for this bounded canary turn.",
    )
