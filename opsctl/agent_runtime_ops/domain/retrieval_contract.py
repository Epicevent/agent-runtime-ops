from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

import yaml

from ..yamlio import dump_yaml
from .common import is_dev_slot
from .artifact_probe import (
    ArtifactProbeError,
    CommandResult,
    DockerCommandRunner,
    _default_docker_runner,
)


RETRIEVAL_SCHEMA = "jitech-embedded-retrieval/v1"
RETRIEVAL_STATUS_SCHEMA = "jitech-embedded-retrieval-status/v1"
RETRIEVAL_APPROVAL_SCHEMA = "jitech-retrieval-component-approval/v1"
RETRIEVAL_APPROVAL_POLICY_NAME = "retrieval-component-approved.yaml"
RETRIEVAL_LABEL_PREFIX = "com.epicevent.agent-runtime.retrieval."
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:@+=,-]+$")
ALLOWED_VERIFY_ARGV = {
    ("hermes", "kwrag-slot", "status", "--json"),
}
RESOURCE_KEYS = {
    "cpuReservationMillicores",
    "gpuAccess",
    "memoryReservationBytes",
    "pidsReservation",
    "profileDigest",
}
CAPABILITY_LABEL_SUFFIXES = {
    "component-digest",
    "component-manifest-digest",
    "contract-digest",
    "default-enabled",
    "host-port-count",
    "nas-read-only",
    "resource.json",
    "schema",
    "source-archive-digest",
    "source-revision",
    "transport",
    "verify-command.json",
}
CONTRACT_KEYS = {
    "component_digest",
    "component_manifest_digest",
    "contract_digest",
    "default_enabled",
    "host_port_count",
    "nas_read_only",
    "resource",
    "schema",
    "source_archive_digest",
    "source_revision",
    "transport",
    "verify_argv",
}
BINDING_KEYS = {
    "componentDigest",
    "containerNasRoot",
    "contractDigest",
    "enabled",
    "family",
    "hostPortCount",
    "instanceId",
    "mountReadOnly",
    "resourceProfileDigest",
    "runtimeProfileDigest",
    "schema",
    "transport",
}
STATUS_KEYS = {
    "bindingDigest",
    "componentDigest",
    "consumerHealth",
    "gpuAccessStatus",
    "hostPortCount",
    "linkageStatus",
    "mountReadOnly",
    "operationReceiptDigest",
    "resourceProfileDigest",
    "resourceStatus",
    "resultReceiptDigest",
    "revocationStatus",
    "schema",
    "consumptionReceiptDigest",
}
RETRIEVAL_PROBE_TIMEOUT_SECONDS = 15
RETRIEVAL_PROBE_OUTPUT_LIMIT_BYTES = 64 * 1024
APPROVAL_ITEM_KEYS = {
    "approved_at",
    "approved_by",
    "component_digest",
    "component_manifest_digest",
    "contract_digest",
    "product_image_digest",
    "resource_profile_digest",
    "source_archive_digest",
    "source_revision",
}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"retrieval component approval policy has duplicate key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _strict_canonical_json(raw: str, name: str) -> object:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{name} contains a duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{name} is not strict JSON: {exc}") from exc
    if raw != _canonical_bytes(value).decode("utf-8"):
        raise ValueError(f"{name} is not canonical JSON")
    return value


def parse_retrieval_status_output(raw: bytes | str) -> object:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("retrieval verifier output is not UTF-8") from exc
    else:
        text = raw
    if text.endswith("\n"):
        text = text[:-1]
    return _strict_canonical_json(text, "retrieval verifier output")


def _label(labels: dict[str, str], name: str) -> str:
    return str(labels.get(RETRIEVAL_LABEL_PREFIX + name) or "")


def _digest(value: object, field: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise ValueError(f"{field} must be sha256:<64 lower-case hex>")
    return text


def _parse_verify_argv(raw: str) -> list[str]:
    value = _strict_canonical_json(raw, "retrieval verify argv")
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError("retrieval verify argv must contain 1..16 items")
    argv: list[str] = []
    for item in value:
        text = str(item)
        if not text or len(text) > 256 or not SAFE_TOKEN_RE.fullmatch(text):
            raise ValueError("retrieval verify argv contains an unsafe item")
        argv.append(text)
    if tuple(argv) not in ALLOWED_VERIFY_ARGV:
        raise ValueError("retrieval verify argv is not an allowed product verifier")
    return argv


def _parse_resource_envelope(raw: str) -> dict[str, object]:
    value = _strict_canonical_json(raw, "retrieval resource envelope")
    if not isinstance(value, dict) or set(value) != RESOURCE_KEYS:
        raise ValueError("retrieval resource envelope has unexpected fields")
    profile_digest = _digest(value["profileDigest"], "retrieval.resource.profileDigest")
    memory = value["memoryReservationBytes"]
    cpu = value["cpuReservationMillicores"]
    pids = value["pidsReservation"]
    if not isinstance(memory, int) or isinstance(memory, bool) or not 1 <= memory <= 2**50:
        raise ValueError("retrieval memoryReservationBytes is invalid")
    if not isinstance(cpu, int) or isinstance(cpu, bool) or not 1 <= cpu <= 1_000_000:
        raise ValueError("retrieval cpuReservationMillicores is invalid")
    if not isinstance(pids, int) or isinstance(pids, bool) or not 1 <= pids <= 65_536:
        raise ValueError("retrieval pidsReservation is invalid")
    gpu_access = value["gpuAccess"]
    if gpu_access not in {"none", "shared_stateless"}:
        raise ValueError("retrieval gpuAccess must be none or shared_stateless")
    result = {
        "cpuReservationMillicores": cpu,
        "gpuAccess": gpu_access,
        "memoryReservationBytes": memory,
        "pidsReservation": pids,
        "profileDigest": profile_digest,
    }
    digest_payload = {key: result[key] for key in RESOURCE_KEYS if key != "profileDigest"}
    if canonical_digest(digest_payload) != profile_digest:
        raise ValueError("retrieval resource profileDigest does not match its canonical fields")
    return result


def retrieval_contract_from_labels(labels: dict[str, str]) -> dict[str, object] | None:
    suffixes = {
        key[len(RETRIEVAL_LABEL_PREFIX) :]
        for key in labels
        if key.startswith(RETRIEVAL_LABEL_PREFIX)
    }
    if not suffixes:
        return None
    if suffixes != CAPABILITY_LABEL_SUFFIXES:
        raise ValueError("embedded retrieval capability labels are incomplete or unexpected")
    schema = _label(labels, "schema")
    if schema != RETRIEVAL_SCHEMA:
        raise ValueError(f"unsupported embedded retrieval schema: {schema}")
    source_revision = _label(labels, "source-revision")
    if not REVISION_RE.fullmatch(source_revision):
        raise ValueError("retrieval source revision must be 40 lower-case hex")
    if _label(labels, "transport") != "in_process":
        raise ValueError("embedded retrieval transport must be in_process")
    if _label(labels, "default-enabled") != "false":
        raise ValueError("embedded retrieval must be default-disabled")
    if _label(labels, "host-port-count") != "0":
        raise ValueError("embedded retrieval must declare zero host ports")
    if _label(labels, "nas-read-only") != "true":
        raise ValueError("embedded retrieval must require a read-only NAS mount")
    return validate_retrieval_contract_object({
        "schema": schema,
        "component_digest": _digest(
            _label(labels, "component-digest"), "retrieval.component-digest"
        ),
        "component_manifest_digest": _digest(
            _label(labels, "component-manifest-digest"),
            "retrieval.component-manifest-digest",
        ),
        "contract_digest": _digest(
            _label(labels, "contract-digest"), "retrieval.contract-digest"
        ),
        "default_enabled": False,
        "host_port_count": 0,
        "nas_read_only": True,
        "resource": _parse_resource_envelope(_label(labels, "resource.json")),
        "source_archive_digest": _digest(
            _label(labels, "source-archive-digest"),
            "retrieval.source-archive-digest",
        ),
        "source_revision": source_revision,
        "transport": "in_process",
        "verify_argv": _parse_verify_argv(_label(labels, "verify-command.json")),
    })


def validate_retrieval_contract_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != CONTRACT_KEYS:
        raise ValueError("embedded retrieval contract has unexpected fields")
    if value.get("schema") != RETRIEVAL_SCHEMA:
        raise ValueError("embedded retrieval contract schema mismatch")
    for key in (
        "component_digest",
        "component_manifest_digest",
        "contract_digest",
        "source_archive_digest",
    ):
        _digest(value.get(key), f"retrieval contract {key}")
    source_revision = str(value.get("source_revision") or "")
    if not REVISION_RE.fullmatch(source_revision):
        raise ValueError("retrieval source revision must be 40 lower-case hex")
    if value.get("transport") != "in_process":
        raise ValueError("embedded retrieval transport must be in_process")
    if value.get("default_enabled") is not False:
        raise ValueError("embedded retrieval must be default-disabled")
    if value.get("host_port_count") != 0:
        raise ValueError("embedded retrieval must declare zero host ports")
    if value.get("nas_read_only") is not True:
        raise ValueError("embedded retrieval must require a read-only NAS mount")
    resource = value.get("resource")
    if not isinstance(resource, dict):
        raise ValueError("embedded retrieval resource profile is missing")
    parsed_resource = _parse_resource_envelope(
        _canonical_bytes(resource).decode("utf-8")
    )
    argv = value.get("verify_argv")
    parsed_argv = _parse_verify_argv(_canonical_bytes(argv).decode("utf-8"))
    normalized = dict(value)
    normalized["resource"] = parsed_resource
    normalized["verify_argv"] = parsed_argv
    return normalized


def validate_bound_retrieval_spec(image_spec: dict[str, Any]) -> None:
    enabled = image_spec.get("retrieval_enabled")
    if not isinstance(enabled, bool):
        raise ValueError("retrieval_enabled must be boolean")
    contract_value = image_spec.get("retrieval_contract")
    contract = (
        validate_retrieval_contract_object(contract_value)
        if contract_value is not None
        else None
    )
    if enabled and contract is None:
        raise ValueError("retrieval cannot be enabled without a component contract")
    binding = image_spec.get("retrieval_binding")
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS:
        raise ValueError("retrieval binding has unexpected fields")
    if binding.get("schema") != "agent-runtime-retrieval-binding/v1":
        raise ValueError("retrieval binding schema mismatch")
    if binding.get("enabled") is not enabled:
        raise ValueError("retrieval binding enabled state mismatch")
    if binding.get("transport") != "in_process" or binding.get("hostPortCount") != 0:
        raise ValueError("retrieval binding violates in-process/host-port boundary")
    if binding.get("mountReadOnly") is not True:
        raise ValueError("retrieval binding mount must be read-only")
    if not isinstance(binding.get("containerNasRoot"), str) or not binding.get("containerNasRoot"):
        raise ValueError("retrieval binding container NAS root is missing")
    if not isinstance(binding.get("instanceId"), str) or not binding.get("instanceId"):
        raise ValueError("retrieval binding instance ID is missing")
    if binding.get("family") not in {"hermes", "openclaw"}:
        raise ValueError("retrieval binding family is invalid")
    _digest(binding.get("runtimeProfileDigest"), "retrieval runtime profile digest")
    expected_component = contract.get("component_digest") if contract else None
    expected_contract = contract.get("contract_digest") if contract else None
    resource = contract.get("resource") if contract else None
    expected_resource = resource.get("profileDigest") if isinstance(resource, dict) else None
    if binding.get("componentDigest") != expected_component:
        raise ValueError("retrieval binding component digest mismatch")
    if binding.get("contractDigest") != expected_contract:
        raise ValueError("retrieval binding contract digest mismatch")
    if binding.get("resourceProfileDigest") != expected_resource:
        raise ValueError("retrieval binding resource profile digest mismatch")
    component_digest = str(image_spec.get("retrieval_component_digest") or "")
    if component_digest != str(expected_component or ""):
        raise ValueError("retrieval image spec component digest mismatch")
    binding_digest = str(image_spec.get("retrieval_binding_digest") or "")
    if canonical_digest(binding) != binding_digest:
        raise ValueError("retrieval binding canonical digest mismatch")


def validate_retrieval_target_binding(
    image_spec: dict[str, Any],
    *,
    instance_id: str,
    family: str,
    runtime_profile_digest: str,
    container_nas_root: str,
) -> None:
    validate_bound_retrieval_spec(image_spec)
    binding = image_spec["retrieval_binding"]
    expected = {
        "instanceId": instance_id,
        "family": family,
        "runtimeProfileDigest": runtime_profile_digest,
        "containerNasRoot": container_nas_root,
    }
    mismatched = [key for key, value in expected.items() if binding.get(key) != value]
    if mismatched:
        raise ValueError(
            "retrieval binding target identity mismatch: " + ",".join(sorted(mismatched))
        )


def matched_retrieval_contract(
    wrapper_labels: dict[str, str], product_labels: dict[str, str]
) -> dict[str, object] | None:
    wrapper = retrieval_contract_from_labels(wrapper_labels)
    product = retrieval_contract_from_labels(product_labels)
    if wrapper != product:
        raise ValueError("wrapper and product embedded retrieval provenance do not match")
    return wrapper


def bind_retrieval_intent(
    image_spec: dict[str, Any],
    *,
    instance_id: str,
    family: str,
    runtime_profile_digest: str,
    container_nas_root: str,
    enabled: bool,
) -> dict[str, Any]:
    result = dict(image_spec)
    contract = result.get("retrieval_contract")
    if enabled and not isinstance(contract, dict):
        raise ValueError("retrieval cannot be enabled: product image declares no capability")
    component_digest = str(contract.get("component_digest") or "") if isinstance(contract, dict) else ""
    contract_digest = str(contract.get("contract_digest") or "") if isinstance(contract, dict) else ""
    resource = contract.get("resource") if isinstance(contract, dict) else None
    resource_digest = str(resource.get("profileDigest") or "") if isinstance(resource, dict) else ""
    payload = {
        "schema": "agent-runtime-retrieval-binding/v1",
        "componentDigest": component_digest or None,
        "containerNasRoot": container_nas_root,
        "contractDigest": contract_digest or None,
        "enabled": bool(enabled),
        "family": family,
        "hostPortCount": 0,
        "instanceId": instance_id,
        "mountReadOnly": True,
        "resourceProfileDigest": resource_digest or None,
        "runtimeProfileDigest": runtime_profile_digest,
        "transport": "in_process",
    }
    result["retrieval_component_digest"] = component_digest
    result["retrieval_enabled"] = bool(enabled)
    result["retrieval_binding"] = payload
    result["retrieval_binding_digest"] = canonical_digest(payload)
    validate_bound_retrieval_spec(result)
    return result


def retrieval_env(image_spec: dict[str, Any]) -> dict[str, str]:
    validate_bound_retrieval_spec(image_spec)
    contract = image_spec.get("retrieval_contract")
    resource = contract.get("resource") if isinstance(contract, dict) else None
    return {
        "JITECH_RETRIEVAL_ENABLED": "true" if image_spec.get("retrieval_enabled") is True else "false",
        "JITECH_RETRIEVAL_COMPONENT_DIGEST": str(image_spec.get("retrieval_component_digest") or ""),
        "JITECH_RETRIEVAL_BINDING_DIGEST": str(image_spec.get("retrieval_binding_digest") or ""),
        "JITECH_RETRIEVAL_RESOURCE_PROFILE_DIGEST": (
            str(resource.get("profileDigest") or "") if isinstance(resource, dict) else ""
        ),
    }


def load_retrieval_approvals(state_root: Path) -> dict[str, object]:
    policy_path = state_root / RETRIEVAL_APPROVAL_POLICY_NAME
    if policy_path.is_symlink():
        raise ValueError("retrieval component approval policy must not be a symlink")
    if not policy_path.exists():
        return {}
    if not policy_path.is_file():
        raise ValueError("retrieval component approval policy must be a regular file")
    with policy_path.open("r", encoding="utf-8") as fh:
        data = yaml.load(fh, Loader=_UniqueKeySafeLoader)
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("meta"), dict)
        or data["meta"].get("schema") != RETRIEVAL_APPROVAL_SCHEMA
        or data["meta"].get("scope") != "private_server_state"
        or set(data["meta"]) != {"schema", "scope", "updated_at"}
        or not isinstance(data["meta"].get("updated_at"), str)
        or not data["meta"].get("updated_at")
        or set(data) != {"meta", "components"}
        or not isinstance(data.get("components"), dict)
    ):
        raise ValueError("retrieval component approval policy is invalid")
    components = data["components"]
    for family, item in components.items():
        if family not in {"hermes", "openclaw"}:
            raise ValueError("retrieval component approval family is invalid")
        if not isinstance(item, dict) or set(item) != APPROVAL_ITEM_KEYS:
            raise ValueError("retrieval component approval record is invalid")
        for field in (
            "component_digest",
            "component_manifest_digest",
            "contract_digest",
            "product_image_digest",
            "resource_profile_digest",
            "source_archive_digest",
        ):
            _digest(item.get(field), field)
        if not REVISION_RE.fullmatch(str(item.get("source_revision") or "")):
            raise ValueError("retrieval component approval source revision is invalid")
        if not isinstance(item.get("approved_at"), str) or not item["approved_at"]:
            raise ValueError("retrieval component approval timestamp is invalid")
        if not isinstance(item.get("approved_by"), str):
            raise ValueError("retrieval component approval actor is invalid")
    return dict(components)


def write_retrieval_approval(
    state_root: Path,
    family: str,
    contract: dict[str, object],
    *,
    product_image_digest: str,
) -> Path:
    contract = validate_retrieval_contract_object(contract)
    if family not in {"hermes", "openclaw"}:
        raise ValueError("retrieval approval family must be hermes or openclaw")
    if not state_root.is_dir():
        raise FileNotFoundError(state_root)
    product_digest = _digest(product_image_digest, "product_image_digest")
    policy_path = state_root / RETRIEVAL_APPROVAL_POLICY_NAME
    components = load_retrieval_approvals(state_root)
    components[family] = {
        "component_digest": _digest(contract.get("component_digest"), "component_digest"),
        "component_manifest_digest": _digest(
            contract.get("component_manifest_digest"), "component_manifest_digest"
        ),
        "contract_digest": _digest(contract.get("contract_digest"), "contract_digest"),
        "product_image_digest": product_digest,
        "resource_profile_digest": _digest(
            (contract.get("resource") or {}).get("profileDigest")
            if isinstance(contract.get("resource"), dict)
            else "",
            "resource_profile_digest",
        ),
        "source_revision": str(contract.get("source_revision") or ""),
        "source_archive_digest": _digest(
            contract.get("source_archive_digest"), "source_archive_digest"
        ),
        "approved_at": _now_iso(),
        "approved_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
    }
    data = {
        "meta": {
            "schema": RETRIEVAL_APPROVAL_SCHEMA,
            "scope": "private_server_state",
            "updated_at": _now_iso(),
        },
        "components": components,
    }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_root, delete=False) as fh:
        tmp_path = Path(fh.name)
        fh.write(dump_yaml(data))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        if hasattr(os, "chown"):
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, policy_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return policy_path


def retrieval_contract_is_approved(
    state_root: Path,
    family: str,
    contract: dict[str, object],
    *,
    product_image_digest: str,
) -> bool:
    contract = validate_retrieval_contract_object(contract)
    item = load_retrieval_approvals(state_root).get(family)
    if not isinstance(item, dict):
        return False
    expected = {
        "component_digest": contract.get("component_digest"),
        "component_manifest_digest": contract.get("component_manifest_digest"),
        "contract_digest": contract.get("contract_digest"),
        "product_image_digest": product_image_digest,
        "resource_profile_digest": (
            (contract.get("resource") or {}).get("profileDigest")
            if isinstance(contract.get("resource"), dict)
            else None
        ),
        "source_revision": contract.get("source_revision"),
        "source_archive_digest": contract.get("source_archive_digest"),
    }
    return all(item.get(key) == value for key, value in expected.items())


def require_retrieval_approval(desired: object, state_root: Path) -> None:
    """Fail closed on enabled production retrieval inside the apply lock.

    Command-specific preflights may call this too, but the shared apply path is
    authoritative so an ordinary ``opsctl apply`` cannot bypass approval and a
    policy rotation between planning and mutation is observed.
    """
    image_spec = getattr(desired, "image_spec", None)
    if not isinstance(image_spec, dict) or image_spec.get("retrieval_enabled") is not True:
        return
    slot = str(getattr(desired, "slot", "") or "")
    if is_dev_slot(slot):
        return
    contract = image_spec.get("retrieval_contract")
    if not isinstance(contract, dict):
        raise ValueError("retrieval is enabled without an embedded component contract")
    product_image = image_spec.get("product_image")
    if not isinstance(product_image, str) or "@" not in product_image:
        raise ValueError("retrieval product image must be pinned by digest")
    product_digest = product_image.rsplit("@", 1)[1]
    if not SHA256_RE.fullmatch(product_digest):
        raise ValueError("retrieval product image must be pinned by sha256 digest")
    family = str(getattr(desired, "family", "") or "")
    from .image_approval_policy import is_image_ref_approved

    wrapper_image = image_spec.get("wrapper_image")
    if not is_image_ref_approved(
        state_root, family, "wrapper", wrapper_image
    ):
        raise ValueError(
            "production retrieval enablement requires exact wrapper image approval"
        )
    if not is_image_ref_approved(
        state_root, family, "product", product_image
    ):
        raise ValueError(
            "production retrieval enablement requires exact product image approval"
        )
    if not retrieval_contract_is_approved(
        state_root,
        family,
        contract,
        product_image_digest=product_digest,
    ):
        raise ValueError(
            "production retrieval enablement requires exact component approval"
        )


def validate_retrieval_status(
    value: object,
    *,
    expected_component_digest: str,
    expected_binding_digest: str,
    expected_resource_profile_digest: str,
    expected_gpu_access: str,
    enabled: bool,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != STATUS_KEYS:
        raise ValueError("retrieval status has unexpected fields")
    if value.get("schema") != RETRIEVAL_STATUS_SCHEMA:
        raise ValueError("retrieval status schema mismatch")
    if value.get("componentDigest") != expected_component_digest:
        raise ValueError("retrieval status component digest mismatch")
    if value.get("bindingDigest") != expected_binding_digest:
        raise ValueError("retrieval status binding digest mismatch")
    if value.get("resourceProfileDigest") != expected_resource_profile_digest:
        raise ValueError("retrieval status resource profile digest mismatch")
    host_port_count = value.get("hostPortCount")
    if (
        not isinstance(host_port_count, int)
        or isinstance(host_port_count, bool)
        or host_port_count != 0
        or value.get("mountReadOnly") is not True
    ):
        raise ValueError("retrieval status violates slot-local port/mount boundary")
    if value.get("resourceStatus") not in {"within_declared_reservation", "unavailable"}:
        raise ValueError("retrieval status resourceStatus is invalid")
    if value.get("gpuAccessStatus") not in {"none", "shared_stateless_attested"}:
        raise ValueError("retrieval status gpuAccessStatus is invalid")
    receipt_fields = (
        "operationReceiptDigest",
        "resultReceiptDigest",
        "consumptionReceiptDigest",
    )
    if enabled:
        if value.get("resourceStatus") != "within_declared_reservation":
            raise ValueError("enabled retrieval resource observation is unavailable or over budget")
        expected_gpu_status = (
            "shared_stateless_attested"
            if expected_gpu_access == "shared_stateless"
            else "none"
        )
        if value.get("gpuAccessStatus") != expected_gpu_status:
            raise ValueError("enabled retrieval GPU observation does not match its resource profile")
        if value.get("consumerHealth") != "healthy" or value.get("linkageStatus") != "complete":
            raise ValueError("enabled retrieval consumer/linkage is not complete")
        if value.get("revocationStatus") is not None:
            raise ValueError("enabled retrieval must not claim revocation")
        for field in receipt_fields:
            _digest(value.get(field), f"retrieval status {field}")
    else:
        if value.get("resourceStatus") != "unavailable":
            raise ValueError("disabled retrieval must not claim measured resource use")
        if value.get("gpuAccessStatus") != "none":
            raise ValueError("disabled retrieval must not claim GPU access")
        if value.get("consumerHealth") != "disabled":
            raise ValueError("disabled retrieval consumer is not disabled")
        if value.get("linkageStatus") != "not_applicable":
            raise ValueError("disabled retrieval linkage must be not_applicable")
        if value.get("revocationStatus") != "complete":
            raise ValueError("disabled retrieval revocation is incomplete")
        if any(value.get(field) is not None for field in receipt_fields):
            raise ValueError("disabled retrieval must not expose operation receipts")
    return dict(value)


def run_retrieval_status_probe(
    container: str,
    image_spec: dict[str, Any],
    *,
    runner: DockerCommandRunner = _default_docker_runner,
) -> dict[str, object] | None:
    """Run the image-attested, content-free in-process retrieval verifier.

    A product without the embedded retrieval capability has nothing to probe and returns
    ``None``.  The command is fixed by the approved image labels; no path, shell, backend,
    query, network, grant, or projection input is accepted from the operator.
    """
    contract = image_spec.get("retrieval_contract")
    if not isinstance(contract, dict):
        return None
    validate_bound_retrieval_spec(image_spec)
    argv = contract.get("verify_argv")
    if not isinstance(argv, list):
        raise ValueError("retrieval verifier argv is missing")
    command = ["docker", "exec", container, *[str(item) for item in argv]]
    try:
        result = runner(
            command,
            timeout=RETRIEVAL_PROBE_TIMEOUT_SECONDS,
            output_limit=RETRIEVAL_PROBE_OUTPUT_LIMIT_BYTES,
        )
    except ArtifactProbeError as exc:
        raise ValueError(f"retrieval verifier failed: {exc.code}") from exc
    if not isinstance(result, CommandResult):
        raise ValueError("retrieval verifier runner returned an invalid result")
    if result.returncode != 0:
        raise ValueError(f"retrieval verifier exited nonzero: rc={result.returncode}")
    try:
        value = parse_retrieval_status_output(result.stdout)
    except ValueError as exc:
        raise ValueError("retrieval verifier output is not strict UTF-8 JSON") from exc
    resource = contract.get("resource")
    return validate_retrieval_status(
        value,
        expected_component_digest=str(contract.get("component_digest") or ""),
        expected_binding_digest=str(image_spec.get("retrieval_binding_digest") or ""),
        expected_resource_profile_digest=(
            str(resource.get("profileDigest") or "") if isinstance(resource, dict) else ""
        ),
        expected_gpu_access=(
            str(resource.get("gpuAccess") or "") if isinstance(resource, dict) else ""
        ),
        enabled=image_spec.get("retrieval_enabled") is True,
    )
