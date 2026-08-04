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
RETRIEVAL_ATTACHMENT_STATUS_SCHEMA = "jitech-embedded-retrieval-attachment-status/v1"
BINDING_V1_SCHEMA = "agent-runtime-retrieval-binding/v1"
BINDING_V2_SCHEMA = "agent-runtime-retrieval-binding/v2"
ATTACHMENT_PROOF_MODE = "attachment_only"
RETRIEVAL_APPROVAL_SCHEMA = "jitech-retrieval-component-approval/v1"
RETRIEVAL_APPROVAL_POLICY_NAME = "retrieval-component-approved.yaml"
RETRIEVAL_LABEL_PREFIX = "com.epicevent.agent-runtime.retrieval."
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./:@+=,-]+$")
ALLOWED_VERIFY_ARGV = {
    ("hermes", "kwrag-slot", "status", "--json"),
}
ALLOWED_ATTACHMENT_VERIFY_ARGV = {
    "hermes": ("hermes", "kwrag-slot", "p1-attachment-status", "--json"),
}
HERMES_P1_LABEL_PREFIX = "com.epicevent.hermes.kwrag.p1."
HERMES_P1_LABEL_SUFFIXES = {
    "attachment-decision-digest",
    "caller-explicit",
    "component-manifest-digest",
    "component-wheel-digest",
    "default-enabled",
    "status-schema",
    "verify-command.json",
}
HERMES_P1_DECISION_DIGEST = (
    "sha256:fd4d1068407d0b28d41e7813f8cef7b193a5fe43f39db166588911e6fde3bbb5"
)


def digest_path_component(value: object) -> str:
    digest = str(value or "")
    if SHA256_RE.fullmatch(digest) is None:
        raise ValueError("digest path component requires an exact sha256 digest")
    return digest.removeprefix("sha256:")
ATTACHMENT_CONTRACT_KEYS = {
    "attachment_decision_digest",
    "caller_explicit",
    "component_manifest_digest",
    "component_wheel_digest",
    "default_enabled",
    "status_schema",
    "verify_argv",
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
BINDING_V2_KEYS = {
    "attachmentData",
    "componentDigest",
    "containerNasRoot",
    "contractDigest",
    "enabled",
    "family",
    "hostPortCount",
    "instanceId",
    "mountReadOnly",
    "p1Identity",
    "proofMode",
    "resourceProfileDigest",
    "runtimeProfileDigest",
    "schema",
    "transport",
}
P1_IDENTITY_KEYS = {
    "backendId",
    "pipelineFactoryDigest",
    "pipelineFingerprint",
    "researchDecisionDigest",
    "status",
}
ATTACHMENT_DATA_KEYS = {
    "databaseSha256",
    "indexManifestDigest",
    "readOnlyAuthorityReceiptDigest",
    "slotRuntimeBindingDigest",
    "sourceSnapshotDigest",
}
CONTAINER_NAS_ROOT_BY_FAMILY = {
    "openclaw": "/home/node/nas_docs",
    "hermes": "/workspace/nas_docs",
}
P1_IDENTITY_FIXED = {
    "status": "research_selected_p1_attachment_probe_candidate",
    "pipelineFactoryDigest": (
        "sha256:0dbe54f5a8bc56a6c821e181a0dc6cfda85d25be8cea6a01235cb5e347782f0e"
    ),
    "backendId": "slot-local-fts5-trigram-or-attachment-v1",
    "pipelineFingerprint": (
        "sha256:53e14752cc9d147dfb4129e00234d1c7fb9f6558df00da7c03189db8da8e4606"
    ),
    "researchDecisionDigest": (
        "sha256:81e6f4d83e6cde6a9c83a9aa435c65354a1122dded735bf607462c3497e9b25d"
    ),
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
ATTACHMENT_STATUS_KEYS = {
    "attachmentDataDigest",
    "attachmentHealth",
    "bindingDigest",
    "componentDigest",
    "consumptionReceiptDigest",
    "consumptionStatus",
    "enabled",
    "gpuAccessStatus",
    "hostPortCount",
    "linkageStatus",
    "mountReadOnly",
    "operationReceiptDigest",
    "p1IdentityDigest",
    "proofMode",
    "resourceProfileDigest",
    "resourceStatus",
    "resultReceiptDigest",
    "revocationStatus",
    "schema",
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
            raise ValueError(
                f"retrieval component approval policy has duplicate key: {key}"
            )
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
    if (
        not isinstance(memory, int)
        or isinstance(memory, bool)
        or not 1 <= memory <= 2**50
    ):
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
    digest_payload = {
        key: result[key] for key in RESOURCE_KEYS if key != "profileDigest"
    }
    if canonical_digest(digest_payload) != profile_digest:
        raise ValueError(
            "retrieval resource profileDigest does not match its canonical fields"
        )
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
        raise ValueError(
            "embedded retrieval capability labels are incomplete or unexpected"
        )
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
    return validate_retrieval_contract_object(
        {
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
        }
    )


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


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_p1_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != P1_IDENTITY_KEYS:
        raise ValueError("retrieval P1 identity has unexpected fields")
    _required_text(value.get("status"), "retrieval P1 status")
    _required_text(value.get("backendId"), "retrieval P1 backend ID")
    for field in (
        "pipelineFactoryDigest",
        "pipelineFingerprint",
        "researchDecisionDigest",
    ):
        _digest(value.get(field), f"retrieval P1 {field}")
    if value != P1_IDENTITY_FIXED:
        raise ValueError("retrieval P1 identity does not match the selected contract")
    return dict(value)


def _validate_attachment_data(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != ATTACHMENT_DATA_KEYS:
        raise ValueError("retrieval attachment data has unexpected fields")
    for field in ATTACHMENT_DATA_KEYS:
        _digest(value.get(field), f"retrieval attachment {field}")
    return dict(value)


def retrieval_attachment_contract_from_labels(
    labels: dict[str, str],
    *,
    family: str,
) -> dict[str, object] | None:
    """Read the exact product-owned attachment verifier contract from OCI labels."""

    if family != "hermes":
        return None
    present = {
        key.removeprefix(HERMES_P1_LABEL_PREFIX)
        for key in labels
        if key.startswith(HERMES_P1_LABEL_PREFIX)
    }
    if not present:
        return None
    if present != HERMES_P1_LABEL_SUFFIXES:
        raise ValueError("Hermes P1 attachment label set is incomplete or unexpected")
    values = {
        suffix: str(labels.get(HERMES_P1_LABEL_PREFIX + suffix) or "")
        for suffix in HERMES_P1_LABEL_SUFFIXES
    }
    for suffix in (
        "attachment-decision-digest",
        "component-manifest-digest",
        "component-wheel-digest",
    ):
        _digest(values[suffix], f"Hermes P1 {suffix}")
    if values["attachment-decision-digest"] != HERMES_P1_DECISION_DIGEST:
        raise ValueError("Hermes P1 attachment decision digest mismatch")
    if values["caller-explicit"] != "true" or values["default-enabled"] != "false":
        raise ValueError(
            "Hermes P1 attachment must remain caller-explicit and default-off"
        )
    if values["status-schema"] != RETRIEVAL_ATTACHMENT_STATUS_SCHEMA:
        raise ValueError("Hermes P1 attachment status schema mismatch")
    try:
        argv = json.loads(values["verify-command.json"])
    except json.JSONDecodeError as exc:
        raise ValueError("Hermes P1 attachment verifier argv is invalid") from exc
    expected_argv = ALLOWED_ATTACHMENT_VERIFY_ARGV[family]
    if not isinstance(argv, list) or tuple(argv) != expected_argv:
        raise ValueError("Hermes P1 attachment verifier argv mismatch")
    return _validate_retrieval_attachment_contract(
        {
            "attachment_decision_digest": values["attachment-decision-digest"],
            "caller_explicit": True,
            "component_manifest_digest": values["component-manifest-digest"],
            "component_wheel_digest": values["component-wheel-digest"],
            "default_enabled": False,
            "status_schema": values["status-schema"],
            "verify_argv": list(expected_argv),
        },
        family=family,
    )


def _validate_retrieval_attachment_contract(
    value: object,
    *,
    family: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != ATTACHMENT_CONTRACT_KEYS:
        raise ValueError("retrieval attachment verifier contract has unexpected fields")
    if family != "hermes":
        raise ValueError("retrieval attachment verifier family is unsupported")
    for field in (
        "attachment_decision_digest",
        "component_manifest_digest",
        "component_wheel_digest",
    ):
        _digest(value.get(field), f"retrieval attachment verifier {field}")
    if value.get("attachment_decision_digest") != HERMES_P1_DECISION_DIGEST:
        raise ValueError("retrieval attachment verifier decision digest mismatch")
    if (
        value.get("caller_explicit") is not True
        or value.get("default_enabled") is not False
    ):
        raise ValueError(
            "retrieval attachment verifier must remain caller-explicit and default-off"
        )
    if value.get("status_schema") != RETRIEVAL_ATTACHMENT_STATUS_SCHEMA:
        raise ValueError("retrieval attachment verifier status schema mismatch")
    expected = ALLOWED_ATTACHMENT_VERIFY_ARGV[family]
    argv = value.get("verify_argv")
    if not isinstance(argv, list) or tuple(argv) != expected:
        raise ValueError("retrieval attachment verifier argv mismatch")
    return dict(value)


def _validate_binding_common(binding: dict[str, object], enabled: bool) -> None:
    if binding.get("enabled") is not enabled:
        raise ValueError("retrieval binding enabled state mismatch")
    host_port_count = binding.get("hostPortCount")
    if (
        binding.get("transport") != "in_process"
        or not isinstance(host_port_count, int)
        or isinstance(host_port_count, bool)
        or host_port_count != 0
    ):
        raise ValueError("retrieval binding violates in-process/host-port boundary")
    if binding.get("mountReadOnly") is not True:
        raise ValueError("retrieval binding mount must be read-only")
    family = binding.get("family")
    if family not in CONTAINER_NAS_ROOT_BY_FAMILY:
        raise ValueError("retrieval binding family is invalid")
    _required_text(binding.get("containerNasRoot"), "retrieval container NAS root")
    _required_text(binding.get("instanceId"), "retrieval instance ID")
    _digest(binding.get("runtimeProfileDigest"), "retrieval runtime profile digest")


def _validate_binding_v1(binding: object, enabled: bool) -> dict[str, object]:
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS:
        raise ValueError("retrieval binding v1 has unexpected fields")
    if binding.get("schema") != BINDING_V1_SCHEMA:
        raise ValueError("retrieval binding v1 schema mismatch")
    _validate_binding_common(binding, enabled)
    return dict(binding)


def _validate_binding_v2(binding: object, enabled: bool) -> dict[str, object]:
    if not isinstance(binding, dict) or set(binding) != BINDING_V2_KEYS:
        raise ValueError("retrieval binding v2 has unexpected fields")
    if binding.get("schema") != BINDING_V2_SCHEMA:
        raise ValueError("retrieval binding v2 schema mismatch")
    if binding.get("proofMode") != ATTACHMENT_PROOF_MODE:
        raise ValueError("retrieval binding v2 proof mode mismatch")
    _validate_binding_common(binding, enabled)
    family = str(binding["family"])
    if binding.get("containerNasRoot") != CONTAINER_NAS_ROOT_BY_FAMILY[family]:
        raise ValueError("retrieval binding v2 container NAS root mismatch")
    _validate_p1_identity(binding.get("p1Identity"))
    if enabled:
        _validate_attachment_data(binding.get("attachmentData"))
    elif binding.get("attachmentData") is not None:
        raise ValueError(
            "disabled retrieval binding v2 must not contain attachment data"
        )
    return dict(binding)


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
    binding_value = image_spec.get("retrieval_binding")
    schema = binding_value.get("schema") if isinstance(binding_value, dict) else None
    if schema == BINDING_V1_SCHEMA:
        binding = _validate_binding_v1(binding_value, enabled)
    elif schema == BINDING_V2_SCHEMA:
        binding = _validate_binding_v2(binding_value, enabled)
    else:
        raise ValueError("retrieval binding schema mismatch")
    if enabled and contract is None:
        raise ValueError("retrieval cannot be enabled without a component contract")
    if schema == BINDING_V2_SCHEMA and contract is None:
        raise ValueError("retrieval binding v2 requires a component contract")
    attachment_contract = image_spec.get("retrieval_attachment_contract")
    if schema == BINDING_V2_SCHEMA:
        _validate_retrieval_attachment_contract(
            attachment_contract,
            family=str(binding.get("family") or ""),
        )
    elif attachment_contract is not None:
        raise ValueError("retrieval attachment verifier requires binding v2")
    expected_component = contract.get("component_digest") if contract else None
    expected_contract = contract.get("contract_digest") if contract else None
    resource = contract.get("resource") if contract else None
    expected_resource = (
        resource.get("profileDigest") if isinstance(resource, dict) else None
    )
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
            "retrieval binding target identity mismatch: "
            + ",".join(sorted(mismatched))
        )


def matched_retrieval_contract(
    wrapper_labels: dict[str, str], product_labels: dict[str, str]
) -> dict[str, object] | None:
    wrapper = retrieval_contract_from_labels(wrapper_labels)
    product = retrieval_contract_from_labels(product_labels)
    if wrapper != product:
        raise ValueError(
            "wrapper and product embedded retrieval provenance do not match"
        )
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
        raise ValueError(
            "retrieval cannot be enabled: product image declares no capability"
        )
    component_digest = (
        str(contract.get("component_digest") or "")
        if isinstance(contract, dict)
        else ""
    )
    contract_digest = (
        str(contract.get("contract_digest") or "") if isinstance(contract, dict) else ""
    )
    resource = contract.get("resource") if isinstance(contract, dict) else None
    resource_digest = (
        str(resource.get("profileDigest") or "") if isinstance(resource, dict) else ""
    )
    payload = {
        "schema": BINDING_V1_SCHEMA,
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


def bind_retrieval_attachment_intent(
    image_spec: dict[str, Any],
    *,
    instance_id: str,
    family: str,
    runtime_profile_digest: str,
    container_nas_root: str,
    enabled: bool,
    p1_identity: dict[str, object],
    attachment_data: dict[str, object] | None,
) -> dict[str, Any]:
    """Bind the private attachment-only v2 tuple without making it executable.

    Product-owned verifier fixtures are not landed yet.  This builder makes the
    canonical private tuple readable and rollback-preservable; the shared probe
    remains fail closed for v2 until those exact interfaces land.
    """

    result = dict(image_spec)
    contract = result.get("retrieval_contract")
    if not isinstance(contract, dict):
        raise ValueError("retrieval binding v2 requires a component contract")
    contract = validate_retrieval_contract_object(contract)
    resource = contract["resource"]
    assert isinstance(resource, dict)
    identity = _validate_p1_identity(p1_identity)
    data = _validate_attachment_data(attachment_data) if enabled else None
    if not enabled and attachment_data is not None:
        raise ValueError(
            "disabled retrieval binding v2 must not contain attachment data"
        )
    payload = {
        "schema": BINDING_V2_SCHEMA,
        "proofMode": ATTACHMENT_PROOF_MODE,
        "enabled": bool(enabled),
        "family": family,
        "instanceId": instance_id,
        "runtimeProfileDigest": runtime_profile_digest,
        "containerNasRoot": container_nas_root,
        "transport": "in_process",
        "hostPortCount": 0,
        "mountReadOnly": True,
        "componentDigest": contract["component_digest"],
        "contractDigest": contract["contract_digest"],
        "resourceProfileDigest": resource["profileDigest"],
        "p1Identity": identity,
        "attachmentData": data,
    }
    result["retrieval_component_digest"] = contract["component_digest"]
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
        "JITECH_RETRIEVAL_ENABLED": "true"
        if image_spec.get("retrieval_enabled") is True
        else "false",
        "JITECH_RETRIEVAL_COMPONENT_DIGEST": str(
            image_spec.get("retrieval_component_digest") or ""
        ),
        "JITECH_RETRIEVAL_BINDING_DIGEST": str(
            image_spec.get("retrieval_binding_digest") or ""
        ),
        "JITECH_RETRIEVAL_RESOURCE_PROFILE_DIGEST": (
            str(resource.get("profileDigest") or "")
            if isinstance(resource, dict)
            else ""
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
        "component_digest": _digest(
            contract.get("component_digest"), "component_digest"
        ),
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
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=state_root, delete=False
    ) as fh:
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
    if (
        not isinstance(image_spec, dict)
        or image_spec.get("retrieval_enabled") is not True
    ):
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
    if not is_image_ref_approved(state_root, family, "wrapper", wrapper_image):
        raise ValueError(
            "production retrieval enablement requires exact wrapper image approval"
        )
    if not is_image_ref_approved(state_root, family, "product", product_image):
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
    if value.get("resourceStatus") not in {
        "within_declared_reservation",
        "unavailable",
    }:
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
            raise ValueError(
                "enabled retrieval resource observation is unavailable or over budget"
            )
        expected_gpu_status = (
            "shared_stateless_attested"
            if expected_gpu_access == "shared_stateless"
            else "none"
        )
        if value.get("gpuAccessStatus") != expected_gpu_status:
            raise ValueError(
                "enabled retrieval GPU observation does not match its resource profile"
            )
        if (
            value.get("consumerHealth") != "healthy"
            or value.get("linkageStatus") != "complete"
        ):
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


def validate_retrieval_attachment_status(
    value: object,
    *,
    image_spec: dict[str, Any],
) -> dict[str, object]:
    validate_bound_retrieval_spec(image_spec)
    binding = image_spec["retrieval_binding"]
    if binding.get("schema") != BINDING_V2_SCHEMA:
        raise ValueError("attachment status requires retrieval binding v2")
    if not isinstance(value, dict) or set(value) != ATTACHMENT_STATUS_KEYS:
        raise ValueError("retrieval attachment status has unexpected fields")
    if value.get("schema") != RETRIEVAL_ATTACHMENT_STATUS_SCHEMA:
        raise ValueError("retrieval attachment status schema mismatch")
    if value.get("proofMode") != ATTACHMENT_PROOF_MODE:
        raise ValueError("retrieval attachment status proof mode mismatch")
    enabled = image_spec.get("retrieval_enabled") is True
    if value.get("enabled") is not enabled:
        raise ValueError("retrieval attachment status enabled state mismatch")
    expected_digests = {
        "componentDigest": binding["componentDigest"],
        "bindingDigest": image_spec["retrieval_binding_digest"],
        "resourceProfileDigest": binding["resourceProfileDigest"],
        "p1IdentityDigest": canonical_digest(binding["p1Identity"]),
    }
    for field, expected in expected_digests.items():
        if value.get(field) != expected:
            raise ValueError(f"retrieval attachment status {field} mismatch")
    host_port_count = value.get("hostPortCount")
    if (
        not isinstance(host_port_count, int)
        or isinstance(host_port_count, bool)
        or host_port_count != 0
        or value.get("mountReadOnly") is not True
    ):
        raise ValueError(
            "retrieval attachment status violates slot-local port/mount boundary"
        )
    receipt_fields = (
        "operationReceiptDigest",
        "resultReceiptDigest",
        "consumptionReceiptDigest",
    )
    if enabled:
        expected_attachment_digest = canonical_digest(binding["attachmentData"])
        if value.get("attachmentDataDigest") != expected_attachment_digest:
            raise ValueError("retrieval attachment status data digest mismatch")
        if value.get("attachmentHealth") != "healthy":
            raise ValueError("retrieval attachment status is not healthy")
        if value.get("resourceStatus") != "within_declared_reservation":
            raise ValueError("retrieval attachment resource observation is unavailable")
        if value.get("gpuAccessStatus") != "none":
            raise ValueError("retrieval attachment status must not claim GPU access")
        if value.get("consumptionStatus") != "not_consumed":
            raise ValueError("retrieval attachment status overclaims consumption")
        if value.get("linkageStatus") != "complete":
            raise ValueError("retrieval attachment receipt linkage is incomplete")
        if value.get("revocationStatus") is not None:
            raise ValueError("enabled retrieval attachment must not claim revocation")
        for field in receipt_fields:
            _digest(value.get(field), f"retrieval attachment status {field}")
    else:
        expected = {
            "attachmentDataDigest": None,
            "attachmentHealth": "disabled",
            "resourceStatus": "unavailable",
            "gpuAccessStatus": "none",
            "consumptionStatus": "not_applicable",
            "linkageStatus": "not_applicable",
            "revocationStatus": "complete",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise ValueError(f"disabled retrieval attachment {field} mismatch")
        if any(value.get(field) is not None for field in receipt_fields):
            raise ValueError("disabled retrieval attachment must not expose receipts")
    return dict(value)


def validate_retrieval_status_for_spec(
    value: object,
    image_spec: dict[str, Any],
) -> dict[str, object]:
    validate_bound_retrieval_spec(image_spec)
    binding = image_spec["retrieval_binding"]
    if binding.get("schema") == BINDING_V2_SCHEMA:
        return validate_retrieval_attachment_status(value, image_spec=image_spec)
    contract = image_spec.get("retrieval_contract")
    if not isinstance(contract, dict):
        raise ValueError("retrieval status requires a component contract")
    resource = contract.get("resource")
    if not isinstance(resource, dict):
        raise ValueError("retrieval status resource profile is missing")
    return validate_retrieval_status(
        value,
        expected_component_digest=str(contract.get("component_digest") or ""),
        expected_binding_digest=str(image_spec.get("retrieval_binding_digest") or ""),
        expected_resource_profile_digest=str(resource.get("profileDigest") or ""),
        expected_gpu_access=str(resource.get("gpuAccess") or ""),
        enabled=image_spec.get("retrieval_enabled") is True,
    )


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
    binding = image_spec["retrieval_binding"]
    if binding.get("schema") == BINDING_V2_SCHEMA:
        attachment_contract = image_spec.get("retrieval_attachment_contract")
        if not isinstance(attachment_contract, dict):
            raise ValueError("retrieval attachment verifier contract is unavailable")
        argv = attachment_contract.get("verify_argv")
        expected = ALLOWED_ATTACHMENT_VERIFY_ARGV.get(str(binding.get("family") or ""))
        if not isinstance(argv, list) or expected is None or tuple(argv) != expected:
            raise ValueError("retrieval attachment verifier argv mismatch")
    else:
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
    return validate_retrieval_status_for_spec(value, image_spec)
