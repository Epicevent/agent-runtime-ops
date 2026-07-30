from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import sys
from typing import Any

from ..canonical_recipes import load_canonical_recipe
from ..domain.common import is_dev_slot
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_approval_policy import (
    load_image_approvals,
    policy_key,
    validate_image_approval_target,
)
from ..domain.retrieval_contract import RETRIEVAL_SCHEMA, SHA256_RE
from ..domain.runtime_backup import pending_rollback_identity
from ..domain.runtime_truth import live_runtime_truth
from ..domain.update_policy import (
    approved_update_from_policy,
    installed_source_commit,
    validate_update_target,
)
from ..routing import get_runtime_binding
from ..state import load_runtime_target


READONLY_OBSERVATION_SCHEMA = "agent-runtime-svcops-readonly-observation/v1"
MAX_READONLY_OBSERVATION_BYTES = 256 * 1024
_REVISION_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_CHECK_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_LINUX_ACCOUNT_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_-]{0,127}")
_LABEL_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
_IMAGE_REF_RE = re.compile(
    r"[a-z0-9][a-z0-9._:-]{0,127}"
    r"(?:/[a-z0-9][a-z0-9._-]{0,127})+"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
)
_INSTANCE_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_MAX_TEXT_BYTES = 2048
_MAX_RUNTIME_CHECKS = 64

_RUNTIME_FIELDS = (
    "instance_id",
    "linux_account",
    "truth_source",
    "truth_status",
    "family",
    "runtime_class",
    "enabled",
    "gateway_port",
    "bridge_port",
    "wrapper_image",
    "product_image",
    "runtime_profile",
    "runtime_contract",
    "canonical_recipe_name",
    "canonical_recipe_digest",
    "ops_repo_commit",
    "container_nas_root",
    "nas_read_only",
    "retrieval_labels_present",
    "retrieval_contract_complete",
    "retrieval_projection_labels_present",
    "retrieval_projection_complete",
    "retrieval_projection_consistent",
    "retrieval_schema",
    "retrieval_transport",
    "retrieval_default_enabled",
    "retrieval_enabled",
    "retrieval_component_digest",
    "retrieval_binding_digest",
    "retrieval_expected_binding_digest",
    "retrieval_resource_profile_digest",
)


class ReadonlyObservationError(RuntimeError):
    """The requested observation could not be represented safely."""


def _canonical(value: dict[str, Any]) -> bytes:
    raw = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_READONLY_OBSERVATION_BYTES:
        raise ReadonlyObservationError("observation_exceeds_output_bound")
    return raw


def _safe_text(value: object, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ReadonlyObservationError(f"{field}_is_not_text")
    if not allow_empty and not value:
        raise ReadonlyObservationError(f"{field}_is_empty")
    if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise ReadonlyObservationError(f"{field}_exceeds_bound")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ReadonlyObservationError(f"{field}_contains_control_character")
    return value


def _validated_image_digest(value: str, field: str) -> str:
    match = _IMAGE_REF_RE.fullmatch(value)
    if match is None:
        raise ReadonlyObservationError(f"{field}_not_digest_pinned")
    return match.group("digest")


def _error_payload(reason_code: str) -> dict[str, object]:
    if re.fullmatch(r"[a-z0-9_]{1,128}", reason_code) is None:
        reason_code = "observation_failed_closed"
    return {
        "schema": READONLY_OBSERVATION_SCHEMA,
        "result": "error",
        "reason_code": reason_code,
        "writes": 0,
        "network": False,
        "local_docker_read_only": True,
        "preexisting_or_product_process_signals": 0,
    }


def _update_observation(state_root: Any) -> dict[str, object]:
    installed = installed_source_commit()
    if installed and _REVISION_RE.fullmatch(installed) is None:
        return {"status": "unavailable", "reason_code": "installed_identity_invalid"}
    try:
        repo_url, approved = approved_update_from_policy(state_root)
        validate_update_target(repo_url, approved)
    except Exception:
        value: dict[str, object] = {
            "status": "not_ready",
            "approved_matches_installed": False,
        }
        if installed:
            value["installed_ref"] = installed
        return value
    matches = bool(installed) and installed == approved
    return {
        "status": "current" if matches else "ready",
        "installed_ref": installed or None,
        "approved_ref": approved,
        "approved_matches_installed": matches,
    }


def _image_identity(
    approvals: dict[str, object], family: str, role: str
) -> dict[str, object]:
    item = approvals.get(policy_key(family, role))
    if item is None:
        return {"status": "not_approved"}
    if not isinstance(item, dict):
        return {"status": "unavailable", "reason_code": "approval_record_invalid"}
    try:
        image_ref = _safe_text(item.get("approved_ref"), "approved_ref", allow_empty=False)
        digest = _safe_text(
            item.get("approved_digest"), "approved_digest", allow_empty=False
        )
        validated_digest = validate_image_approval_target(family, role, image_ref)
        if digest != validated_digest or _DIGEST_RE.fullmatch(digest) is None:
            raise ReadonlyObservationError("approved_digest_mismatch")
        source_commit = _safe_text(item.get("source_commit") or "", "source_commit")
        image_revision = _safe_text(
            item.get("image_revision") or "", "image_revision"
        )
        for field, value in (
            ("source_commit", source_commit),
            ("image_revision", image_revision),
        ):
            if value and _REVISION_RE.fullmatch(value) is None:
                raise ReadonlyObservationError(f"{field}_invalid")
    except (ReadonlyObservationError, TypeError, ValueError):
        return {"status": "unavailable", "reason_code": "approval_record_invalid"}
    return {
        "status": "approved",
        "image_ref": image_ref,
        "digest": digest,
        "source_commit": source_commit or None,
        "image_revision": image_revision or None,
    }


def _images_observation(
    state_root: Any,
    family: str,
    target: str,
    rollout: dict[str, object],
) -> dict[str, object]:
    if is_dev_slot(target):
        return {
            "status": "not_required",
            "family": family,
            "approval_required": False,
            "binding_status": "not_required_dev_target",
            "product": {"status": "not_approved"},
            "wrapper": {"status": "not_approved"},
        }
    try:
        approvals = load_image_approvals(state_root)
    except Exception:
        return {"status": "unavailable", "reason_code": "approval_policy_invalid"}
    product = _image_identity(approvals, family, "product")
    wrapper = _image_identity(approvals, family, "wrapper")
    approval_required = True
    if rollout.get("status") != "observed":
        status = "degraded"
        binding_status = "rollout_unavailable"
    elif (
        product.get("status") == "approved"
        and wrapper.get("status") == "approved"
        and product.get("digest") == rollout.get("product_digest")
        and wrapper.get("digest") == rollout.get("wrapper_digest")
    ):
        status = "observed"
        binding_status = "exact"
    elif (
        product.get("status") == "approved"
        and wrapper.get("status") == "approved"
    ):
        status = "degraded"
        binding_status = "digest_mismatch"
    else:
        status = "degraded"
        binding_status = "approval_missing"
    return {
        "status": status,
        "family": family,
        "approval_required": approval_required,
        "binding_status": binding_status,
        "product": product,
        "wrapper": wrapper,
    }


def _rollout_observation(
    state_root: Any, target: str, family: str
) -> dict[str, object]:
    try:
        runtime_target = load_runtime_target(target, state_root)
        if runtime_target.target != target:
            raise ReadonlyObservationError("runtime_manifest_target_mismatch")
        if runtime_target.family != family:
            raise ReadonlyObservationError("runtime_manifest_family_mismatch")
        observed_family = _safe_text(runtime_target.family, "runtime_family", allow_empty=False)
        runtime_class = _safe_text(
            runtime_target.runtime_class, "runtime_class", allow_empty=False
        )
        runtime_profile = _safe_text(
            runtime_target.runtime_profile, "runtime_profile", allow_empty=False
        )
        spec = runtime_target.image_spec
        wrapper_image = _safe_text(
            spec.get("wrapper_image"), "wrapper_image", allow_empty=False
        )
        product_image = _safe_text(
            spec.get("product_image"), "product_image", allow_empty=False
        )
        wrapper_digest = _validated_image_digest(wrapper_image, "wrapper_image")
        product_digest = _validated_image_digest(product_image, "product_image")
        component_digest = _safe_text(
            spec.get("retrieval_component_digest") or "",
            "retrieval_component_digest",
        )
        binding_digest = _safe_text(
            spec.get("retrieval_binding_digest") or "",
            "retrieval_binding_digest",
        )
        for field, value in (
            ("retrieval_component_digest", component_digest),
            ("retrieval_binding_digest", binding_digest),
        ):
            if value and _DIGEST_RE.fullmatch(value) is None:
                raise ReadonlyObservationError(f"{field}_invalid")
    except Exception:
        return {"status": "unavailable", "reason_code": "runtime_manifest_invalid"}
    return {
        "status": "observed",
        "target": target,
        "family": observed_family,
        "runtime_class": runtime_class,
        "runtime_profile": runtime_profile,
        "wrapper_image": wrapper_image,
        "wrapper_digest": wrapper_digest,
        "product_image": product_image,
        "product_digest": product_digest,
        "retrieval_enabled": spec.get("retrieval_enabled") is True,
        "retrieval_component_digest": component_digest or None,
        "retrieval_binding_digest": binding_digest or None,
    }


def _retrieval_projection_identity_is_exact(fields: dict[str, str]) -> bool:
    enabled = fields.get("retrieval_enabled")
    capability_declared = fields.get("retrieval_contract_complete") == "true"
    component = fields.get("retrieval_component_digest") or ""
    binding = fields.get("retrieval_binding_digest") or ""
    expected_binding = fields.get("retrieval_expected_binding_digest") or ""
    resource = fields.get("retrieval_resource_profile_digest") or ""
    common_binding_exact = bool(
        enabled in {"true", "false"}
        and fields.get("retrieval_projection_complete") == "true"
        and fields.get("retrieval_projection_consistent") == "true"
        and SHA256_RE.fullmatch(binding)
        and SHA256_RE.fullmatch(expected_binding)
        and binding == expected_binding
    )
    if not common_binding_exact:
        return False
    if capability_declared:
        return bool(
            SHA256_RE.fullmatch(component) and SHA256_RE.fullmatch(resource)
        )
    return enabled == "false" and component == "" and resource == ""


def _runtime_observation(state_root: Any, target: str) -> dict[str, object]:
    try:
        truth, checks = live_runtime_truth(target, state_root)
        fields = {
            key: _safe_text(truth[key], f"runtime_{key}")
            for key in _RUNTIME_FIELDS
            if key in truth
        }
        _validate_runtime_fields(fields, target)
        if len(checks) > _MAX_RUNTIME_CHECKS:
            raise ReadonlyObservationError("runtime_check_count_exceeds_bound")
        check_values: list[dict[str, object]] = []
        for passed, name, _detail in checks:
            if not isinstance(passed, bool) or _CHECK_NAME_RE.fullmatch(name) is None:
                raise ReadonlyObservationError("runtime_check_invalid")
            check_values.append({"name": name, "passed": passed})
        check_values.append(
            {
                "name": "observation_retrieval_projection_identity",
                "passed": _retrieval_projection_identity_is_exact(fields),
            }
        )
    except Exception:
        return {"status": "unavailable", "reason_code": "runtime_truth_invalid"}
    passed = fields.get("truth_status") == "ok" and all(
        item["passed"] is True for item in check_values
    )
    return {
        "status": "ok" if passed else "degraded",
        "fields": fields,
        "checks": check_values,
    }


def _validate_runtime_fields(fields: dict[str, str], target: str) -> None:
    if _LINUX_ACCOUNT_RE.fullmatch(target) is None:
        raise ReadonlyObservationError("target_grammar_invalid")
    if fields.get("linux_account") != target:
        raise ReadonlyObservationError("runtime_target_mismatch")
    if fields.get("family") not in {"openclaw", "hermes"}:
        raise ReadonlyObservationError("runtime_family_invalid")
    if _INSTANCE_ID_RE.fullmatch(fields.get("instance_id") or "") is None:
        raise ReadonlyObservationError("runtime_instance_id_invalid")
    for field in ("gateway_port", "bridge_port"):
        value = fields.get(field) or ""
        if not value.isdecimal() or not 1 <= int(value) <= 65535:
            raise ReadonlyObservationError(f"runtime_{field}_invalid")
    if fields.get("truth_status") != "ok":
        raise ReadonlyObservationError("runtime_truth_status_invalid")
    if fields.get("truth_source") != "live_image":
        raise ReadonlyObservationError("runtime_truth_source_invalid")
    if fields.get("runtime_class") not in {"customer", "dev"}:
        raise ReadonlyObservationError("runtime_runtime_class_invalid")
    for field in ("runtime_profile",):
        value = fields.get(field) or ""
        if _TOKEN_RE.fullmatch(value) is None:
            raise ReadonlyObservationError(f"runtime_{field}_invalid")
    if fields.get("enabled") not in {"yes", "no"}:
        raise ReadonlyObservationError("runtime_enabled_invalid")
    for field in (
        "nas_read_only",
        "retrieval_labels_present",
        "retrieval_contract_complete",
        "retrieval_projection_labels_present",
        "retrieval_projection_complete",
        "retrieval_projection_consistent",
        "retrieval_enabled",
    ):
        if fields.get(field) not in {"true", "false"}:
            raise ReadonlyObservationError(f"runtime_{field}_invalid")
    if fields.get("nas_read_only") != "true":
        raise ReadonlyObservationError("runtime_nas_read_only_policy_mismatch")
    for field in ("wrapper_image", "product_image"):
        value = fields.get(field) or ""
        _validated_image_digest(value, f"runtime_{field}")
    if _DIGEST_RE.fullmatch(fields.get("canonical_recipe_digest") or "") is None:
        raise ReadonlyObservationError("runtime_canonical_recipe_digest_invalid")
    for field in (
        "retrieval_component_digest",
        "retrieval_binding_digest",
        "retrieval_expected_binding_digest",
        "retrieval_resource_profile_digest",
    ):
        value = fields.get(field) or ""
        if value and _DIGEST_RE.fullmatch(value) is None:
            raise ReadonlyObservationError(f"runtime_{field}_invalid")
    capability_declared = fields.get("retrieval_contract_complete") == "true"
    retrieval_enabled = fields.get("retrieval_enabled")
    retrieval_schema = fields.get("retrieval_schema") or ""
    retrieval_transport = fields.get("retrieval_transport") or ""
    retrieval_default_enabled = fields.get("retrieval_default_enabled") or ""
    retrieval_component = fields.get("retrieval_component_digest") or ""
    retrieval_resource = fields.get("retrieval_resource_profile_digest") or ""
    if capability_declared:
        if retrieval_schema != RETRIEVAL_SCHEMA:
            raise ReadonlyObservationError("runtime_retrieval_schema_mismatch")
        if retrieval_transport != "in_process":
            raise ReadonlyObservationError("runtime_retrieval_transport_mismatch")
        if retrieval_default_enabled != "false":
            raise ReadonlyObservationError(
                "runtime_retrieval_default_enabled_policy_mismatch"
            )
        if not (
            _DIGEST_RE.fullmatch(retrieval_component)
            and _DIGEST_RE.fullmatch(retrieval_resource)
        ):
            raise ReadonlyObservationError(
                "runtime_retrieval_capability_digest_mismatch"
            )
    elif not (
        retrieval_enabled == "false"
        and retrieval_schema == ""
        and retrieval_transport == ""
        and retrieval_default_enabled == ""
        and retrieval_component == ""
        and retrieval_resource == ""
    ):
        raise ReadonlyObservationError(
            "runtime_retrieval_capability_absence_mismatch"
        )
    if _REVISION_RE.fullmatch(fields.get("ops_repo_commit") or "") is None:
        raise ReadonlyObservationError("runtime_ops_repo_commit_invalid")
    recipe_name = fields.get("canonical_recipe_name") or ""
    runtime_contract = fields.get("runtime_contract") or ""
    if _TOKEN_RE.fullmatch(recipe_name) is None:
        raise ReadonlyObservationError("runtime_canonical_recipe_name_invalid")
    if _LABEL_VALUE_RE.fullmatch(runtime_contract) is None:
        raise ReadonlyObservationError("runtime_contract_invalid")
    try:
        recipe = load_canonical_recipe(recipe_name)
        runtime_class = fields["runtime_class"]
        expected_contracts = recipe.data.get("runtime_contracts")
        expected_profiles = recipe.data.get("runtime_profiles")
        if not isinstance(expected_contracts, dict) or not isinstance(
            expected_profiles, dict
        ):
            raise ReadonlyObservationError("runtime_canonical_recipe_invalid")
        if recipe.data.get("family") != fields.get("family"):
            raise ReadonlyObservationError("runtime_canonical_recipe_family_mismatch")
        if recipe.digest != fields.get("canonical_recipe_digest"):
            raise ReadonlyObservationError("runtime_canonical_recipe_digest_mismatch")
        if expected_contracts.get(runtime_class) != runtime_contract:
            raise ReadonlyObservationError("runtime_contract_mismatch")
        if expected_profiles.get(runtime_class) != fields.get("runtime_profile"):
            raise ReadonlyObservationError("runtime_profile_mismatch")
        if fields.get("container_nas_root") != recipe.data.get(
            "container_nas_root"
        ):
            raise ReadonlyObservationError("runtime_container_nas_root_mismatch")
    except ReadonlyObservationError:
        raise
    except Exception as exc:
        raise ReadonlyObservationError("runtime_canonical_recipe_invalid") from exc
    if capability_declared:
        for field in ("retrieval_schema", "retrieval_transport"):
            if _LABEL_VALUE_RE.fullmatch(fields.get(field) or "") is None:
                raise ReadonlyObservationError(f"runtime_{field}_invalid")
    container_nas_root = fields.get("container_nas_root") or ""
    if not container_nas_root.startswith("/") or ".." in container_nas_root.split("/"):
        raise ReadonlyObservationError("runtime_container_nas_root_invalid")


def _binding_identity(binding: Any, target: str) -> dict[str, object]:
    if binding.linux_account != target or _LINUX_ACCOUNT_RE.fullmatch(target) is None:
        raise ReadonlyObservationError("target_alias_not_allowed")
    if binding.family not in {"openclaw", "hermes"}:
        raise ReadonlyObservationError("target_family_invalid")
    if _TOKEN_RE.fullmatch(str(binding.runtime_class)) is None:
        raise ReadonlyObservationError("target_runtime_class_invalid")
    if _INSTANCE_ID_RE.fullmatch(str(binding.instance_id)) is None:
        raise ReadonlyObservationError("target_instance_id_invalid")
    if _HOST_RE.fullmatch(str(binding.public_host)) is None:
        raise ReadonlyObservationError("target_public_host_invalid")
    for field in ("gateway_port", "bridge_port"):
        value = getattr(binding, field)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
            raise ReadonlyObservationError(f"target_{field}_invalid")
    return {
        "bridge_port": int(binding.bridge_port),
        "enabled": bool(binding.enabled),
        "family": str(binding.family),
        "gateway_port": int(binding.gateway_port),
        "instance_id": str(binding.instance_id),
        "linux_account": str(binding.linux_account),
        "public_host": str(binding.public_host),
        "runtime_class": str(binding.runtime_class),
    }


def _transaction_observation(state_root: Any, target: str) -> dict[str, object]:
    try:
        identity = pending_rollback_identity(state_root, target)
    except Exception:
        return {
            "status": "unavailable",
            "state": "unavailable",
            "reason_code": "rollback_transaction_invalid",
        }
    if identity is None:
        return {
            "status": "observed",
            "state": "no_pending_transaction",
            "pending_marker": False,
        }
    return {
        "status": "observed",
        "state": "pending",
        "pending_marker": True,
        **identity,
    }


def _coherence_observation(
    initial_binding: dict[str, object],
    final_binding: dict[str, object],
    initial_rollout: dict[str, object],
    final_rollout: dict[str, object],
    initial_transaction: dict[str, object],
    final_transaction: dict[str, object],
    runtime: dict[str, object],
) -> dict[str, object]:
    if (
        initial_binding != final_binding
        or initial_rollout != final_rollout
        or initial_transaction != final_transaction
    ):
        return {"status": "changed_during_observation"}
    if initial_rollout.get("status") != "observed" or runtime.get("status") not in {
        "ok",
        "degraded",
    }:
        return {"status": "unavailable"}
    fields = runtime.get("fields")
    if not isinstance(fields, dict):
        return {"status": "unavailable"}
    matches = all(
        (
            fields.get("instance_id") == initial_binding.get("instance_id"),
            fields.get("linux_account") == initial_rollout.get("target"),
            fields.get("family") == initial_rollout.get("family"),
            fields.get("runtime_class") == initial_rollout.get("runtime_class"),
            fields.get("gateway_port")
            == str(initial_binding.get("gateway_port")),
            fields.get("bridge_port") == str(initial_binding.get("bridge_port")),
            fields.get("runtime_profile") == initial_rollout.get("runtime_profile"),
            fields.get("wrapper_image") == initial_rollout.get("wrapper_image"),
            fields.get("product_image") == initial_rollout.get("product_image"),
        )
    )
    return {"status": "consistent" if matches else "mixed_snapshot"}


def build_readonly_observation(args: argparse.Namespace) -> dict[str, object]:
    state_root = _state_root(args)
    target = _safe_text(args.target, "target", allow_empty=False)
    try:
        binding = get_runtime_binding(target, state_root)
        if not binding.enabled:
            raise ReadonlyObservationError("target_disabled")
        if binding.linux_account != target:
            raise ReadonlyObservationError("target_alias_not_allowed")
        family = binding.family
        if family not in {"openclaw", "hermes"}:
            raise ReadonlyObservationError("target_family_invalid")
    except Exception as exc:
        if isinstance(exc, ReadonlyObservationError):
            raise
        raise ReadonlyObservationError("target_not_observable") from exc
    initial_binding = _binding_identity(binding, target)
    initial_rollout = _rollout_observation(state_root, target, family)
    observations = {
        "update": _update_observation(state_root),
        "images": _images_observation(
            state_root, family, target, initial_rollout
        ),
        "rollout": initial_rollout,
        "runtime": _runtime_observation(state_root, target),
        "transaction": _transaction_observation(state_root, target),
    }
    try:
        final_binding = _binding_identity(
            get_runtime_binding(target, state_root), target
        )
        final_rollout = _rollout_observation(state_root, target, family)
        final_transaction = _transaction_observation(state_root, target)
    except Exception:
        final_binding = {}
        final_rollout = {"status": "unavailable"}
        final_transaction = {"status": "unavailable", "state": "unavailable"}
    observations["coherence"] = _coherence_observation(
        initial_binding,
        final_binding,
        observations["rollout"],
        final_rollout,
        observations["transaction"],
        final_transaction,
        observations["runtime"],
    )
    runtime_status = observations["runtime"].get("status")
    runtime_state = (
        "healthy"
        if runtime_status == "ok"
        else "degraded" if runtime_status == "degraded" else "unavailable"
    )
    transaction_state = str(observations["transaction"].get("state"))
    terminal_state = "unknown"
    source_planes_current = all(
        (
            observations["update"].get("status") == "current",
            observations["images"].get("status")
            in {"observed", "not_required"},
            observations["rollout"].get("status") == "observed",
        )
    )
    if (
        not source_planes_current
        or observations["coherence"].get("status") != "consistent"
        or runtime_state != "healthy"
        or transaction_state == "unavailable"
    ):
        result = "degraded"
    elif transaction_state == "pending":
        result = "incomplete"
    else:
        result = "observed"
    return {
        "schema": READONLY_OBSERVATION_SCHEMA,
        "result": result,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target,
        "family": family,
        "runtime_state": runtime_state,
        "transaction_state": transaction_state,
        "terminal_state": terminal_state,
        "canary_completion_claimed": False,
        "claim_scope": "runtime_observation_only",
        "observations": observations,
        "writes": 0,
        "network": False,
        "local_docker_read_only": True,
        "preexisting_or_product_process_signals": 0,
    }


def _emit(value: dict[str, object]) -> None:
    sys.stdout.buffer.write(_canonical(value))


def cmd_observation_status(args: argparse.Namespace) -> int:
    if not _is_root():
        _emit(_error_payload("root_observation_required"))
        return 2
    try:
        value = build_readonly_observation(args)
        _emit(value)
    except ReadonlyObservationError as exc:
        _emit(_error_payload(str(exc)))
        return 2
    except Exception:
        _emit(_error_payload("observation_failed_closed"))
        return 2
    return 0 if value["result"] == "observed" else 1
