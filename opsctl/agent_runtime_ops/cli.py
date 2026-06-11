from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import getpass
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.error
import urllib.request
from pathlib import Path

from .apache import parse_apache_route
from .commands.apache import cmd_apache_set_host, cmd_apache_status
from .commands.binding import (
    cmd_binding_list,
    cmd_binding_normalize,
    cmd_binding_set_public_host,
    cmd_binding_status,
)
from .commands.diagnostics import cmd_diagnostics_show
from .commands.document_tools import cmd_document_tools_status
from .commands.profile import cmd_profile_list
from .commands.runtime_truth import _live_runtime_truth, cmd_runtime_truth
from .commands.status import cmd_plan, cmd_status
from .commands.update import cmd_self_update, cmd_update_approve, cmd_update_status
from .canonical_recipes import (
    canonical_label_values,
    canonical_recipe_for_product,
    canonical_recipe_for_image_spec,
    canonical_recipe_identity,
    list_canonical_recipe_names,
    load_canonical_recipe,
    projection_checks as canonical_projection_checks,
    validate_canonical_recipe,
)
from .compose_contract import validate_compose_contract
from .domain.runtime_truth import local_canonical_recipe_check_from_truth as _local_canonical_recipe_check_from_truth
from .domain.apache_route_checks import apache_route_checks as _apache_route_checks
from .domain.source_provenance import require_fresh_clean_source_provenance as _require_fresh_clean_source_provenance
from .domain.source_provenance import source_provenance as _source_provenance
from .domain.update_policy import installed_source_commit as _installed_source_commit
from .host.fstab import (
    fstab_escape as _fstab_escape,
    managed_fstab_marker as _managed_fstab_marker,
    remove_managed_fstab_entry as _remove_managed_fstab_entry,
    write_managed_fstab_entry as _host_write_managed_fstab_entry,
)
from .host.files import atomic_write_text as _atomic_write_text
from .host.files import fsync_parent as _fsync_parent
from .host.mounts import (
    findmnt_one as _findmnt_one,
    findmnt_tree as _findmnt_tree,
    findmnt_under as _findmnt_under,
    is_readonly_mount as _is_readonly_mount,
    mount_prepared_share as _host_mount_prepared_share,
    mounted_child_cifs_count as _mounted_child_cifs_count,
    propagation_satisfies as _propagation_satisfies,
    safe_mountpoint_path as _safe_mountpoint_path,
)
from .image_components import image_component_name as _image_component_name
from .image_components import image_repo as _image_repo
from .paths import DEFAULT_STATE_ROOT, REPO_ROOT
from .nas import (
    agent_nas_dir,
    check_nas_policy,
    customer_credential_path,
    history_dir,
    mountpoint_for_share,
    parse_smb_share,
    request_dir,
    request_path,
    root_credential_path,
)
from .profiles import load_profile
from .redaction import redact
from .renderer import render_compose
from .routing import (
    RuntimeBinding,
    get_runtime_binding,
    load_runtime_bindings,
    validate_linux_account,
)
from .runtime_secrets import (
    RUNTIME_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_runtime_secret_values,
)
from .state import RuntimeTarget, digest_from_image_ref, image_spec_from_manifest, load_runtime_target, runtime_manifest_path
from .yamlio import dump_yaml, load_yaml

SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"
DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"
IMAGE_RECIPE_LABEL_PREFIX = "com.epicevent.agent-runtime."
IMAGE_RECIPE_SCHEMA = "v1"
IMAGE_ROLLOUT_IMAGE_NAME = "direct-image"


def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


def _apache_public_host(slot: str) -> str:
    try:
        return parse_apache_route(slot).public_host
    except Exception:
        return ""


def _has_digest_ref(value: object) -> bool:
    return isinstance(value, str) and "@sha256:" in value


def _digest_from_image_ref(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def _validate_safe_name(name: str) -> None:
    if not SAFE_NAME_RE.match(name):
        raise ValueError("name must contain only letters, numbers, '.', '_', or '-'")


def _validate_image_digest_ref(image_ref: str) -> str:
    if not IMAGE_REF_RE.match(image_ref):
        raise ValueError("image reference must be pinned by digest: REGISTRY/IMAGE@sha256:<64 hex>")
    digest = _digest_from_image_ref(image_ref)
    if not digest or not DIGEST_RE.match(digest):
        raise ValueError("image reference digest must be sha256:<64 hex>")
    return digest


def _optional_safe_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if text and not SAFE_TEXT_RE.match(text):
        raise ValueError(f"{name} must not contain control characters")
    return text


def _allowed_image_ref(family: object, role: str, image_ref: object) -> bool:
    if not isinstance(family, str) or not isinstance(image_ref, str):
        return False
    allowed = {
        ("openclaw", "wrapper"): (
            "ghcr.io/epicevent/agent-runtime-openclaw@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("openclaw", "product"): (
            "ghcr.io/epicevent/openclaw-jitech@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("hermes", "wrapper"): (
            "ghcr.io/epicevent/agent-runtime-hermes@sha256:",
            "ghcr.io/epicevent/hermes-jitech@sha256:",
            "ghcr.io/epicevent/hermes-workspace@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("hermes", "product"): (
            "ghcr.io/epicevent/hermes-jitech@sha256:",
            "ghcr.io/epicevent/hermes-runtime@sha256:",
            "ghcr.io/epicevent/hermes-workspace@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
    }
    return image_ref.startswith(allowed.get((family, role), ()))


def _metadata_list(value: object) -> list[str]:
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if isinstance(item, dict) and len(item) == 1 and next(iter(item.values())) is None:
                items.append(str(next(iter(item.keys()))))
            elif str(item):
                items.append(str(item))
        return items
    if isinstance(value, str) and value:
        return [value]
    return []


def _csv(values: list[str]) -> str:
    return ",".join(values)


def _label_map_from_string(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        key, sep, raw_value = item.partition("=")
        if not sep:
            raise ValueError(f"invalid label map item: {item}")
        key = key.strip()
        raw_value = raw_value.strip()
        if not SAFE_NAME_RE.match(key):
            raise ValueError(f"invalid label map key: {key}")
        if not raw_value:
            raise ValueError(f"empty label map value: {key}")
        result[key] = raw_value
    return result


def _label_map_from_json(value: str) -> dict[str, str]:
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid label map json: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("label map json must be an object")
    result: dict[str, str] = {}
    for key, raw_value in data.items():
        key_text = str(key).strip()
        value_text = str(raw_value).strip()
        if not SAFE_NAME_RE.match(key_text):
            raise ValueError(f"invalid label map key: {key_text}")
        if not value_text:
            raise ValueError(f"empty label map value: {key_text}")
        result[key_text] = value_text
    return result


def _label_map_from_labels(labels: dict[str, str], name: str) -> dict[str, str]:
    json_value = _recipe_label(labels, f"{name}.json")
    if json_value:
        return _label_map_from_json(json_value)
    csv_value = _recipe_label(labels, name)
    return _label_map_from_string(csv_value) if csv_value else {}


def _label_map_to_string(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    return ",".join(f"{key}={value[key]}" for key in sorted(value) if str(key) and str(value[key]))


def _label_map_to_json(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    result = {str(key): str(item) for key, item in value.items() if str(key) and str(item)}
    if not result:
        return ""
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def _profile_runtime_contract(profile) -> str:
    return str(profile.metadata.get("runtime_contract") or "")


def _profile_customer_surface(profile) -> str:
    return str(profile.metadata.get("customer_surface") or "")


def _image_spec_recipe_payload(image_spec: dict) -> dict[str, object]:
    product_image = image_spec.get("product_image")
    wrapper_image = image_spec.get("wrapper_image")
    image_recipe = _image_spec_recipe(image_spec)
    canonical_recipe = canonical_recipe_for_image_spec(image_spec)
    payload: dict[str, object] = {
        "mode": image_spec.get("mode") or "unknown",
        "product_component": image_recipe.get("product_component") or _image_component_name(product_image),
        "wrapper_component": image_recipe.get("wrapper_component") or _image_component_name(wrapper_image),
        "product_repo": _image_repo(product_image),
        "wrapper_repo": _image_repo(wrapper_image),
    }
    payload.update(canonical_recipe_identity(canonical_recipe))
    components = image_spec.get("components")
    if isinstance(components, dict):
        payload["components"] = {str(key): str(value) for key, value in components.items()}
    if image_recipe:
        payload["image_recipe"] = image_recipe
    return payload


def _image_spec_recipe_tokens(image_spec: dict) -> dict[str, str]:
    recipe = _image_spec_recipe_payload(image_spec)
    return {
        "recipe_mode": str(recipe.get("mode") or "unknown"),
        "product_component": str(recipe.get("product_component") or "unknown"),
        "wrapper_component": str(recipe.get("wrapper_component") or "unknown"),
        "canonical_recipe_name": str(recipe.get("canonical_recipe_name") or "unknown"),
        "canonical_recipe_digest": str(recipe.get("canonical_recipe_digest") or "unknown"),
    }


def _derived_image_components(product_image: str, wrapper_image: str) -> dict[str, str]:
    return {
        "product_image": product_image,
        "wrapper_image": wrapper_image,
        "product_component": _image_component_name(product_image),
        "wrapper_component": _image_component_name(wrapper_image),
    }


def _image_recipe_labels_from_wrapper(wrapper_image: str) -> dict[str, str]:
    docker = shutil.which("docker")
    if not docker:
        raise ValueError("docker is required to inspect wrapper image recipe labels")
    inspect = _run_text([docker, "image", "inspect", wrapper_image, "--format", "{{json .Config.Labels}}"], timeout=60)
    if inspect.returncode != 0:
        pull = _run_text([docker, "pull", wrapper_image], timeout=600)
        if pull.returncode != 0:
            raise ValueError(f"failed to pull wrapper image for recipe labels: {pull.stderr.strip() or pull.stdout.strip()}")
        inspect = _run_text([docker, "image", "inspect", wrapper_image, "--format", "{{json .Config.Labels}}"], timeout=60)
    if inspect.returncode != 0:
        raise ValueError(f"failed to inspect wrapper image recipe labels: {inspect.stderr.strip() or inspect.stdout.strip()}")
    try:
        labels = json.loads(inspect.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"wrapper image labels are not valid JSON: {exc}") from exc
    if not isinstance(labels, dict):
        raise ValueError("wrapper image labels are missing")
    return {str(key): str(value) for key, value in labels.items()}


def _recipe_label(labels: dict[str, str], name: str) -> str:
    return str(labels.get(IMAGE_RECIPE_LABEL_PREFIX + name) or "")


def _image_recipe_from_wrapper_image(wrapper_image: str, *, family: str, product_image: str) -> dict[str, object]:
    labels = _image_recipe_labels_from_wrapper(wrapper_image)
    schema = _recipe_label(labels, "recipe.schema")
    if schema != IMAGE_RECIPE_SCHEMA:
        raise ValueError(
            "wrapper image is missing agent-runtime recipe labels; rebuild wrapper with current publish workflow"
        )
    label_family = _recipe_label(labels, "family")
    label_product_image = _recipe_label(labels, "product-image")
    if label_family != family:
        raise ValueError(f"wrapper image recipe family mismatch: label={label_family or 'missing'} requested={family}")
    if label_product_image != product_image:
        raise ValueError("wrapper image recipe product-image does not match --product-image")
    customer_profile = _recipe_label(labels, "runtime-profile.customer")
    dev_profile = _recipe_label(labels, "runtime-profile.dev")
    customer_contract = _recipe_label(labels, "runtime-contract.customer")
    dev_contract = _recipe_label(labels, "runtime-contract.dev")
    product_component = _recipe_label(labels, "product-component")
    wrapper_component = _recipe_label(labels, "wrapper-component")
    command_mode = _recipe_label(labels, "command-mode")
    http_port = _recipe_label(labels, "http-port")
    source_output_target = _recipe_label(labels, "source-output-target")
    nas_container_root = _recipe_label(labels, "nas.container-root")
    nas_host_root_template = _recipe_label(labels, "nas.host-root-template")
    nas_read_only = _recipe_label(labels, "nas.read-only")
    nas_propagation = _recipe_label(labels, "nas.propagation")
    nas_child_mount_mode = _recipe_label(labels, "nas.child-mount-mode")
    contract_version = _recipe_label(labels, "contract.version")
    health_endpoints_label = _recipe_label(labels, "health.endpoints")
    health_endpoints_json_label = _recipe_label(labels, "health.endpoints.json")
    canonical_name = _recipe_label(labels, "recipe.name")
    canonical_digest = _recipe_label(labels, "recipe.digest")
    if not canonical_name:
        raise ValueError("wrapper image recipe is missing canonical recipe name")
    if not canonical_digest:
        raise ValueError("wrapper image recipe is missing canonical recipe digest")
    required = {
        "recipe.name": canonical_name,
        "recipe.digest": canonical_digest,
        "product-component": product_component,
        "wrapper-component": wrapper_component,
        "runtime-profile.customer": customer_profile,
        "runtime-profile.dev": dev_profile,
        "runtime-contract.customer": customer_contract,
        "runtime-contract.dev": dev_contract,
        "command-mode": command_mode,
        "http-port": http_port,
        "source-output-target": source_output_target,
        "nas.container-root": nas_container_root,
        "nas.host-root-template": nas_host_root_template,
        "nas.read-only": nas_read_only,
        "nas.propagation": nas_propagation,
        "nas.child-mount-mode": nas_child_mount_mode,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError("wrapper image recipe labels are incomplete: " + ",".join(missing))
    derived_product_component = _image_component_name(product_image)
    derived_wrapper_component = _image_component_name(wrapper_image)
    if product_component != derived_product_component:
        raise ValueError(
            f"wrapper image recipe product-component mismatch: label={product_component} derived={derived_product_component}"
        )
    if wrapper_component != derived_wrapper_component:
        raise ValueError(
            f"wrapper image recipe wrapper-component mismatch: label={wrapper_component} derived={derived_wrapper_component}"
        )
    canonical_recipe = load_canonical_recipe(canonical_name)
    canonical_failures = [name for ok, name, _ in validate_canonical_recipe(canonical_recipe) if not ok]
    if canonical_failures:
        raise ValueError("canonical runtime recipe validation failed: " + ",".join(canonical_failures))
    expected_labels = canonical_label_values(canonical_recipe)
    label_checks = {
        "product-component": product_component,
        "wrapper-component": wrapper_component,
        "runtime-profile.customer": customer_profile,
        "runtime-profile.dev": dev_profile,
        "runtime-contract.customer": customer_contract,
        "runtime-contract.dev": dev_contract,
        "command-mode": command_mode,
        "working-dir": _recipe_label(labels, "working-dir"),
        "http-port": http_port,
        "source-output-target": source_output_target,
        "nas.container-root": nas_container_root,
        "nas.host-root-template": nas_host_root_template,
        "nas.read-only": nas_read_only,
        "nas.propagation": nas_propagation,
        "nas.child-mount-mode": nas_child_mount_mode,
    }
    if expected_labels.get("contract.version"):
        label_checks["contract.version"] = contract_version
    for label_name, actual in label_checks.items():
        expected = expected_labels[label_name]
        if actual != expected:
            raise ValueError(
                f"wrapper image canonical recipe mismatch: {label_name} label={actual or 'missing'} canonical={expected or 'missing'}"
            )
    if expected_labels.get("health.endpoints.json"):
        expected_health_endpoints = _label_map_from_json(expected_labels["health.endpoints.json"])
        actual_health_endpoints = _label_map_from_labels(labels, "health.endpoints")
        if actual_health_endpoints != expected_health_endpoints:
            actual = health_endpoints_json_label or health_endpoints_label
            raise ValueError(
                "wrapper image canonical recipe mismatch: health.endpoints "
                f"label={actual or 'missing'} canonical={expected_labels['health.endpoints.json']}"
            )
    if canonical_name and canonical_name != canonical_recipe.name:
        raise ValueError(f"wrapper image canonical recipe name mismatch: label={canonical_name} canonical={canonical_recipe.name}")
    if canonical_digest and canonical_digest != canonical_recipe.digest:
        raise ValueError(
            f"wrapper image canonical recipe digest mismatch: label={canonical_digest} canonical={canonical_recipe.digest}"
        )
    recipe = {
        "schema": schema,
        "source": "wrapper_image_labels",
        "canonical_recipe_name": canonical_recipe.name,
        "canonical_recipe_digest": canonical_recipe.digest,
        "family": label_family,
        "product_image": label_product_image,
        "product_component": product_component,
        "wrapper_component": wrapper_component,
        "runtime_profiles": {
            "customer": customer_profile,
            "dev": dev_profile,
        },
        "runtime_contracts": {
            "customer": customer_contract,
            "dev": dev_contract,
        },
        "command_mode": command_mode,
        "working_dir": _recipe_label(labels, "working-dir"),
        "http_port": http_port,
        "source_output_target": source_output_target,
        "container_nas_root": nas_container_root,
        "host_nas_root_template": nas_host_root_template,
        "nas_read_only": nas_read_only,
        "nas_mount_propagation": nas_propagation,
        "nas_child_mount_mode": nas_child_mount_mode,
        "contract_version": contract_version,
        "health_endpoints": _label_map_from_labels(labels, "health.endpoints"),
        "ops_repo_commit": _recipe_label(labels, "ops-repo-commit"),
    }
    for runtime_class, profile_name in recipe["runtime_profiles"].items():
        profile = load_profile(str(profile_name))
        if profile.metadata.get("family") != family:
            raise ValueError(f"recipe {runtime_class} profile family mismatch: {profile_name}")
        if profile.metadata.get("slot_class") != runtime_class:
            raise ValueError(f"recipe {runtime_class} profile runtime_class mismatch: {profile_name}")
        expected_contract = recipe["runtime_contracts"][runtime_class]
        if profile.metadata.get("runtime_contract") != expected_contract:
            raise ValueError(f"recipe {runtime_class} profile contract mismatch: {profile_name}")
        profile_component = str(profile.metadata.get("product_component") or "")
        if profile_component and profile_component != product_component:
            raise ValueError(f"recipe {runtime_class} profile product_component mismatch: {profile_name}")
    return recipe


def _image_recipe_from_wrapper_image_auto(wrapper_image: str, *, product_image: str) -> dict[str, object]:
    labels = _image_recipe_labels_from_wrapper(wrapper_image)
    family = _recipe_label(labels, "family")
    if family not in {"openclaw", "hermes"}:
        raise ValueError(f"wrapper image recipe family mismatch: label={family or 'missing'}")
    return _image_recipe_from_wrapper_image(wrapper_image, family=family, product_image=product_image)


def _image_spec_from_direct_images(wrapper_image: str, product_image: str) -> dict[str, object]:
    wrapper_digest = _validate_image_digest_ref(wrapper_image)
    product_digest = _validate_image_digest_ref(product_image)
    image_recipe = _image_recipe_from_wrapper_image_auto(wrapper_image, product_image=product_image)
    family = str(image_recipe.get("family") or "")
    if family not in {"openclaw", "hermes"}:
        raise ValueError("wrapper image recipe did not declare a supported family")
    if not _allowed_image_ref(family, "wrapper", wrapper_image):
        raise ValueError(f"wrapper image repository is not allowed for {family}")
    if not _allowed_image_ref(family, "product", product_image):
        raise ValueError(f"product image repository is not allowed for {family}")
    components = _derived_image_components(product_image, wrapper_image)
    components.update(
        {
            "product_component": str(image_recipe.get("product_component") or components["product_component"]),
            "wrapper_component": str(image_recipe.get("wrapper_component") or components["wrapper_component"]),
            "canonical_recipe_name": str(image_recipe.get("canonical_recipe_name") or ""),
            "canonical_recipe_digest": str(image_recipe.get("canonical_recipe_digest") or ""),
            "runtime_profile_customer": str(
                (image_recipe.get("runtime_profiles") or {}).get("customer")
                if isinstance(image_recipe.get("runtime_profiles"), dict)
                else ""
            ),
            "runtime_profile_dev": str(
                (image_recipe.get("runtime_profiles") or {}).get("dev")
                if isinstance(image_recipe.get("runtime_profiles"), dict)
                else ""
            ),
        }
    )
    return {
        "family": family,
        "image_name": IMAGE_ROLLOUT_IMAGE_NAME,
        "product_image": product_image,
        "wrapper_image": wrapper_image,
        "digest": wrapper_digest,
        "product_digest": product_digest,
        "components": components,
        "mode": "wrapped_product_image",
        "image_recipe": image_recipe,
    }


def _image_spec_recipe(image_spec: dict) -> dict[str, object]:
    recipe = image_spec.get("image_recipe")
    return recipe if isinstance(recipe, dict) else {}


def _image_spec_runtime_profile_name(image_spec: dict, runtime_class: str, fallback: str | None = None) -> str:
    recipe = _image_spec_recipe(image_spec)
    profiles = recipe.get("runtime_profiles")
    if isinstance(profiles, dict) and profiles.get(runtime_class):
        return str(profiles[runtime_class])
    if image_spec.get("mode") == "wrapped_product_image":
        raise ValueError("wrapped image is missing image recipe runtime profile; rebuild a labeled wrapper image")
    return str(fallback or "")


def _image_spec_profile_contract_checks(image_spec: dict, profile) -> list[tuple[bool, str, str | None]]:
    runtime_contract = _profile_runtime_contract(profile)
    customer_surface = _profile_customer_surface(profile)
    expected_components = _metadata_list(profile.metadata.get("expected_image_components"))
    compatible_product_prefixes = _metadata_list(profile.metadata.get("compatible_product_image_prefixes"))
    product_image = str(image_spec.get("product_image") or "")
    runtime_class = str(profile.metadata.get("slot_class") or "")
    image_recipe = _image_spec_recipe(image_spec)
    canonical_recipe = canonical_recipe_for_image_spec(image_spec)
    checks: list[tuple[bool, str, str | None]] = [
        (bool(runtime_contract), "runtime_contract_declared", f"contract={runtime_contract or 'missing'}"),
        (
            bool(customer_surface),
            "runtime_contract_customer_surface_declared",
            f"surface={customer_surface or 'missing'}",
        ),
    ]
    if canonical_recipe is not None:
        runtime_class = str(profile.metadata.get("slot_class") or "")
        canonical_profiles = canonical_recipe.data.get("runtime_profiles")
        canonical_profile_name = (
            canonical_profiles.get(runtime_class)
            if isinstance(canonical_profiles, dict)
            else ""
        )
        checks.extend(
            [
                (True, "canonical_recipe_identified", f"name={canonical_recipe.name} digest={canonical_recipe.digest}"),
                (
                    canonical_profile_name == profile.name,
                    "canonical_projection_matches_runtime_profile",
                    f"recipe={canonical_profile_name or 'missing'} profile={profile.name}",
                ),
                (
                    _image_repo(product_image) == canonical_recipe.data.get("product_image_repo"),
                    "canonical_product_repo_matches_image_spec",
                    f"image_spec={_image_repo(product_image) or 'missing'} canonical={canonical_recipe.data.get('product_image_repo') or 'missing'}",
                ),
                (
                    image_spec.get("mode") != "wrapped_product_image"
                    or _image_repo(image_spec.get("wrapper_image")) == canonical_recipe.data.get("wrapper_repo"),
                    "canonical_wrapper_repo_matches_image_spec",
                    f"image_spec={_image_repo(image_spec.get('wrapper_image')) or 'missing'} canonical={canonical_recipe.data.get('wrapper_repo') or 'missing'}",
                ),
                (
                    not image_recipe or image_recipe.get("canonical_recipe_digest") in (None, "", canonical_recipe.digest),
                    "canonical_recipe_digest_matches_image_spec",
                    f"image_spec={image_recipe.get('canonical_recipe_digest') if image_recipe else 'derived'} canonical={canonical_recipe.digest}",
                ),
            ]
        )
        checks.extend(canonical_projection_checks(canonical_recipe, runtime_class))
    elif image_spec.get("mode") == "wrapped_product_image":
        checks.append((False, "canonical_recipe_identified", f"product_image={product_image or 'missing'}"))
    else:
        checks.append((True, "canonical_recipe_not_required_for_unwrapped_image", f"product_image={product_image or 'missing'}"))
    if image_recipe:
        runtime_profiles = image_recipe.get("runtime_profiles")
        expected_profile = runtime_profiles.get(runtime_class) if isinstance(runtime_profiles, dict) else ""
        checks.append(
            (
                expected_profile == profile.name,
                "image_recipe_profile_matches_runtime_profile",
                f"recipe={expected_profile or 'missing'} profile={profile.name}",
            )
        )
        runtime_contracts = image_recipe.get("runtime_contracts")
        expected_contract = runtime_contracts.get(runtime_class) if isinstance(runtime_contracts, dict) else ""
        checks.append(
            (
                expected_contract == runtime_contract,
                "image_recipe_contract_matches_profile",
                f"recipe={expected_contract or 'missing'} profile={runtime_contract or 'missing'}",
            )
        )
        checks.append(
            (
                image_recipe.get("product_image") == product_image,
                "image_recipe_product_image_matches_spec",
                f"recipe={image_recipe.get('product_image') or 'missing'} image_spec={product_image or 'missing'}",
            )
        )
        profile_component = str(profile.metadata.get("product_component") or "")
        if profile_component:
            checks.append(
                (
                    image_recipe.get("product_component") == profile_component,
                    "image_recipe_product_component_matches_profile",
                    f"recipe={image_recipe.get('product_component') or 'missing'} profile={profile_component}",
                )
            )
    if expected_components:
        checks.append(
            (
                True,
                "runtime_contract_expected_components",
                "components=" + _csv(expected_components),
            )
        )
    if compatible_product_prefixes:
        ok = any(product_image.startswith(prefix) for prefix in compatible_product_prefixes)
        checks.append(
            (
                ok,
                "product_image_matches_runtime_contract",
                (
                    f"contract={runtime_contract or 'unknown'} "
                    f"product_component={_image_component_name(product_image)} "
                    f"expected_prefixes={_csv(compatible_product_prefixes)}"
                ),
            )
        )
    return checks


def _image_spec_profile_contract_failures(image_spec: dict, profile) -> list[str]:
    return [name for ok, name, _ in _image_spec_profile_contract_checks(image_spec, profile) if not ok]


def _container_name(slot: str, profile) -> str:
    service = profile.metadata.get("service") or "openclaw-gateway"
    return f"openclaw-{slot}-{service}-1"


def _run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _run_text_cwd(command: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _http_backend_smoke(slot: str, path: str, state_root: Path) -> tuple[bool, str]:
    try:
        binding = get_runtime_binding(slot, state_root)
        apache_route = parse_apache_route(binding.linux_account)
    except Exception as exc:
        return False, f"binding_truth_missing reason={exc}"
    port = binding.gateway_port
    smoke_path = path if path.startswith("/") else f"/{path}"
    url = f"http://127.0.0.1:{port}{smoke_path}"
    request = urllib.request.Request(url, headers={"Host": binding.public_host})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = int(response.getcode())
            return 200 <= status < 500, f"url={url} host={binding.public_host} status={status}"
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        return 200 <= status < 500, f"url={url} host={binding.public_host} status={status}"
    except Exception as exc:
        return False, f"url={url} host={binding.public_host} reason={exc}"


def _contract_health_endpoints(desired, profile) -> dict[str, str]:
    image_recipe = _image_spec_recipe(desired.image_spec)
    endpoints = image_recipe.get("health_endpoints")
    if isinstance(endpoints, dict):
        return {str(key): str(value) for key, value in endpoints.items() if str(key) and str(value)}
    profile_endpoints = profile.metadata.get("required_internal_http")
    if isinstance(profile_endpoints, dict):
        return {str(key): str(value) for key, value in profile_endpoints.items() if str(key) and str(value)}
    return {}


def _internal_http_check_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip().lower()).strip("_")
    return safe or "endpoint"


def _run_internal_http_check(nsenter: str, pid: int, name: str, url: str) -> tuple[bool, str, str]:
    check_name = f"live_internal_http_{_internal_http_check_name(name)}_ok"
    curl = shutil.which("curl")
    if not curl:
        return False, check_name, "curl_missing"
    proc = _run_text([nsenter, "-t", str(pid), "-n", curl, "-fsS", "--max-time", "5", url], timeout=8)
    if proc.returncode == 0:
        return True, check_name, f"url={url}"
    detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
    return False, check_name, f"url={url} error={detail[:160]}"


def _run_live_slot_checks(desired, profile, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not _is_root():
        return [(False, "live_check_requires_root", "run as root/admin or a restricted root helper")]

    binding = get_runtime_binding(desired.slot, state_root)
    container, container_lookup = _find_gateway_container(binding, profile)
    checks.append((bool(container), "live_container_lookup", container_lookup))
    if not container:
        return checks
    target_home = f"/home/{desired.slot}"
    host_nas_root = f"{target_home}/nas_docs"
    container_nas_root = str(profile.metadata.get("container_nas_root") or "")
    required_read_only_nas = profile.metadata.get("required_read_only_nas") is True
    required_propagation = str(profile.metadata.get("required_mount_propagation") or "")

    docker = shutil.which("docker")
    checks.append((bool(docker), "live_docker_cli_available", docker))
    if not docker:
        return checks
    nsenter = shutil.which("nsenter")
    checks.append((bool(nsenter), "live_nsenter_available", nsenter))
    if not nsenter:
        return checks

    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "live_container_exists", container))
    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout).strip()
        checks.append((False, "live_container_inspect_ok", detail[:200] if detail else None))
        return checks

    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "live_container_inspect_parse_ok", str(exc)))
        return checks
    try:
        truth, truth_checks = _live_runtime_truth(desired.slot, state_root)
        checks.extend(truth_checks)
        checks.append(
            (
                truth.get("truth_status") == "ok",
                "live_image_truth_labeled",
                f"status={truth.get('truth_status')}",
            )
        )
        checks.append(
            (
                truth.get("runtime_profile") in {"", profile.name} if truth.get("truth_status") != "ok" else truth.get("runtime_profile") == profile.name,
                "live_image_truth_profile_matches",
                f"image={truth.get('runtime_profile') or 'missing'} profile={profile.name}",
            )
        )
        checks.append(
            (
                truth.get("canonical_recipe_name") not in {None, "", "unknown"} if truth.get("truth_status") == "ok" else True,
                "live_image_truth_canonical_present",
                f"name={truth.get('canonical_recipe_name') or 'missing'}",
            )
        )
    except Exception as exc:
        checks.append((False, "live_image_truth_read_ok", str(exc)))
    state = info.get("State") or {}
    config = info.get("Config") or {}
    image_data = info.get("Image") or ""
    repo_digests = info.get("RepoDigests") or []
    running = str(state.get("Running")).lower()
    pid = int(state.get("Pid") or 0)
    health_data = state.get("Health") or {}
    health = str(health_data.get("Status") or "none")
    image = str(config.get("Image") or "")
    user = str(config.get("User") or "")
    runtime_user_mode = str(profile.metadata.get("runtime_user_mode") or "compose")
    checks.append((running == "true", "live_container_running", f"running={running}"))
    checks.append((pid > 0, "live_container_pid_present", f"pid={pid}"))
    checks.append((health in {"healthy", "none", ""}, "live_container_health_ok", f"health={health}"))
    checks.append((bool(image), "live_container_image_present", image or None))
    desired_image = str(desired.image_spec.get("wrapper_image") or "")
    desired_digest = str(desired.image_spec.get("digest") or "")
    image_matches = bool(desired_image) and (
        image == desired_image
        or desired_image in repo_digests
        or (desired_digest and (desired_digest in image or desired_digest in image_data or any(desired_digest in item for item in repo_digests)))
    )
    checks.append((image_matches, "live_container_image_matches_spec", f"image={image}"))
    if runtime_user_mode == "image-managed":
        checks.append((user in {"", "0", "0:0", "root"}, "live_container_user_image_managed", f"user={user or 'empty'}"))
    else:
        checks.append((bool(user) and user not in {"0", "0:0", "root"}, "live_container_user_non_root", f"user={user or 'empty'}"))
    if pid <= 0:
        return checks

    smoke_path = str(profile.metadata.get("http_smoke_path") or "")
    if smoke_path:
        smoke_ok, smoke_detail = _http_backend_smoke(desired.slot, smoke_path, state_root)
        checks.append((smoke_ok, "live_backend_http_smoke_ok", smoke_detail))

    for endpoint_name, endpoint_url in _contract_health_endpoints(desired, profile).items():
        checks.append(_run_internal_http_check(nsenter, pid, endpoint_name, endpoint_url))

    host_rc, host_error, host_mounts = _findmnt_under(host_nas_root)
    checks.append((host_rc == 0, "live_host_nas_root_findmnt_ok", host_error if host_rc != 0 else host_nas_root))
    host_cifs = [row for row in host_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(host_nas_root + "/")]
    checks.append((True, "live_host_child_cifs_count", f"count={len(host_cifs)}"))
    for row in host_cifs:
        source = row.get("source") or ""
        if source.startswith("//") and desired.runtime_class == "customer":
            try:
                decision = check_nas_policy(desired.slot, source, state_root)
                checks.append((decision.allowed, "live_host_child_cifs_allowed_by_policy", f"source={source} reason={decision.reason}"))
            except Exception as exc:
                checks.append((False, "live_host_child_cifs_policy_check_ok", f"source={source} reason={exc}"))
        elif source.startswith("//"):
            checks.append((True, "live_host_child_cifs_policy_not_required_for_dev", f"source={source}"))
    if required_read_only_nas and host_cifs:
        host_ro = all(_is_readonly_mount(row) for row in host_cifs)
        checks.append((bool(host_cifs) and host_ro, "live_host_child_cifs_readonly", f"count={len(host_cifs)}"))

    if not container_nas_root:
        checks.append((False, "live_container_nas_root_configured", None))
        return checks

    container_rc, container_error, container_mounts = _findmnt_tree(container_nas_root, container_pid=pid)
    checks.append(
        (
            container_rc == 0,
            "live_container_nas_root_findmnt_ok",
            container_error if container_rc != 0 else container_nas_root,
        )
    )
    root_rows = [row for row in container_mounts if row.get("target") == container_nas_root]
    checks.append((bool(root_rows), "live_container_nas_root_mounted", container_nas_root))
    if required_read_only_nas:
        checks.append(
            (
                bool(root_rows) and _is_readonly_mount(root_rows[0]),
                "live_container_nas_root_readonly",
                root_rows[0].get("options") if root_rows else None,
            )
        )
    if root_rows and required_propagation:
        checks.append(
            (
                _propagation_satisfies(root_rows[0].get("propagation"), required_propagation),
                "live_container_nas_root_propagation",
                f"required={required_propagation} actual={root_rows[0].get('propagation')}",
            )
        )

    container_cifs = [
        row for row in container_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(container_nas_root + "/")
    ]
    checks.append((True, "live_container_child_cifs_count", f"count={len(container_cifs)}"))
    if required_read_only_nas and container_cifs:
        container_ro = all(_is_readonly_mount(row) for row in container_cifs)
        checks.append((bool(container_cifs) and container_ro, "live_container_child_cifs_readonly", f"count={len(container_cifs)}"))

    host_sources = {row.get("source") for row in host_cifs if row.get("source")}
    container_sources = {row.get("source") for row in container_cifs if row.get("source")}
    if host_sources:
        checks.append(
            (
                host_sources.issubset(container_sources),
                "live_container_sees_host_cifs_sources",
                f"host={len(host_sources)} container={len(container_sources)}",
            )
        )
    else:
        checks.append((True, "live_no_host_child_cifs_mounted", None))
    return checks


def _run_static_slot_checks(desired, profile, rendered=None) -> list[tuple[bool, str, str | None]]:
    target_family = desired.family
    runtime_class = desired.runtime_class
    profile_family = profile.metadata.get("family")
    profile_runtime_class = profile.metadata.get("slot_class")
    profile_mode = profile.metadata.get("mode")
    image_family = desired.image_spec.get("family")
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    image_digest = desired.image_spec.get("digest")
    wrapper_digest = _digest_from_image_ref(wrapper_image)
    allow_source_mount = profile.metadata.get("allow_source_mount")

    checks: list[tuple[bool, str, str | None]] = [
        (target_family == profile_family, "target_family_matches_profile", f"target={target_family} profile={profile_family}"),
        (
            runtime_class == profile_runtime_class,
            "target_runtime_class_matches_profile",
            f"target={runtime_class} profile={profile_runtime_class}",
        ),
        (
            image_family == target_family == profile_family,
            "image_family_matches_target",
            f"image={image_family} target={target_family}",
        ),
        (bool(wrapper_image), "wrapper_image_present", str(wrapper_image) if wrapper_image else None),
        (bool(product_image), "product_image_present", str(product_image) if product_image else None),
        (_has_digest_ref(wrapper_image), "wrapper_image_pinned_by_digest", str(wrapper_image) if wrapper_image else None),
        (_has_digest_ref(product_image), "product_image_pinned_by_digest", str(product_image) if product_image else None),
        (
            isinstance(image_digest, str) and image_digest.startswith("sha256:"),
            "wrapper_image_digest_present",
            str(image_digest) if image_digest else None,
        ),
        (
            bool(wrapper_digest) and wrapper_digest == image_digest,
            "wrapper_image_digest_matches_spec",
            f"wrapper={wrapper_digest} image_spec={image_digest}",
        ),
        (
            _allowed_image_ref(target_family, "wrapper", wrapper_image),
            "wrapper_image_repository_allowed",
            str(wrapper_image) if wrapper_image else None,
        ),
        (
            _allowed_image_ref(target_family, "product", product_image),
            "product_image_repository_allowed",
            str(product_image) if product_image else None,
        ),
    ]
    checks.extend(_image_spec_profile_contract_checks(desired.image_spec, profile))

    if runtime_class == "customer":
        checks.extend(
            [
                (
                    bool(getattr(desired, "route", None)) and desired.route.runtime_class == "customer",
                    "binding_runtime_class_customer",
                    f"binding={getattr(desired.route, 'runtime_class', 'missing') if getattr(desired, 'route', None) else 'missing'}",
                ),
                (profile_mode == "image", "customer_profile_mode_image", f"mode={profile_mode}"),
                (allow_source_mount is False, "customer_source_mount_disabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    elif runtime_class == "dev":
        checks.extend(
            [
                (
                    bool(getattr(desired, "route", None)) and desired.route.runtime_class == "dev",
                    "binding_runtime_class_dev",
                    f"binding={getattr(desired.route, 'runtime_class', 'missing') if getattr(desired, 'route', None) else 'missing'}",
                ),
                (profile_mode == "source", "dev_profile_mode_source", f"mode={profile_mode}"),
                (allow_source_mount is True, "dev_source_mount_enabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    else:
        checks.append((False, "known_runtime_class", f"runtime_class={runtime_class}"))

    if rendered is not None:
        checks.extend(
            (item.ok, item.name, item.detail)
            for item in validate_compose_contract(profile, desired, rendered.text)
        )

    return checks


def cmd_check(args: argparse.Namespace) -> int:
    try:
        state_root = _state_root(args)
        if args.live:
            desired, profile = _desired_from_live_image_truth(args.slot, state_root)
        else:
            desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
        rendered = render_compose(profile, desired)
    except Exception as exc:
        print(f"target={args.slot}")
        print("check_status=not_ready")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"image_name={desired.image_name}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"runtime_contract={_profile_runtime_contract(profile)}")
    print(f"customer_surface={_profile_customer_surface(profile)}")
    for key, value in canonical_recipe_identity(canonical_recipe_for_image_spec(desired.image_spec)).items():
        print(f"{key}={value}")
    print(f"compose_sha256={rendered.sha256}")
    print("check_mode=non_mutating")
    print(f"live_runtime_check={'enabled' if args.live else 'not_run'}")

    failed = 0
    for ok, name, detail in _run_static_slot_checks(desired, profile, rendered):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1

    _check_line(bool(rendered.text.strip()), "compose_rendered")
    if not rendered.text.strip():
        failed += 1

    if args.live:
        for ok, name, detail in _run_live_slot_checks(desired, profile, _state_root(args)):
            _check_line(ok, name, detail)
            if not ok:
                failed += 1
    else:
        print("INFO live_runtime_check_not_run use='opsctl check --live TARGET'")

    if failed:
        print(f"check_status=fail failed={failed}")
        return 1
    if args.live:
        print("check_status=pass scope=contract_and_live")
    else:
        print("check_status=pass scope=contract_only")
    return 0


def _slot_runtime_dir(slot: str) -> Path:
    validate_linux_account(slot)
    target_home = Path("/home") / slot
    runtime_dir = target_home / "openclaw"
    for path in (target_home, runtime_dir):
        if path.is_symlink():
            raise ValueError(f"managed path must not be symlink: {path}")
        if not path.is_dir():
            raise FileNotFoundError(path)
    return runtime_dir


def _agent_compose_path(runtime_dir: Path) -> Path:
    return runtime_dir / "docker-compose.agent-runtime.yml"


def _agent_manifest_path(runtime_dir: Path) -> Path:
    return runtime_dir / ".agent-runtime-manifest"


def _agent_backup_root(runtime_dir: Path) -> Path:
    return runtime_dir / ".agent-runtime-backups"


def _safe_managed_file(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed file must not be symlink: {path}")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"managed parent is not a safe directory: {parent}")


def _compose_project_name(slot: str) -> str:
    return f"openclaw-{slot}"


def _docker_compose_command(slot: str, compose_path: Path, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        _compose_project_name(slot),
        "-f",
        str(compose_path),
        *args,
    ]


def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    _safe_managed_file(path)
    _atomic_write_text(path, text, mode=mode)


def _required_compose_variables(rendered_text: str) -> set[str]:
    return set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", rendered_text))


def _env_file_keys(path: Path) -> set[str]:
    _safe_managed_file(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    keys: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            keys.add(key)
    return keys


def _state_runtime_dir(state_root: Path, slot: str, *, create: bool = False) -> Path:
    runtime_root = state_root / "runtime"
    slot_dir = runtime_root / slot
    for path in (state_root, runtime_root, slot_dir):
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed state path must not be symlink: {path}")
    if create:
        runtime_root.mkdir(mode=0o755, exist_ok=True)
        slot_dir.mkdir(mode=0o755, exist_ok=True)
    return slot_dir


def _state_manifest_path(state_root: Path, slot: str, *, create_parent: bool = False) -> Path:
    return _state_runtime_dir(state_root, slot, create=create_parent) / "manifest.yaml"


def _manifest_payload(
    *,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> dict:
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    payload = {
        "schema_version": 1,
        "target": desired.slot,
        "linux_account": desired.route.linux_account if getattr(desired, "route", None) else desired.slot,
        "applied_at": applied_at,
        "ops_commit": _installed_source_commit(),
        "image_name": desired.image_name,
        "family": desired.family,
        "runtime_class": desired.runtime_class,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "runtime_contract": _profile_runtime_contract(profile),
        "customer_surface": _profile_customer_surface(profile),
        "public_host": _apache_public_host(desired.slot),
        "gateway_port": desired.route.gateway_port if getattr(desired, "route", None) else "",
        "bridge_port": desired.route.bridge_port if getattr(desired, "route", None) else "",
        "wrapper_image": wrapper_image,
        "wrapper_image_digest": _digest_from_image_ref(wrapper_image),
        "product_image": product_image,
        "product_image_digest": _digest_from_image_ref(product_image),
        "recipe": _image_spec_recipe_payload(desired.image_spec),
        "compose_sha256": rendered.sha256,
        "compose_path": str(compose_path),
    }
    if previous_manifest is not None:
        payload["previous_manifest"] = str(previous_manifest)
    return payload


def _desired_from_runtime_manifest(slot: str, state_root: Path):
    target = load_runtime_target(slot, state_root)
    profile = load_profile(target.runtime_profile)
    if profile.metadata.get("family") != target.family:
        raise ValueError(f"runtime manifest profile family mismatch: profile={profile.metadata.get('family')} manifest={target.family}")
    if profile.metadata.get("slot_class") != target.runtime_class:
        raise ValueError(
            f"runtime manifest profile runtime_class mismatch: profile={profile.metadata.get('slot_class')} manifest={target.runtime_class}"
        )
    return target, profile


def _write_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    applied_at: str,
) -> None:
    lines = [
        f"target={desired.slot}",
        f"linux_account={desired.route.linux_account if getattr(desired, 'route', None) else desired.slot}",
        f"image_name={desired.image_name}",
        f"family={desired.family}",
        f"runtime_class={desired.runtime_class}",
        f"runtime_profile={profile.name}",
        f"runtime_profile_digest={profile.digest}",
        f"runtime_contract={_profile_runtime_contract(profile)}",
        f"customer_surface={_profile_customer_surface(profile)}",
        f"public_host={_apache_public_host(desired.slot)}",
        f"gateway_port={desired.route.gateway_port if getattr(desired, 'route', None) else ''}",
        f"bridge_port={desired.route.bridge_port if getattr(desired, 'route', None) else ''}",
        f"ops_repo_commit={_installed_source_commit()}",
        f"wrapper_image={desired.image_spec.get('wrapper_image')}",
        f"product_image={desired.image_spec.get('product_image')}",
        f"recipe_mode={_image_spec_recipe_tokens(desired.image_spec)['recipe_mode']}",
        f"product_component={_image_spec_recipe_tokens(desired.image_spec)['product_component']}",
        f"wrapper_image_digest={desired.image_spec.get('digest')}",
        f"compose_sha256={rendered.sha256}",
        f"compose_file={path.parent / 'docker-compose.agent-runtime.yml'}",
        f"applied_at={applied_at}",
    ]
    _atomic_write(path, "\n".join(lines) + "\n", 0o644)


def _write_state_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> None:
    _atomic_write(
        path,
        dump_yaml(
            _manifest_payload(
                desired=desired,
                profile=profile,
                rendered=rendered,
                compose_path=compose_path,
                applied_at=applied_at,
                previous_manifest=previous_manifest,
            )
        ),
        0o644,
    )


def _write_slot_manifests(
    *,
    state_root: Path,
    runtime_dir: Path,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> tuple[Path, Path]:
    legacy_path = _agent_manifest_path(runtime_dir)
    state_path = _state_manifest_path(state_root, desired.slot, create_parent=True)
    _write_slot_manifest(
        legacy_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        applied_at=applied_at,
    )
    _write_state_slot_manifest(
        state_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        compose_path=compose_path,
        applied_at=applied_at,
        previous_manifest=previous_manifest,
    )
    return legacy_path, state_path


def _backup_agent_runtime_state(slot: str, runtime_dir: Path, state_root: Path) -> Path:
    backup_root = _agent_backup_root(runtime_dir)
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o755, exist_ok=True)
    backup_dir = backup_root / datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    suffix = 1
    original_backup_dir = backup_dir
    while backup_dir.exists():
        suffix += 1
        backup_dir = Path(f"{original_backup_dir}.{suffix}")
    backup_dir.mkdir(mode=0o755)

    compose_path = _agent_compose_path(runtime_dir)
    manifest_path = _agent_manifest_path(runtime_dir)
    state_manifest_path = _state_manifest_path(state_root, slot)
    metadata = {
        "created_at": _now_iso(),
        "had_compose": compose_path.is_file() and not compose_path.is_symlink(),
        "had_manifest": manifest_path.is_file() and not manifest_path.is_symlink(),
        "had_state_manifest": state_manifest_path.is_file() and not state_manifest_path.is_symlink(),
        "state_manifest_path": str(state_manifest_path),
    }
    if metadata["had_compose"]:
        shutil.copy2(compose_path, backup_dir / "docker-compose.agent-runtime.yml")
    if metadata["had_manifest"]:
        shutil.copy2(manifest_path, backup_dir / ".agent-runtime-manifest")
    if metadata["had_state_manifest"]:
        shutil.copy2(state_manifest_path, backup_dir / "manifest.yaml")
    (backup_dir / "backup.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return backup_dir


def _latest_backup(runtime_dir: Path) -> Path | None:
    backup_root = _agent_backup_root(runtime_dir)
    if not backup_root.is_dir():
        return None
    backups = sorted([item for item in backup_root.iterdir() if item.is_dir()])
    return backups[-1] if backups else None


def _restore_backup(slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path) -> tuple[bool, str]:
    metadata = load_yaml(backup_dir / "backup.json")
    compose_path = _agent_compose_path(runtime_dir)
    manifest_path = _agent_manifest_path(runtime_dir)
    state_manifest_path = _state_manifest_path(state_root, slot, create_parent=True)
    had_compose = bool(metadata.get("had_compose"))
    had_manifest = bool(metadata.get("had_manifest"))
    had_state_manifest = bool(metadata.get("had_state_manifest"))

    if had_compose:
        shutil.copy2(backup_dir / "docker-compose.agent-runtime.yml", compose_path)
    else:
        compose_path.unlink(missing_ok=True)
    if had_manifest:
        shutil.copy2(backup_dir / ".agent-runtime-manifest", manifest_path)
    else:
        manifest_path.unlink(missing_ok=True)
    if had_state_manifest:
        shutil.copy2(backup_dir / "manifest.yaml", state_manifest_path)
    else:
        state_manifest_path.unlink(missing_ok=True)

    if not had_compose:
        return False, "no_previous_agent_runtime_compose"

    config = _run_text_cwd(_docker_compose_command(slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        return False, (config.stderr or config.stdout).strip() or "rollback_compose_config_failed"
    up = _run_text_cwd(
        _docker_compose_command(slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=180,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "rollback_compose_up_failed"
    return True, "rollback_applied"


def _read_legacy_slot_manifest(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = raw_line.partition("=")
        if sep:
            data[key.strip()] = value.strip()
    return data


def _backup_manifest_data(backup_dir: Path) -> dict:
    yaml_manifest = backup_dir / "manifest.yaml"
    if yaml_manifest.is_file():
        data = load_yaml(yaml_manifest)
        if isinstance(data, dict):
            return data
    return _read_legacy_slot_manifest(backup_dir / ".agent-runtime-manifest")


def _desired_from_manifest(slot: str, manifest: dict, state_root: Path):
    target = str(manifest.get("target") or manifest.get("slot") or slot)
    family = str(manifest.get("family") or "")
    runtime_class = str(manifest.get("runtime_class") or manifest.get("slot_class") or "")
    image_spec = {
        "family": family,
        "image_name": str(manifest.get("image_name") or manifest.get("release") or IMAGE_ROLLOUT_IMAGE_NAME),
        "wrapper_image": manifest.get("wrapper_image"),
        "product_image": manifest.get("product_image"),
        "digest": manifest.get("wrapper_image_digest") or manifest.get("release_digest"),
        "product_digest": manifest.get("product_image_digest"),
        "mode": "wrapped_product_image",
    }
    return RuntimeTarget(
        target=target,
        family=family,
        runtime_class=runtime_class,
        image_name=str(image_spec["image_name"]),
        image_spec=image_spec,
        runtime_profile=str(manifest.get("runtime_profile") or ""),
        route=get_runtime_binding(target, state_root),
    )


def _load_backup_runtime_contract(slot: str, backup_dir: Path, state_root: Path):
    manifest = _backup_manifest_data(backup_dir)
    desired = _desired_from_manifest(slot, manifest, state_root)
    if not desired.runtime_profile:
        raise ValueError("backup manifest is missing runtime_profile")
    return desired, load_profile(desired.runtime_profile)


def _print_process_result(prefix: str, proc: subprocess.CompletedProcess[str], limit: int = 2000) -> None:
    detail = (proc.stderr or proc.stdout).strip()
    if detail:
        print(f"{prefix}={detail[:limit]}")


def _write_failed_container_diagnostics(binding: RuntimeBinding, profile, backup_dir: Path) -> Path | None:
    try:
        container, lookup = _find_gateway_container(binding, profile)
        diag_dir = backup_dir / "failed-container"
        diag_dir.mkdir(mode=0o700, exist_ok=True)
        (diag_dir / "lookup.txt").write_text(f"container={container or ''}\nlookup={lookup or ''}\n", encoding="utf-8")
        if not container:
            return diag_dir
        commands = {
            "inspect.json": ["docker", "inspect", container],
            "logs.txt": ["docker", "logs", "--tail", "300", container],
            "ports.txt": ["docker", "port", container],
            "top.txt": ["docker", "top", container],
        }
        for name, command in commands.items():
            proc = _run_text(command, timeout=30)
            body = {
                "argv": command,
                "returncode": proc.returncode,
                "stdout": redact(proc.stdout or ""),
                "stderr": redact(proc.stderr or ""),
            }
            (diag_dir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return diag_dir
    except Exception as exc:
        try:
            diag_dir = backup_dir / "failed-container"
            diag_dir.mkdir(mode=0o700, exist_ok=True)
            (diag_dir / "error.txt").write_text(str(exc) + "\n", encoding="utf-8")
            return diag_dir
        except Exception:
            return None


def _is_under_path(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _run_live_slot_checks_with_wait(desired, profile, state_root: Path, timeout_seconds: int = 90) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    wait_names = {
        "live_container_running",
        "live_container_pid_present",
        "live_container_health_ok",
        "live_backend_http_smoke_ok",
    }
    while True:
        checks = _run_live_slot_checks(desired, profile, state_root)
        last_checks = checks
        failed_names = {name for ok, name, _ in checks if not ok}
        if not failed_names:
            return checks
        if not (failed_names & wait_names) and not any(name.startswith("live_internal_http_") for name in failed_names):
            return checks
        if time.monotonic() >= deadline:
            return checks
        time.sleep(5)


def _profile_startup_timeout_seconds(profile) -> int:
    raw_value = profile.metadata.get("startup_timeout_seconds", 90)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return 90
    return max(30, min(value, 600))


def _apply_desired_slot(
    *,
    desired,
    profile,
    state_root: Path,
    allow_first_apply: bool,
    action_name: str = "apply",
) -> int:
    try:
        rendered = render_compose(profile, desired)
        static_failures = [
            name for ok, name, _ in _run_static_slot_checks(desired, profile, rendered) if not ok
        ]
        if static_failures:
            raise ValueError(f"static contract check failed: {','.join(static_failures)}")
        runtime_dir = _slot_runtime_dir(desired.slot)
        compose_path = _agent_compose_path(runtime_dir)
        manifest_path = _agent_manifest_path(runtime_dir)
        state_manifest_path = _state_manifest_path(state_root, desired.slot)
        env_path = runtime_dir / ".env"
        required = _required_compose_variables(rendered.text)
        present = _env_file_keys(env_path)
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"missing required .env keys: {','.join(missing)}")
        if not manifest_path.exists() and not state_manifest_path.exists() and not allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        previous_manifest = state_manifest_path if state_manifest_path.exists() else manifest_path if manifest_path.exists() else None
        guidance_result = _ensure_runtime_workspace_guidance(desired.slot, profile)
        backup_dir = _backup_agent_runtime_state(desired.slot, runtime_dir, state_root)
        _atomic_write(compose_path, rendered.text, 0o644)
    except Exception as exc:
        print(f"target={getattr(desired, 'slot', '')}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, action_name, getattr(desired, "slot", ""), getattr(desired, "slot", ""), "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_dir={runtime_dir}")
    print(f"compose_file={compose_path}")
    print(f"manifest={manifest_path}")
    print(f"state_manifest={state_manifest_path}")
    print(f"backup_dir={backup_dir}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")
    for key, value in guidance_result.items():
        print(f"{key}={value}")

    config = _run_text_cwd(_docker_compose_command(desired.slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        _print_process_result("compose_config_error", config)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_config_failed")
        return config.returncode or 1

    up = _run_text_cwd(
        _docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        _print_process_result("compose_up_error", up)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_up_failed")
        return up.returncode or 1

    failed = 0
    for ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    if failed:
        diagnostics_dir = _write_failed_container_diagnostics(desired.route, profile, backup_dir)
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print(f"apply_status=fail live_failed={failed}")
        if diagnostics_dir:
            print(f"failure_diagnostics_dir={diagnostics_dir}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"live_failed={failed}")
        return 1

    applied_at = _now_iso()
    try:
        _write_slot_manifests(
            state_root=state_root,
            runtime_dir=runtime_dir,
            desired=desired,
            profile=profile,
            rendered=rendered,
            compose_path=compose_path,
            applied_at=applied_at,
            previous_manifest=previous_manifest,
        )
        _append_action_log(state_root, action_name, desired.slot, desired.image_name, "ok", rendered.sha256)
    except Exception as exc:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        print(f"reason=manifest_write_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        try:
            _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"manifest_write_failed:{exc}")
        except Exception:
            pass
        return 1
    print("apply_status=ok")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "apply", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    return _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(args.allow_first_apply),
        action_name="apply",
    )


def cmd_rollback(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollback TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        runtime_dir = _slot_runtime_dir(args.slot)
        backup_dir = _latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = _restore_backup(args.slot, runtime_dir, backup_dir, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollback", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"target={args.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_reason={reason}")
    if not ok:
        print("rollback_status=fail")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", reason)
        return 1

    try:
        desired, profile = _load_backup_runtime_contract(args.slot, backup_dir, state_root)
    except Exception as exc:
        print("rollback_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", str(exc))
        return 1

    failed = 0
    for check_ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(check_ok, name, detail)
        if not check_ok:
            failed += 1
    if failed:
        print(f"rollback_status=fail live_failed={failed}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", f"live_failed={failed}")
        return 1

    print("rollback_status=ok")
    _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "ok", reason)
    return 0


def _slot_home(slot: str) -> Path:
    return Path(_passwd_record(slot).pw_dir)


def _workspace_guidance_paths(slot: str, family: str) -> tuple[Path, Path, list[Path], Path, str, str]:
    home = _slot_home(slot)
    expected_home = Path("/home") / slot
    if home != expected_home:
        raise ValueError(f"unexpected slot home: {home}")
    if home.exists() and home.is_symlink():
        raise ValueError(f"managed home must not be symlink: {home}")
    if family == "hermes":
        app_home = home / ".hermes"
        workspace = app_home / "workspace"
        source = REPO_ROOT / "images" / "shared-document-tools" / "hermes-workspace-guidance.md"
        begin = "<!-- BEGIN OPENCLAW HERMES GUIDANCE -->"
        end = "<!-- END OPENCLAW HERMES GUIDANCE -->"
        names = ["AGENTS.md", "CLAUDE.md", "GEMINI.md"]
    elif family == "openclaw":
        app_home = home / ".openclaw"
        workspace = app_home / "workspace"
        source = REPO_ROOT / "images" / "shared-document-tools" / "openclaw-workspace-guidance.md"
        begin = "<!-- BEGIN OPENCLAW WORKSPACE GUIDANCE -->"
        end = "<!-- END OPENCLAW WORKSPACE GUIDANCE -->"
        names = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", "TOOLS.md"]
    else:
        raise ValueError(f"unsupported runtime family for workspace guidance: {family}")
    targets = [workspace / name for name in names]
    return app_home, workspace, targets, source, begin, end


def _upsert_managed_guidance_block(existing: str, source_text: str, begin: str, end: str) -> str:
    block = f"{begin}\n{source_text.rstrip()}\n{end}\n"
    has_begin = begin in existing
    has_end = end in existing
    if has_begin != has_end:
        raise ValueError("managed workspace guidance marker is incomplete")
    if has_begin and has_end:
        before, rest = existing.split(begin, 1)
        _old, after = rest.split(end, 1)
        return before.rstrip() + "\n\n" + block + after.lstrip()
    if existing.strip():
        return existing.rstrip() + "\n\n" + block
    return block


def _atomic_write_owned_text(path: Path, text: str, mode: int, uid: int, gid: int) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed guidance file must not be symlink: {path}")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError(f"managed guidance parent is not a safe directory: {path.parent}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.chown(tmp_path, uid, gid)
        os.replace(tmp_path, path)
        try:
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            pass
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _ensure_runtime_workspace_guidance(slot: str, profile) -> dict[str, str]:
    family = str(profile.metadata.get("family") or "")
    if family not in {"hermes", "openclaw"}:
        return {"workspace_guidance": "skipped", "workspace_guidance_reason": f"family={family or 'unknown'}"}
    app_home, workspace, targets, source, begin, end = _workspace_guidance_paths(slot, family)
    if not source.is_file() or source.is_symlink():
        raise FileNotFoundError(f"workspace guidance source missing: {source}")

    home = _slot_home(slot)
    _ensure_not_symlink_chain(app_home, home)
    _ensure_not_symlink_chain(workspace, home)
    for target in targets:
        _ensure_not_symlink_chain(target, home)
        if target.exists() and target.is_symlink():
            raise ValueError(f"managed guidance file must not be symlink: {target}")

    if family == "hermes":
        uid, _runtime_gid, data_gid = _runtime_ids(slot)
        gid = data_gid
        app_mode = 0o750
        workspace_mode = 0o750
    else:
        uid, gid, _data_gid = _runtime_ids(slot)
        app_mode = 0o750
        workspace_mode = 0o750

    app_home.mkdir(mode=app_mode, parents=True, exist_ok=True)
    workspace.mkdir(mode=workspace_mode, parents=True, exist_ok=True)
    _ensure_not_symlink_chain(workspace, home)
    os.chown(app_home, uid, gid)
    os.chmod(app_home, app_mode)
    os.chown(workspace, uid, gid)
    os.chmod(workspace, workspace_mode)

    source_text = source.read_text(encoding="utf-8")
    changed = 0
    for target in targets:
        existing = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else ""
        updated = _upsert_managed_guidance_block(existing, source_text, begin, end)
        if updated != existing:
            changed += 1
        _atomic_write_owned_text(target, updated, 0o644, uid, gid)
    return {
        "workspace_guidance": "updated" if changed else "present",
        "workspace_guidance_family": family,
        "workspace_guidance_workspace": str(workspace),
        "workspace_guidance_files": ",".join(str(target) for target in targets),
    }


from .commands.runtime_secret import (
    _assert_secret_path_safe,
    _run_runtime_secret_container_checks,
    _run_runtime_secret_container_checks_with_wait,
    cmd_runtime_secret_set,
    cmd_runtime_secret_status,
)

from .commands.handoff import (
    cmd_handoff_print,
    cmd_handoff_status,
    cmd_handoff_value_command,
)

from .commands.heartbeat import (
    cmd_heartbeat_disable,
    cmd_heartbeat_status,
)

def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: enable lane rollout only after single-slot apply/rollback migration tests pass", file=sys.stderr)
    return 2


from .commands.recipe import (
    _build_arg_lines_for_canonical_recipe,
    _dev_recipe_runtime_env,
    _ensure_dev_runtime_dir,
    cmd_recipe_capture_dev,
    cmd_recipe_dev_apply,
    cmd_recipe_dev_status,
    cmd_recipe_list_canonical,
    cmd_recipe_validate_canonical,
)

from .commands.rollout import (
    _desired_from_direct_images,
    _desired_from_live_image_truth,
    cmd_rollout_image_canary,
    cmd_rollout_image_dev_apply,
    cmd_rollout_image_plan,
    cmd_rollout_image_promote,
    cmd_rollout_status,
)

def _read_key_value_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        data[key] = value
    return data


def _atomic_write_key_value(path: Path, data: dict[str, str], mode: int, uid: int | None = None, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, value in data.items():
                handle.write(f"{key}={value}\n")
        os.chmod(tmp_path, mode)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            os.chown(tmp_path, uid, gid)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _passwd_record(name: str):
    import pwd

    return pwd.getpwnam(name)


def _group_gid(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


def _slot_uid_gid(slot: str) -> tuple[int, int]:
    record = _passwd_record(slot)
    return int(record.pw_uid), int(record.pw_gid)


def _runtime_ids(slot: str) -> tuple[int, int, int]:
    runtime = _passwd_record(f"{slot}_rt")
    data_gid = _group_gid(f"{slot}_data")
    return int(runtime.pw_uid), int(runtime.pw_gid), data_gid


def _ensure_not_symlink_chain(path: Path, stop_at: Path) -> None:
    current = path
    checked: list[Path] = []
    while True:
        checked.append(current)
        if current == stop_at:
            break
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(checked):
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"path component must not be symlink: {candidate}")


def _ensure_customer_agent_dirs(slot: str) -> None:
    uid, gid = _slot_uid_gid(slot)
    base = agent_nas_dir(slot)
    home = Path("/home") / slot
    _ensure_not_symlink_chain(base, home)
    for path, mode in [
        (base, 0o700),
        (request_dir(slot), 0o700),
        (base / "credentials", 0o700),
        (base / "history", 0o700),
        (history_dir(slot, "approved"), 0o700),
        (history_dir(slot, "rejected"), 0o700),
    ]:
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def _read_password_from_stdin() -> str:
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    if password.endswith("\r"):
        password = password[:-1]
    if not password:
        raise ValueError("password stdin is empty")
    return password


def _write_credential_file(path: Path, username: str, password: str, domain: str | None, uid: int, gid: int) -> None:
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    _ensure_not_symlink_chain(path.parent, path.parents[2] if len(path.parents) > 2 else path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, uid, gid)
    os.chmod(path.parent, 0o700)
    data = {"username": username, "password": password}
    if domain:
        data["domain"] = domain
    _atomic_write_key_value(path, data, 0o600, uid, gid)


def _credential_file_is_safe(path: Path, uid: int | None = None) -> None:
    if path.is_symlink():
        raise ValueError(f"credential file must not be symlink: {path}")
    stat_result = path.stat()
    if not path.is_file():
        raise ValueError(f"credential path is not a regular file: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"credential file must be 0600: {path}")
    if uid is not None and stat_result.st_uid != uid:
        raise ValueError(f"credential file owner mismatch: {path}")


def _credential_file_is_safe_for_slot(slot: str, path: Path, uid: int | None = None) -> None:
    customer_root = agent_nas_dir(slot) / "credentials"
    root_credential_root = Path("/root") / "agent-runtime-ops" / "nas-credentials" / slot
    resolved = path.resolve(strict=False)
    if str(resolved).startswith(str(customer_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/home") / slot)
    elif str(resolved).startswith(str(root_credential_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/root"))
    else:
        raise ValueError(f"credential path outside managed roots: {path}")
    _credential_file_is_safe(path, uid=uid)


def _credential_presence(path: Path) -> str:
    try:
        path.stat()
        return "yes"
    except FileNotFoundError:
        return "no"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"


from .commands.nas import (
    _append_action_log,
    _approve_auto_once,
    _delete_official_credentials,
    _official_credential_status,
    _prepare_mount_entry,
    _write_managed_fstab_entry,
    cmd_nas_approve_auto,
    cmd_nas_credential_set,
    cmd_nas_credential_status,
    cmd_nas_mount,
    cmd_nas_mounted,
    cmd_nas_policy_check,
    cmd_nas_remove,
    cmd_nas_request,
    cmd_nas_requests,
    cmd_nas_unmount,
)

def cmd_admin_serve(args: argparse.Namespace) -> int:
    from .admin_server import main as admin_main

    return admin_main(["--host", args.host, "--port", str(args.port)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)

    self_update = sub.add_parser("self-update")
    self_update.set_defaults(func=cmd_self_update)

    update = sub.add_parser("update")
    update_sub = update.add_subparsers(dest="update_command", required=True)
    update_approve = update_sub.add_parser("approve")
    update_approve.add_argument("ref", help="approved full 40-character commit sha")
    update_approve.set_defaults(func=cmd_update_approve)
    update_status = update_sub.add_parser("status")
    update_status.set_defaults(func=cmd_update_status)

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list")
    profile_list.set_defaults(func=cmd_profile_list)

    binding = sub.add_parser("binding")
    binding_sub = binding.add_subparsers(dest="binding_command", required=True)
    binding_list = binding_sub.add_parser("list")
    binding_list.set_defaults(func=cmd_binding_list)
    binding_status = binding_sub.add_parser("status")
    binding_status.add_argument("target", nargs="?")
    binding_status.set_defaults(func=cmd_binding_status)
    binding_normalize = binding_sub.add_parser("normalize")
    binding_normalize.add_argument("--write", action="store_true")
    binding_normalize.set_defaults(func=cmd_binding_normalize)
    binding_set_host = binding_sub.add_parser("set-public-host")
    binding_set_host.add_argument("target")
    binding_set_host.add_argument("host")
    binding_set_host.set_defaults(func=cmd_binding_set_public_host)

    apache = sub.add_parser("apache")
    apache_sub = apache.add_subparsers(dest="apache_command", required=True)
    apache_status = apache_sub.add_parser("status")
    apache_status.add_argument("target", nargs="?")
    apache_status.set_defaults(func=cmd_apache_status)
    apache_set_host = apache_sub.add_parser("set-host")
    apache_set_host.add_argument("linux_account")
    apache_set_host.add_argument("host")
    apache_set_host.set_defaults(func=cmd_apache_set_host)

    runtime = sub.add_parser("runtime")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_truth = runtime_sub.add_parser("truth")
    runtime_truth.add_argument("slot", nargs="?", metavar="target")
    runtime_truth.add_argument("--all", action="store_true")
    runtime_truth.set_defaults(func=cmd_runtime_truth)

    document_tools = sub.add_parser("document-tools")
    document_tools_sub = document_tools.add_subparsers(dest="document_tools_command", required=True)
    document_tools_status = document_tools_sub.add_parser("status")
    document_tools_status.add_argument("slot", nargs="?", metavar="target")
    document_tools_status.add_argument("--all", action="store_true")
    document_tools_status.set_defaults(func=cmd_document_tools_status)

    for name, func in (("status", cmd_status), ("plan", cmd_plan), ("check", cmd_check)):
        item = sub.add_parser(name)
        item.add_argument("slot", metavar="target")
        if name == "check":
            item.add_argument("--live", action="store_true", help="also inspect Docker and NAS runtime state without writing")
        item.set_defaults(func=func)

    apply = sub.add_parser("apply")
    apply.add_argument("slot", metavar="target")
    apply.add_argument("--allow-first-apply", action="store_true")
    apply.set_defaults(func=cmd_apply)

    rollback = sub.add_parser("rollback")
    rollback.add_argument("slot", metavar="target")
    rollback.set_defaults(func=cmd_rollback)

    diagnostics = sub.add_parser("diagnostics")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command", required=True)
    diagnostics_show = diagnostics_sub.add_parser("show")
    diagnostics_show.add_argument("slot", metavar="target")
    diagnostics_show.add_argument("--dir", help="absolute backup dir or failed-container dir to show")
    diagnostics_show.add_argument("--tail", type=int, default=120)
    diagnostics_show.set_defaults(func=cmd_diagnostics_show)

    rollout = sub.add_parser("rollout", description="Inspect runtime manifests and apply digest-pinned wrapper/product images.")
    rollout_sub = rollout.add_subparsers(dest="rollout_command", required=True)
    rollout_status = rollout_sub.add_parser("status", help="summarize runtime manifests for a product family")
    rollout_status.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_status.set_defaults(func=cmd_rollout_status)
    rollout_image_plan = rollout_sub.add_parser("image-plan", help="validate digest-pinned images without release state")
    rollout_image_plan.add_argument("--wrapper-image", required=True)
    rollout_image_plan.add_argument("--product-image", required=True)
    rollout_image_plan.add_argument("--target", dest="slot")
    rollout_image_plan.add_argument("--targets", dest="slots", nargs="*")
    rollout_image_plan.set_defaults(func=cmd_rollout_image_plan)
    rollout_image_dev_apply = rollout_sub.add_parser("image-dev-apply", help="apply digest-pinned images to a dev target")
    rollout_image_dev_apply.add_argument("--target", dest="slot", required=True)
    rollout_image_dev_apply.add_argument("--wrapper-image", required=True)
    rollout_image_dev_apply.add_argument("--product-image", required=True)
    rollout_image_dev_apply.add_argument("--allow-first-apply", action="store_true")
    rollout_image_dev_apply.set_defaults(func=cmd_rollout_image_dev_apply)
    rollout_image_canary = rollout_sub.add_parser("image-canary", help="apply digest-pinned images to one customer canary target")
    rollout_image_canary.add_argument("--target", dest="slot", required=True)
    rollout_image_canary.add_argument("--wrapper-image", required=True)
    rollout_image_canary.add_argument("--product-image", required=True)
    rollout_image_canary.add_argument("--allow-first-apply", action="store_true")
    rollout_image_canary.set_defaults(func=cmd_rollout_image_canary)
    rollout_image_promote = rollout_sub.add_parser("image-promote", help="promote the exact live canary image to explicit targets")
    rollout_image_promote.add_argument("--from-target", dest="from_slot", required=True)
    rollout_image_promote.add_argument("--targets", dest="slots", required=True, help="comma-separated customer targets to apply")
    rollout_image_promote.set_defaults(func=cmd_rollout_image_promote)

    recipe = sub.add_parser("recipe")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_list_canonical = recipe_sub.add_parser("list-canonical")
    recipe_list_canonical.set_defaults(func=cmd_recipe_list_canonical)
    recipe_validate_canonical = recipe_sub.add_parser("validate-canonical")
    recipe_validate_canonical.add_argument("name")
    recipe_validate_canonical.add_argument("--emit-build-args", action="store_true")
    recipe_validate_canonical.set_defaults(func=cmd_recipe_validate_canonical)
    recipe_status = recipe_sub.add_parser("status")
    recipe_status.add_argument("slot", metavar="target")
    recipe_status.set_defaults(func=cmd_recipe_dev_status)
    recipe_apply_dev = recipe_sub.add_parser("apply-dev")
    recipe_apply_dev.add_argument("slot", metavar="target")
    recipe_apply_dev.add_argument("--recipe-name")
    source_group = recipe_apply_dev.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source-output")
    source_group.add_argument("--sync-from")
    recipe_apply_dev.add_argument("--build-command")
    recipe_apply_dev.add_argument("--allow-first-apply", action="store_true")
    recipe_apply_dev.add_argument("--no-apply", action="store_true")
    recipe_apply_dev.set_defaults(func=cmd_recipe_dev_apply)
    recipe_capture_dev = recipe_sub.add_parser("capture-dev")
    recipe_capture_dev.add_argument("slot", metavar="target")
    recipe_capture_dev.add_argument("--recipe-name", default="hermes-runtime")
    recipe_capture_dev.set_defaults(func=cmd_recipe_capture_dev)

    runtime_secret = sub.add_parser("runtime-secret")
    runtime_secret_sub = runtime_secret.add_subparsers(dest="runtime_secret_command", required=True)
    runtime_secret_set = runtime_secret_sub.add_parser("set")
    runtime_secret_set.add_argument("slot", metavar="target")
    runtime_secret_set.add_argument("--env-file")
    runtime_secret_set.add_argument("--key")
    runtime_secret_set.add_argument("--value-stdin", action="store_true")
    runtime_secret_set.add_argument("--no-restart", action="store_true")
    runtime_secret_set.add_argument("--check", action="store_true")
    runtime_secret_set.set_defaults(func=cmd_runtime_secret_set)
    runtime_secret_status = runtime_secret_sub.add_parser("status")
    runtime_secret_status.add_argument("slot", metavar="target")
    runtime_secret_status.set_defaults(func=cmd_runtime_secret_status)

    handoff = sub.add_parser("handoff")
    handoff_sub = handoff.add_subparsers(dest="handoff_command", required=True)
    handoff_status = handoff_sub.add_parser("status")
    handoff_status.add_argument("slot", metavar="target")
    handoff_status.set_defaults(func=cmd_handoff_status)
    handoff_value_command = handoff_sub.add_parser("value-command")
    handoff_value_command.add_argument("slot", metavar="target")
    handoff_value_command.set_defaults(func=cmd_handoff_value_command)
    handoff_print = handoff_sub.add_parser("print")
    handoff_print.add_argument("slot", metavar="target")
    handoff_print.set_defaults(func=cmd_handoff_print)

    heartbeat = sub.add_parser("heartbeat")
    heartbeat_sub = heartbeat.add_subparsers(dest="heartbeat_command", required=True)
    heartbeat_status = heartbeat_sub.add_parser("status")
    heartbeat_status.add_argument("slot", metavar="target")
    heartbeat_status.set_defaults(func=cmd_heartbeat_status)
    heartbeat_disable = heartbeat_sub.add_parser("disable")
    heartbeat_disable.add_argument("slot", metavar="target")
    heartbeat_disable.set_defaults(func=cmd_heartbeat_disable)

    nas = sub.add_parser("nas")
    nas_sub = nas.add_subparsers(dest="nas_command", required=True)
    nas_requests = nas_sub.add_parser("requests")
    nas_requests.set_defaults(func=cmd_nas_requests)
    nas_auto = nas_sub.add_parser("approve-auto")
    nas_auto.add_argument("--watch", action="store_true")
    nas_auto.add_argument("--interval", type=int, default=15)
    nas_auto.set_defaults(func=cmd_nas_approve_auto)
    nas_request = nas_sub.add_parser("request")
    nas_request.add_argument("share")
    nas_request.set_defaults(func=cmd_nas_request)
    nas_credential = nas_sub.add_parser("credential")
    nas_credential_sub = nas_credential.add_subparsers(dest="credential_command", required=True)
    nas_credential_set = nas_credential_sub.add_parser("set")
    nas_credential_set.add_argument("share")
    nas_credential_set.add_argument("--username", required=True)
    nas_credential_set.add_argument("--password-stdin", action="store_true", required=True)
    nas_credential_set.add_argument("--domain")
    nas_credential_set.set_defaults(func=cmd_nas_credential_set)
    nas_credential_status = nas_credential_sub.add_parser("status")
    nas_credential_status.add_argument("slot", metavar="target")
    nas_credential_status.add_argument("share")
    nas_credential_status.set_defaults(func=cmd_nas_credential_status)
    nas_mounted = nas_sub.add_parser("mounted")
    nas_mounted.add_argument("slot", metavar="target")
    nas_mounted.set_defaults(func=cmd_nas_mounted)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot", metavar="target")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)
    nas_mount = nas_sub.add_parser("mount")
    nas_mount.add_argument("slot", metavar="target")
    nas_mount.add_argument("share")
    nas_mount.add_argument("--username")
    nas_mount.add_argument("--password-stdin", action="store_true")
    nas_mount.add_argument("--domain")
    nas_mount.add_argument("--keep-fstab-on-failure", action="store_true")
    nas_mount.set_defaults(func=cmd_nas_mount)
    nas_unmount = nas_sub.add_parser("unmount")
    nas_unmount.add_argument("slot", metavar="target")
    nas_unmount.add_argument("share")
    nas_unmount.add_argument("--lazy", action="store_true")
    nas_unmount.add_argument("--delete-empty-dir", action="store_true")
    nas_unmount.set_defaults(func=cmd_nas_unmount)
    nas_remove = nas_sub.add_parser("remove")
    nas_remove.add_argument("slot", metavar="target")
    nas_remove.add_argument("share")
    nas_remove.add_argument("--lazy", action="store_true")
    nas_remove.add_argument("--delete-empty-dir", action="store_true")
    nas_remove.set_defaults(func=cmd_nas_remove)

    admin = sub.add_parser("admin")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    serve = admin_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=18088, type=int)
    serve.set_defaults(func=cmd_admin_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
