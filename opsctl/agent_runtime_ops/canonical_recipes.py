from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .image_components import image_repo
from .paths import RUNTIME_RECIPE_ROOT
from .profiles import RuntimeProfile, load_profile
from .yamlio import load_yaml


CANONICAL_RECIPE_SCHEMA = "v1"


@dataclass(frozen=True)
class CanonicalRuntimeRecipe:
    name: str
    path: Path
    data: dict[str, Any]
    digest: str


def _normalized_recipe_yaml(data: dict[str, Any]) -> bytes:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=True).encode("utf-8")


def canonical_recipe_digest(data: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_normalized_recipe_yaml(data)).hexdigest()


def list_canonical_recipe_names(recipe_root: Path = RUNTIME_RECIPE_ROOT) -> list[str]:
    if not recipe_root.exists():
        return []
    return sorted(path.stem for path in recipe_root.glob("*.yaml") if path.is_file())


def load_canonical_recipe(name: str, recipe_root: Path = RUNTIME_RECIPE_ROOT) -> CanonicalRuntimeRecipe:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ValueError(f"invalid canonical recipe name: {name}")
    path = recipe_root / f"{name}.yaml"
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ValueError(f"canonical recipe must be a mapping: {name}")
    if data.get("schema") != CANONICAL_RECIPE_SCHEMA:
        raise ValueError(f"canonical recipe schema mismatch: {name}")
    if data.get("name") != name:
        raise ValueError(f"canonical recipe name mismatch: path={name} declared={data.get('name')!r}")
    return CanonicalRuntimeRecipe(name=name, path=path, data=data, digest=canonical_recipe_digest(data))


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _bool_label(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "false"}:
            return lowered
    return ""


def _label_map(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    pairs: list[str] = []
    for key, item in sorted(value.items()):
        key_text = str(key).strip()
        item_text = str(item).strip()
        if key_text and item_text:
            pairs.append(f"{key_text}={item_text}")
    return ",".join(pairs)


def _label_map_json(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    result = {str(key).strip(): str(item).strip() for key, item in value.items() if str(key).strip() and str(item).strip()}
    if not result:
        return ""
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def normalized_selftest_contract(value: Any) -> dict[str, Any] | None:
    """Return a deterministic selftest_contract mapping, or None if malformed/absent.

    A valid contract needs a name, a non-empty command argv list, a non-empty
    required_checks list, and a positive integer timeout_seconds. The shape is the
    family-agnostic unit the product image must attest to.
    """
    if not isinstance(value, dict):
        return None
    name = str(value.get("name") or "").strip()
    command_raw = value.get("command")
    command = [str(item) for item in command_raw] if isinstance(command_raw, list) else []
    required_raw = value.get("required_checks")
    required = [str(item) for item in required_raw] if isinstance(required_raw, list) else []
    timeout_raw = value.get("timeout_seconds")
    timeout = timeout_raw if isinstance(timeout_raw, int) and not isinstance(timeout_raw, bool) else 0
    if not name or not command or not required or timeout <= 0:
        return None
    return {
        "name": name,
        "command": command,
        "required_checks": required,
        "timeout_seconds": timeout,
    }


def selftest_contract_digest(data: dict[str, Any]) -> str:
    """Digest of just the normalized selftest_contract sub-block (empty if none).

    Scoped to the contract so unrelated recipe edits do not churn the attested
    selftest identity. Carried in the wrapper image as the ``selftest.digest`` label.
    """
    contract = normalized_selftest_contract(data.get("selftest_contract"))
    if contract is None:
        return ""
    return "sha256:" + hashlib.sha256(_normalized_recipe_yaml(contract)).hexdigest()


def _selftest_label_values(data: dict[str, Any]) -> dict[str, str]:
    # Only name + digest are attested in the wrapper image. The digest cryptographically
    # binds the full contract (command, required_checks, timeout), and opsctl reads those
    # fields from the digest-verified on-disk canonical recipe -- so they do not need to be
    # carried as labels (which also avoids putting JSON/quotes into Docker LABEL values).
    contract = normalized_selftest_contract(data.get("selftest_contract"))
    if contract is None:
        return {"selftest.name": "", "selftest.digest": ""}
    return {
        "selftest.name": contract["name"],
        "selftest.digest": selftest_contract_digest(data),
    }


def canonical_recipe_for_product(family: str, product_image: object) -> CanonicalRuntimeRecipe | None:
    product_repo = image_repo(product_image)
    for name in list_canonical_recipe_names():
        recipe = load_canonical_recipe(name)
        if recipe.data.get("family") != family:
            continue
        if recipe.data.get("product_image_repo") == product_repo:
            return recipe
    return None


def canonical_recipe_for_image_spec(image_spec: dict[str, Any]) -> CanonicalRuntimeRecipe | None:
    image_recipe = image_spec.get("image_recipe")
    if isinstance(image_recipe, dict):
        recipe_name = image_recipe.get("canonical_recipe_name") or image_recipe.get("recipe_name")
        if recipe_name:
            return load_canonical_recipe(str(recipe_name))
    family = str(image_spec.get("family") or "")
    product_image = image_spec.get("product_image")
    return canonical_recipe_for_product(family, product_image)


def canonical_recipe_identity(recipe: CanonicalRuntimeRecipe | None) -> dict[str, str]:
    if recipe is None:
        return {"canonical_recipe_name": "", "canonical_recipe_digest": ""}
    return {"canonical_recipe_name": recipe.name, "canonical_recipe_digest": recipe.digest}


def canonical_label_values(recipe: CanonicalRuntimeRecipe) -> dict[str, str]:
    runtime_profiles = _string_map(recipe.data.get("runtime_profiles"))
    runtime_contracts = _string_map(recipe.data.get("runtime_contracts"))
    values = {
        "recipe.name": recipe.name,
        "recipe.digest": recipe.digest,
        "contract.version": str(recipe.data.get("runtime_contract_version") or ""),
        "family": str(recipe.data.get("family") or ""),
        "product-component": str(recipe.data.get("product_component") or ""),
        "wrapper-component": str(recipe.data.get("wrapper_component") or ""),
        "runtime-profile.customer": runtime_profiles.get("customer", ""),
        "runtime-profile.dev": runtime_profiles.get("dev", ""),
        "runtime-contract.customer": runtime_contracts.get("customer", ""),
        "runtime-contract.dev": runtime_contracts.get("dev", ""),
        "command-mode": str(recipe.data.get("command_mode") or ""),
        "working-dir": str(recipe.data.get("working_dir") or ""),
        "http-port": str(recipe.data.get("http_port") or ""),
        "source-output-target": str(recipe.data.get("source_output_target") or ""),
        "nas.container-root": str(recipe.data.get("container_nas_root") or ""),
        "nas.host-root-template": str(recipe.data.get("host_nas_root_template") or ""),
        "nas.read-only": _bool_label(recipe.data.get("nas_read_only")),
        "nas.propagation": str(recipe.data.get("nas_mount_propagation") or ""),
        "nas.child-mount-mode": str(recipe.data.get("nas_child_mount_mode") or ""),
        "health.endpoints": _label_map(recipe.data.get("health_endpoints")),
        "health.endpoints.json": _label_map_json(recipe.data.get("health_endpoints")),
    }
    values.update(_selftest_label_values(recipe.data))
    return values


def _metadata_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _command_mode_matches(recipe: CanonicalRuntimeRecipe, profile: RuntimeProfile) -> bool:
    command_mode = str(recipe.data.get("command_mode") or "")
    if command_mode == "image-default":
        return profile.metadata.get("image_default_command") is True
    if command_mode == "gateway-run":
        return _metadata_list(profile.metadata.get("required_command")) == ["gateway", "run"]
    if command_mode == "compose-command":
        return profile.metadata.get("image_default_command") is not True and profile.metadata.get("required_command") is None
    return False


def projection_checks(recipe: CanonicalRuntimeRecipe, runtime_class: str) -> list[tuple[bool, str, str | None]]:
    runtime_profiles = _string_map(recipe.data.get("runtime_profiles"))
    runtime_contracts = _string_map(recipe.data.get("runtime_contracts"))
    profile_name = runtime_profiles.get(runtime_class, "")
    checks: list[tuple[bool, str, str | None]] = [
        (runtime_class in {"customer", "dev"}, "canonical_projection_known", f"runtime_class={runtime_class}"),
        (bool(profile_name), "canonical_projection_profile_declared", f"profile={profile_name or 'missing'}"),
    ]
    if not profile_name:
        return checks

    profile = load_profile(profile_name)
    expected_source_mount = runtime_class == "dev"
    expected_working_dir = str(recipe.data.get("working_dir") or "")
    expected_http_port = str(recipe.data.get("http_port") or "")
    expected_source_output = str(recipe.data.get("source_output_target") or "")
    expected_nas_root = str(recipe.data.get("container_nas_root") or "")
    expected_nas_propagation = str(recipe.data.get("nas_mount_propagation") or "")
    expected_host_nas_template = str(recipe.data.get("host_nas_root_template") or "")
    expected_components = _metadata_list(recipe.data.get("expected_image_components"))
    profile_components = _metadata_list(profile.metadata.get("expected_image_components"))
    health_endpoints = _string_map(recipe.data.get("health_endpoints"))
    requires_health_contract = str(recipe.data.get("runtime_contract_version") or "") == "v2"
    checks.extend(
        [
            (
                profile.metadata.get("family") == recipe.data.get("family"),
                "canonical_profile_family_matches",
                f"recipe={recipe.data.get('family') or 'missing'} profile={profile.metadata.get('family') or 'missing'}",
            ),
            (
                profile.metadata.get("slot_class") == runtime_class,
                "canonical_profile_runtime_class_matches",
                f"recipe={runtime_class} profile={profile.metadata.get('slot_class') or 'missing'}",
            ),
            (
                profile.metadata.get("product_component") == recipe.data.get("product_component"),
                "canonical_product_component_matches",
                f"recipe={recipe.data.get('product_component') or 'missing'} profile={profile.metadata.get('product_component') or 'missing'}",
            ),
            (
                profile.metadata.get("runtime_contract") == runtime_contracts.get(runtime_class),
                "canonical_runtime_contract_matches",
                f"recipe={runtime_contracts.get(runtime_class, 'missing')} profile={profile.metadata.get('runtime_contract') or 'missing'}",
            ),
            (
                profile.metadata.get("customer_surface") == recipe.data.get("customer_surface"),
                "canonical_customer_surface_matches",
                f"recipe={recipe.data.get('customer_surface') or 'missing'} profile={profile.metadata.get('customer_surface') or 'missing'}",
            ),
            (
                profile_components == expected_components,
                "canonical_expected_components_match",
                f"recipe={','.join(expected_components)} profile={','.join(profile_components)}",
            ),
            (
                not requires_health_contract or "hermes-workspace-server" not in expected_components or bool(health_endpoints.get("workspace")),
                "canonical_workspace_health_declared",
                f"workspace={health_endpoints.get('workspace') or 'missing'}",
            ),
            (
                not requires_health_contract or "hermes-gateway" not in expected_components or bool(health_endpoints.get("gateway")),
                "canonical_gateway_health_declared",
                f"gateway={health_endpoints.get('gateway') or 'missing'}",
            ),
            (
                not requires_health_contract or "hermes-dashboard" not in expected_components or bool(health_endpoints.get("dashboard")),
                "canonical_dashboard_health_declared",
                f"dashboard={health_endpoints.get('dashboard') or 'missing'}",
            ),
            (
                profile.metadata.get("container_nas_root") == expected_nas_root,
                "canonical_nas_root_matches",
                f"recipe={expected_nas_root or 'missing'} profile={profile.metadata.get('container_nas_root') or 'missing'}",
            ),
            (
                expected_host_nas_template == "/home/{slot}/nas_docs",
                "canonical_host_nas_root_template_declared",
                f"recipe={expected_host_nas_template or 'missing'}",
            ),
            (
                profile.metadata.get("required_read_only_nas") is recipe.data.get("nas_read_only"),
                "canonical_nas_read_only_matches",
                f"recipe={_bool_label(recipe.data.get('nas_read_only')) or 'missing'} profile={profile.metadata.get('required_read_only_nas')}",
            ),
            (
                str(profile.metadata.get("required_mount_propagation") or "") == expected_nas_propagation,
                "canonical_nas_propagation_matches",
                f"recipe={expected_nas_propagation or 'missing'} profile={profile.metadata.get('required_mount_propagation') or 'missing'}",
            ),
            (
                profile.metadata.get("allow_source_mount") is expected_source_mount,
                "canonical_source_mount_policy_matches",
                f"runtime_class={runtime_class} allow_source_mount={profile.metadata.get('allow_source_mount')}",
            ),
            (
                runtime_class == "customer"
                or profile.metadata.get("source_output_target") == expected_source_output,
                "canonical_source_mount_target_matches",
                f"recipe={expected_source_output or 'missing'} profile={profile.metadata.get('source_output_target') or 'missing'}",
            ),
            (
                profile.metadata.get("runtime_user_mode") == recipe.data.get("runtime_user_mode"),
                "canonical_runtime_user_mode_matches",
                f"recipe={recipe.data.get('runtime_user_mode') or 'missing'} profile={profile.metadata.get('runtime_user_mode') or 'missing'}",
            ),
            (
                _command_mode_matches(recipe, profile),
                "canonical_command_mode_matches",
                f"recipe={recipe.data.get('command_mode') or 'missing'} profile={profile.name}",
            ),
            (
                str(profile.metadata.get("required_working_dir") or "") == expected_working_dir,
                "canonical_working_dir_matches",
                f"recipe={expected_working_dir or 'empty'} profile={profile.metadata.get('required_working_dir') or 'empty'}",
            ),
            (
                str(profile.metadata.get("required_http_container_port") or "") == expected_http_port,
                "canonical_http_port_matches",
                f"recipe={expected_http_port or 'missing'} profile={profile.metadata.get('required_http_container_port') or 'missing'}",
            ),
        ]
    )
    return checks


def validate_canonical_recipe(recipe: CanonicalRuntimeRecipe) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = [
        (bool(recipe.data.get("family")), "canonical_family_declared", f"family={recipe.data.get('family') or 'missing'}"),
        (
            bool(recipe.data.get("product_image_repo")),
            "canonical_product_image_repo_declared",
            f"repo={recipe.data.get('product_image_repo') or 'missing'}",
        ),
        (
            bool(recipe.data.get("wrapper_repo")),
            "canonical_wrapper_repo_declared",
            f"repo={recipe.data.get('wrapper_repo') or 'missing'}",
        ),
        (
            str(recipe.data.get("host_nas_root_template") or "") == "/home/{slot}/nas_docs",
            "canonical_host_nas_root_template_declared",
            f"template={recipe.data.get('host_nas_root_template') or 'missing'}",
        ),
        (
            recipe.data.get("nas_read_only") is True,
            "canonical_nas_read_only_declared",
            f"read_only={recipe.data.get('nas_read_only')}",
        ),
        (
            bool(recipe.data.get("nas_mount_propagation")),
            "canonical_nas_propagation_declared",
            f"propagation={recipe.data.get('nas_mount_propagation') or 'missing'}",
        ),
        (
            str(recipe.data.get("nas_child_mount_mode") or "") == "host-propagated-cifs",
            "canonical_nas_child_mount_mode_declared",
            f"mode={recipe.data.get('nas_child_mount_mode') or 'missing'}",
        ),
    ]
    selftest_raw = recipe.data.get("selftest_contract")
    if selftest_raw is not None:
        contract = normalized_selftest_contract(selftest_raw)
        checks.append(
            (
                contract is not None,
                "canonical_selftest_contract_valid",
                "ok"
                if contract is not None
                else "selftest_contract requires name, non-empty command list, required_checks list, positive timeout_seconds",
            )
        )
        if contract is not None:
            checks.append(
                (
                    bool(selftest_contract_digest(recipe.data)),
                    "canonical_selftest_digest_computed",
                    f"name={contract['name']}",
                )
            )
    checks.extend(projection_checks(recipe, "customer"))
    checks.extend(projection_checks(recipe, "dev"))
    return checks
