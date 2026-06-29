from __future__ import annotations

import json
import re
import shutil
import subprocess

from ..canonical_recipes import (
    canonical_label_values,
    canonical_recipe_for_image_spec,
    canonical_recipe_identity,
    load_canonical_recipe,
    projection_checks as canonical_projection_checks,
    validate_canonical_recipe,
)
from ..image_components import image_component_name as _image_component_name
from ..image_components import image_repo as _image_repo
from ..profiles import load_profile


def _run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
IMAGE_RECIPE_LABEL_PREFIX = "com.epicevent.agent-runtime."
IMAGE_RECIPE_SCHEMA = "v1"
IMAGE_ROLLOUT_IMAGE_NAME = "direct-image"


def has_digest_ref(value: object) -> bool:
    return isinstance(value, str) and "@sha256:" in value


def digest_from_image_ref(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def validate_safe_name(name: str) -> None:
    if not SAFE_NAME_RE.match(name):
        raise ValueError("name must contain only letters, numbers, '.', '_', or '-'")


def validate_image_digest_ref(image_ref: str) -> str:
    if not IMAGE_REF_RE.match(image_ref):
        raise ValueError("image reference must be pinned by digest: REGISTRY/IMAGE@sha256:<64 hex>")
    digest = digest_from_image_ref(image_ref)
    if not digest or not DIGEST_RE.match(digest):
        raise ValueError("image reference digest must be sha256:<64 hex>")
    return digest


def optional_safe_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if text and not SAFE_TEXT_RE.match(text):
        raise ValueError(f"{name} must not contain control characters")
    return text


def allowed_image_ref(family: object, role: str, image_ref: object) -> bool:
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


def metadata_list(value: object) -> list[str]:
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


def label_map_from_string(value: str) -> dict[str, str]:
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


def label_map_from_json(value: str) -> dict[str, str]:
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


def label_map_from_labels(labels: dict[str, str], name: str) -> dict[str, str]:
    json_value = recipe_label(labels, f"{name}.json")
    if json_value:
        return label_map_from_json(json_value)
    csv_value = recipe_label(labels, name)
    return label_map_from_string(csv_value) if csv_value else {}


def label_map_to_string(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    return ",".join(f"{key}={value[key]}" for key in sorted(value) if str(key) and str(value[key]))


def label_map_to_json(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    result = {str(key): str(item) for key, item in value.items() if str(key) and str(item)}
    if not result:
        return ""
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def profile_runtime_contract(profile) -> str:
    return str(profile.metadata.get("runtime_contract") or "")


def profile_customer_surface(profile) -> str:
    return str(profile.metadata.get("customer_surface") or "")


def image_spec_recipe_payload(image_spec: dict) -> dict[str, object]:
    product_image = image_spec.get("product_image")
    wrapper_image = image_spec.get("wrapper_image")
    image_recipe = image_spec_recipe(image_spec)
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


def image_spec_recipe_tokens(image_spec: dict) -> dict[str, str]:
    recipe = image_spec_recipe_payload(image_spec)
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


def image_recipe_labels_from_wrapper(wrapper_image: str) -> dict[str, str]:
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


def recipe_label(labels: dict[str, str], name: str) -> str:
    return str(labels.get(IMAGE_RECIPE_LABEL_PREFIX + name) or "")


def image_recipe_from_wrapper_image(wrapper_image: str, *, family: str, product_image: str) -> dict[str, object]:
    labels = image_recipe_labels_from_wrapper(wrapper_image)
    schema = recipe_label(labels, "recipe.schema")
    if schema != IMAGE_RECIPE_SCHEMA:
        raise ValueError(
            "wrapper image is missing agent-runtime recipe labels; rebuild wrapper with current publish workflow"
        )
    label_family = recipe_label(labels, "family")
    label_product_image = recipe_label(labels, "product-image")
    if label_family != family:
        raise ValueError(f"wrapper image recipe family mismatch: label={label_family or 'missing'} requested={family}")
    if label_product_image != product_image:
        raise ValueError("wrapper image recipe product-image does not match --product-image")
    customer_profile = recipe_label(labels, "runtime-profile.customer")
    dev_profile = recipe_label(labels, "runtime-profile.dev")
    customer_contract = recipe_label(labels, "runtime-contract.customer")
    dev_contract = recipe_label(labels, "runtime-contract.dev")
    product_component = recipe_label(labels, "product-component")
    wrapper_component = recipe_label(labels, "wrapper-component")
    command_mode = recipe_label(labels, "command-mode")
    http_port = recipe_label(labels, "http-port")
    source_output_target = recipe_label(labels, "source-output-target")
    nas_container_root = recipe_label(labels, "nas.container-root")
    nas_host_root_template = recipe_label(labels, "nas.host-root-template")
    nas_read_only = recipe_label(labels, "nas.read-only")
    nas_propagation = recipe_label(labels, "nas.propagation")
    nas_child_mount_mode = recipe_label(labels, "nas.child-mount-mode")
    contract_version = recipe_label(labels, "contract.version")
    health_endpoints_label = recipe_label(labels, "health.endpoints")
    health_endpoints_json_label = recipe_label(labels, "health.endpoints.json")
    # Self-contained selftest contract: the product image carries the invocation in a
    # plain-string label (inherited by the wrapper). The required checks come from the
    # selftest's own JSON output. Trust is anchored by the root-approved image digest
    # (opsctl image approve), not by the recipe.
    selftest_command = recipe_label(labels, "selftest.command")
    selftest_name = recipe_label(labels, "selftest.name")
    selftest_timeout = recipe_label(labels, "selftest.timeout")
    # Self-contained config contract: the product image carries its own config
    # validate/migrate invocations in plain-string labels (inherited by the wrapper).
    # opsctl never reimplements the config schema; it runs the product's own commands
    # to gate rollouts (validate before recreate) and migrate (doctor --fix) on demand.
    config_validate_command = recipe_label(labels, "config-validate.command")
    config_migrate_command = recipe_label(labels, "config-migrate.command")
    config_name = recipe_label(labels, "config.name")
    config_validate_timeout = recipe_label(labels, "config-validate.timeout")
    config_migrate_timeout = recipe_label(labels, "config-migrate.timeout")
    canonical_name = recipe_label(labels, "recipe.name")
    canonical_digest = recipe_label(labels, "recipe.digest")
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
        "working-dir": recipe_label(labels, "working-dir"),
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
        expected_health_endpoints = label_map_from_json(expected_labels["health.endpoints.json"])
        actual_health_endpoints = label_map_from_labels(labels, "health.endpoints")
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
        "working_dir": recipe_label(labels, "working-dir"),
        "http_port": http_port,
        "source_output_target": source_output_target,
        "container_nas_root": nas_container_root,
        "host_nas_root_template": nas_host_root_template,
        "nas_read_only": nas_read_only,
        "nas_mount_propagation": nas_propagation,
        "nas_child_mount_mode": nas_child_mount_mode,
        "contract_version": contract_version,
        "health_endpoints": label_map_from_labels(labels, "health.endpoints"),
        "ops_repo_commit": recipe_label(labels, "ops-repo-commit"),
    }
    if selftest_command:
        recipe["selftest_contract"] = {
            "name": selftest_name or "selftest",
            "command": selftest_command.split(),
            "timeout_seconds": int(selftest_timeout) if selftest_timeout.isdigit() else 120,
        }
    if config_validate_command:
        recipe["config_contract"] = {
            "name": config_name or "config",
            "validate_command": config_validate_command.split(),
            "migrate_command": config_migrate_command.split() if config_migrate_command else [],
            "validate_timeout_seconds": int(config_validate_timeout) if config_validate_timeout.isdigit() else 120,
            "migrate_timeout_seconds": int(config_migrate_timeout) if config_migrate_timeout.isdigit() else 180,
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


def image_recipe_from_wrapper_image_auto(wrapper_image: str, *, product_image: str) -> dict[str, object]:
    labels = image_recipe_labels_from_wrapper(wrapper_image)
    family = recipe_label(labels, "family")
    if family not in {"openclaw", "hermes"}:
        raise ValueError(f"wrapper image recipe family mismatch: label={family or 'missing'}")
    return image_recipe_from_wrapper_image(wrapper_image, family=family, product_image=product_image)


def image_spec_from_direct_images(wrapper_image: str, product_image: str) -> dict[str, object]:
    wrapper_digest = validate_image_digest_ref(wrapper_image)
    product_digest = validate_image_digest_ref(product_image)
    image_recipe = image_recipe_from_wrapper_image_auto(wrapper_image, product_image=product_image)
    family = str(image_recipe.get("family") or "")
    if family not in {"openclaw", "hermes"}:
        raise ValueError("wrapper image recipe did not declare a supported family")
    if not allowed_image_ref(family, "wrapper", wrapper_image):
        raise ValueError(f"wrapper image repository is not allowed for {family}")
    if not allowed_image_ref(family, "product", product_image):
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


def image_spec_recipe(image_spec: dict) -> dict[str, object]:
    recipe = image_spec.get("image_recipe")
    return recipe if isinstance(recipe, dict) else {}


def image_spec_selftest_contract(image_spec: dict) -> dict[str, object] | None:
    """Return the attested selftest_contract from a verified wrapper image, or None.

    Only populated by ``image_recipe_from_wrapper_image`` after the wrapper labels
    pass the canonical-recipe digest checks, so callers can trust the command/digest
    without re-verifying. None for images/families that declare no contract.
    """
    contract = image_spec_recipe(image_spec).get("selftest_contract")
    return contract if isinstance(contract, dict) else None


def image_spec_config_contract(image_spec: dict) -> dict[str, object] | None:
    """Return the attested config_contract from a verified wrapper image, or None.

    Carries the product's own ``config validate`` / ``doctor --fix`` invocations so
    opsctl can gate a rollout on the on-disk config being valid for the target image
    (before recreate) and migrate it on demand, without reimplementing the schema.
    None for images/families that declare no config contract.
    """
    contract = image_spec_recipe(image_spec).get("config_contract")
    return contract if isinstance(contract, dict) else None


def config_contract_from_image_labels(image_ref: str) -> dict[str, object] | None:
    """Read just the config contract directly from an image's labels (product or wrapper).

    Unlike ``image_recipe_from_wrapper_image`` this does no full recipe validation — it is
    the bootstrap path used to migrate a slot whose currently-running image predates the
    contract, using the TARGET image's own validate/migrate commands. Returns None when the
    image declares no config contract.
    """
    labels = image_recipe_labels_from_wrapper(image_ref)
    validate_command = recipe_label(labels, "config-validate.command")
    if not validate_command:
        return None
    migrate_command = recipe_label(labels, "config-migrate.command")
    name = recipe_label(labels, "config.name")
    validate_timeout = recipe_label(labels, "config-validate.timeout")
    migrate_timeout = recipe_label(labels, "config-migrate.timeout")
    return {
        "name": name or "config",
        "validate_command": validate_command.split(),
        "migrate_command": migrate_command.split() if migrate_command else [],
        "validate_timeout_seconds": int(validate_timeout) if validate_timeout.isdigit() else 120,
        "migrate_timeout_seconds": int(migrate_timeout) if migrate_timeout.isdigit() else 180,
    }


def image_spec_runtime_profile_name(image_spec: dict, runtime_class: str, fallback: str | None = None) -> str:
    recipe = image_spec_recipe(image_spec)
    profiles = recipe.get("runtime_profiles")
    if isinstance(profiles, dict) and profiles.get(runtime_class):
        return str(profiles[runtime_class])
    if image_spec.get("mode") == "wrapped_product_image":
        raise ValueError("wrapped image is missing image recipe runtime profile; rebuild a labeled wrapper image")
    return str(fallback or "")


def image_spec_profile_contract_checks(image_spec: dict, profile) -> list[tuple[bool, str, str | None]]:
    runtime_contract = profile_runtime_contract(profile)
    customer_surface = profile_customer_surface(profile)
    expected_components = metadata_list(profile.metadata.get("expected_image_components"))
    compatible_product_prefixes = metadata_list(profile.metadata.get("compatible_product_image_prefixes"))
    product_image = str(image_spec.get("product_image") or "")
    runtime_class = str(profile.metadata.get("slot_class") or "")
    image_recipe = image_spec_recipe(image_spec)
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


def image_spec_profile_contract_failures(image_spec: dict, profile) -> list[str]:
    return [name for ok, name, _ in image_spec_profile_contract_checks(image_spec, profile) if not ok]
