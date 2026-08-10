from __future__ import annotations

import json
from pathlib import Path
import subprocess

from ..apache import parse_apache_route
from ..canonical_recipes import load_canonical_recipe
from ..routing import RuntimeBinding, get_runtime_binding
from .apache_route_checks import apache_route_checks
from .common import container_name, run_readonly_docker
from .image_specs import (
    IMAGE_RECIPE_SCHEMA,
    recipe_label,
)

# Compatibility name retained for focused tests and downstream monkeypatches. The
# implementation is the fixed Docker ps/inspect-only bounded runner.
run_text = run_readonly_docker


def local_canonical_recipe_check_from_truth(truth: dict[str, str]) -> tuple[bool, str, str | None]:
    name = truth.get("canonical_recipe_name") or ""
    digest = truth.get("canonical_recipe_digest") or ""
    check_name = "truth_canonical_recipe_digest_matches_local"
    if not name or not digest:
        return False, check_name, "missing"
    try:
        recipe = load_canonical_recipe(name)
    except Exception as exc:
        return False, check_name, str(exc)
    return recipe.digest == digest, check_name, f"image={digest} local={recipe.digest}"


def find_gateway_container(binding: RuntimeBinding, profile) -> tuple[str | None, str | None]:
    service_label = "gateway"
    by_label = run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.instance-id={binding.instance_id}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if by_label.returncode == 0:
        ids = [line.strip() for line in by_label.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "instance_label"
        if len(ids) > 1:
            return None, f"multiple_instance_label_matches:{len(ids)}"
    legacy = run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={binding.linux_account}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if legacy.returncode == 0:
        ids = [line.strip() for line in legacy.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "legacy_linux_account_label"
        if len(ids) > 1:
            return None, f"multiple_legacy_label_matches:{len(ids)}"
    return container_name(binding.linux_account, profile), "fallback_name"


def find_gateway_container_by_binding(binding: RuntimeBinding) -> tuple[str | None, str | None]:
    by_label = run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.instance-id={binding.instance_id}",
            "--filter",
            "label=agent-runtime.service=gateway",
            "--format",
            "{{.ID}}",
        ]
    )
    if by_label.returncode != 0:
        return None, (by_label.stderr or by_label.stdout).strip() or "docker_ps_failed"
    ids = [line.strip() for line in by_label.stdout.splitlines() if line.strip()]
    if len(ids) == 1:
        return ids[0], "instance_label"
    if len(ids) > 1:
        return None, f"multiple_instance_label_matches:{len(ids)}"
    legacy = run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={binding.linux_account}",
            "--filter",
            "label=agent-runtime.service=gateway",
            "--format",
            "{{.ID}}",
        ]
    )
    if legacy.returncode != 0:
        return None, (legacy.stderr or legacy.stdout).strip() or "docker_ps_failed"
    ids = [line.strip() for line in legacy.stdout.splitlines() if line.strip()]
    if len(ids) == 1:
        return ids[0], "legacy_linux_account_label"
    if len(ids) > 1:
        return None, f"multiple_legacy_label_matches:{len(ids)}"
    return None, "not_found"


def labels_from_container_info(info: dict) -> dict[str, str]:
    config = info.get("Config") if isinstance(info, dict) else {}
    labels = config.get("Labels") if isinstance(config, dict) else {}
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def live_image_truth_from_info(binding: RuntimeBinding, info: dict, apache_route) -> dict[str, str]:
    labels = labels_from_container_info(info)
    config = info.get("Config") if isinstance(info, dict) else {}
    image = str((config or {}).get("Image") or "")
    runtime_class = binding.runtime_class
    schema = recipe_label(labels, "recipe.schema")
    family = recipe_label(labels, "family")
    product_image = recipe_label(labels, "product-image")
    runtime_profile = recipe_label(labels, f"runtime-profile.{runtime_class}")
    runtime_contract = recipe_label(labels, f"runtime-contract.{runtime_class}")
    canonical_recipe_name = recipe_label(labels, "recipe.name")
    canonical_recipe_digest = recipe_label(labels, "recipe.digest")
    truth_status = "ok"
    if schema != IMAGE_RECIPE_SCHEMA:
        truth_status = "legacy_or_unlabeled"
    elif not canonical_recipe_name or not canonical_recipe_digest:
        truth_status = "incomplete_recipe_labels"
    return {
        "instance_id": binding.instance_id,
        "linux_account": binding.linux_account,
        "truth_source": "live_image",
        "truth_status": truth_status,
        "public_host": binding.public_host,
        "actual_public_host": apache_route.public_host,
        "gateway_port": str(binding.gateway_port),
        "apache_gateway_port": str(apache_route.gateway_port),
        "bridge_port": str(binding.bridge_port),
        "enabled": "yes" if binding.enabled else "no",
        "family": binding.family,
        "runtime_class": runtime_class,
        "wrapper_image": image,
        "image_family": family,
        "product_image": product_image,
        "product_component": recipe_label(labels, "product-component"),
        "wrapper_component": recipe_label(labels, "wrapper-component"),
        "runtime_profile": runtime_profile,
        "runtime_contract": runtime_contract,
        "canonical_recipe_name": canonical_recipe_name,
        "canonical_recipe_digest": canonical_recipe_digest,
        "source_output_target": recipe_label(labels, "source-output-target"),
        "container_nas_root": recipe_label(labels, "nas.container-root"),
        "host_nas_root_template": recipe_label(labels, "nas.host-root-template"),
        "nas_read_only": recipe_label(labels, "nas.read-only"),
        "nas_mount_propagation": recipe_label(labels, "nas.propagation"),
        "nas_child_mount_mode": recipe_label(labels, "nas.child-mount-mode"),
        "contract_version": recipe_label(labels, "contract.version"),
        "health_endpoints": recipe_label(labels, "health.endpoints"),
        "health_endpoints_json": recipe_label(labels, "health.endpoints.json"),
        "ops_repo_commit": recipe_label(labels, "ops-repo-commit"),
    }


def live_runtime_truth(
    slot: str,
    state_root: Path,
    *,
    expected_image_spec: dict[str, object] | None = None,
    expected_runtime_profile_digest: str | None = None,
) -> tuple[dict[str, str], list[tuple[bool, str, str | None]]]:
    checks: list[tuple[bool, str, str | None]] = []
    binding = get_runtime_binding(slot, state_root)
    apache_route = parse_apache_route(binding.linux_account)
    checks.extend(apache_route_checks(binding, apache_route))
    rootless_info = None
    if getattr(binding, "upstream_kind", "managed-rootful") == "developer-rootless":
        uid_proc = subprocess.run(["id", "-u", binding.upstream_owner], text=True, capture_output=True, check=False)
        inspect = subprocess.run(
            ["runuser", "-u", binding.upstream_owner, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid_proc.stdout.strip()}", "docker", "inspect", binding.upstream_container],
            text=True, capture_output=True, check=False,
        ) if uid_proc.returncode == 0 else uid_proc
        try:
            rootless_info = json.loads(inspect.stdout)[0] if inspect.returncode == 0 else None
        except Exception:
            rootless_info = None
        container, lookup = (binding.upstream_container if rootless_info else None), "binding_rootless_upstream"
    else:
        container, lookup = find_gateway_container_by_binding(binding)
    checks.append((bool(container), "truth_container_lookup", lookup))
    if not container:
        return (
            {
                "instance_id": binding.instance_id,
                "linux_account": binding.linux_account,
                "truth_source": "live_image",
                "truth_status": "not_running",
                "public_host": binding.public_host,
                "actual_public_host": apache_route.public_host,
                "gateway_port": str(binding.gateway_port),
                "apache_gateway_port": str(apache_route.gateway_port),
                "bridge_port": str(binding.bridge_port),
                "enabled": "yes" if binding.enabled else "no",
                "family": binding.family,
                "runtime_class": binding.runtime_class,
            },
            checks,
        )
    inspect = None if rootless_info is not None else run_text(["docker", "inspect", container])
    checks.append((rootless_info is not None or inspect.returncode == 0, "truth_container_inspect_ok", container))
    if rootless_info is None and inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout).strip()
        return (
            {
                "linux_account": binding.linux_account,
                "truth_source": "live_image",
                "truth_status": "inspect_failed",
                "reason": detail[:200],
            },
            checks,
        )
    try:
        info = rootless_info if rootless_info is not None else json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "truth_container_inspect_parse_ok", str(exc)))
        return ({"linux_account": binding.linux_account, "truth_source": "live_image", "truth_status": "parse_failed", "reason": str(exc)}, checks)
    truth = live_image_truth_from_info(binding, info, apache_route)
    labels = labels_from_container_info(info)
    checks.extend(
        [
            (truth["truth_status"] == "ok", "truth_image_labeled", truth["truth_status"]),
            (truth.get("image_family") == binding.family, "truth_family_matches_binding", f"image={truth.get('image_family') or 'missing'} binding={binding.family}"),
            (bool(truth.get("runtime_profile")), "truth_runtime_profile_present", truth.get("runtime_profile") or "missing"),
            (
                labels.get("agent-runtime.instance-id") in {None, binding.instance_id},
                "truth_container_instance_label_matches",
                f"label={labels.get('agent-runtime.instance-id') or 'missing'} binding={binding.instance_id}",
            ),
            (
                labels.get("agent-runtime.linux-account") in {None, binding.linux_account}
                and labels.get("agent-runtime.slot") in {None, binding.linux_account},
                "truth_container_linux_account_label_matches",
                f"label={labels.get('agent-runtime.linux-account') or labels.get('agent-runtime.slot') or 'missing'} binding={binding.linux_account}",
            ),
            local_canonical_recipe_check_from_truth(truth),
        ]
    )
    return truth, checks
