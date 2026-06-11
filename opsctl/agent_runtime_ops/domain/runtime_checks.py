from __future__ import annotations

import json
import re
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..apache import parse_apache_route
from ..compose_contract import validate_compose_contract
from ..host.mounts import (
    findmnt_tree as _findmnt_tree,
    findmnt_under as _findmnt_under,
    is_readonly_mount as _is_readonly_mount,
    propagation_satisfies as _propagation_satisfies,
)
from ..nas import check_nas_policy
from ..routing import get_runtime_binding
from .common import is_root, run_text
from .image_specs import (
    allowed_image_ref,
    digest_from_image_ref,
    has_digest_ref,
    image_spec_profile_contract_checks,
    image_spec_recipe,
)
from .runtime_truth import find_gateway_container, live_runtime_truth


def http_backend_smoke(slot: str, path: str, state_root: Path) -> tuple[bool, str]:
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


def contract_health_endpoints(desired, profile) -> dict[str, str]:
    image_recipe = image_spec_recipe(desired.image_spec)
    endpoints = image_recipe.get("health_endpoints")
    if isinstance(endpoints, dict):
        return {str(key): str(value) for key, value in endpoints.items() if str(key) and str(value)}
    profile_endpoints = profile.metadata.get("required_internal_http")
    if isinstance(profile_endpoints, dict):
        return {str(key): str(value) for key, value in profile_endpoints.items() if str(key) and str(value)}
    return {}


def internal_http_check_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip().lower()).strip("_")
    return safe or "endpoint"


def run_internal_http_check(nsenter: str, pid: int, name: str, url: str) -> tuple[bool, str, str]:
    check_name = f"live_internal_http_{internal_http_check_name(name)}_ok"
    curl = shutil.which("curl")
    if not curl:
        return False, check_name, "curl_missing"
    proc = run_text([nsenter, "-t", str(pid), "-n", curl, "-fsS", "--max-time", "5", url], timeout=8)
    if proc.returncode == 0:
        return True, check_name, f"url={url}"
    detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
    return False, check_name, f"url={url} error={detail[:160]}"


def run_live_slot_checks(desired, profile, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not is_root():
        return [(False, "live_check_requires_root", "run as root/admin or a restricted root helper")]

    binding = get_runtime_binding(desired.slot, state_root)
    container, container_lookup = find_gateway_container(binding, profile)
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

    inspect = run_text(["docker", "inspect", container])
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
        truth, truth_checks = live_runtime_truth(desired.slot, state_root)
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
        smoke_ok, smoke_detail = http_backend_smoke(desired.slot, smoke_path, state_root)
        checks.append((smoke_ok, "live_backend_http_smoke_ok", smoke_detail))

    for endpoint_name, endpoint_url in contract_health_endpoints(desired, profile).items():
        checks.append(run_internal_http_check(nsenter, pid, endpoint_name, endpoint_url))

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


def run_static_slot_checks(desired, profile, rendered=None) -> list[tuple[bool, str, str | None]]:
    target_family = desired.family
    runtime_class = desired.runtime_class
    profile_family = profile.metadata.get("family")
    profile_runtime_class = profile.metadata.get("slot_class")
    profile_mode = profile.metadata.get("mode")
    image_family = desired.image_spec.get("family")
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    image_digest = desired.image_spec.get("digest")
    wrapper_digest = digest_from_image_ref(wrapper_image)
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
        (has_digest_ref(wrapper_image), "wrapper_image_pinned_by_digest", str(wrapper_image) if wrapper_image else None),
        (has_digest_ref(product_image), "product_image_pinned_by_digest", str(product_image) if product_image else None),
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
            allowed_image_ref(target_family, "wrapper", wrapper_image),
            "wrapper_image_repository_allowed",
            str(wrapper_image) if wrapper_image else None,
        ),
        (
            allowed_image_ref(target_family, "product", product_image),
            "product_image_repository_allowed",
            str(product_image) if product_image else None,
        ),
    ]
    checks.extend(image_spec_profile_contract_checks(desired.image_spec, profile))

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


def run_live_slot_checks_with_wait(desired, profile, state_root: Path, timeout_seconds: int = 90) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    wait_names = {
        "live_container_running",
        "live_container_pid_present",
        "live_container_health_ok",
        "live_backend_http_smoke_ok",
    }
    while True:
        checks = run_live_slot_checks(desired, profile, state_root)
        last_checks = checks
        failed_names = {name for ok, name, _ in checks if not ok}
        if not failed_names:
            return checks
        if not (failed_names & wait_names) and not any(name.startswith("live_internal_http_") for name in failed_names):
            return checks
        if time.monotonic() >= deadline:
            return checks
        time.sleep(5)


def profile_startup_timeout_seconds(profile) -> int:
    raw_value = profile.metadata.get("startup_timeout_seconds", 90)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return 90
    return max(30, min(value, 600))


_http_backend_smoke = http_backend_smoke
_contract_health_endpoints = contract_health_endpoints
_internal_http_check_name = internal_http_check_name
_run_internal_http_check = run_internal_http_check
_run_live_slot_checks = run_live_slot_checks
_run_static_slot_checks = run_static_slot_checks
_run_live_slot_checks_with_wait = run_live_slot_checks_with_wait
_profile_startup_timeout_seconds = profile_startup_timeout_seconds
