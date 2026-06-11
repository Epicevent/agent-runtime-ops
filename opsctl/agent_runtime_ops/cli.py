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
from .commands.admin import cmd_admin_serve
from .commands.apache import cmd_apache_set_host, cmd_apache_status
from .commands.apply import cmd_apply, cmd_rollback
from .commands.binding import (
    cmd_binding_list,
    cmd_binding_normalize,
    cmd_binding_set_public_host,
    cmd_binding_status,
)
from .commands.blocked import cmd_blocked_mutation
from .commands.check import cmd_check
from .commands.diagnostics import cmd_diagnostics_show
from .commands.document_tools import cmd_document_tools_status
from .commands.profile import cmd_profile_list
from .commands.runtime_truth import (
    _find_gateway_container,
    _find_gateway_container_by_binding,
    _live_runtime_truth,
    cmd_runtime_truth,
)
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
from .domain.runtime_state import (
    _agent_backup_root,
    _agent_compose_path,
    _agent_manifest_path,
    _atomic_write,
    _backup_agent_runtime_state,
    _backup_manifest_data,
    _compose_project_name,
    _desired_from_manifest,
    _desired_from_runtime_manifest,
    _docker_compose_command,
    _env_file_keys,
    _latest_backup,
    _load_backup_runtime_contract,
    _manifest_payload,
    _read_legacy_slot_manifest,
    _required_compose_variables,
    _restore_backup,
    _safe_managed_file,
    _slot_runtime_dir,
    _state_manifest_path,
    _state_runtime_dir,
    _write_slot_manifest,
    _write_slot_manifests,
    _write_state_slot_manifest,
)
from .domain.apache_route_checks import apache_route_checks as _apache_route_checks
from .domain.image_specs import (
    DIGEST_RE,
    IMAGE_RECIPE_LABEL_PREFIX,
    IMAGE_RECIPE_SCHEMA,
    IMAGE_REF_RE,
    IMAGE_ROLLOUT_IMAGE_NAME,
    SAFE_NAME_RE,
    SAFE_TEXT_RE,
    _allowed_image_ref,
    _csv,
    _derived_image_components,
    _digest_from_image_ref,
    _has_digest_ref,
    _image_recipe_from_wrapper_image,
    _image_recipe_from_wrapper_image_auto,
    _image_recipe_labels_from_wrapper,
    _image_spec_from_direct_images,
    _image_spec_profile_contract_checks,
    _image_spec_profile_contract_failures,
    _image_spec_recipe,
    _image_spec_recipe_payload,
    _image_spec_recipe_tokens,
    _image_spec_runtime_profile_name,
    _label_map_from_json,
    _label_map_from_labels,
    _label_map_from_string,
    _label_map_to_json,
    _label_map_to_string,
    _metadata_list,
    _optional_safe_text,
    _profile_customer_surface,
    _profile_runtime_contract,
    _recipe_label,
    _validate_image_digest_ref,
    _validate_safe_name,
)
from .domain.source_provenance import require_fresh_clean_source_provenance as _require_fresh_clean_source_provenance
from .domain.source_provenance import source_provenance as _source_provenance
from .domain.update_policy import installed_source_commit as _installed_source_commit
from .host.account_files import (
    _atomic_write_key_value,
    _credential_file_is_safe,
    _credential_file_is_safe_for_slot,
    _credential_presence,
    _ensure_customer_agent_dirs,
    _ensure_not_symlink_chain,
    _group_gid,
    _passwd_record,
    _read_key_value_file,
    _read_password_from_stdin,
    _runtime_ids,
    _slot_uid_gid,
    _write_credential_file,
)
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

DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"
DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"


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
