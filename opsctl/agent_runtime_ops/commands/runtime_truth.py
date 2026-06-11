from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

from ..domain.runtime_truth import local_canonical_recipe_check_from_truth as _local_canonical_recipe_check_from_truth
from ..routing import RuntimeBinding


def _cli_mod():
    from .. import cli

    return cli


def _state_root(args: argparse.Namespace) -> Path:
    return _cli_mod()._state_root(args)


def _container_name(slot: str, profile) -> str:
    return _cli_mod()._container_name(slot, profile)


def _run_text(command: list[str], timeout: int = 20):
    return _cli_mod()._run_text(command, timeout=timeout)


def _label_map_from_labels(labels: dict[str, str], name: str) -> dict[str, str]:
    return _cli_mod()._label_map_from_labels(labels, name)


def _profile_runtime_contract(profile) -> str:
    return _cli_mod()._profile_runtime_contract(profile)


def _profile_customer_surface(profile) -> str:
    return _cli_mod()._profile_customer_surface(profile)


def _apache_route_checks(binding: RuntimeBinding, apache_route) -> list[tuple[bool, str, str | None]]:
    return _cli_mod()._apache_route_checks(binding, apache_route)


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    _cli_mod()._check_line(ok, name, detail)


def _is_root() -> bool:
    return _cli_mod()._is_root()


def _image_spec_recipe_tokens(image_spec: dict) -> dict[str, str]:
    return _cli_mod()._image_spec_recipe_tokens(image_spec)


def _recipe_label(labels: dict[str, str], name: str) -> str:
    return _cli_mod()._recipe_label(labels, name)


def parse_apache_route(slot: str):
    return _cli_mod().parse_apache_route(slot)


def load_runtime_bindings(state_root: Path):
    return _cli_mod().load_runtime_bindings(state_root)


def get_runtime_binding(target: str, state_root: Path):
    return _cli_mod().get_runtime_binding(target, state_root)


def load_profile(name: str):
    return _cli_mod().load_profile(name)


IMAGE_RECIPE_SCHEMA = "v1"


def _find_gateway_container(binding: RuntimeBinding, profile) -> tuple[str | None, str | None]:
    service_label = "gateway"
    by_label = _run_text(
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
    legacy = _run_text(
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
    return _container_name(binding.linux_account, profile), "fallback_name"


def _find_gateway_container_by_binding(binding: RuntimeBinding) -> tuple[str | None, str | None]:
    by_label = _run_text(
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
    legacy = _run_text(
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


def _labels_from_container_info(info: dict) -> dict[str, str]:
    config = info.get("Config") if isinstance(info, dict) else {}
    labels = config.get("Labels") if isinstance(config, dict) else {}
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def _live_image_truth_from_info(binding: RuntimeBinding, info: dict, apache_route) -> dict[str, str]:
    labels = _labels_from_container_info(info)
    config = info.get("Config") if isinstance(info, dict) else {}
    image = str((config or {}).get("Image") or "")
    runtime_class = binding.runtime_class
    schema = _recipe_label(labels, "recipe.schema")
    family = _recipe_label(labels, "family")
    product_image = _recipe_label(labels, "product-image")
    runtime_profile = _recipe_label(labels, f"runtime-profile.{runtime_class}")
    runtime_contract = _recipe_label(labels, f"runtime-contract.{runtime_class}")
    canonical_recipe_name = _recipe_label(labels, "recipe.name")
    canonical_recipe_digest = _recipe_label(labels, "recipe.digest")
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
        "product_component": _recipe_label(labels, "product-component"),
        "wrapper_component": _recipe_label(labels, "wrapper-component"),
        "runtime_profile": runtime_profile,
        "runtime_contract": runtime_contract,
        "canonical_recipe_name": canonical_recipe_name,
        "canonical_recipe_digest": canonical_recipe_digest,
        "source_output_target": _recipe_label(labels, "source-output-target"),
        "container_nas_root": _recipe_label(labels, "nas.container-root"),
        "host_nas_root_template": _recipe_label(labels, "nas.host-root-template"),
        "nas_read_only": _recipe_label(labels, "nas.read-only"),
        "nas_mount_propagation": _recipe_label(labels, "nas.propagation"),
        "nas_child_mount_mode": _recipe_label(labels, "nas.child-mount-mode"),
        "contract_version": _recipe_label(labels, "contract.version"),
        "health_endpoints": _recipe_label(labels, "health.endpoints"),
        "health_endpoints_json": _recipe_label(labels, "health.endpoints.json"),
        "ops_repo_commit": _recipe_label(labels, "ops-repo-commit"),
    }


def _live_runtime_truth(slot: str, state_root: Path) -> tuple[dict[str, str], list[tuple[bool, str, str | None]]]:
    checks: list[tuple[bool, str, str | None]] = []
    binding = get_runtime_binding(slot, state_root)
    apache_route = parse_apache_route(binding.linux_account)
    checks.extend(_apache_route_checks(binding, apache_route))
    container, lookup = _find_gateway_container_by_binding(binding)
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
    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "truth_container_inspect_ok", container))
    if inspect.returncode != 0:
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
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "truth_container_inspect_parse_ok", str(exc)))
        return ({"linux_account": binding.linux_account, "truth_source": "live_image", "truth_status": "parse_failed", "reason": str(exc)}, checks)
    truth = _live_image_truth_from_info(binding, info, apache_route)
    labels = _labels_from_container_info(info)
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
            _local_canonical_recipe_check_from_truth(truth),
        ]
    )
    return truth, checks


def _print_key_values(data: dict[str, object]) -> None:
    for key, value in data.items():
        print(f"{key}={value}")


def cmd_runtime_truth(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime truth ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        all_slots = bool(getattr(args, "all", False))
        slot_arg = getattr(args, "slot", None)
        if all_slots and slot_arg:
            raise ValueError("provide either TARGET or --all, not both")
        if not all_slots and not slot_arg:
            raise ValueError("provide TARGET or --all")
        if all_slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        else:
            slots = [str(slot_arg)]
        all_ok = True
        for slot in slots:
            truth, checks = _live_runtime_truth(slot, state_root)
            if len(slots) > 1:
                summary = " ".join(f"{key}={value}" for key, value in truth.items())
                print(summary)
            else:
                _print_key_values(truth)
                for ok, name, detail in checks:
                    _check_line(ok, name, detail)
            if truth.get("truth_status") != "ok":
                all_ok = False
            if any(not ok for ok, _, _ in checks):
                all_ok = False
    except Exception as exc:
        print("runtime_truth_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"runtime_truth_status={'ok' if all_ok else 'fail'} count={len(slots)}")
    return 0 if all_ok else 1


