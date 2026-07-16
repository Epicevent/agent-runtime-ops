from __future__ import annotations

import argparse
import shutil
import sys

from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.hermes_smoke import run_hermes_http_smoke
from ..domain.hermes_config import current_model, hermes_config_path, read_hermes_config, runtime_provider_id
from ..domain.common import state_root as _state_root
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..domain.runtime_truth import find_gateway_container
from ..runtime_secrets import parse_secret_env_text, primary_profile_secret_file


HERMES_RUNTIME_REQUIRED_CHECKS = {
    "live_internal_http_dashboard_ok",
    "live_internal_http_gateway_ok",
    "live_internal_http_workspace_ok",
    "live_workspace_node_process_present",
    "live_workspace_node_uid_not_default_10000",
    "live_workspace_node_gid_not_default_10000",
    "live_workspace_node_uid_matches_slot",
    "live_workspace_node_gid_matches_slot",
    "live_workspace_node_groups_include_data_gid",
    "live_container_nas_docs_listing_ok",
    "live_workspace_user_nas_docs_listing_ok",
    "live_workspace_api_status_ok",
    "live_workspace_files_root_listing_ok",
    "live_workspace_files_nas_docs_listing_ok",
    "live_workspace_cifs_floor_ok",
}

# The required set is opsctl's OWN infra/edge checks only. Customer-truth depth comes
# from the product-attested selftest, represented here by the single aggregate
# `selftest_contract_ok`: the product declares its own `required_checks` in the selftest
# output and `run_image_selftest_contract` fails the aggregate if any of them fail. So a
# NEW product selftest check (e.g. a new gateway RPC) is gated automatically by this
# aggregate with NO edit here — opsctl never restates the product's check names. The
# individual selftest_* checks still emit (and show) in the output; they just aren't
# duplicated into this set. live_public_route_readyz_ok is the external edge opsctl adds.
OPENCLAW_RUNTIME_REQUIRED_CHECKS = {
    "live_container_running",
    "live_container_image_matches_spec",
    "live_container_user_non_root",
    "live_backend_http_smoke_ok",
    "live_container_nas_docs_listing_ok",
    "live_workspace_user_nas_docs_listing_ok",
    "selftest_contract_ok",
    "live_public_route_readyz_ok",
    "config_disk_valid_for_running_image_ok",
    "live_workspace_cifs_floor_ok",
}

# Map a --pack name to the family it gates. A pack used against the wrong family is a
# usage error. The actual depth comes from the live checks + selftest contract, not the
# pack name; the name only selects which required set must be present.
_PACK_FAMILY = {
    "hermes-runtime": "hermes",
    "openclaw-runtime": "openclaw",
}


def _require_pack_family(pack: str, family: str) -> None:
    expected = _PACK_FAMILY.get(pack)
    if expected is not None and expected != family:
        raise ValueError(f"checklist pack {pack} requires family={expected}: target family={family}")


def _provider_state_checks(desired, profile) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    try:
        config_path = hermes_config_path(desired.slot)
        config = read_hermes_config(config_path)
        provider, model, source = current_model(config)
        provider_runtime = runtime_provider_id(provider) if provider else ""
        checks.extend(
            [
                (
                    bool(provider_runtime),
                    "checklist_provider_configured",
                    f"provider_raw={provider or 'missing'} provider_runtime={provider_runtime or 'missing'} source={source}",
                ),
                (bool(model), "checklist_model_configured", f"model={model or 'missing'} source={source}"),
            ]
        )
    except Exception as exc:
        checks.extend(
            [
                (False, "checklist_provider_configured", str(exc)),
                (False, "checklist_model_configured", str(exc)),
            ]
        )
        provider = ""
    try:
        secret_file = primary_profile_secret_file(profile, desired.slot)
        values = parse_secret_env_text(secret_file.path.read_text(encoding="utf-8", errors="replace"), source=str(secret_file.path))
        checks.append((bool(values.get("API_SERVER_KEY")), "checklist_api_server_key_present", "secret_value_printed=no"))
        provider_name = runtime_provider_id(str(provider or ""))
        if provider_name in {"google", "gemini"} or "gemini" in provider_name:
            gemini_present = bool(values.get("GEMINI_API_KEY") or values.get("GOOGLE_API_KEY"))
            checks.append((gemini_present, "checklist_gemini_secret_present", "secret_value_printed=no"))
    except Exception as exc:
        checks.append((False, "checklist_runtime_secret_file_readable", str(exc)))
    return checks


def _workspace_endpoint_checks(container: str, *, gemini_chat_smoke: bool) -> list[tuple[bool, str, str | None]]:
    return run_hermes_http_smoke(container, chat_smoke=gemini_chat_smoke)


def _hermes_runtime_pack_checks(desired, profile, *, gemini_chat_smoke: bool) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    checks.extend(_provider_state_checks(desired, profile))
    docker = shutil.which("docker")
    checks.append((bool(docker), "checklist_docker_cli_available", docker))
    if not docker:
        return checks
    container, lookup = find_gateway_container(desired.route, profile)
    checks.append((bool(container), "checklist_container_lookup", lookup))
    if not container:
        return checks
    checks.extend(_workspace_endpoint_checks(container, gemini_chat_smoke=gemini_chat_smoke))
    return checks


def cmd_checklist_pack(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl checklist pack TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _desired_from_live_image_truth(args.slot, state_root)
        family = desired.family
        _require_pack_family(args.pack, family)
        if family == "hermes":
            required = HERMES_RUNTIME_REQUIRED_CHECKS
        elif family == "openclaw":
            required = OPENCLAW_RUNTIME_REQUIRED_CHECKS
        else:
            raise ValueError(f"checklist pack is not supported for family={family}")
        checks = list(_run_live_slot_checks(desired, profile, state_root))
        seen = {name for _ok, name, _detail in checks}
        for name in sorted(required - seen):
            checks.append((False, name, "missing_from_live_check"))
        # Hermes uses an ops-side reach-in smoke; OpenClaw's customer-truth runs inside
        # run_live_slot_checks via the product-attested selftest contract (no extra here).
        if family == "hermes":
            checks.extend(
                _hermes_runtime_pack_checks(
                    desired,
                    profile,
                    gemini_chat_smoke=bool(getattr(args, "gemini_chat_smoke", False)),
                )
            )
    except Exception as exc:
        print(f"target={args.slot}")
        print("checklist_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"checklist_pack={args.pack}")
    print(f"runtime_profile={profile.name}")
    print(f"gemini_chat_smoke={'enabled' if getattr(args, 'gemini_chat_smoke', False) else 'not_run'}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"checklist_status={'pass' if failed == 0 else 'fail'} failed={failed}")
    return 0 if failed == 0 else 1
