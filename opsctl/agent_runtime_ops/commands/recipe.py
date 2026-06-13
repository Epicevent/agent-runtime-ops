from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

from ..canonical_recipes import (
    canonical_label_values,
    canonical_recipe_for_image_spec,
    canonical_recipe_identity,
    list_canonical_recipe_names,
    load_canonical_recipe,
    validate_canonical_recipe,
)
from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import now_iso as _now_iso
from ..domain.common import run_text_cwd as _run_text_cwd
from ..domain.common import state_root as _state_root
from ..domain.dev_recipe_state import load_dev_recipe_state as _load_dev_recipe_state
from ..domain.dev_recipe_state import write_dev_recipe_state as _write_dev_recipe_state
from ..domain.dev_recipe_runtime import dev_recipe_runtime_env as _dev_recipe_runtime_env
from ..domain.dev_recipe_runtime import ensure_dev_runtime_dir as _ensure_dev_runtime_dir
from ..domain.dev_recipe_runtime import safe_existing_directory as _safe_existing_directory
from ..domain.dev_recipe_runtime import sync_dev_source_output as _sync_dev_source_output
from ..domain.dev_recipe_runtime import upsert_runtime_env_file as _upsert_runtime_env_file
from ..domain.image_specs import (
    image_spec_recipe,
    label_map_to_string,
    optional_safe_text,
    validate_safe_name,
)
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..domain.source_provenance import require_fresh_clean_source_provenance as _require_fresh_clean_source_provenance
from ..domain.source_provenance import source_provenance as _source_provenance
from ..host.account_files import (
    slot_uid_gid,
)
from ..profiles import load_profile
from ..state import load_runtime_target
from .apply import cmd_apply


def _validate_recipe_name(name: str) -> None:
    validate_safe_name(name)


def _refresh_git_source_output(source_output: Path, git_ref: str) -> None:
    ref = optional_safe_text(git_ref, "--git-ref")
    if not ref:
        return
    git_dir = source_output / ".git"
    if not git_dir.exists() or git_dir.is_symlink():
        raise ValueError("--git-ref requires --source-output to be a git checkout")
    git = ["git", "-c", f"safe.directory={source_output}"]
    remote = _run_text_cwd([*git, "remote", "get-url", "origin"], source_output, timeout=20)
    if remote.returncode != 0:
        detail = (remote.stderr or remote.stdout).strip()
        raise ValueError(f"failed to read source git origin: {detail}")
    origin = remote.stdout.strip()
    if origin != "https://github.com/Epicevent/hermes-workspace.git":
        raise ValueError(f"unsupported dev source git origin: {origin}")
    status = _run_text_cwd([*git, "status", "--porcelain"], source_output, timeout=20)
    if status.returncode != 0:
        detail = (status.stderr or status.stdout).strip()
        raise ValueError(f"failed to read source git status: {detail}")
    if status.stdout.strip():
        raise ValueError("source git tree is dirty; commit or clean it before --git-ref")
    fetch = _run_text_cwd([*git, "fetch", "--prune", "origin", ref], source_output, timeout=180)
    if fetch.returncode != 0:
        detail = (fetch.stderr or fetch.stdout).strip()
        raise ValueError(f"failed to fetch source git ref: {detail}")
    merge = _run_text_cwd([*git, "merge", "--ff-only", "FETCH_HEAD"], source_output, timeout=180)
    if merge.returncode != 0:
        detail = (merge.stderr or merge.stdout).strip()
        raise ValueError(f"failed to fast-forward source git ref: {detail}")


def _build_arg_lines_for_canonical_recipe(name: str) -> list[str]:
    recipe = load_canonical_recipe(name)
    labels = canonical_label_values(recipe)
    return [
        f"CANONICAL_RECIPE_NAME={recipe.name}",
        f"CANONICAL_RECIPE_DIGEST={recipe.digest}",
        f"RUNTIME_FAMILY={labels['family']}",
        f"PRODUCT_COMPONENT={labels['product-component']}",
        f"WRAPPER_COMPONENT={labels['wrapper-component']}",
        f"RUNTIME_PROFILE_CUSTOMER={labels['runtime-profile.customer']}",
        f"RUNTIME_PROFILE_DEV={labels['runtime-profile.dev']}",
        f"RUNTIME_CONTRACT_CUSTOMER={labels['runtime-contract.customer']}",
        f"RUNTIME_CONTRACT_DEV={labels['runtime-contract.dev']}",
        f"RUNTIME_COMMAND_MODE={labels['command-mode']}",
        f"RUNTIME_WORKING_DIR={labels['working-dir']}",
        f"RUNTIME_HTTP_PORT={labels['http-port']}",
        f"RUNTIME_CONTRACT_VERSION={labels['contract.version']}",
        f"RUNTIME_SOURCE_OUTPUT_TARGET={labels['source-output-target']}",
        f"RUNTIME_NAS_CONTAINER_ROOT={labels['nas.container-root']}",
        f"RUNTIME_NAS_HOST_ROOT_TEMPLATE={labels['nas.host-root-template']}",
        f"RUNTIME_NAS_READ_ONLY={labels['nas.read-only']}",
        f"RUNTIME_NAS_PROPAGATION={labels['nas.propagation']}",
        f"RUNTIME_NAS_CHILD_MOUNT_MODE={labels['nas.child-mount-mode']}",
        f"RUNTIME_HEALTH_ENDPOINTS={labels['health.endpoints']}",
        f"RUNTIME_HEALTH_ENDPOINTS_JSON={shlex.quote(labels['health.endpoints.json'])}",
    ]


def cmd_recipe_validate_canonical(args: argparse.Namespace) -> int:
    name = str(args.name)
    try:
        recipe = load_canonical_recipe(name)
        checks = validate_canonical_recipe(recipe)
    except Exception as exc:
        print(f"name={name}")
        print("canonical_recipe_status=fail")
        print(f"reason={exc}")
        return 1

    failed = sum(1 for ok, _check_name, _detail in checks if not ok)
    if getattr(args, "emit_build_args", False):
        if failed:
            print(f"canonical_recipe_status=fail failed={failed}", file=sys.stderr)
            return 1
        for line in _build_arg_lines_for_canonical_recipe(name):
            print(line)
        return 0

    print(f"name={recipe.name}")
    print(f"canonical_recipe_digest={recipe.digest}")
    print(f"family={recipe.data.get('family')}")
    print(f"product_component={recipe.data.get('product_component')}")
    for ok, check_name, detail in checks:
        _check_line(ok, check_name, detail)
    if failed:
        print(f"canonical_recipe_status=fail failed={failed}")
        return 1
    print("canonical_recipe_status=ok")
    return 0


def cmd_recipe_list_canonical(args: argparse.Namespace) -> int:
    for name in list_canonical_recipe_names():
        recipe = load_canonical_recipe(name)
        print(f"{recipe.name} {recipe.digest}")
    return 0


def cmd_recipe_dev_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_runtime_target(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        recipes = _load_dev_recipe_state(state_root).get("recipes") or {}
        recipe = recipes.get(slot) if isinstance(recipes, dict) else None
    except Exception as exc:
        print(f"target={slot}")
        print("recipe_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"image_name={desired.image_name}")
    print(f"runtime_profile={profile.name}")
    print(f"mode={profile.metadata.get('mode')}")
    if isinstance(recipe, dict):
        print("recipe_status=present")
        for key in ("recipe_name", "source_output", "sync_from", "build_command", "updated_at"):
            print(f"{key}={recipe.get(key, '')}")
        source_provenance = recipe.get("source_provenance")
        if isinstance(source_provenance, dict):
            for key in ("status", "git_head", "git_dirty", "git_toplevel", "git_remote_origin"):
                print(f"source_provenance_{key}={source_provenance.get(key, '')}")
    else:
        print("recipe_status=missing")
    return 0


def cmd_recipe_dev_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl recipe apply-dev TARGET ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_runtime_target(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        if desired.runtime_class != "dev" or profile.metadata.get("mode") != "source":
            raise ValueError("recipe apply-dev requires a dev target using source mode")
        recipe_name = str(args.recipe_name or slot)
        _validate_recipe_name(recipe_name)
        sync_from = str(args.sync_from or "").strip()
        source_output_arg = str(args.source_output or "").strip()
        if bool(sync_from) == bool(source_output_arg):
            raise ValueError("provide exactly one of --sync-from or --source-output")
        if sync_from:
            source = _safe_existing_directory(sync_from, "--sync-from")
            source_output = _sync_dev_source_output(slot, recipe_name, source)
            sync_from_value = str(source)
            if getattr(args, "git_ref", None):
                raise ValueError("--git-ref is only supported with --source-output")
        else:
            source_output = _safe_existing_directory(source_output_arg, "--source-output")
            _refresh_git_source_output(source_output, str(getattr(args, "git_ref", "") or ""))
            sync_from_value = ""
        provenance_source = source if sync_from else source_output
        runtime_dir = _ensure_dev_runtime_dir(slot)
        uid, gid = slot_uid_gid(slot)
        env_updates = _dev_recipe_runtime_env(desired, state_root)
        env_updates["SOURCE_OUTPUT"] = str(source_output)
        _upsert_runtime_env_file(runtime_dir / ".env", env_updates, uid, gid)
        recipe_state = _load_dev_recipe_state(state_root)
        recipes = recipe_state.setdefault("recipes", {})
        if not isinstance(recipes, dict):
            raise ValueError("dev recipe state recipes must be a mapping")
        recipes[slot] = {
            "target": slot,
            "family": desired.family,
            "runtime_profile": profile.name,
            "recipe_name": recipe_name,
            "source_output": str(source_output),
            "sync_from": sync_from_value,
            "source_provenance": _source_provenance(provenance_source),
            "build_command": optional_safe_text(args.build_command, "--build-command"),
            "updated_at": _now_iso(),
            "updated_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
        }
        backup_path = _write_dev_recipe_state(state_root, recipe_state)
        _append_action_log(state_root, "recipe_apply_dev", slot, recipe_name, "prepared", f"source_output={source_output}")
    except Exception as exc:
        print(f"target={slot}")
        print("recipe_apply_dev_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "recipe_apply_dev", slot, slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={slot}")
    print(f"runtime_profile={profile.name}")
    print("mode=source")
    print(f"recipe_name={recipe_name}")
    print(f"source_output={source_output}")
    if sync_from_value:
        print(f"sync_from={sync_from_value}")
    if backup_path:
        print(f"backup={backup_path}")
    print("recipe_apply_dev_status=prepared")
    if args.no_apply:
        print("apply=skipped")
        return 0
    print("apply=running")
    rc = cmd_apply(
        SimpleNamespace(
            state_root=str(state_root),
            slot=slot,
            allow_first_apply=bool(args.allow_first_apply),
        )
    )
    _append_action_log(state_root, "recipe_apply_dev", slot, recipe_name, "ok" if rc == 0 else "fail", f"apply_rc={rc}")
    return rc


def cmd_recipe_capture_dev(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl recipe capture-dev TARGET ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    recipe_name = str(getattr(args, "recipe_name", "") or "hermes-runtime")
    try:
        _validate_recipe_name(recipe_name)
        desired, profile = _desired_from_live_image_truth(slot, state_root)
        if desired.runtime_class != "dev" or profile.metadata.get("mode") != "source":
            raise ValueError("recipe capture-dev requires a dev target using source mode")
        image_recipe = image_spec_recipe(desired.image_spec)
        canonical_recipe = canonical_recipe_for_image_spec(desired.image_spec)
        if canonical_recipe.name != recipe_name:
            raise ValueError(f"live image recipe mismatch: image={canonical_recipe.name} requested={recipe_name}")
        if recipe_name == "hermes-runtime" and str(image_recipe.get("contract_version") or "") != "v2":
            raise ValueError("hermes-runtime capture requires runtime contract version v2")
        recipes = _load_dev_recipe_state(state_root).get("recipes") or {}
        dev_recipe = recipes.get(desired.slot) if isinstance(recipes, dict) else None
        if not isinstance(dev_recipe, dict):
            raise ValueError("dev recipe state is missing; run recipe apply-dev first")
        if str(dev_recipe.get("recipe_name") or "") != recipe_name:
            raise ValueError(
                f"dev recipe state mismatch: state={dev_recipe.get('recipe_name') or 'missing'} requested={recipe_name}"
            )
        source_output = str(dev_recipe.get("source_output") or "")
        if not source_output:
            raise ValueError("dev recipe state is missing source_output")
        stored_provenance = dev_recipe.get("source_provenance")
        provenance = _require_fresh_clean_source_provenance(dev_recipe)
        checks = _run_live_slot_checks(desired, profile, state_root)
        failed = [name for ok, name, _detail in checks if not ok]
        if failed:
            raise ValueError("live checks failed: " + ",".join(failed))
        health_endpoints = image_recipe.get("health_endpoints")
        _append_action_log(
            state_root,
            "recipe_capture_dev",
            desired.slot,
            recipe_name,
            "ok",
            f"source_output={source_output}",
        )
    except Exception as exc:
        print(f"target={slot}")
        print("recipe_capture_dev_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "recipe_capture_dev", slot, recipe_name, "fail", str(exc))
        except Exception:
            pass
        return 1

    identity = canonical_recipe_identity(canonical_recipe)
    print(f"target={desired.slot}")
    print("recipe_capture_dev_status=ok")
    print(f"recipe_name={canonical_recipe.name}")
    print(f"canonical_recipe_digest={identity['canonical_recipe_digest']}")
    print(f"runtime_profile={profile.name}")
    print(f"wrapper_image={desired.image_spec.get('wrapper_image')}")
    print(f"product_image={desired.image_spec.get('product_image')}")
    print(f"contract_version={image_recipe.get('contract_version') or ''}")
    print(f"health_endpoints={label_map_to_string(health_endpoints)}")
    print(f"source_output={source_output}")
    print(f"source_git_head={provenance.get('git_head') or ''}")
    print(f"source_git_dirty={provenance.get('git_dirty')}")
    if isinstance(stored_provenance, dict):
        print(f"source_git_head_at_apply={stored_provenance.get('git_head') or ''}")
    print("secret_value_printed=no")
    print("next_action=build product image from source_git_head, then wrap with this canonical_recipe_digest")
    return 0

