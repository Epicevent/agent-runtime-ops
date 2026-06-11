from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

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
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.image_specs import (
    image_spec_recipe,
    label_map_to_string,
    optional_safe_text,
    validate_safe_name,
)
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_state import _slot_runtime_dir
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..domain.source_provenance import require_fresh_clean_source_provenance as _require_fresh_clean_source_provenance
from ..domain.source_provenance import source_provenance as _source_provenance
from ..host.account_files import (
    _atomic_write_key_value,
    _ensure_not_symlink_chain,
    _read_key_value_file,
    _runtime_ids,
    _slot_uid_gid,
)
from ..host.files import atomic_write_text as _atomic_write_text
from ..host.files import fsync_parent as _fsync_parent
from ..paths import DEFAULT_STATE_ROOT
from ..profiles import load_profile
from ..routing import get_runtime_binding
from ..runtime_secrets import primary_profile_secret_file
from ..state import load_runtime_target
from ..yamlio import dump_yaml, load_yaml


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"
DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"


def _assert_state_parent_safe(path: Path) -> None:
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError(f"managed state parent must not be symlink: {parent}")
    parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")


def _backup_state_file(state_root: Path, path: Path) -> Path | None:
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")
    backup_root = state_root / "backups" / "state"
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"managed backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    backup_path = backup_root / f"{path.name}.{stamp}"
    suffix = 1
    while backup_path.exists():
        suffix += 1
        backup_path = backup_root / f"{path.name}.{stamp}.{suffix}"
    shutil.copy2(path, backup_path)
    return backup_path


def _write_state_yaml_file(state_root: Path, name: str, data: dict) -> Path | None:
    path = state_root / name
    _assert_state_parent_safe(path)
    backup_path = _backup_state_file(state_root, path)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(dump_yaml(data))
            handle.flush()
            os.fsync(handle.fileno())
        if hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
        _fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return backup_path


def _state_meta(source: str | None = None) -> dict[str, object]:
    meta: dict[str, object] = {
        "schema_version": 1,
        "updated_at": _now_iso(),
        "scope": "private_server_state",
    }
    if source:
        meta["source"] = source
    return meta


def _load_dev_recipe_state(state_root: Path) -> dict:
    data = load_yaml(state_root / DEV_RECIPE_STATE_NAME, default={})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("meta", _state_meta("opsctl recipe"))
    data.setdefault("recipes", {})
    return data


def _write_dev_recipe_state(state_root: Path, data: dict) -> Path | None:
    data["meta"] = _state_meta("opsctl recipe")
    data.setdefault("recipes", {})
    return _write_state_yaml_file(state_root, DEV_RECIPE_STATE_NAME, data)


def _validate_recipe_name(name: str) -> None:
    validate_safe_name(name)


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


def _safe_existing_directory(value: object, name: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if path.is_symlink():
        raise ValueError(f"{name} must not be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{name} must be an existing directory")
    return resolved


def _reject_tree_symlinks(root: Path) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        for name in [*dirs, *files]:
            item = current_path / name
            if item.is_symlink():
                raise ValueError(f"source tree must not contain symlinks: {item}")


def _assert_child_of(child: Path, parent: Path) -> None:
    child_resolved = child.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    if child_resolved != parent_resolved and parent_resolved not in child_resolved.parents:
        raise ValueError(f"path escaped managed root: {child}")


def _ensure_dev_runtime_dir(slot: str) -> Path:
    uid, gid = _slot_uid_gid(slot)
    home = Path("/home") / slot
    if home.is_symlink():
        raise ValueError(f"managed home must not be symlink: {home}")
    if not home.is_dir():
        raise FileNotFoundError(home)
    runtime_dir = home / "openclaw"
    if runtime_dir.exists() and runtime_dir.is_symlink():
        raise ValueError(f"managed runtime dir must not be symlink: {runtime_dir}")
    runtime_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(runtime_dir, uid, gid)
    os.chmod(runtime_dir, 0o750)
    return runtime_dir


def _chmod_source_tree(root: Path, uid: int, gid: int) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        os.chown(current_path, uid, gid)
        os.chmod(current_path, 0o750)
        for dirname in dirs:
            path = current_path / dirname
            os.chown(path, uid, gid)
            os.chmod(path, 0o750)
        for filename in files:
            path = current_path / filename
            mode = path.stat().st_mode
            file_mode = 0o750 if mode & stat.S_IXUSR else 0o640
            os.chown(path, uid, gid)
            os.chmod(path, file_mode)


def _sync_dev_source_output(slot: str, recipe_name: str, source: Path) -> Path:
    _reject_tree_symlinks(source)
    runtime_uid, _, data_gid = _runtime_ids(slot)
    home = Path("/home") / slot
    stage_root = home / DEV_RECIPE_STAGE_ROOT
    if stage_root.exists() and stage_root.is_symlink():
        raise ValueError(f"managed source stage root must not be symlink: {stage_root}")
    stage_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(stage_root, runtime_uid, data_gid)
    os.chmod(stage_root, 0o750)
    dest = stage_root / recipe_name
    tmp = stage_root / f".{recipe_name}.tmp.{os.getpid()}"
    backup = stage_root / f".{recipe_name}.previous.{os.getpid()}"
    for path in (dest, tmp, backup):
        _assert_child_of(path, stage_root)
    if tmp.exists():
        shutil.rmtree(tmp)
    if backup.exists():
        shutil.rmtree(backup)
    shutil.copytree(source, tmp, symlinks=False)
    _chmod_source_tree(tmp, runtime_uid, data_gid)
    if dest.exists():
        if dest.is_symlink():
            raise ValueError(f"managed source stage must not be symlink: {dest}")
        os.replace(dest, backup)
    os.replace(tmp, dest)
    if backup.exists():
        shutil.rmtree(backup)
    return dest


def _upsert_runtime_env_file(path: Path, updates: dict[str, str], uid: int, gid: int) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"runtime env file must not be symlink: {path}")
    data = _read_key_value_file(path) if path.exists() else {}
    data.update({key: value for key, value in updates.items() if value})
    _atomic_write_key_value(path, data, 0o640, uid, gid)


def _dev_recipe_runtime_env(desired, state_root: Path) -> dict[str, str]:
    family = str(desired.family or "")
    binding = get_runtime_binding(desired.slot, state_root)
    env = {
        "OPENCLAW_RUNTIME_FAMILY": family,
        "OPENCLAW_IMAGE": str(desired.image_spec.get("wrapper_image") or ""),
        "OPENCLAW_GATEWAY_PORT": str(binding.gateway_port),
        "OPENCLAW_BRIDGE_PORT": str(binding.bridge_port),
    }
    return env


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
        else:
            source_output = _safe_existing_directory(source_output_arg, "--source-output")
            sync_from_value = ""
        provenance_source = source if sync_from else source_output
        runtime_dir = _ensure_dev_runtime_dir(slot)
        uid, gid = _slot_uid_gid(slot)
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


