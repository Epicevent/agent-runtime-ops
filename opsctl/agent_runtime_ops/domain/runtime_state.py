from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess

from ..apache import parse_apache_route
from ..domain.image_specs import (
    IMAGE_ROLLOUT_IMAGE_NAME,
    _digest_from_image_ref,
    _image_spec_recipe_payload,
    _image_spec_recipe_tokens,
    _profile_customer_surface,
    _profile_runtime_contract,
)
from ..domain.update_policy import installed_source_commit as _installed_source_commit
from ..host.files import atomic_write_text as _atomic_write_text
from ..paths import DEFAULT_STATE_ROOT
from ..profiles import load_profile
from ..routing import get_runtime_binding, validate_linux_account
from ..state import RuntimeTarget, load_runtime_target
from ..yamlio import dump_yaml, load_yaml


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _apache_public_host(slot: str) -> str:
    try:
        return parse_apache_route(slot).public_host
    except Exception:
        return ""


def _run_text_cwd(command: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


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
