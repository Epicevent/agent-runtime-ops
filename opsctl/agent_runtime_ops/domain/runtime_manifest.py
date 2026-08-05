from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..profiles import load_profile
from ..routing import get_runtime_binding
from ..state import RuntimeTarget, load_runtime_target
from ..yamlio import dump_yaml
from .common import apache_public_host
from .image_specs import (
    IMAGE_ROLLOUT_IMAGE_NAME,
    digest_from_image_ref,
    image_spec_recipe_payload,
    image_spec_recipe_tokens,
    profile_customer_surface,
    profile_runtime_contract,
)
from .runtime_paths import agent_manifest_path, atomic_write, state_manifest_path
from .update_policy import installed_source_commit as _installed_source_commit


def manifest_payload(
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
        "runtime_contract": profile_runtime_contract(profile),
        "customer_surface": profile_customer_surface(profile),
        "public_host": apache_public_host(desired.slot),
        "gateway_port": desired.route.gateway_port if getattr(desired, "route", None) else "",
        "bridge_port": desired.route.bridge_port if getattr(desired, "route", None) else "",
        "wrapper_image": wrapper_image,
        "wrapper_image_digest": digest_from_image_ref(wrapper_image),
        "product_image": product_image,
        "product_image_digest": digest_from_image_ref(product_image),
        "retrieval_component_digest": desired.image_spec.get("retrieval_component_digest") or "",
        "retrieval_enabled": desired.image_spec.get("retrieval_enabled") is True,
        "retrieval_binding_digest": desired.image_spec.get("retrieval_binding_digest") or "",
        "recipe": image_spec_recipe_payload(desired.image_spec),
        "compose_sha256": rendered.sha256,
        "compose_path": str(compose_path),
    }
    if previous_manifest is not None:
        payload["previous_manifest"] = str(previous_manifest)
    return payload


def desired_from_runtime_manifest(slot: str, state_root: Path):
    target = load_runtime_target(slot, state_root)
    profile = load_profile(target.runtime_profile)
    if profile.metadata.get("family") != target.family:
        raise ValueError(f"runtime manifest profile family mismatch: profile={profile.metadata.get('family')} manifest={target.family}")
    if profile.metadata.get("slot_class") != target.runtime_class:
        raise ValueError(
            f"runtime manifest profile runtime_class mismatch: profile={profile.metadata.get('slot_class')} manifest={target.runtime_class}"
        )
    from .retrieval_contract import (
        bind_retrieval_intent,
        validate_retrieval_target_binding,
    )

    if "retrieval_binding" not in target.image_spec:
        if (
            isinstance(target.image_spec.get("retrieval_contract"), dict)
            or bool(target.image_spec.get("retrieval_component_digest"))
            or target.image_spec.get("retrieval_enabled") is True
            or bool(target.image_spec.get("retrieval_binding_digest"))
        ):
            raise ValueError(
                "runtime manifest has an incomplete retrieval projection migration"
            )
        target = replace(
            target,
            image_spec=bind_retrieval_intent(
                target.image_spec,
                instance_id=target.route.instance_id,
                family=target.family,
                runtime_profile_digest=profile.digest,
                container_nas_root=str(
                    profile.metadata.get("container_nas_root") or ""
                ),
                enabled=False,
            ),
        )

    if "retrieval_binding" in target.image_spec:
        validate_retrieval_target_binding(
            target.image_spec,
            instance_id=target.route.instance_id,
            family=target.family,
            runtime_profile_digest=profile.digest,
            container_nas_root=str(profile.metadata.get("container_nas_root") or ""),
        )
    return target, profile


def write_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    applied_at: str,
) -> None:
    recipe_tokens = image_spec_recipe_tokens(desired.image_spec)
    lines = [
        f"target={desired.slot}",
        f"linux_account={desired.route.linux_account if getattr(desired, 'route', None) else desired.slot}",
        f"image_name={desired.image_name}",
        f"family={desired.family}",
        f"runtime_class={desired.runtime_class}",
        f"runtime_profile={profile.name}",
        f"runtime_profile_digest={profile.digest}",
        f"runtime_contract={profile_runtime_contract(profile)}",
        f"customer_surface={profile_customer_surface(profile)}",
        f"public_host={apache_public_host(desired.slot)}",
        f"gateway_port={desired.route.gateway_port if getattr(desired, 'route', None) else ''}",
        f"bridge_port={desired.route.bridge_port if getattr(desired, 'route', None) else ''}",
        f"ops_repo_commit={_installed_source_commit()}",
        f"wrapper_image={desired.image_spec.get('wrapper_image')}",
        f"product_image={desired.image_spec.get('product_image')}",
        f"retrieval_component_digest={desired.image_spec.get('retrieval_component_digest') or ''}",
        f"retrieval_enabled={'true' if desired.image_spec.get('retrieval_enabled') is True else 'false'}",
        f"retrieval_binding_digest={desired.image_spec.get('retrieval_binding_digest') or ''}",
        f"recipe_mode={recipe_tokens['recipe_mode']}",
        f"product_component={recipe_tokens['product_component']}",
        f"wrapper_image_digest={desired.image_spec.get('digest')}",
        f"compose_sha256={rendered.sha256}",
        f"compose_file={path.parent / 'docker-compose.agent-runtime.yml'}",
        f"applied_at={applied_at}",
    ]
    atomic_write(path, "\n".join(lines) + "\n", 0o644)


def write_state_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> None:
    atomic_write(
        path,
        dump_yaml(
            manifest_payload(
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


def write_slot_manifests(
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
    legacy_path = agent_manifest_path(runtime_dir)
    state_path = state_manifest_path(state_root, desired.slot, create_parent=True)
    write_slot_manifest(
        legacy_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        applied_at=applied_at,
    )
    write_state_slot_manifest(
        state_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        compose_path=compose_path,
        applied_at=applied_at,
        previous_manifest=previous_manifest,
    )
    return legacy_path, state_path


def read_legacy_slot_manifest(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = raw_line.partition("=")
        if sep:
            data[key.strip()] = value.strip()
    return data


def desired_from_manifest(slot: str, manifest: dict, state_root: Path):
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
    recipe = manifest.get("recipe")
    if isinstance(recipe, dict):
        retrieval_contract = recipe.get("retrieval_contract")
        retrieval_binding = recipe.get("retrieval_binding")
        retrieval_attachment_contract = recipe.get("retrieval_attachment_contract")
        if isinstance(retrieval_contract, dict):
            image_spec["retrieval_contract"] = retrieval_contract
        if isinstance(retrieval_binding, dict):
            image_spec["retrieval_binding"] = retrieval_binding
        if isinstance(retrieval_attachment_contract, dict):
            image_spec["retrieval_attachment_contract"] = retrieval_attachment_contract
    image_spec["retrieval_component_digest"] = str(
        manifest.get("retrieval_component_digest") or ""
    )
    image_spec["retrieval_enabled"] = manifest.get("retrieval_enabled") is True
    image_spec["retrieval_binding_digest"] = str(
        manifest.get("retrieval_binding_digest") or ""
    )
    if "retrieval_binding" in image_spec:
        from .retrieval_contract import validate_bound_retrieval_spec

        validate_bound_retrieval_spec(image_spec)
    route = get_runtime_binding(target, state_root)
    profile = load_profile(str(manifest.get("runtime_profile") or ""))
    if "retrieval_binding" in image_spec:
        from .retrieval_contract import validate_retrieval_target_binding

        validate_retrieval_target_binding(
            image_spec,
            instance_id=route.instance_id,
            family=family,
            runtime_profile_digest=str(
                manifest.get("runtime_profile_digest") or profile.digest
            ),
            container_nas_root=str(profile.metadata.get("container_nas_root") or ""),
        )
    return RuntimeTarget(
        target=target,
        family=family,
        runtime_class=runtime_class,
        image_name=str(image_spec["image_name"]),
        image_spec=image_spec,
        runtime_profile=str(manifest.get("runtime_profile") or ""),
        route=route,
    )
