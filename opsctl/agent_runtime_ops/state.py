from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import DEFAULT_STATE_ROOT
from .routing import RuntimeBinding, get_runtime_binding
from .yamlio import load_yaml


IMAGE_ROLLOUT_IMAGE_NAME = "direct-image"


@dataclass(frozen=True)
class RuntimeTarget:
    target: str
    family: str
    runtime_class: str
    image_name: str
    image_spec: dict[str, Any]
    runtime_profile: str
    route: RuntimeBinding

    @property
    def slot(self) -> str:
        return self.target


def runtime_manifest_path(state_root: Path, target: str, *, create_parent: bool = False) -> Path:
    binding = get_runtime_binding(target, state_root)
    runtime_root = state_root / "runtime"
    target_dir = runtime_root / binding.linux_account
    for path in (state_root, runtime_root, target_dir):
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed runtime manifest path must not be symlink: {path}")
    if create_parent:
        runtime_root.mkdir(mode=0o755, exist_ok=True)
        target_dir.mkdir(mode=0o755, exist_ok=True)
    return target_dir / "manifest.yaml"


def digest_from_image_ref(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def image_spec_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    recipe = manifest.get("recipe")
    recipe_data = recipe if isinstance(recipe, dict) else {}
    components = recipe_data.get("components")
    component_data = components if isinstance(components, dict) else {}
    image_recipe = recipe_data.get("image_recipe")
    image_recipe_data = image_recipe if isinstance(image_recipe, dict) else {}

    wrapper_image = str(manifest.get("wrapper_image") or component_data.get("wrapper_image") or "")
    product_image = str(manifest.get("product_image") or component_data.get("product_image") or "")
    if not wrapper_image:
        raise ValueError("runtime manifest is missing wrapper_image")
    if not product_image:
        raise ValueError("runtime manifest is missing product_image")

    family = str(manifest.get("family") or image_recipe_data.get("family") or "")
    if family not in {"openclaw", "hermes"}:
        raise ValueError(f"runtime manifest has invalid family: {family or 'missing'}")

    image_spec: dict[str, Any] = {
        "family": family,
        "image_name": str(manifest.get("image_name") or manifest.get("release") or IMAGE_ROLLOUT_IMAGE_NAME),
        "wrapper_image": wrapper_image,
        "product_image": product_image,
        "digest": manifest.get("wrapper_image_digest") or manifest.get("release_digest") or digest_from_image_ref(wrapper_image),
        "product_digest": manifest.get("product_image_digest") or digest_from_image_ref(product_image),
        "mode": recipe_data.get("mode") or "wrapped_product_image",
    }
    if isinstance(components, dict):
        image_spec["components"] = {str(key): str(value) for key, value in components.items()}
    if image_recipe_data:
        image_spec["image_recipe"] = image_recipe_data
    return image_spec


def load_runtime_target(target: str, state_root: Path = DEFAULT_STATE_ROOT) -> RuntimeTarget:
    binding = get_runtime_binding(target, state_root)
    path = runtime_manifest_path(state_root, binding.linux_account)
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed runtime manifest must not be symlink: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"runtime manifest not found: {path}")
    manifest = load_yaml(path)
    if not isinstance(manifest, dict):
        raise ValueError(f"runtime manifest is not a mapping: {path}")

    manifest_target = str(manifest.get("target") or manifest.get("slot") or "")
    if manifest_target and manifest_target != binding.linux_account:
        raise ValueError(f"runtime manifest target mismatch: manifest={manifest_target} binding={binding.linux_account}")

    family = str(manifest.get("family") or "")
    runtime_class = str(manifest.get("runtime_class") or manifest.get("slot_class") or "")
    if family != binding.family:
        raise ValueError(f"runtime manifest family mismatch: manifest={family or 'missing'} binding={binding.family}")
    if runtime_class != binding.runtime_class:
        raise ValueError(
            f"runtime manifest runtime_class mismatch: manifest={runtime_class or 'missing'} binding={binding.runtime_class}"
        )

    runtime_profile = str(manifest.get("runtime_profile") or "")
    if not runtime_profile:
        raise ValueError("runtime manifest is missing runtime_profile")
    image_spec = image_spec_from_manifest(manifest)
    return RuntimeTarget(
        target=binding.linux_account,
        family=family,
        runtime_class=runtime_class,
        image_name=str(image_spec.get("image_name") or IMAGE_ROLLOUT_IMAGE_NAME),
        image_spec=image_spec,
        runtime_profile=runtime_profile,
        route=binding,
    )
