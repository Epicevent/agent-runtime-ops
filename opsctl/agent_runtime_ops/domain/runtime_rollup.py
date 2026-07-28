from __future__ import annotations

from pathlib import Path

from .image_specs import IMAGE_ROLLOUT_IMAGE_NAME
from .runtime_paths import state_manifest_path
from ..yamlio import load_yaml


def runtime_manifest_rollup(state_root: Path, slots: list[str], family: str) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for slot in slots:
        path = state_manifest_path(state_root, slot)
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed runtime manifest must not be symlink: {path}")
        if not path.is_file():
            continue
        manifest = load_yaml(path, default={})
        if not isinstance(manifest, dict) or str(manifest.get("family") or "") != family:
            continue
        rows.append(manifest)
        seen_slots.add(slot)

    def item_target(item: dict[str, object]) -> str:
        return str(item.get("target") or item.get("slot") or "")

    def item_runtime_class(item: dict[str, object]) -> str:
        return str(item.get("runtime_class") or item.get("slot_class") or "")

    def item_image_name(item: dict[str, object]) -> str:
        return str(item.get("image_name") or item.get("release") or "")

    direct_targets = [item_target(item) for item in rows if item_image_name(item) == IMAGE_ROLLOUT_IMAGE_NAME]
    customer_targets = [item_target(item) for item in rows if item_runtime_class(item) == "customer"]
    dev_targets = [item_target(item) for item in rows if item_runtime_class(item) == "dev"]
    recipes: list[str] = []
    recipe_digests: list[str] = []
    wrapper_images: list[str] = []
    product_images: list[str] = []
    retrieval_enabled_targets: list[str] = []
    retrieval_disabled_targets: list[str] = []
    retrieval_component_digests: list[str] = []
    retrieval_binding_digests: list[str] = []
    for item in rows:
        recipe = item.get("recipe")
        recipe_name = ""
        recipe_digest = ""
        if isinstance(recipe, dict):
            recipe_name = str(recipe.get("canonical_recipe_name") or "")
            recipe_digest = str(recipe.get("canonical_recipe_digest") or "")
        if recipe_name:
            recipes.append(recipe_name)
        if recipe_digest:
            recipe_digests.append(recipe_digest)
        if item.get("wrapper_image"):
            wrapper_images.append(str(item.get("wrapper_image")))
        if item.get("product_image"):
            product_images.append(str(item.get("product_image")))
        if item.get("retrieval_enabled") is True:
            retrieval_enabled_targets.append(item_target(item))
        else:
            retrieval_disabled_targets.append(item_target(item))
        if item.get("retrieval_component_digest"):
            retrieval_component_digests.append(str(item.get("retrieval_component_digest")))
        if item.get("retrieval_binding_digest"):
            retrieval_binding_digests.append(str(item.get("retrieval_binding_digest")))

    return {
        "count": len(rows),
        "targets": [item_target(item) for item in rows],
        "customer_targets": customer_targets,
        "dev_targets": dev_targets,
        "direct_targets": direct_targets,
        "missing_targets": [slot for slot in slots if slot not in seen_slots],
        "wrapper_images": sorted(set(wrapper_images)),
        "product_images": sorted(set(product_images)),
        "canonical_recipe_names": sorted(set(recipes)),
        "canonical_recipe_digests": sorted(set(recipe_digests)),
        "retrieval_enabled_targets": sorted(retrieval_enabled_targets),
        "retrieval_disabled_targets": sorted(retrieval_disabled_targets),
        "retrieval_component_digests": sorted(set(retrieval_component_digests)),
        "retrieval_binding_digests": sorted(set(retrieval_binding_digests)),
    }
