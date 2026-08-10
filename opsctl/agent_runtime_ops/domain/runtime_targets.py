from __future__ import annotations

from pathlib import Path

from ..profiles import load_profile
from ..routing import get_runtime_binding
from ..state import RuntimeTarget
from .image_specs import IMAGE_ROLLOUT_IMAGE_NAME, image_spec_from_direct_images, image_spec_recipe
from .runtime_truth import live_runtime_truth


def desired_from_direct_images(
    slot: str,
    image_spec: dict,
    state_root: Path,
):
    binding = get_runtime_binding(slot, state_root)
    runtime_class = binding.runtime_class
    image_recipe = image_spec_recipe(image_spec)
    profiles = image_recipe.get("runtime_profiles") if isinstance(image_recipe, dict) else {}
    runtime_profile = profiles.get(runtime_class) if isinstance(profiles, dict) else ""
    if not runtime_profile:
        raise ValueError(f"wrapper image recipe has no runtime profile for runtime_class={runtime_class}")
    family = str(image_recipe.get("family") or image_spec.get("family") or "")
    profile = load_profile(str(runtime_profile))
    if profile.metadata.get("family") != family:
        raise ValueError(f"slot image family/profile mismatch: image={family} profile={profile.metadata.get('family')}")
    if profile.metadata.get("slot_class") != runtime_class:
        raise ValueError(
            f"binding image runtime_class/profile mismatch: binding={runtime_class} profile={profile.metadata.get('slot_class')}"
        )
    if family != binding.family:
        raise ValueError(f"binding image family mismatch: image={family} binding={binding.family}")
    desired = RuntimeTarget(
        target=binding.linux_account,
        family=family,
        runtime_class=runtime_class,
        image_name=IMAGE_ROLLOUT_IMAGE_NAME,
        image_spec=image_spec,
        runtime_profile=str(runtime_profile),
        route=binding,
    )
    return desired, profile


def desired_from_live_image_truth(slot: str, state_root: Path):
    truth, checks = live_runtime_truth(slot, state_root)
    failed = [name for ok, name, _ in checks if not ok]
    if failed or truth.get("truth_status") != "ok":
        raise ValueError(f"live image truth is not ok: status={truth.get('truth_status')} failed={','.join(failed)}")
    wrapper_image = str(truth.get("wrapper_image") or "")
    product_image = str(truth.get("product_image") or "")
    image_spec = image_spec_from_direct_images(wrapper_image, product_image)
    return desired_from_direct_images(slot, image_spec, state_root)
