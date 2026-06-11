from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..canonical_recipes import canonical_recipe_for_image_spec, canonical_recipe_identity
from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import apache_public_host as _apache_public_host
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_specs import (
    IMAGE_ROLLOUT_IMAGE_NAME,
    image_spec_from_direct_images,
    image_spec_recipe_payload,
    profile_runtime_contract,
)
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..domain.runtime_checks import run_static_slot_checks as _run_static_slot_checks
from ..domain.runtime_state import _state_manifest_path
from ..domain.runtime_targets import (
    desired_from_direct_images as _desired_from_direct_images,
    desired_from_live_image_truth as _desired_from_live_image_truth,
)
from ..domain.runtime_truth import live_runtime_truth
from ..renderer import render_compose
from ..routing import load_runtime_bindings
from ..yamlio import load_yaml


def _runtime_manifest_rollup(state_root: Path, slots: list[str], family: str) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for slot in slots:
        path = _state_manifest_path(state_root, slot)
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
    }


def cmd_rollout_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        family = str(args.family)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        bindings = [binding for binding in load_runtime_bindings(state_root) if binding.enabled and binding.family == family]
        runtime_slots = [binding.linux_account for binding in bindings]
        runtime_rollup = _runtime_manifest_rollup(state_root, runtime_slots, family)
    except Exception as exc:
        print("rollout_status=fail")
        print(f"reason={exc}")
        return 1
    print("rollout_status=ok")
    print("status_source=runtime_manifests")
    print(f"family={family}")
    print(f"binding_targets={','.join(runtime_slots)}")
    print(f"runtime_manifest_count={runtime_rollup['count']}")
    print(f"runtime_manifest_targets={','.join(runtime_rollup['targets'])}")
    print(f"runtime_manifest_customer_targets={','.join(runtime_rollup['customer_targets'])}")
    print(f"runtime_manifest_dev_targets={','.join(runtime_rollup['dev_targets'])}")
    print(f"runtime_manifest_direct_image_targets={','.join(runtime_rollup['direct_targets'])}")
    print(f"runtime_manifest_missing_targets={','.join(runtime_rollup['missing_targets'])}")
    print(f"runtime_manifest_wrapper_images={','.join(runtime_rollup['wrapper_images'])}")
    print(f"runtime_manifest_product_images={','.join(runtime_rollup['product_images'])}")
    print(f"runtime_manifest_canonical_recipe_names={','.join(runtime_rollup['canonical_recipe_names'])}")
    print(f"runtime_manifest_canonical_recipe_digests={','.join(runtime_rollup['canonical_recipe_digests'])}")
    return 0


def _image_spec_canonical_record(image_spec: dict) -> dict[str, str]:
    return canonical_recipe_identity(canonical_recipe_for_image_spec(image_spec))


def _direct_image_spec_from_args(args: argparse.Namespace) -> dict[str, object]:
    return image_spec_from_direct_images(str(args.wrapper_image), str(args.product_image))


def cmd_rollout_image_plan(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        image_spec = _direct_image_spec_from_args(args)
        slots = [str(item) for item in (getattr(args, "slots", None) or [])]
        if getattr(args, "slot", None):
            slots.append(str(args.slot))
        if not slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        plans = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            rendered = render_compose(profile, desired)
            checks = [
                {"ok": ok, "name": name, "detail": detail}
                for ok, name, detail in _run_static_slot_checks(desired, profile, rendered)
            ]
            plans.append(
                {
                    "linux_account": desired.slot,
                    "runtime_class": desired.runtime_class,
                    "public_host": _apache_public_host(slot),
                    "gateway_port": desired.route.gateway_port if desired.route else "",
                    "bridge_port": desired.route.bridge_port if desired.route else "",
                    "runtime_profile": profile.name,
                    "runtime_contract": profile_runtime_contract(profile),
                    "checks": checks,
                    "compatible": all(item["ok"] for item in checks),
                    "compose_sha256": rendered.sha256,
                }
            )
        payload = {
            "rollout_image_plan_status": "ok",
            "truth_source": "wrapper_image_labels",
            "family": image_spec.get("family"),
            "wrapper_image": image_spec.get("wrapper_image"),
            "product_image": image_spec.get("product_image"),
            "recipe": image_spec_recipe_payload(image_spec),
            "targets": plans,
            "mutates": False,
        }
    except Exception as exc:
        print(json.dumps({"rollout_image_plan_status": "fail", "reason": str(exc), "mutates": False}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_rollout_image_apply_slot(args: argparse.Namespace, *, required_runtime_class: str, action_name: str) -> int:
    if not _is_root():
        print(f"error: run as root/admin: sudo /usr/local/bin/opsctl rollout {action_name} ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        image_spec = _direct_image_spec_from_args(args)
        desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
        if desired.runtime_class != required_runtime_class:
            raise ValueError(f"{action_name} requires runtime_class={required_runtime_class}: {slot}")
    except Exception as exc:
        print(f"rollout_{action_name.replace('-', '_')}_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, f"rollout_{action_name}", slot, IMAGE_ROLLOUT_IMAGE_NAME, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"rollout_{action_name.replace('-', '_')}_state=direct_image")
    print(f"target={slot}")
    print(f"family={desired.family}")
    print(f"runtime_profile={profile.name}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    for key, value in _image_spec_canonical_record(image_spec).items():
        print(f"{key}={value}")
    rc = _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(getattr(args, "allow_first_apply", False)),
        action_name=f"rollout_{action_name}",
    )
    if rc == 0:
        print(f"rollout_{action_name.replace('-', '_')}_status=ok")
    return rc


def cmd_rollout_image_dev_apply(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="dev", action_name="image-dev-apply")


def cmd_rollout_image_canary(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="customer", action_name="image-canary")


def cmd_rollout_image_promote(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout image-promote ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    from_slot = str(args.from_slot)
    try:
        source_truth, source_checks = live_runtime_truth(from_slot, state_root)
        failed = [name for ok, name, _ in source_checks if not ok]
        if failed or source_truth.get("truth_status") != "ok":
            raise ValueError(
                f"from-target live image truth is not ok: status={source_truth.get('truth_status')} failed={','.join(failed)}"
            )
        wrapper_image = str(source_truth.get("wrapper_image") or "")
        product_image = str(source_truth.get("product_image") or "")
        image_spec = image_spec_from_direct_images(wrapper_image, product_image)
        slots = [item.strip() for item in str(args.slots).split(",") if item.strip()]
        if not slots:
            raise ValueError("--targets must name the promotion targets explicitly")
        applied: list[str] = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            if desired.runtime_class != "customer":
                raise ValueError(f"promotion target is not a customer target: {slot}")
            rc = _apply_desired_slot(
                desired=desired,
                profile=profile,
                state_root=state_root,
                allow_first_apply=False,
                action_name="rollout_image_promote",
            )
            if rc != 0:
                print("rollout_image_promote_status=partial")
                print(f"failed_target={slot}")
                _append_action_log(state_root, "rollout_image_promote", slot, wrapper_image, "partial", "slot_apply_failed")
                return rc or 1
            applied.append(slot)
    except Exception as exc:
        print("rollout_image_promote_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_image_promote", from_slot, from_slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print("rollout_image_promote_status=ok")
    print(f"from_target={from_slot}")
    print(f"targets={','.join(applied)}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    _append_action_log(state_root, "rollout_image_promote", from_slot, str(image_spec.get("wrapper_image") or ""), "ok", f"targets={len(applied)}")
    return 0


