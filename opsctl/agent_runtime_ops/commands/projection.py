from __future__ import annotations

import argparse
import json
import sys

from ..apache import parse_apache_route
from ..canonical_recipes import canonical_recipe_for_image_spec, canonical_recipe_identity
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_specs import image_spec_from_direct_images, profile_runtime_contract
from ..domain.runtime_checks import run_static_slot_checks as _run_static_slot_checks
from ..domain.runtime_manifest import desired_from_runtime_manifest
from ..domain.runtime_targets import desired_from_direct_images as _desired_from_direct_images
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..domain.runtime_truth import live_runtime_truth
from ..renderer import render_compose
from ..routing import get_runtime_binding


def _desired_for_projection(slot: str, state_root, *, live: bool):
    if live:
        return _desired_from_live_image_truth(slot, state_root)
    return desired_from_runtime_manifest(slot, state_root)


def cmd_projection_describe(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    live = bool(getattr(args, "live", False))
    if live and not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl projection describe TARGET --live", file=sys.stderr)
        return 2
    try:
        binding = get_runtime_binding(args.slot, state_root)
        apache_route = parse_apache_route(binding.linux_account)
        desired, profile = _desired_for_projection(binding.linux_account, state_root, live=live)
        rendered = render_compose(profile, desired)
        recipe = canonical_recipe_identity(canonical_recipe_for_image_spec(desired.image_spec))
        payload = {
            "projection_status": "ok",
            "target": binding.linux_account,
            "family": binding.family,
            "runtime_class": binding.runtime_class,
            "public_host": binding.public_host,
            "apache_public_host": apache_route.public_host,
            "gateway_port": binding.gateway_port,
            "apache_gateway_port": apache_route.gateway_port,
            "bridge_port": binding.bridge_port,
            "runtime_profile": profile.name,
            "runtime_contract": profile_runtime_contract(profile),
            "wrapper_image": desired.image_spec.get("wrapper_image"),
            "product_image": desired.image_spec.get("product_image"),
            "canonical_recipe_name": recipe.get("canonical_recipe_name"),
            "canonical_recipe_digest": recipe.get("canonical_recipe_digest"),
            "allow_source_mount": profile.metadata.get("allow_source_mount"),
            "compose_sha256": rendered.sha256,
            "truth_source": "live_image" if live else "runtime_manifest",
        }
        if live:
            truth, truth_checks = live_runtime_truth(binding.linux_account, state_root)
            payload["live_truth_status"] = truth.get("truth_status")
            payload["live_wrapper_image"] = truth.get("wrapper_image")
            payload["live_product_image"] = truth.get("product_image")
            payload["live_failed_checks"] = [name for ok, name, _ in truth_checks if not ok]
    except Exception as exc:
        print(json.dumps({"projection_status": "fail", "target": str(args.slot), "reason": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _verify_static_projection(slot: str, wrapper_image: str, product_image: str, state_root):
    image_spec = image_spec_from_direct_images(wrapper_image, product_image)
    desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
    rendered = render_compose(profile, desired)
    checks = list(_run_static_slot_checks(desired, profile, rendered))
    checks.append((bool(rendered.text.strip()), "projection_compose_rendered", rendered.sha256))
    checks.append(
        (
            profile.metadata.get("allow_source_mount") is False if desired.runtime_class == "customer" else True,
            "projection_customer_source_mount_absent",
            f"allow_source_mount={profile.metadata.get('allow_source_mount')}",
        )
    )
    return desired, profile, checks


def cmd_projection_verify_target(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    live = bool(getattr(args, "live", False))
    if live and not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl projection verify-target TARGET --live ...", file=sys.stderr)
        return 2
    try:
        desired, profile, checks = _verify_static_projection(
            str(args.slot),
            str(args.wrapper_image),
            str(args.product_image),
            state_root,
        )
        if live:
            truth, truth_checks = live_runtime_truth(desired.slot, state_root)
            checks.extend(truth_checks)
            checks.extend(
                [
                    (
                        truth.get("wrapper_image") == args.wrapper_image,
                        "projection_live_wrapper_matches_verified_digest",
                        f"live={truth.get('wrapper_image') or 'missing'} expected={args.wrapper_image}",
                    ),
                    (
                        truth.get("product_image") == args.product_image,
                        "projection_live_product_matches_verified_digest",
                        f"live={truth.get('product_image') or 'missing'} expected={args.product_image}",
                    ),
                    (
                        truth.get("runtime_contract") == profile_runtime_contract(profile),
                        "projection_live_runtime_contract_matches",
                        f"live={truth.get('runtime_contract') or 'missing'} expected={profile_runtime_contract(profile)}",
                    ),
                ]
            )
    except Exception as exc:
        print(f"target={args.slot}")
        print("projection_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_contract={profile_runtime_contract(profile)}")
    print(f"wrapper_image={args.wrapper_image}")
    print(f"product_image={args.product_image}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"projection_status={'pass' if failed == 0 else 'fail'} failed={failed}")
    return 0 if failed == 0 else 1


def cmd_projection_compare(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl projection compare ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        left, left_checks = live_runtime_truth(str(args.from_slot), state_root)
        right, right_checks = live_runtime_truth(str(args.to_slot), state_root)
        checks = list(left_checks) + list(right_checks)
        comparisons = [
            ("wrapper_image", "projection_wrapper_image_matches"),
            ("product_image", "projection_product_image_matches"),
            ("canonical_recipe_name", "projection_canonical_recipe_name_matches"),
            ("canonical_recipe_digest", "projection_canonical_recipe_digest_matches"),
            ("runtime_contract", "projection_runtime_contract_matches"),
        ]
        for key, name in comparisons:
            checks.append((left.get(key) == right.get(key), name, f"from={left.get(key) or 'missing'} to={right.get(key) or 'missing'}"))
    except Exception as exc:
        print("projection_compare_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"from_target={args.from_slot}")
    print(f"to_target={args.to_slot}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"projection_compare_status={'pass' if failed == 0 else 'fail'} failed={failed}")
    return 0 if failed == 0 else 1
