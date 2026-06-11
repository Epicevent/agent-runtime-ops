from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..apache import parse_apache_route
from ..domain.apache_route_checks import apache_route_checks as _apache_route_checks
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_specs import (
    image_spec_recipe_payload,
    profile_customer_surface,
    profile_runtime_contract,
)
from ..domain.runtime_manifest import desired_from_runtime_manifest
from ..domain.runtime_truth import live_runtime_truth as _live_runtime_truth
from ..renderer import render_compose
from ..routing import get_runtime_binding


def cmd_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        binding = get_runtime_binding(args.slot, state_root)
        apache_route = parse_apache_route(binding.linux_account)
    except Exception as exc:
        print("status=unknown")
        print(f"reason={exc}")
        return 1
    print(f"instance_id={binding.instance_id}")
    print(f"linux_account={binding.linux_account}")
    print(f"public_host={binding.public_host}")
    print(f"actual_public_host={apache_route.public_host}")
    print(f"family={binding.family}")
    print(f"runtime_class={binding.runtime_class}")
    print(f"gateway_port={binding.gateway_port}")
    print(f"apache_gateway_port={apache_route.gateway_port}")
    print(f"bridge_port={binding.bridge_port}")
    print(f"enabled={'yes' if binding.enabled else 'no'}")
    for ok, name, detail in _apache_route_checks(binding, apache_route):
        _check_line(ok, name, detail)
        if not ok:
            print("status=fail")
            return 1
    if not _is_root():
        print("truth_source=live_image")
        print("truth_status=requires_live_root")
        print(f"next_action=sudo /usr/local/bin/opsctl runtime truth {binding.linux_account}")
        return 0
    try:
        truth, checks = _live_runtime_truth(binding.linux_account, state_root)
    except Exception as exc:
        print("truth_source=live_image")
        print("truth_status=fail")
        print(f"reason={exc}")
        return 1
    for key, value in truth.items():
        if key not in {
            "instance_id",
            "linux_account",
            "public_host",
            "actual_public_host",
            "family",
            "runtime_class",
            "gateway_port",
            "apache_gateway_port",
            "bridge_port",
            "enabled",
        }:
            print(f"{key}={value}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"status={'ok' if failed == 0 and truth.get('truth_status') == 'ok' else 'fail'}")
    return 0 if failed == 0 and truth.get("truth_status") == "ok" else 1


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        desired, profile = desired_from_runtime_manifest(args.slot, _state_root(args))
    except Exception as exc:
        plan = {
            "target": args.slot,
            "status": "not_ready",
            "reason": str(exc),
            "mutates": False,
        }
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 1
    rendered = render_compose(profile, desired)
    plan = {
        "target": desired.slot,
        "linux_account": desired.route.linux_account,
        "family": desired.family,
        "runtime_class": desired.runtime_class,
        "image_name": desired.image_name,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "runtime_contract": profile_runtime_contract(profile),
        "customer_surface": profile_customer_surface(profile),
        "wrapper_image": desired.image_spec.get("wrapper_image"),
        "product_image": desired.image_spec.get("product_image"),
        "recipe": image_spec_recipe_payload(desired.image_spec),
        "compose_sha256": rendered.sha256,
        "mutates": False,
    }
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0
