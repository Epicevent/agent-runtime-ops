from __future__ import annotations

import argparse

from ..canonical_recipes import canonical_recipe_for_image_spec, canonical_recipe_identity
from ..domain.common import check_line as _check_line
from ..domain.common import state_root as _state_root
from ..domain.image_specs import _profile_customer_surface, _profile_runtime_contract
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_checks import run_static_slot_checks as _run_static_slot_checks
from ..domain.runtime_state import _desired_from_runtime_manifest
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..renderer import render_compose


def cmd_check(args: argparse.Namespace) -> int:
    try:
        state_root = _state_root(args)
        if args.live:
            desired, profile = _desired_from_live_image_truth(args.slot, state_root)
        else:
            desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
        rendered = render_compose(profile, desired)
    except Exception as exc:
        print(f"target={args.slot}")
        print("check_status=not_ready")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"image_name={desired.image_name}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"runtime_contract={_profile_runtime_contract(profile)}")
    print(f"customer_surface={_profile_customer_surface(profile)}")
    for key, value in canonical_recipe_identity(canonical_recipe_for_image_spec(desired.image_spec)).items():
        print(f"{key}={value}")
    print(f"compose_sha256={rendered.sha256}")
    print("check_mode=non_mutating")
    print(f"live_runtime_check={'enabled' if args.live else 'not_run'}")

    failed = 0
    for ok, name, detail in _run_static_slot_checks(desired, profile, rendered):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1

    _check_line(bool(rendered.text.strip()), "compose_rendered")
    if not rendered.text.strip():
        failed += 1

    if args.live:
        for ok, name, detail in _run_live_slot_checks(desired, profile, _state_root(args)):
            _check_line(ok, name, detail)
            if not ok:
                failed += 1
    else:
        print("INFO live_runtime_check_not_run use='opsctl check --live TARGET'")

    if failed:
        print(f"check_status=fail failed={failed}")
        return 1
    if args.live:
        print("check_status=pass scope=contract_and_live")
    else:
        print("check_status=pass scope=contract_only")
    return 0
