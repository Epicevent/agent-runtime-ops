from __future__ import annotations

import argparse
from pathlib import Path

from ..canonical_recipes import canonical_recipe_for_image_spec, canonical_recipe_identity
from ..renderer import render_compose


def _cli_mod():
    from .. import cli

    return cli


def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def _desired_from_live_image_truth(slot: str, state_root: Path):
    return _cli_mod()._desired_from_live_image_truth(slot, state_root)


def _desired_from_runtime_manifest(slot: str, state_root: Path):
    return _cli_mod()._desired_from_runtime_manifest(slot, state_root)


def _profile_runtime_contract(profile) -> str:
    return _cli_mod()._profile_runtime_contract(profile)


def _profile_customer_surface(profile) -> str:
    return _cli_mod()._profile_customer_surface(profile)


def _run_static_slot_checks(desired, profile, rendered):
    return _cli_mod()._run_static_slot_checks(desired, profile, rendered)


def _run_live_slot_checks(desired, profile, state_root: Path):
    return _cli_mod()._run_live_slot_checks(desired, profile, state_root)


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


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
