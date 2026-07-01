from __future__ import annotations

import argparse
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.config_contract import (
    config_json_diff,
    config_owner_run_as,
    preview_config_migrate,
    read_config_json,
    run_config_validate_in_image,
    run_config_migrate_in_image,
)
from ..domain.image_specs import config_contract_from_image_labels, image_spec_config_contract
from ..domain.runtime_paths import slot_config_dir
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth


def _resolve(args: argparse.Namespace):
    """Resolve a slot to (config_contract, host_config_dir, product_image, run_as).

    When ``--product-image`` is given, the contract is read straight from that image's
    labels (bootstrap: the slot's currently-running image may predate the contract). Else
    it comes from the running image's verified recipe (steady state).
    """
    state_root = _state_root(args)
    desired, _profile = _desired_from_live_image_truth(args.slot, state_root)
    override_image = str(getattr(args, "product_image", "") or "")
    if override_image:
        product_image = override_image
        contract = config_contract_from_image_labels(product_image)
        if not contract:
            raise ValueError(f"product image {product_image} declares no config contract labels")
    else:
        product_image = str(desired.image_spec.get("product_image") or "")
        contract = image_spec_config_contract(desired.image_spec)
        if not contract:
            raise ValueError(
                f"slot {args.slot} running image declares no config contract; "
                f"pass --product-image <new image@sha256:...> to migrate to a contract-bearing image"
            )
    if not product_image:
        raise ValueError("could not resolve a product image for the target slot")
    host_config_dir = slot_config_dir(args.slot)
    return contract, host_config_dir, product_image, config_owner_run_as(host_config_dir)


def cmd_config_validate(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl config validate SLOT", file=sys.stderr)
        return 2
    try:
        contract, host_config_dir, product_image, run_as = _resolve(args)
        valid, detail = run_config_validate_in_image(product_image, host_config_dir, contract, run_as=run_as)
    except Exception as exc:
        print(f"target={args.slot}")
        print("config_validate_status=error")
        print(f"reason={exc}")
        return 2
    print(f"target={args.slot}")
    print(f"product_image={product_image}")
    print(f"config_valid={'yes' if valid else 'no'}")
    print(f"detail={detail}")
    return 0 if valid else 1


def cmd_config_migrate(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl config migrate SLOT", file=sys.stderr)
        return 2
    try:
        contract, host_config_dir, product_image, run_as = _resolve(args)
    except Exception as exc:
        print(f"target={args.slot}")
        print("config_migrate_status=error")
        print(f"reason={exc}")
        return 2

    dry_run = bool(getattr(args, "dry_run", False))
    print(f"target={args.slot}")
    print(f"product_image={product_image}")
    print(f"dry_run={'yes' if dry_run else 'no'}")

    before_valid, before_detail = run_config_validate_in_image(product_image, host_config_dir, contract, run_as=run_as)
    print(f"before_valid={'yes' if before_valid else 'no'} before_detail={before_detail}")
    if before_valid:
        print("config_migrate_status=noop")
        print("note=config already valid for target image; nothing to migrate")
        return 0

    if dry_run:
        # Preview on a throwaway copy — show what WOULD change, write nothing.
        ran_ok, detail, diff = preview_config_migrate(product_image, host_config_dir, contract, run_as=run_as)
        print(f"migrate_ran={'ok' if ran_ok else 'fail'} migrate_detail={detail}")
        _print_diff(diff)
        print(f"config_migrate_status={'preview' if ran_ok else 'fail'}")
        print("note=DRY RUN — nothing written. Review the diff above, then run without --dry-run to apply.")
        return 0 if ran_ok else 1

    before_cfg = read_config_json(host_config_dir)
    migrated, migrate_detail = run_config_migrate_in_image(product_image, host_config_dir, contract, run_as=run_as)
    print(f"migrate_ran={'ok' if migrated else 'fail'} migrate_detail={migrate_detail}")
    if not migrated:
        print("config_migrate_status=fail")
        return 1

    after_cfg = read_config_json(host_config_dir)
    _print_diff(config_json_diff(before_cfg or {}, after_cfg or {}))

    after_valid, after_detail = run_config_validate_in_image(product_image, host_config_dir, contract, run_as=run_as)
    print(f"after_valid={'yes' if after_valid else 'no'} after_detail={after_detail}")
    print(f"config_migrate_status={'ok' if after_valid else 'fail'}")
    print("note=a timestamped openclaw.json.bak was written before the rewrite; review the diff above and restore the .bak if unexpected")
    return 0 if after_valid else 1


def _print_diff(diff: list[str]) -> None:
    """Surface exactly what the migration changed so the operator reviews it, not trusts it."""
    print(f"config_diff_lines={len(diff)}")
    if not diff:
        print("diff (none — config unchanged by migrate)")
    for line in diff:
        print(f"diff {line}")
