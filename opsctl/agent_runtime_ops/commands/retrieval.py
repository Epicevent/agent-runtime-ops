from __future__ import annotations

import argparse
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_approval_policy import is_image_ref_approved
from ..domain.image_specs import (
    allowed_image_ref,
    image_recipe_labels_from_wrapper,
    validate_image_digest_ref,
)
from ..domain.retrieval_contract import (
    RETRIEVAL_APPROVAL_POLICY_NAME,
    load_retrieval_approvals,
    retrieval_contract_from_labels,
    write_retrieval_approval,
)


def cmd_retrieval_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl retrieval approve FAMILY PRODUCT@sha256:...",
            file=sys.stderr,
        )
        return 2
    state_root = _state_root(args)
    try:
        validate_image_digest_ref(args.product_image)
        if not allowed_image_ref(args.family, "product", args.product_image):
            raise ValueError("product image repository is not allowed for this family")
        if not is_image_ref_approved(
            state_root, args.family, "product", args.product_image
        ):
            raise ValueError("exact product image must be root-approved before its retrieval component")
        contract = retrieval_contract_from_labels(
            image_recipe_labels_from_wrapper(args.product_image)
        )
        if contract is None:
            raise ValueError("product image declares no embedded retrieval component")
        policy_path = write_retrieval_approval(
            state_root,
            args.family,
            contract,
            product_image_digest=validate_image_digest_ref(args.product_image),
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"approved_family={args.family}")
    print(f"approved_product_image={args.product_image}")
    print(f"approved_component_digest={contract['component_digest']}")
    print(f"approved_component_manifest_digest={contract['component_manifest_digest']}")
    print(f"approved_contract_digest={contract['contract_digest']}")
    print(f"approved_source_archive_digest={contract['source_archive_digest']}")
    print(f"approved_resource_profile_digest={contract['resource']['profileDigest']}")
    print(f"policy_file={policy_path}")
    return 0


def cmd_retrieval_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        approvals = load_retrieval_approvals(state_root)
    except Exception as exc:
        print("retrieval_approval_status=fail")
        print(f"reason={exc}")
        return 1
    print("retrieval_approval_status=ok")
    print(f"policy_file={state_root / RETRIEVAL_APPROVAL_POLICY_NAME}")
    print(f"approved_count={len(approvals)}")
    for family in sorted(approvals):
        item = approvals[family]
        if not isinstance(item, dict):
            continue
        print(
            "retrieval "
            f"family={family} component_digest={item.get('component_digest') or 'none'} "
            f"component_manifest_digest={item.get('component_manifest_digest') or 'none'} "
            f"contract_digest={item.get('contract_digest') or 'none'} "
            f"source_archive_digest={item.get('source_archive_digest') or 'none'} "
            f"resource_profile_digest={item.get('resource_profile_digest') or 'none'} "
            f"product_image_digest={item.get('product_image_digest') or 'none'} "
            f"source_revision={item.get('source_revision') or 'none'}"
        )
    return 0
