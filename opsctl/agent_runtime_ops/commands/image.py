from __future__ import annotations

import argparse
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_approval_policy import (
    IMAGE_APPROVAL_POLICY_NAME,
    load_image_approvals,
    write_image_approval,
)


def cmd_image_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl image approve FAMILY ROLE IMAGE@sha256:...",
            file=sys.stderr,
        )
        return 2
    try:
        policy_path = write_image_approval(
            _state_root(args),
            args.family,
            args.role,
            args.image,
            source_commit=str(getattr(args, "source_commit", "") or ""),
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"approved_family={args.family}")
    print(f"approved_role={args.role}")
    print(f"approved_image={args.image}")
    print(f"policy_file={policy_path}")
    return 0


def cmd_image_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    approvals = load_image_approvals(state_root)
    print(f"policy_file={state_root / IMAGE_APPROVAL_POLICY_NAME}")
    print(f"approved_count={len(approvals)}")
    for key in sorted(approvals):
        item = approvals[key]
        if not isinstance(item, dict):
            continue
        digest = str(item.get("approved_digest") or "")
        ref = str(item.get("approved_ref") or "")
        source_commit = str(item.get("source_commit") or "")
        approved_at = str(item.get("approved_at") or "")
        approved_by = str(item.get("approved_by") or "")
        print(
            f"image {key} digest={digest} ref={ref} "
            f"source_commit={source_commit or 'none'} approved_at={approved_at} approved_by={approved_by}"
        )
    return 0
