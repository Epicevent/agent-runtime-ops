from __future__ import annotations

import argparse
import sys

from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_approval_policy import (
    IMAGE_APPROVAL_POLICY_NAME,
    load_image_approvals,
    verify_source_commit,
    write_image_approval,
)
from ..domain.image_specs import OCI_REVISION_LABEL, image_recipe_labels_from_wrapper
from ..domain.source_provenance import OCI_SOURCE_LABEL, verify_commit_on_default_branch
from ..domain.update_signal import probe_image_version, write_update_signals


def _announce_product_approval(args: argparse.Namespace, state_root) -> None:
    """Announce a newly approved openclaw product to running slots (announce-only).

    The product's control UI reads <stateDir>/update-signal.json and shows a
    display-only banner when availableVersion is newer than the running version;
    slots already on this version stay silent. Failures are printed, never raised:
    the approval itself is the trust act and must stand regardless.
    """
    try:
        available_version = probe_image_version(args.image)
    except Exception as exc:
        print(f"update_signal_status=skipped reason=version_probe_failed detail={exc}")
        return
    results = write_update_signals(
        state_root, args.family, args.image, available_version=available_version
    )
    written = 0
    for slot, ok, detail in results:
        print(f"update_signal slot={slot} {'ok' if ok else 'FAIL'} {detail}")
        written += 1 if ok else 0
    print(
        f"update_signal_status=written count={written}/{len(results)} "
        f"availableVersion={available_version}"
    )


def cmd_image_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl image approve FAMILY ROLE IMAGE@sha256:...",
            file=sys.stderr,
        )
        return 2
    source_commit = str(getattr(args, "source_commit", "") or "")
    try:
        # Provenance gate: read the image's own revision label and bind it to the claim.
        labels = image_recipe_labels_from_wrapper(args.image)
        revision = str(labels.get(OCI_REVISION_LABEL) or "")
        verify_source_commit(source_commit, revision)
        # Ancestry gate: a claimed source commit must be merged to the default branch
        # of the repo the image itself names (OCI source label). Unmerged approvals made
        # main lie once; --allow-unmerged-source is the audited emergency override.
        if source_commit:
            source_repo = str(labels.get(OCI_SOURCE_LABEL) or "")
            if getattr(args, "allow_unmerged_source", False):
                print("source_ancestry=skipped reason=allow-unmerged-source")
            elif not source_repo:
                raise ValueError(
                    f"image carries no {OCI_SOURCE_LABEL} label; cannot verify source-commit "
                    "ancestry (rebuild with the current build script, or use --allow-unmerged-source)"
                )
            else:
                branch = verify_commit_on_default_branch(source_repo, source_commit)
                print(f"source_ancestry=merged branch={branch}")
        policy_path = write_image_approval(
            _state_root(args),
            args.family,
            args.role,
            args.image,
            source_commit=source_commit,
            revision=revision,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"approved_family={args.family}")
    print(f"approved_role={args.role}")
    print(f"approved_image={args.image}")
    print(f"image_revision={revision or 'none'}")
    print(f"policy_file={policy_path}")
    # Only the openclaw product carries the update-signal contract (the wrapper is an
    # ops layer and hermes has no signal reader).
    if args.family == "openclaw" and args.role == "product":
        _announce_product_approval(args, _state_root(args))
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
        image_revision = str(item.get("image_revision") or "")
        approved_at = str(item.get("approved_at") or "")
        approved_by = str(item.get("approved_by") or "")
        print(
            f"image {key} digest={digest} ref={ref} "
            f"source_commit={source_commit or 'none'} image_revision={image_revision or 'none'} "
            f"approved_at={approved_at} approved_by={approved_by}"
        )
    return 0
