"""Root-approved product/wrapper image digests — commit-addressed image trust.

This mirrors the `opsctl update approve <full-SHA>` model (domain/update_policy.py):
trust does not come from WHERE an image was built (CI vs a dev/build account) but from
a root operator explicitly approving an exact image digest. opsctl then refuses to roll
out any digest that is not approved, and `rollout image-promote` already applies the one
approved digest identically to every slot — so a fast server-side build becomes
trustworthy and all slots stay consistent.

State lives in `/srv/openclaw-ops/image-approved.yaml` (private server state), keyed by
`<family>:<role>` (e.g. `openclaw:product`, `openclaw:wrapper`).
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile

from ..yamlio import dump_yaml, load_yaml
from .image_specs import (
    DIGEST_RE,
    OCI_REVISION_LABEL,
    allowed_image_ref,
    digest_from_image_ref,
    validate_image_digest_ref,
)


IMAGE_APPROVAL_POLICY_NAME = "image-approved.yaml"
FAMILIES = ("openclaw", "hermes")
ROLES = ("product", "wrapper")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def policy_key(family: str, role: str) -> str:
    return f"{family}:{role}"


def validate_image_approval_target(family: str, role: str, image_ref: str) -> str:
    """Validate the (family, role, image_ref) triple and return the sha256 digest.

    Rejects unknown family/role, non-digest-pinned refs, and refs whose repository is
    not allowed for that family/role (so an openclaw product slot can never be approved
    with a hermes or otherwise unexpected repository).
    """
    if family not in FAMILIES:
        raise ValueError(f"unknown family: {family} (expected one of {', '.join(FAMILIES)})")
    if role not in ROLES:
        raise ValueError(f"unknown role: {role} (expected one of {', '.join(ROLES)})")
    digest = validate_image_digest_ref(image_ref)
    if not allowed_image_ref(family, role, image_ref):
        raise ValueError(f"image repository is not allowed for {family} {role}: {image_ref}")
    return digest


def verify_source_commit(source_commit: str, image_revision: str) -> None:
    """Provenance gate: a claimed --source-commit must equal the image's own revision label.

    This binds an approved digest mechanically to the commit it was built from. Trust does
    not rest on reproducibility (two builds of one commit differ); it rests on approving the
    exact artifact whose provenance is verified here. Empty source_commit = no claim to check.
    """
    if not source_commit:
        return
    if not image_revision:
        raise ValueError(
            f"image has no {OCI_REVISION_LABEL} label; cannot verify --source-commit {source_commit}"
        )
    if source_commit != image_revision:
        raise ValueError(
            f"--source-commit {source_commit} does not match image {OCI_REVISION_LABEL} "
            f"{image_revision} (approving a digest whose provenance does not match the claim)"
        )


def load_image_approvals(state_root: Path) -> dict:
    data = load_yaml(state_root / IMAGE_APPROVAL_POLICY_NAME, default={})
    images = data.get("images") if isinstance(data, dict) else None
    return images if isinstance(images, dict) else {}


def approved_image_digest(state_root: Path, family: str, role: str) -> str:
    """Return the approved sha256 digest for a family/role, or "" if none is approved."""
    item = load_image_approvals(state_root).get(policy_key(family, role))
    if not isinstance(item, dict):
        return ""
    digest = str(item.get("approved_digest") or "")
    return digest if DIGEST_RE.match(digest) else ""


def is_image_digest_approved(state_root: Path, family: str, role: str, digest: str) -> bool:
    approved = approved_image_digest(state_root, family, role)
    return bool(approved) and bool(digest) and approved == digest


def is_image_ref_approved(state_root: Path, family: str, role: str, image_ref: object) -> bool:
    digest = digest_from_image_ref(image_ref) if image_ref else None
    return bool(digest) and is_image_digest_approved(state_root, family, role, digest)


def write_image_approval(
    state_root: Path,
    family: str,
    role: str,
    image_ref: str,
    *,
    source_commit: str = "",
    revision: str = "",
) -> Path:
    """Record root approval for an exact image digest (merges; does not clobber others).

    `revision` is the image's own org.opencontainers.image.revision label (the verified
    provenance), recorded so `image status` shows the exact commit each digest was built from.
    """
    digest = validate_image_approval_target(family, role, image_ref)
    if not state_root.is_dir():
        raise FileNotFoundError(state_root)

    policy_path = state_root / IMAGE_APPROVAL_POLICY_NAME
    existing = load_yaml(policy_path, default={})
    images = dict(existing.get("images") or {}) if isinstance(existing, dict) else {}
    images[policy_key(family, role)] = {
        "approved_ref": image_ref,
        "approved_digest": digest,
        "source_commit": source_commit,
        "image_revision": revision,
        "approved_at": _now_iso(),
        "approved_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
    }
    data = {
        "meta": {"schema_version": 1, "updated_at": _now_iso(), "scope": "private_server_state"},
        "images": images,
    }

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_root, delete=False) as fh:
        tmp_path = Path(fh.name)
        fh.write(dump_yaml(data))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        if hasattr(os, "chown"):
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, policy_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return policy_path
