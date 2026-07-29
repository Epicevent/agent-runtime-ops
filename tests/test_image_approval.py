"""Tests for root-approved image-digest trust (commit-addressed image approval).

Mirrors the `opsctl update approve` model: trust comes from a root operator approving
an exact image digest, not from where the image was built. The rollout static gate then
refuses any non-approved digest (progressively: enforced for a family/role only once an
approval exists for it, so deploying the gate is non-breaking).
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_runtime_ops.domain import image_approval_policy as ia
from agent_runtime_ops.domain import runtime_checks
from agent_runtime_ops.domain.image_specs import digest_from_image_ref


PRODUCT = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "a" * 64
WRAPPER = "ghcr.io/epicevent/agent-runtime-openclaw@sha256:" + "b" * 64
OTHER = "ghcr.io/epicevent/openclaw-jitech@sha256:" + "9" * 64
HERMES_PRODUCT = "ghcr.io/epicevent/hermes-jitech@sha256:" + "c" * 64


# --------------------------------------------------------------------------- #
# policy: validate / write+merge / lookup
# --------------------------------------------------------------------------- #

def test_validate_returns_digest_and_rejects_bad_targets():
    assert ia.validate_image_approval_target("openclaw", "product", PRODUCT) == digest_from_image_ref(PRODUCT)
    for family, role, ref in [
        ("openclaw", "product", HERMES_PRODUCT),  # wrong repo for family/role
        ("nope", "product", PRODUCT),  # bad family
        ("openclaw", "nope", PRODUCT),  # bad role
        ("openclaw", "product", "ghcr.io/epicevent/openclaw-jitech:tag"),  # not digest-pinned
    ]:
        with pytest.raises(ValueError):
            ia.validate_image_approval_target(family, role, ref)


def test_write_merges_and_lookup(tmp_path):
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT, source_commit="deadbeef")
    ia.write_image_approval(tmp_path, "openclaw", "wrapper", WRAPPER)  # must not clobber product
    assert ia.approved_image_digest(tmp_path, "openclaw", "product") == digest_from_image_ref(PRODUCT)
    assert ia.approved_image_digest(tmp_path, "openclaw", "wrapper") == digest_from_image_ref(WRAPPER)
    assert ia.is_image_ref_approved(tmp_path, "openclaw", "product", PRODUCT)
    assert not ia.is_image_ref_approved(tmp_path, "openclaw", "product", OTHER)
    # provenance recorded
    item = ia.load_image_approvals(tmp_path)["openclaw:product"]
    assert item["source_commit"] == "deadbeef"


def test_image_approval_rotation_uses_runtime_host_mutation_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    @contextmanager
    def locked(_state_root: Path):
        events.append("lock_enter")
        yield
        events.append("lock_exit")

    def write(*_args: object, **_kwargs: object) -> Path:
        events.append("policy_write")
        return tmp_path / ia.IMAGE_APPROVAL_POLICY_NAME

    monkeypatch.setattr(ia, "runtime_host_mutation_lock", locked)
    monkeypatch.setattr(ia, "_write_image_approval_locked", write)

    result = ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT)

    assert result == tmp_path / ia.IMAGE_APPROVAL_POLICY_NAME
    assert events == ["lock_enter", "policy_write", "lock_exit"]


COMMIT = "9eaf9fb5a46259c76dc5856c6d8847891f5b700e"


def test_verify_source_commit_matches_and_empty_skips():
    ia.verify_source_commit(COMMIT, COMMIT)  # match -> ok
    ia.verify_source_commit("", "anything")  # no claim -> ok
    ia.verify_source_commit("", "")  # no claim -> ok


def test_verify_source_commit_mismatch_raises():
    with pytest.raises(ValueError):
        ia.verify_source_commit(COMMIT, "0" * 40)  # claim != image revision


def test_verify_source_commit_missing_label_raises():
    with pytest.raises(ValueError):
        ia.verify_source_commit(COMMIT, "")  # claimed a commit but image has no revision label


def test_write_records_image_revision(tmp_path):
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT, source_commit=COMMIT, revision=COMMIT)
    item = ia.load_image_approvals(tmp_path)["openclaw:product"]
    assert item["image_revision"] == COMMIT
    assert item["source_commit"] == COMMIT


def test_unapproved_and_missing_are_empty(tmp_path):
    assert ia.approved_image_digest(tmp_path, "openclaw", "product") == ""  # missing policy file
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT)
    assert ia.approved_image_digest(tmp_path, "hermes", "product") == ""  # never approved
    assert not ia.is_image_digest_approved(tmp_path, "openclaw", "product", digest_from_image_ref(OTHER))


# --------------------------------------------------------------------------- #
# rollout static gate: progressive enforcement
# --------------------------------------------------------------------------- #

def _desired_profile(slot="oc3"):
    # customer-class slot. The gate applies to PRODUCTION customer slots (oc*), NOT to
    # dev-owned image-mode canaries (dev-*-img) which the developer validates pre-approval.
    desired = SimpleNamespace(
        slot=slot,
        family="openclaw",
        runtime_class="customer",
        route=SimpleNamespace(runtime_class="customer"),
        image_spec={
            "family": "openclaw",
            "wrapper_image": WRAPPER,
            "product_image": PRODUCT,
            "digest": digest_from_image_ref(WRAPPER),
        },
    )
    profile = SimpleNamespace(
        name="openclaw-customer",
        metadata={"family": "openclaw", "slot_class": "customer", "mode": "image"},
    )
    return desired, profile


def _gate(checks, name):
    return next(((ok, detail) for ok, n, detail in checks if n == name), None)


def test_gate_absent_until_an_approval_exists(tmp_path, monkeypatch):
    # isolate from the heavy canonical contract checks
    monkeypatch.setattr(runtime_checks, "image_spec_profile_contract_checks", lambda *a, **k: [])
    desired, profile = _desired_profile()
    checks = runtime_checks.run_static_slot_checks(desired, profile, None, state_root=tmp_path)
    # no approvals yet -> gate not emitted (non-breaking)
    assert _gate(checks, "product_image_digest_approved") is None
    assert _gate(checks, "wrapper_image_digest_approved") is None


def test_gate_passes_for_approved_and_fails_for_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_checks, "image_spec_profile_contract_checks", lambda *a, **k: [])
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT)
    ia.write_image_approval(tmp_path, "openclaw", "wrapper", WRAPPER)
    desired, profile = _desired_profile()

    # matching digests -> gate passes
    checks = runtime_checks.run_static_slot_checks(desired, profile, None, state_root=tmp_path)
    assert _gate(checks, "product_image_digest_approved")[0] is True
    assert _gate(checks, "wrapper_image_digest_approved")[0] is True

    # tamper the product digest -> gate fails (rejects unapproved digest)
    desired.image_spec["product_image"] = OTHER
    checks = runtime_checks.run_static_slot_checks(desired, profile, None, state_root=tmp_path)
    assert _gate(checks, "product_image_digest_approved")[0] is False


def test_gate_skipped_when_no_state_root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_checks, "image_spec_profile_contract_checks", lambda *a, **k: [])
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT)
    desired, profile = _desired_profile()
    checks = runtime_checks.run_static_slot_checks(desired, profile, None)  # no state_root
    assert _gate(checks, "product_image_digest_approved") is None


def test_gate_skipped_for_dev_owned_image_canary(tmp_path, monkeypatch):
    # dev-*-img is customer-class (image-mode fidelity) but dev-OWNED: the production
    # approval gate must NOT apply, so a developer can validate a new build BEFORE root
    # approval (restoring build -> validate -> approve -> promote).
    monkeypatch.setattr(runtime_checks, "image_spec_profile_contract_checks", lambda *a, **k: [])
    ia.write_image_approval(tmp_path, "openclaw", "product", PRODUCT)
    ia.write_image_approval(tmp_path, "openclaw", "wrapper", WRAPPER)
    desired, profile = _desired_profile(slot="dev-oc-img")
    # even an unapproved (mismatched) digest emits no gate check for a dev-owned slot
    desired.image_spec["product_image"] = OTHER
    checks = runtime_checks.run_static_slot_checks(desired, profile, None, state_root=tmp_path)
    assert _gate(checks, "product_image_digest_approved") is None
    assert _gate(checks, "wrapper_image_digest_approved") is None
