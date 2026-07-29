from __future__ import annotations

import argparse
import sys

from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.image_approval_policy import is_image_ref_approved
from ..domain.image_specs import digest_from_image_ref
from ..domain.model_roundtrip import run_model_roundtrip_probe
from ..domain.retrieval_contract import (
    retrieval_contract_is_approved,
    run_retrieval_status_probe,
)
from ..domain.runtime_targets import desired_from_live_image_truth
from ..domain.runtime_truth import find_gateway_container_by_binding, live_runtime_truth
from ..routing import get_runtime_binding
from .checklist import cmd_checklist_pack
from .rollout import _authorize_deploy_target

# Engraved replacement for the hand-run post-apply sequence
# (runtime truth -> approved-digest gate -> runtime checklist pack).
# One command, one verdict line: rollout_verify_status=pass|fail.


def cmd_rollout_verify(args: argparse.Namespace) -> int:
    if not _is_root():
        print(
            "error: run as root/admin: sudo /usr/local/bin/opsctl rollout verify TARGET",
            file=sys.stderr,
        )
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    # verify runs the checklist inside the target container, so it inherits the same
    # boundary as deploys: dev accounts may only verify their own dev-* slots.
    denial = _authorize_deploy_target("rollout verify", slot)
    if denial:
        print("rollout_verify_status=fail")
        print(f"reason={denial}")
        return 2
    ok = True
    try:
        truth, truth_checks = live_runtime_truth(slot, state_root)
        for key, value in truth.items():
            print(f"{key}={value}")
        for check_ok, name, detail in truth_checks:
            _check_line(check_ok, name, detail)
            ok = ok and check_ok
        if truth.get("truth_status") != "ok":
            ok = False

        family = str(truth.get("family") or "")
        if slot.startswith("dev-"):
            # dev-* is the environment boundary: no root-approval gate applies there.
            _check_line(True, "verify_approval_gate", "dev-target-exempt")
        else:
            for role in ("product", "wrapper"):
                image_ref = truth.get(f"{role}_image")
                approved = is_image_ref_approved(state_root, family, role, image_ref)
                _check_line(approved, f"verify_{role}_digest_approved", str(image_ref))
                ok = ok and approved

        if truth.get("retrieval_labels_present") == "true":
            desired, _ = desired_from_live_image_truth(slot, state_root)
            retrieval_contract = desired.image_spec.get("retrieval_contract")
            if not isinstance(retrieval_contract, dict):
                raise ValueError("retrieval capability label is present but contract is invalid")
            resource = retrieval_contract.get("resource")
            expected_resource = (
                str(resource.get("profileDigest") or "")
                if isinstance(resource, dict)
                else ""
            )
            retrieval_checks = (
                (
                    truth.get("retrieval_component_digest")
                    == desired.image_spec.get("retrieval_component_digest"),
                    "verify_retrieval_component_digest_matches",
                    str(truth.get("retrieval_component_digest") or "missing"),
                ),
                (
                    truth.get("retrieval_binding_digest")
                    == desired.image_spec.get("retrieval_binding_digest"),
                    "verify_retrieval_binding_digest_matches",
                    str(truth.get("retrieval_binding_digest") or "missing"),
                ),
                (
                    truth.get("retrieval_resource_profile_digest") == expected_resource,
                    "verify_retrieval_resource_profile_digest_matches",
                    str(truth.get("retrieval_resource_profile_digest") or "missing"),
                ),
            )
            for check_ok, name, detail in retrieval_checks:
                _check_line(check_ok, name, detail)
                ok = ok and check_ok
            if desired.image_spec.get("retrieval_enabled") is True and not slot.startswith("dev-"):
                product_digest = digest_from_image_ref(truth.get("product_image")) or ""
                approved = retrieval_contract_is_approved(
                    state_root,
                    family,
                    retrieval_contract,
                    product_image_digest=product_digest,
                )
                _check_line(
                    approved,
                    "verify_retrieval_component_approved",
                    str(retrieval_contract.get("component_digest") or "missing"),
                )
                ok = ok and approved
            binding = get_runtime_binding(slot, state_root)
            container, lookup = find_gateway_container_by_binding(binding)
            if not container:
                _check_line(False, "verify_retrieval_probe_container", str(lookup))
                ok = False
            else:
                status = run_retrieval_status_probe(container, desired.image_spec)
                if status is None:
                    raise ValueError("retrieval capability declared but verifier was unavailable")
                for key in sorted(status):
                    print(f"retrieval_{key}={status[key]}")
                _check_line(True, "verify_retrieval_status", str(status.get("consumerHealth")))
        elif (
            truth.get("retrieval_projection_labels_present") == "true"
            and truth.get("retrieval_projection_consistent") != "true"
        ):
            _check_line(False, "verify_retrieval_status", "invalid-runtime-projection")
            ok = False
        else:
            _check_line(True, "verify_retrieval_status", "capability-absent")

        pack = getattr(args, "pack", None) or f"{family}-runtime"
        pack_args = argparse.Namespace(
            slot=slot,
            pack=pack,
            gemini_chat_smoke=bool(getattr(args, "gemini_chat_smoke", False)),
            state_root=args.state_root,
        )
        ok = cmd_checklist_pack(pack_args) == 0 and ok

        # Customer round-trip: prove the configured model actually answers before
        # this deploy is blessed. The one thing an oc1-style green-but-down hides
        # (429/expired/blocked key passes every other check). hermes-only —
        # openclaw attests its round-trip inside its own selftest contract — and
        # deploy-gate only (one completion per verify), skippable with
        # --skip-model-probe.
        if family == "hermes" and not getattr(args, "skip_model_probe", False):
            binding = get_runtime_binding(slot, state_root)
            container, lookup = find_gateway_container_by_binding(binding)
            if not container:
                _check_line(False, "verify_model_roundtrip_ok", f"container_lookup_failed {lookup}")
                ok = False
            else:
                probe_ok, detail = run_model_roundtrip_probe(
                    container, timeout=int(getattr(args, "model_probe_timeout", 90) or 90)
                )
                _check_line(probe_ok, "verify_model_roundtrip_ok", detail)
                ok = ok and probe_ok
    except Exception as exc:
        print(f"target={slot}")
        print("rollout_verify_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"rollout_verify_status={'pass' if ok else 'fail'}")
    return 0 if ok else 1
