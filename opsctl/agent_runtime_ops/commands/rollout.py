from __future__ import annotations

import argparse
import json
import sys

from ..canonical_recipes import canonical_recipe_for_image_spec, canonical_recipe_identity
from ..domain.actions import append_action_log as _append_action_log
from ..domain.common import check_line as _check_line
from ..domain.common import apache_public_host as _apache_public_host
from ..domain.common import is_dev_slot as _is_dev_slot
from ..domain.common import is_root as _is_root
from ..domain.common import sudo_user as _sudo_user
from ..domain.common import OPERATOR_ACCOUNTS as _OPERATOR_ACCOUNTS
from ..domain.common import state_root as _state_root
from ..domain.image_specs import (
    IMAGE_ROLLOUT_IMAGE_NAME,
    image_spec_from_direct_images,
    image_spec_recipe_payload,
    profile_runtime_contract,
)
from ..domain.dev_recipe_runtime import ensure_dev_runtime_dir as _ensure_runtime_dir
from ..domain.dev_recipe_runtime import upsert_runtime_env_file as _upsert_runtime_env_file
from ..domain.runtime_apply import apply_desired_slot as _apply_desired_slot
from ..domain.runtime_backup import pending_rollback_backup as _pending_rollback_backup
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_checks import run_static_slot_checks as _run_static_slot_checks
from ..domain.runtime_rollup import runtime_manifest_rollup
from ..domain.runtime_targets import (
    desired_from_direct_images as _desired_from_direct_images,
    desired_from_live_image_truth as _desired_from_live_image_truth,
)
from ..renderer import render_compose
from ..host.account_files import slot_uid_gid
from ..routing import get_runtime_binding, load_runtime_bindings
from ..runtime_secrets import parse_secret_env_text, primary_profile_secret_file


def _is_dev_named_target(slot: str) -> bool:
    return _is_dev_slot(slot)


def _authorize_deploy_target(action_name: str, slot: str) -> str | None:
    """Scope a developer's deploy to their own dev-* slots.

    sudoers cannot scope by `--target` value, so the boundary is enforced here: an
    operator account (root/svcops) may deploy any slot; any other account that reached
    this command (via a scoped dev sudoers grant) may only deploy dev-* slots. Returns an
    error message when the deploy must be refused, else None.
    """
    invoker = _sudo_user()
    if invoker and invoker not in _OPERATOR_ACCOUNTS and not _is_dev_slot(slot):
        return (
            f"{action_name}: account {invoker} may only deploy dev-* slots, not {slot} "
            f"(production deploys are operator/root-only)"
        )
    return None


def cmd_rollout_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        family = str(args.family)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        bindings = [binding for binding in load_runtime_bindings(state_root) if binding.enabled and binding.family == family]
        runtime_slots = [binding.linux_account for binding in bindings]
        runtime_rollup = runtime_manifest_rollup(state_root, runtime_slots, family)
    except Exception as exc:
        print("rollout_status=fail")
        print(f"reason={exc}")
        return 1
    print("rollout_status=ok")
    print("status_source=runtime_manifests")
    print(f"family={family}")
    print(f"binding_targets={','.join(runtime_slots)}")
    print(f"runtime_manifest_count={runtime_rollup['count']}")
    print(f"runtime_manifest_targets={','.join(runtime_rollup['targets'])}")
    print(f"runtime_manifest_customer_targets={','.join(runtime_rollup['customer_targets'])}")
    print(f"runtime_manifest_dev_targets={','.join(runtime_rollup['dev_targets'])}")
    print(f"runtime_manifest_direct_image_targets={','.join(runtime_rollup['direct_targets'])}")
    print(f"runtime_manifest_missing_targets={','.join(runtime_rollup['missing_targets'])}")
    print(f"runtime_manifest_wrapper_images={','.join(runtime_rollup['wrapper_images'])}")
    print(f"runtime_manifest_product_images={','.join(runtime_rollup['product_images'])}")
    print(f"runtime_manifest_canonical_recipe_names={','.join(runtime_rollup['canonical_recipe_names'])}")
    print(f"runtime_manifest_canonical_recipe_digests={','.join(runtime_rollup['canonical_recipe_digests'])}")
    return 0


def _image_spec_canonical_record(image_spec: dict) -> dict[str, str]:
    return canonical_recipe_identity(canonical_recipe_for_image_spec(image_spec))


def _direct_image_spec_from_args(args: argparse.Namespace) -> dict[str, object]:
    return image_spec_from_direct_images(str(args.wrapper_image), str(args.product_image))


def _prepare_runtime_env_for_direct_image(desired, profile) -> None:
    runtime_dir = _ensure_runtime_dir(desired.slot)
    uid, gid = slot_uid_gid(desired.slot)
    updates = {
        "OPENCLAW_RUNTIME_FAMILY": str(desired.family or ""),
        "OPENCLAW_IMAGE": str(desired.image_spec.get("wrapper_image") or ""),
        "OPENCLAW_GATEWAY_PORT": str(desired.route.gateway_port if desired.route else ""),
        "OPENCLAW_BRIDGE_PORT": str(desired.route.bridge_port if desired.route else ""),
    }
    secret_file = primary_profile_secret_file(profile, desired.slot)
    if secret_file.path.exists():
        if secret_file.path.is_symlink() or not secret_file.path.is_file():
            raise ValueError(f"unsafe runtime secret file: {secret_file.path}")
        values = parse_secret_env_text(
            secret_file.path.read_text(encoding="utf-8", errors="replace"),
            source=str(secret_file.path),
        )
        if values.get("API_SERVER_KEY"):
            updates["API_SERVER_KEY"] = values["API_SERVER_KEY"]
    _upsert_runtime_env_file(
        runtime_dir / ".env",
        updates,
        uid,
        gid,
    )


def _prepare_direct_image_runtime(desired, profile) -> None:
    _prepare_runtime_env_for_direct_image(desired, profile)


def cmd_rollout_image_plan(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        image_spec = _direct_image_spec_from_args(args)
        slots = [str(item) for item in (getattr(args, "slots", None) or [])]
        if getattr(args, "slot", None):
            slots.append(str(args.slot))
        if not slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        plans = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            rendered = render_compose(profile, desired)
            checks = [
                {"ok": ok, "name": name, "detail": detail}
                for ok, name, detail in _run_static_slot_checks(desired, profile, rendered, state_root=state_root)
            ]
            plans.append(
                {
                    "linux_account": desired.slot,
                    "runtime_class": desired.runtime_class,
                    "public_host": _apache_public_host(slot),
                    "gateway_port": desired.route.gateway_port if desired.route else "",
                    "bridge_port": desired.route.bridge_port if desired.route else "",
                    "runtime_profile": profile.name,
                    "runtime_contract": profile_runtime_contract(profile),
                    "checks": checks,
                    "compatible": all(item["ok"] for item in checks),
                    "compose_sha256": rendered.sha256,
                }
            )
        payload = {
            "rollout_image_plan_status": "ok",
            "truth_source": "wrapper_image_labels",
            "family": image_spec.get("family"),
            "wrapper_image": image_spec.get("wrapper_image"),
            "product_image": image_spec.get("product_image"),
            "recipe": image_spec_recipe_payload(image_spec),
            "targets": plans,
            "mutates": False,
        }
    except Exception as exc:
        print(json.dumps({"rollout_image_plan_status": "fail", "reason": str(exc), "mutates": False}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_rollout_image_apply_slot(args: argparse.Namespace, *, required_runtime_class: str, action_name: str) -> int:
    if not _is_root():
        print(f"error: run as root/admin: sudo /usr/local/bin/opsctl rollout {action_name} ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    denial = _authorize_deploy_target(action_name, slot)
    if denial:
        print(f"error: {denial}", file=sys.stderr)
        return 2
    try:
        image_spec = _direct_image_spec_from_args(args)
        desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
        if desired.runtime_class != required_runtime_class:
            raise ValueError(f"{action_name} requires runtime_class={required_runtime_class}: {slot}")
        _ensure_runtime_dir(desired.slot)
    except Exception as exc:
        print(f"rollout_{action_name.replace('-', '_')}_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, f"rollout_{action_name}", slot, IMAGE_ROLLOUT_IMAGE_NAME, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"rollout_{action_name.replace('-', '_')}_state=direct_image")
    print(f"target={slot}")
    print(f"family={desired.family}")
    print(f"runtime_profile={profile.name}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    for key, value in _image_spec_canonical_record(image_spec).items():
        print(f"{key}={value}")
    rc = _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(getattr(args, "allow_first_apply", False)),
        action_name=f"rollout_{action_name}",
        prepare_runtime_env=lambda: _prepare_direct_image_runtime(desired, profile),
    )
    if rc == 0:
        print(f"rollout_{action_name.replace('-', '_')}_status=ok")
    return rc


def cmd_rollout_image_dev_apply(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="dev", action_name="image-dev-apply")


def cmd_rollout_image_canary(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="customer", action_name="image-canary")


def cmd_rollout_image_promote(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout image-promote ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    from_slot = str(args.from_slot)
    try:
        if _is_dev_named_target(from_slot):
            raise ValueError(f"image-promote source must not be a dev target: {from_slot}")
        source_desired, source_profile = _desired_from_live_image_truth(from_slot, state_root)
        if source_desired.runtime_class != "customer":
            raise ValueError(f"image-promote source must be a customer target: {from_slot}")
        print("phase=projection_gate")
        rendered = render_compose(source_profile, source_desired)
        projection_failed = 0
        for ok, name, detail in _run_static_slot_checks(source_desired, source_profile, rendered, state_root=state_root):
            _check_line(ok, name, detail)
            if not ok:
                projection_failed += 1
        _check_line(bool(rendered.text.strip()), "projection_compose_rendered", rendered.sha256)
        if not rendered.text.strip():
            projection_failed += 1
        if projection_failed:
            raise ValueError(f"projection gate failed: failed={projection_failed}")
        print("phase=checklist_gate")
        checklist_failed = 0
        for ok, name, detail in _run_live_slot_checks(source_desired, source_profile, state_root):
            _check_line(ok, name, detail)
            if not ok:
                checklist_failed += 1
        if checklist_failed:
            raise ValueError(f"checklist gate failed: failed={checklist_failed}")
        slots = [item.strip() for item in str(args.slots).split(",") if item.strip()]
        if not slots:
            raise ValueError("--targets must name the promotion targets explicitly")
        for slot in slots:
            if _is_dev_named_target(slot):
                raise ValueError(
                    f"image-promote target must not be a dev target: {slot}"
                )
        source_binding = get_runtime_binding(from_slot, state_root)
        if _is_dev_named_target(source_binding.linux_account):
            raise ValueError(
                "image-promote source must not be a dev target: "
                f"{source_binding.linux_account}"
            )
        if source_binding != source_desired.route:
            raise ValueError("image-promote source binding changed during validation")
        target_bindings = [get_runtime_binding(slot, state_root) for slot in slots]
        for binding in target_bindings:
            if _is_dev_named_target(binding.linux_account):
                raise ValueError(
                    "image-promote target must not be a dev target: "
                    f"{binding.linux_account}"
                )
            if binding.runtime_class != "customer":
                raise ValueError(
                    "promotion target is not a customer target: "
                    f"{binding.linux_account}"
                )
            if binding.family != source_binding.family:
                raise ValueError(
                    "promotion target family does not match source: "
                    f"target={binding.linux_account} "
                    f"target_family={binding.family} "
                    f"source_family={source_binding.family}"
                )
        target_instance_ids = [binding.instance_id for binding in target_bindings]
        if len(set(target_instance_ids)) != len(target_instance_ids):
            raise ValueError("image-promote targets must be unique")
        if source_binding.instance_id in target_instance_ids:
            raise ValueError("image-promote source must not also be a target")
        slots = [binding.linux_account for binding in target_bindings]
        wrapper_image = str(source_desired.image_spec.get("wrapper_image") or "")
        product_image = str(source_desired.image_spec.get("product_image") or "")
        image_spec = image_spec_from_direct_images(wrapper_image, product_image)
        target_plans = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            if desired.runtime_class != "customer":
                raise ValueError(f"promotion target is not a customer target: {slot}")
            target_plans.append((slot, desired, profile))
        for slot, desired, profile in target_plans:
            _ensure_runtime_dir(
                slot,
                create=False,
                state_root=state_root,
                require_existing_manifest=True,
            )
            pending_backup = _pending_rollback_backup(state_root, slot)
            if pending_backup is not None:
                raise ValueError(
                    "promotion target has a pending rollback transaction: "
                    f"target={slot} backup={pending_backup.name}"
                )
            target_rendered = render_compose(profile, desired)
            target_projection_failed = 0
            for ok, name, detail in _run_static_slot_checks(
                desired,
                profile,
                target_rendered,
                state_root=state_root,
            ):
                _check_line(ok, f"target_{slot}_{name}", detail)
                if not ok:
                    target_projection_failed += 1
            if not target_rendered.text.strip():
                target_projection_failed += 1
            if target_projection_failed:
                raise ValueError(
                    "promotion target projection gate failed: "
                    f"target={slot} failed={target_projection_failed}"
                )
        applied: list[str] = []
        for slot, desired, profile in target_plans:
            if _is_dev_named_target(slot):
                raise ValueError(f"image-promote target must not be a dev target: {slot}")
            if desired.runtime_class != "customer":
                raise ValueError(f"promotion target is not a customer target: {slot}")

            def verify_target_before_apply(*, target: str = slot) -> None:
                _ensure_runtime_dir(
                    target,
                    create=False,
                    state_root=state_root,
                    require_existing_manifest=True,
                )
                pending_backup = _pending_rollback_backup(state_root, target)
                if pending_backup is not None:
                    raise ValueError(
                        "promotion target has a pending rollback transaction: "
                        f"target={target} backup={pending_backup.name}"
                    )
                refreshed_source, _ = _desired_from_live_image_truth(
                    source_desired.route.instance_id,
                    state_root,
                )
                if refreshed_source != source_desired:
                    raise ValueError(
                        "promotion source live tuple changed during promotion"
                    )

            rc = _apply_desired_slot(
                desired=desired,
                profile=profile,
                state_root=state_root,
                allow_first_apply=False,
                action_name="rollout_image_promote",
                prepare_runtime_env=lambda desired=desired, profile=profile: (
                    _prepare_runtime_env_for_direct_image(desired, profile)
                ),
                pre_apply_admission=verify_target_before_apply,
            )
            if rc != 0:
                print("rollout_image_promote_status=partial")
                print(f"failed_target={slot}")
                _append_action_log(state_root, "rollout_image_promote", slot, wrapper_image, "partial", "slot_apply_failed")
                return rc or 1
            applied.append(slot)
    except Exception as exc:
        print("rollout_image_promote_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_image_promote", from_slot, from_slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print("rollout_image_promote_status=ok")
    print(f"from_target={from_slot}")
    print(f"targets={','.join(applied)}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    _append_action_log(
        state_root,
        "rollout_image_promote",
        from_slot,
        str(image_spec.get("wrapper_image") or ""),
        "ok",
        f"targets={len(applied)}",
    )
    return 0
