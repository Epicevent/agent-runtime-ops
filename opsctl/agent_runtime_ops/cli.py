from __future__ import annotations

import argparse

from .commands.admin import cmd_admin_create_image_dev, cmd_admin_serve
from .commands.apache import cmd_apache_set_host, cmd_apache_status
from .commands.apply import cmd_apply, cmd_rollback
from .commands.binding import (
    cmd_binding_list,
    cmd_binding_normalize,
    cmd_binding_set_public_host,
    cmd_binding_status,
)
from .commands.blocked import cmd_blocked_mutation
from .commands.check import cmd_check
from .commands.checklist import cmd_checklist_pack
from .commands.diagnostics import cmd_diagnostics_show
from .commands.document_tools import cmd_document_tools_status
from .commands.handoff import (
    cmd_handoff_print,
    cmd_handoff_status,
    cmd_handoff_value_command,
)
from .commands.heartbeat import cmd_heartbeat_disable, cmd_heartbeat_status
from .commands.nas_view import (
    cmd_nas_view_assign,
    cmd_nas_view_detach,
    cmd_nas_view_restore,
    cmd_nas_view_status,
)
from .commands.nas import (
    cmd_nas_approve_auto,
    cmd_nas_credential_set,
    cmd_nas_credential_status,
    cmd_nas_mount,
    cmd_nas_mounted,
    cmd_nas_policy_check,
    cmd_nas_remove,
    cmd_nas_request,
    cmd_nas_requests,
    cmd_nas_unmount,
)
from .commands.profile import cmd_profile_list
from .commands.projection import cmd_projection_compare, cmd_projection_describe, cmd_projection_verify_target
from .commands.recipe import (
    cmd_recipe_capture_dev,
    cmd_recipe_dev_apply,
    cmd_recipe_dev_status,
    cmd_recipe_list_canonical,
    cmd_recipe_validate_canonical,
)
from .commands.rollout import (
    cmd_rollout_image_canary,
    cmd_rollout_image_dev_apply,
    cmd_rollout_image_plan,
    cmd_rollout_image_promote,
    cmd_rollout_status,
)
from .commands.rollout_verify import cmd_rollout_verify
from .commands.mitigation import (
    cmd_mitigation_add,
    cmd_mitigation_check,
    cmd_mitigation_list,
    cmd_mitigation_remove,
)
from .commands.runtime_secret import cmd_runtime_secret_set, cmd_runtime_secret_status
from .commands.runtime_config import cmd_runtime_config_sanitize, cmd_runtime_config_status, cmd_runtime_set_model
from .commands.runtime_truth import cmd_runtime_truth
from .commands.status import cmd_plan, cmd_status
from .commands.update import cmd_self_update, cmd_update_approve, cmd_update_status
from .commands.image import cmd_image_approve, cmd_image_status
from .commands.config import cmd_config_validate, cmd_config_migrate
from .paths import DEFAULT_STATE_ROOT

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)

    self_update = sub.add_parser("self-update")
    self_update.set_defaults(func=cmd_self_update)

    update = sub.add_parser("update")
    update_sub = update.add_subparsers(dest="update_command", required=True)
    update_approve = update_sub.add_parser("approve")
    update_approve.add_argument("ref", help="approved full 40-character commit sha")
    update_approve.set_defaults(func=cmd_update_approve)
    update_status = update_sub.add_parser("status")
    update_status.set_defaults(func=cmd_update_status)

    image = sub.add_parser("image")
    image_sub = image.add_subparsers(dest="image_command", required=True)
    image_approve = image_sub.add_parser("approve", help="root-approve an exact product/wrapper image digest")
    image_approve.add_argument("family", choices=["openclaw", "hermes"])
    image_approve.add_argument("role", choices=["product", "wrapper"])
    image_approve.add_argument("image", metavar="IMAGE@sha256:...", help="digest-pinned image reference")
    image_approve.add_argument("--source-commit", dest="source_commit", default="", help="optional source commit for provenance")
    image_approve.add_argument(
        "--allow-unmerged-source",
        action="store_true",
        help="audited emergency override: approve a source commit not merged to the default branch",
    )
    image_approve.set_defaults(func=cmd_image_approve)
    image_status = image_sub.add_parser("status")
    image_status.set_defaults(func=cmd_image_status)

    config = sub.add_parser("config")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_validate = config_sub.add_parser(
        "validate", help="validate a slot's on-disk config against its target product image (read-only)"
    )
    config_validate.add_argument("slot", metavar="target")
    config_validate.add_argument(
        "--product-image", dest="product_image", default="", help="override target product image (default: slot's current)"
    )
    config_validate.set_defaults(func=cmd_config_validate)
    config_migrate = config_sub.add_parser(
        "migrate", help="migrate a slot's on-disk config via the product's own doctor --fix (atomic, backed up)"
    )
    config_migrate.add_argument("slot", metavar="target")
    config_migrate.add_argument(
        "--product-image", dest="product_image", default="", help="override target product image (default: slot's current)"
    )
    config_migrate.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="preview the change on a throwaway copy and show a diff; write nothing",
    )
    config_migrate.set_defaults(func=cmd_config_migrate)

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list")
    profile_list.set_defaults(func=cmd_profile_list)

    binding = sub.add_parser("binding")
    binding_sub = binding.add_subparsers(dest="binding_command", required=True)
    binding_list = binding_sub.add_parser("list")
    binding_list.set_defaults(func=cmd_binding_list)
    binding_status = binding_sub.add_parser("status")
    binding_status.add_argument("target", nargs="?")
    binding_status.set_defaults(func=cmd_binding_status)
    binding_normalize = binding_sub.add_parser("normalize")
    binding_normalize.add_argument("--write", action="store_true")
    binding_normalize.set_defaults(func=cmd_binding_normalize)
    binding_set_host = binding_sub.add_parser("set-public-host")
    binding_set_host.add_argument("target")
    binding_set_host.add_argument("host")
    binding_set_host.set_defaults(func=cmd_binding_set_public_host)

    apache = sub.add_parser("apache")
    apache_sub = apache.add_subparsers(dest="apache_command", required=True)
    apache_status = apache_sub.add_parser("status")
    apache_status.add_argument("target", nargs="?")
    apache_status.set_defaults(func=cmd_apache_status)
    apache_set_host = apache_sub.add_parser("set-host")
    apache_set_host.add_argument("linux_account")
    apache_set_host.add_argument("host")
    apache_set_host.set_defaults(func=cmd_apache_set_host)

    runtime = sub.add_parser("runtime")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_truth = runtime_sub.add_parser("truth")
    runtime_truth.add_argument("slot", nargs="?", metavar="target")
    runtime_truth.add_argument("--all", action="store_true")
    runtime_truth.set_defaults(func=cmd_runtime_truth)
    runtime_config_status = runtime_sub.add_parser("config-status")
    runtime_config_status.add_argument("slot", metavar="target")
    runtime_config_status.set_defaults(func=cmd_runtime_config_status)
    runtime_set_model = runtime_sub.add_parser("set-model")
    runtime_set_model.add_argument("slot", metavar="target")
    runtime_set_model.add_argument("--provider", required=True)
    runtime_set_model.add_argument("--model", required=True)
    runtime_set_model.set_defaults(func=cmd_runtime_set_model)
    runtime_config_sanitize = runtime_sub.add_parser("config-sanitize")
    runtime_config_sanitize.add_argument("slot", metavar="target")
    sanitize_mode = runtime_config_sanitize.add_mutually_exclusive_group()
    sanitize_mode.add_argument("--dry-run", action="store_true")
    sanitize_mode.add_argument("--apply", action="store_true")
    runtime_config_sanitize.set_defaults(func=cmd_runtime_config_sanitize)

    document_tools = sub.add_parser("document-tools")
    document_tools_sub = document_tools.add_subparsers(dest="document_tools_command", required=True)
    document_tools_status = document_tools_sub.add_parser("status")
    document_tools_status.add_argument("slot", nargs="?", metavar="target")
    document_tools_status.add_argument("--all", action="store_true")
    document_tools_status.set_defaults(func=cmd_document_tools_status)

    for name, func in (("status", cmd_status), ("plan", cmd_plan), ("check", cmd_check)):
        item = sub.add_parser(name)
        item.add_argument("slot", metavar="target")
        if name == "check":
            item.add_argument("--live", action="store_true", help="also inspect Docker and NAS runtime state without writing")
        item.set_defaults(func=func)

    apply = sub.add_parser("apply")
    apply.add_argument("slot", metavar="target")
    apply.add_argument("--allow-first-apply", action="store_true")
    apply.set_defaults(func=cmd_apply)

    rollback = sub.add_parser("rollback")
    rollback.add_argument("slot", metavar="target")
    rollback.set_defaults(func=cmd_rollback)

    diagnostics = sub.add_parser("diagnostics")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command", required=True)
    diagnostics_show = diagnostics_sub.add_parser("show")
    diagnostics_show.add_argument("slot", metavar="target")
    diagnostics_show.add_argument("--dir", help="absolute backup dir or failed-container dir to show")
    diagnostics_show.add_argument("--tail", type=int, default=120)
    diagnostics_show.set_defaults(func=cmd_diagnostics_show)

    rollout = sub.add_parser("rollout", description="Inspect runtime manifests and apply digest-pinned wrapper/product images.")
    rollout_sub = rollout.add_subparsers(dest="rollout_command", required=True)
    rollout_status = rollout_sub.add_parser("status", help="summarize runtime manifests for a product family")
    rollout_status.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_status.set_defaults(func=cmd_rollout_status)
    rollout_image_plan = rollout_sub.add_parser("image-plan", help="validate digest-pinned images without release state")
    rollout_image_plan.add_argument("--wrapper-image", required=True)
    rollout_image_plan.add_argument("--product-image", required=True)
    rollout_image_plan.add_argument("--target", dest="slot")
    rollout_image_plan.add_argument("--targets", dest="slots", nargs="*")
    rollout_image_plan.set_defaults(func=cmd_rollout_image_plan)
    rollout_image_dev_apply = rollout_sub.add_parser("image-dev-apply", help="apply digest-pinned images to a dev target")
    rollout_image_dev_apply.add_argument("--target", dest="slot", required=True)
    rollout_image_dev_apply.add_argument("--wrapper-image", required=True)
    rollout_image_dev_apply.add_argument("--product-image", required=True)
    rollout_image_dev_apply.add_argument("--allow-first-apply", action="store_true")
    rollout_image_dev_apply.set_defaults(func=cmd_rollout_image_dev_apply)
    rollout_image_canary = rollout_sub.add_parser("image-canary", help="apply digest-pinned images to one customer canary target")
    rollout_image_canary.add_argument("--target", dest="slot", required=True)
    rollout_image_canary.add_argument("--wrapper-image", required=True)
    rollout_image_canary.add_argument("--product-image", required=True)
    rollout_image_canary.add_argument("--allow-first-apply", action="store_true")
    rollout_image_canary.set_defaults(func=cmd_rollout_image_canary)
    rollout_image_promote = rollout_sub.add_parser("image-promote", help="promote the exact live canary image to explicit targets")
    rollout_image_promote.add_argument("--from-target", dest="from_slot", required=True)
    rollout_image_promote.add_argument("--targets", dest="slots", required=True, help="comma-separated customer targets to apply")
    rollout_image_promote.set_defaults(func=cmd_rollout_image_promote)
    rollout_verify = rollout_sub.add_parser(
        "verify", help="post-apply verification: live truth + approved-digest gate + runtime checklist pack"
    )
    rollout_verify.add_argument("slot", metavar="target")
    rollout_verify.add_argument(
        "--pack", default=None, choices=["hermes-runtime", "openclaw-runtime"], help="override the family-derived pack"
    )
    rollout_verify.add_argument("--gemini-chat-smoke", action="store_true")
    rollout_verify.set_defaults(func=cmd_rollout_verify)

    recipe = sub.add_parser("recipe")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_list_canonical = recipe_sub.add_parser("list-canonical")
    recipe_list_canonical.set_defaults(func=cmd_recipe_list_canonical)
    recipe_validate_canonical = recipe_sub.add_parser("validate-canonical")
    recipe_validate_canonical.add_argument("name")
    recipe_validate_canonical.add_argument("--emit-build-args", action="store_true")
    recipe_validate_canonical.set_defaults(func=cmd_recipe_validate_canonical)
    recipe_status = recipe_sub.add_parser("status")
    recipe_status.add_argument("slot", metavar="target")
    recipe_status.set_defaults(func=cmd_recipe_dev_status)
    recipe_apply_dev = recipe_sub.add_parser("apply-dev")
    recipe_apply_dev.add_argument("slot", metavar="target")
    recipe_apply_dev.add_argument("--recipe-name")
    source_group = recipe_apply_dev.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source-output")
    source_group.add_argument("--sync-from")
    recipe_apply_dev.add_argument("--git-ref")
    recipe_apply_dev.add_argument("--build-command")
    recipe_apply_dev.add_argument("--allow-first-apply", action="store_true")
    recipe_apply_dev.add_argument("--no-apply", action="store_true")
    recipe_apply_dev.set_defaults(func=cmd_recipe_dev_apply)
    recipe_capture_dev = recipe_sub.add_parser("capture-dev")
    recipe_capture_dev.add_argument("slot", metavar="target")
    recipe_capture_dev.add_argument("--recipe-name", default="hermes-runtime")
    recipe_capture_dev.set_defaults(func=cmd_recipe_capture_dev)

    runtime_secret = sub.add_parser("runtime-secret")
    runtime_secret_sub = runtime_secret.add_subparsers(dest="runtime_secret_command", required=True)
    runtime_secret_set = runtime_secret_sub.add_parser("set")
    runtime_secret_set.add_argument("slot", metavar="target")
    runtime_secret_set.add_argument("--env-file")
    runtime_secret_set.add_argument("--key")
    runtime_secret_set.add_argument("--value-stdin", action="store_true")
    runtime_secret_set.add_argument("--no-restart", action="store_true")
    runtime_secret_set.add_argument("--check", action="store_true")
    runtime_secret_set.add_argument(
        "--unsafe-service-recreate",
        action="store_true",
        help="bypass full apply/live check and recreate only the service; emergency use only",
    )
    runtime_secret_set.set_defaults(func=cmd_runtime_secret_set)
    runtime_secret_status = runtime_secret_sub.add_parser("status")
    runtime_secret_status.add_argument("slot", metavar="target")
    runtime_secret_status.set_defaults(func=cmd_runtime_secret_status)

    handoff = sub.add_parser("handoff")
    handoff_sub = handoff.add_subparsers(dest="handoff_command", required=True)
    handoff_status = handoff_sub.add_parser("status")
    handoff_status.add_argument("slot", metavar="target")
    handoff_status.set_defaults(func=cmd_handoff_status)
    handoff_value_command = handoff_sub.add_parser("value-command")
    handoff_value_command.add_argument("slot", metavar="target")
    handoff_value_command.set_defaults(func=cmd_handoff_value_command)
    handoff_print = handoff_sub.add_parser("print")
    handoff_print.add_argument("slot", metavar="target")
    handoff_print.set_defaults(func=cmd_handoff_print)

    heartbeat = sub.add_parser("heartbeat")
    heartbeat_sub = heartbeat.add_subparsers(dest="heartbeat_command", required=True)
    heartbeat_status = heartbeat_sub.add_parser("status")
    heartbeat_status.add_argument("slot", metavar="target")
    heartbeat_status.set_defaults(func=cmd_heartbeat_status)
    heartbeat_disable = heartbeat_sub.add_parser("disable")
    heartbeat_disable.add_argument("slot", metavar="target")
    heartbeat_disable.set_defaults(func=cmd_heartbeat_disable)

    nas = sub.add_parser("nas")
    nas_sub = nas.add_subparsers(dest="nas_command", required=True)
    nas_requests = nas_sub.add_parser("requests")
    nas_requests.set_defaults(func=cmd_nas_requests)
    nas_auto = nas_sub.add_parser("approve-auto")
    nas_auto.add_argument("--watch", action="store_true")
    nas_auto.add_argument("--interval", type=int, default=15)
    nas_auto.set_defaults(func=cmd_nas_approve_auto)
    nas_request = nas_sub.add_parser("request")
    nas_request.add_argument("share")
    nas_request.set_defaults(func=cmd_nas_request)
    nas_credential = nas_sub.add_parser("credential")
    nas_credential_sub = nas_credential.add_subparsers(dest="credential_command", required=True)
    nas_credential_set = nas_credential_sub.add_parser("set")
    nas_credential_set.add_argument("share")
    nas_credential_set.add_argument("--username", required=True)
    nas_credential_set.add_argument("--password-stdin", action="store_true", required=True)
    nas_credential_set.add_argument("--domain")
    nas_credential_set.set_defaults(func=cmd_nas_credential_set)
    nas_credential_status = nas_credential_sub.add_parser("status")
    nas_credential_status.add_argument("slot", metavar="target")
    nas_credential_status.add_argument("share")
    nas_credential_status.set_defaults(func=cmd_nas_credential_status)
    nas_mounted = nas_sub.add_parser("mounted")
    nas_mounted.add_argument("slot", metavar="target")
    nas_mounted.set_defaults(func=cmd_nas_mounted)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot", metavar="target")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)
    nas_mount = nas_sub.add_parser("mount")
    nas_mount.add_argument("slot", metavar="target")
    nas_mount.add_argument("share")
    nas_mount.add_argument("--username")
    nas_mount.add_argument("--password-stdin", action="store_true")
    nas_mount.add_argument("--domain")
    nas_mount.add_argument("--keep-fstab-on-failure", action="store_true")
    nas_mount.set_defaults(func=cmd_nas_mount)
    nas_unmount = nas_sub.add_parser("unmount")
    nas_unmount.add_argument("slot", metavar="target")
    nas_unmount.add_argument("share")
    nas_unmount.add_argument("--lazy", action="store_true")
    nas_unmount.add_argument("--delete-empty-dir", action="store_true")
    nas_unmount.set_defaults(func=cmd_nas_unmount)
    nas_remove = nas_sub.add_parser("remove")
    nas_remove.add_argument("slot", metavar="target")
    nas_remove.add_argument("share")
    nas_remove.add_argument("--lazy", action="store_true")
    nas_remove.add_argument("--delete-empty-dir", action="store_true")
    nas_remove.set_defaults(func=cmd_nas_remove)
    nas_view = nas_sub.add_parser("view")
    nas_view_sub = nas_view.add_subparsers(dest="view_command", required=True)
    nas_view_assign = nas_view_sub.add_parser("assign")
    nas_view_assign.add_argument("slot", metavar="target")
    nas_view_assign.add_argument("user_id")
    nas_view_assign.add_argument("--share", required=True)
    nas_view_assign.add_argument("--username")
    nas_view_assign.add_argument("--password-stdin", action="store_true")
    nas_view_assign.add_argument("--domain")
    nas_view_assign.set_defaults(func=cmd_nas_view_assign)
    nas_view_detach = nas_view_sub.add_parser("detach")
    nas_view_detach.add_argument("slot", metavar="target")
    nas_view_detach.add_argument("--share")
    nas_view_detach.set_defaults(func=cmd_nas_view_detach)
    nas_view_status = nas_view_sub.add_parser("status")
    nas_view_status.set_defaults(func=cmd_nas_view_status)
    nas_view_restore = nas_view_sub.add_parser("restore")
    nas_view_restore.add_argument(
        "--nas-wait-seconds",
        type=float,
        default=600.0,
        help="bounded wait for the NAS to answer SMB before restoring (0 = single probe, no wait)",
    )
    nas_view_restore.set_defaults(func=cmd_nas_view_restore)

    admin = sub.add_parser("admin")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    serve = admin_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=18088, type=int)
    serve.set_defaults(func=cmd_admin_serve)
    create_image_dev = admin_sub.add_parser("create-image-dev")
    create_image_dev.add_argument("target")
    create_image_dev.add_argument("--public-host", required=True)
    create_image_dev.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    create_image_dev.add_argument("--gateway-port", required=True, type=int)
    create_image_dev.add_argument("--bridge-port", required=True, type=int)
    create_image_dev.add_argument("--instance-id")
    create_image_dev.add_argument("--clone-config-from")
    create_image_dev.add_argument("--clone-provider-secrets-from")
    create_image_dev.set_defaults(func=cmd_admin_create_image_dev)

    projection = sub.add_parser("projection")
    projection_sub = projection.add_subparsers(dest="projection_command", required=True)
    projection_describe = projection_sub.add_parser("describe")
    projection_describe.add_argument("slot", metavar="target")
    projection_describe.add_argument("--live", action="store_true")
    projection_describe.set_defaults(func=cmd_projection_describe)
    projection_compare = projection_sub.add_parser("compare")
    projection_compare.add_argument("--from-target", dest="from_slot", required=True)
    projection_compare.add_argument("--to-target", dest="to_slot", required=True)
    projection_compare.set_defaults(func=cmd_projection_compare)
    projection_verify = projection_sub.add_parser("verify-target")
    projection_verify.add_argument("slot", metavar="target")
    projection_verify.add_argument("--wrapper-image", required=True)
    projection_verify.add_argument("--product-image", required=True)
    projection_verify.add_argument("--live", action="store_true")
    projection_verify.set_defaults(func=cmd_projection_verify_target)

    mitigation = sub.add_parser("mitigation", help="register of temporary workarounds with machine-checked expiry")
    mitigation_sub = mitigation.add_subparsers(dest="mitigation_command", required=True)
    mitigation_add = mitigation_sub.add_parser("add", help="record a temporary mitigation with its removal condition")
    mitigation_add.add_argument("mitigation_id", metavar="id")
    mitigation_add.add_argument("--slot", dest="slots", action="append", required=True, help="repeatable")
    mitigation_add.add_argument("--kind", choices=["env"], default="env")
    mitigation_add.add_argument("--env-key", required=True, help="env var name (presence-only; values are never read)")
    mitigation_add.add_argument("--reason", required=True)
    mitigation_add.add_argument(
        "--expires-product-version",
        required=True,
        help="the mitigation is obsolete once the slot runs at least this product version",
    )
    mitigation_add.set_defaults(func=cmd_mitigation_add)
    mitigation_list = mitigation_sub.add_parser("list")
    mitigation_list.set_defaults(func=cmd_mitigation_list)
    mitigation_check = mitigation_sub.add_parser(
        "check", help="probe live slots: active / cleared / expired-but-still-present"
    )
    mitigation_check.add_argument("--target", dest="slot", default=None)
    mitigation_check.set_defaults(func=cmd_mitigation_check)
    mitigation_remove = mitigation_sub.add_parser("remove", help="retire a cleared register entry")
    mitigation_remove.add_argument("mitigation_id", metavar="id")
    mitigation_remove.set_defaults(func=cmd_mitigation_remove)

    checklist = sub.add_parser("checklist")
    checklist_sub = checklist.add_subparsers(dest="checklist_command", required=True)
    checklist_pack = checklist_sub.add_parser("pack")
    checklist_pack.add_argument("slot", metavar="target")
    checklist_pack.add_argument("--pack", default="hermes-runtime", choices=["hermes-runtime", "openclaw-runtime"])
    checklist_pack.add_argument("--gemini-chat-smoke", action="store_true")
    checklist_pack.set_defaults(func=cmd_checklist_pack)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
