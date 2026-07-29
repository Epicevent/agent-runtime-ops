from __future__ import annotations

from typing import Any

from .. import validation as v


def image_plan(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(
        args,
        {
            "wrapper_image",
            "product_image",
            "target",
            "targets",
            "retrieval_enabled",
        },
        error_type=server.tool_error,
    )
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        "image-plan",
        "--wrapper-image",
        v.image_ref(args.get("wrapper_image"), error_type=server.tool_error),
        "--product-image",
        v.image_ref(args.get("product_image"), error_type=server.tool_error),
    ]
    if args.get("target"):
        argv.extend(["--target", v.linux_account(args.get("target"), error_type=server.tool_error)])
    slots = args.get("targets")
    if slots is not None:
        if not isinstance(slots, list) or not slots:
            raise server.tool_error("targets must be a non-empty array")
        argv.append("--targets")
        argv.extend(v.linux_account(item, error_type=server.tool_error) for item in slots)
    if v.boolean_arg(
        args,
        "retrieval_enabled",
        default=False,
        error_type=server.tool_error,
    ):
        argv.append("--retrieval-enabled")
    runs = [server._run(argv, timeout=180)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def image_dev_apply(server, args: dict[str, Any]) -> dict[str, Any]:
    return _image_apply(server, args, command="image-dev-apply")


def image_canary(server, args: dict[str, Any]) -> dict[str, Any]:
    return _image_apply(server, args, command="image-canary")


def _image_apply(server, args: dict[str, Any], *, command: str) -> dict[str, Any]:
    v.reject_unknown(
        args,
        {
            "target",
            "wrapper_image",
            "product_image",
            "allow_first_apply",
            "retrieval_enabled",
        },
        error_type=server.tool_error,
    )
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        command,
        "--target",
        v.linux_account(args.get("target"), error_type=server.tool_error),
        "--wrapper-image",
        v.image_ref(args.get("wrapper_image"), error_type=server.tool_error),
        "--product-image",
        v.image_ref(args.get("product_image"), error_type=server.tool_error),
    ]
    if bool(args.get("allow_first_apply", False)):
        argv.append("--allow-first-apply")
    if v.boolean_arg(
        args,
        "retrieval_enabled",
        default=False,
        error_type=server.tool_error,
    ):
        argv.append("--retrieval-enabled")
    runs = [server._run(argv, timeout=900)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)


def image_promote(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"from_target", "targets"}, error_type=server.tool_error)
    slots = args.get("targets")
    if not isinstance(slots, list) or not slots:
        raise server.tool_error("targets must be a non-empty array")
    slot_values = [v.linux_account(item, error_type=server.tool_error) for item in slots]
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        "image-promote",
        "--from-target",
        v.linux_account(args.get("from_target"), error_type=server.tool_error),
        "--targets",
        ",".join(slot_values),
    ]
    runs = [server._run(argv, timeout=1800)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)


def projection_verify_target(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "wrapper_image", "product_image", "live"}, error_type=server.tool_error)
    argv = [
        server.sudo,
        server.opsctl,
        "projection",
        "verify-target",
        v.linux_account(args.get("target"), error_type=server.tool_error),
        "--wrapper-image",
        v.image_ref(args.get("wrapper_image"), error_type=server.tool_error),
        "--product-image",
        v.image_ref(args.get("product_image"), error_type=server.tool_error),
    ]
    if bool(args.get("live", True)):
        argv.append("--live")
    runs = [server._run(argv, timeout=300)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def checklist_pack(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"target", "pack", "gemini_chat_smoke"}, error_type=server.tool_error)
    pack = str(args.get("pack") or "")
    if pack not in {"hermes-runtime", "openclaw-runtime"}:
        raise server.tool_error("pack must be hermes-runtime or openclaw-runtime")
    argv = [
        server.sudo,
        server.opsctl,
        "checklist",
        "pack",
        v.linux_account(args.get("target"), error_type=server.tool_error),
        "--pack",
        pack,
    ]
    if bool(args.get("gemini_chat_smoke", False)):
        argv.append("--gemini-chat-smoke")
    runs = [server._run(argv, timeout=300)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)
