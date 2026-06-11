from __future__ import annotations

from typing import Any


def image_plan(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"wrapper_image", "product_image", "target", "targets"})
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        "image-plan",
        "--wrapper-image",
        server._image_ref(args.get("wrapper_image")),
        "--product-image",
        server._image_ref(args.get("product_image")),
    ]
    if args.get("target"):
        argv.extend(["--target", server._slot(args.get("target"))])
    slots = args.get("targets")
    if slots is not None:
        if not isinstance(slots, list) or not slots:
            raise server.tool_error("targets must be a non-empty array")
        argv.append("--targets")
        argv.extend(server._slot(item) for item in slots)
    runs = [server._run(argv, timeout=180)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def image_dev_apply(server, args: dict[str, Any]) -> dict[str, Any]:
    return _image_apply(server, args, command="image-dev-apply")


def image_canary(server, args: dict[str, Any]) -> dict[str, Any]:
    return _image_apply(server, args, command="image-canary")


def _image_apply(server, args: dict[str, Any], *, command: str) -> dict[str, Any]:
    server._reject_unknown(args, {"target", "wrapper_image", "product_image", "allow_first_apply"})
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        command,
        "--target",
        server._slot(args.get("target")),
        "--wrapper-image",
        server._image_ref(args.get("wrapper_image")),
        "--product-image",
        server._image_ref(args.get("product_image")),
    ]
    if bool(args.get("allow_first_apply", False)):
        argv.append("--allow-first-apply")
    runs = [server._run(argv, timeout=900)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)


def image_promote(server, args: dict[str, Any]) -> dict[str, Any]:
    server._reject_unknown(args, {"from_target", "targets"})
    slots = args.get("targets")
    if not isinstance(slots, list) or not slots:
        raise server.tool_error("targets must be a non-empty array")
    slot_values = [server._slot(item) for item in slots]
    argv = [
        server.sudo,
        server.opsctl,
        "rollout",
        "image-promote",
        "--from-target",
        server._slot(args.get("from_target")),
        "--targets",
        ",".join(slot_values),
    ]
    runs = [server._run(argv, timeout=1800)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=True, runs=runs)
