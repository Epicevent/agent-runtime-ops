from __future__ import annotations

from typing import Any

from .. import validation as v


def _argv(server, args: dict[str, Any], command: str) -> list[str]:
    argv = [
        server.sudo,
        server.opsctl,
        "config",
        command,
        v.linux_account(args.get("target"), error_type=server.tool_error),
    ]
    product_image = args.get("product_image")
    if product_image:
        argv += ["--product-image", v.image_ref(product_image, error_type=server.tool_error)]
    return argv


def validate(server, args: dict[str, Any]) -> dict[str, Any]:
    """Validate a slot's on-disk config against its target product image (read-only)."""
    v.reject_unknown(args, {"target", "product_image"}, error_type=server.tool_error)
    runs = [server._run(_argv(server, args, "validate"), timeout=120)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)


def migrate(server, args: dict[str, Any]) -> dict[str, Any]:
    """Migrate a slot's on-disk config via the product's own doctor --fix (atomic, backed up).

    With ``dry_run: true`` it previews the change on a throwaway copy and returns a diff,
    writing nothing — so an operator can review exactly what will change before applying.
    """
    v.reject_unknown(args, {"target", "product_image", "dry_run"}, error_type=server.tool_error)
    argv = _argv(server, args, "migrate")
    dry_run = bool(args.get("dry_run"))
    if dry_run:
        argv.append("--dry-run")
    runs = [server._run(argv, timeout=300)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=not dry_run, runs=runs)
