from __future__ import annotations

from typing import Any

from .. import validation as v


def status(server, args: dict[str, Any]) -> dict[str, Any]:
    """List the root-approved image digests (the image trust gate state). Read-only.

    `image approve` itself is a root-only trust action and is intentionally NOT exposed as
    an MCP tool — it is run by an actual root login, like `update approve`.
    """
    v.reject_unknown(args, set(), error_type=server.tool_error)
    runs = [server._run([server.opsctl, "image", "status"], timeout=60)]
    return server._common_response(ok=runs[0]["returncode"] == 0, mutated=False, runs=runs)
