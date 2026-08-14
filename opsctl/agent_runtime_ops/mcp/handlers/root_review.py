from __future__ import annotations

import math
from typing import Any

from ...root_review import RootReviewError, RootReviewStore
from .. import validation as v


def _store(server) -> RootReviewStore:
    factory = getattr(server, "root_review_store_factory", None)
    return factory() if factory is not None else RootReviewStore.current()


def _bounded_number(
    value: Any,
    *,
    field: str,
    default: float,
    maximum: float,
    error_type: type[Exception],
) -> float:
    if value is None:
        return default
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
        or float(value) > maximum
    ):
        raise error_type(f"{field} is outside the supported bound")
    return float(value)


def _call(server, callback, *, mutated: bool) -> dict[str, Any]:
    try:
        result = callback()
    except RootReviewError as exc:
        raise server.tool_error(str(exc)) from exc
    return {
        "ok": True,
        "mutated": mutated,
        "root_review": result,
    }


def publish(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(
        args,
        {"purpose", "command", "previous_handle"},
        error_type=server.tool_error,
    )
    purpose = args.get("purpose")
    command = args.get("command")
    previous_handle = args.get("previous_handle")
    if previous_handle is not None and not isinstance(previous_handle, str):
        raise server.tool_error("previous_handle must be an opaque string")
    return _call(
        server,
        lambda: _store(server).publish(
            purpose=purpose,
            command=command,
            previous_handle=previous_handle,
        ),
        mutated=True,
    )


def wait(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(
        args,
        {"handle", "wait_timeout_seconds", "poll_interval_seconds"},
        error_type=server.tool_error,
    )
    handle = args.get("handle")
    if not isinstance(handle, str):
        raise server.tool_error("handle must be an opaque string")
    wait_timeout = _bounded_number(
        args.get("wait_timeout_seconds"),
        field="wait_timeout_seconds",
        default=0.25,
        maximum=50.0,
        error_type=server.tool_error,
    )
    poll_interval = _bounded_number(
        args.get("poll_interval_seconds"),
        field="poll_interval_seconds",
        default=0.05,
        maximum=5.0,
        error_type=server.tool_error,
    )
    return _call(
        server,
        lambda: _store(server).wait(
            raw_handle=handle,
            timeout_seconds=wait_timeout,
            poll_interval_seconds=poll_interval,
        ),
        mutated=False,
    )


def resolve(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"handle"}, error_type=server.tool_error)
    handle = args.get("handle")
    if not isinstance(handle, str):
        raise server.tool_error("handle must be an opaque string")
    return _call(
        server,
        lambda: _store(server).resolve(raw_handle=handle),
        mutated=True,
    )
