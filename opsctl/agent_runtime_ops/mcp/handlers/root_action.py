from __future__ import annotations

import json
import math
import re
import shlex
from typing import Any

from ...root_actions.client import RootActionRequestHandle
from ...root_actions.contracts import (
    ManifestValidationError,
    canonical_manifest_bytes,
    seal_typed_manifest,
)
from ...root_actions.public_projection import (
    PublicProjectionError,
    validate_public_projection,
)
from .. import validation as v


ROOT_ACTION_CLI_RESULT_SCHEMA = "agent-runtime-root-action-cli-result/v1"
MAX_MCP_WAIT_SECONDS = 50.0
MAX_MCP_POLL_INTERVAL_SECONDS = 5.0
_REASON_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_HANDLE_KEYS = {"job_id", "job_digest", "request_id", "reply_target"}
_OK_KEYS = {
    "schema",
    "result",
    "handle",
    "observed_projection_digest",
    "state",
    "terminal_outcome",
    "reason_code",
    "receipt",
    "projection",
}
_ERROR_REQUIRED_KEYS = {"schema", "result", "reason_code"}


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
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_type(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > maximum:
        raise error_type(f"{field} must be in the range (0, {maximum}]")
    return number


def _handle(value: Any, *, error_type: type[Exception]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _HANDLE_KEYS:
        raise error_type("root-action handle field set is invalid")
    try:
        handle = RootActionRequestHandle(
            job_id=value["job_id"],
            job_digest=value["job_digest"],
            request_id=value["request_id"],
            reply_target=value["reply_target"],
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise error_type("root-action handle is invalid") from exc
    return {
        "job_id": handle.job_id,
        "job_digest": handle.job_digest,
        "request_id": handle.request_id,
        "reply_target": handle.reply_target,
    }


def _handle_argv(handle: dict[str, str]) -> list[str]:
    return [
        "--job-id",
        handle["job_id"],
        "--job-digest",
        handle["job_digest"],
        "--request-id",
        handle["request_id"],
        "--reply-target",
        handle["reply_target"],
    ]


def _parse_cli_result(
    run: dict[str, Any], *, error_type: type[Exception]
) -> dict[str, Any]:
    try:
        value = json.loads(run["stdout"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise error_type("root-action CLI did not return one JSON result") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema") != ROOT_ACTION_CLI_RESULT_SCHEMA
    ):
        raise error_type("root-action CLI result schema is invalid")
    result = value.get("result")
    if result == "ok":
        if set(value) != _OK_KEYS:
            raise error_type("root-action CLI success field set is invalid")
        handle = _handle(value["handle"], error_type=error_type)
        projection = value["projection"]
        if not isinstance(projection, dict):
            raise error_type("root-action CLI projection is invalid")
        projection_bytes = (
            json.dumps(
                projection,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        try:
            verified_projection = validate_public_projection(projection_bytes)
        except (TypeError, ValueError, PublicProjectionError) as exc:
            raise error_type("root-action CLI projection is invalid") from exc
        status = projection.get("status")
        state = status.get("state") if isinstance(status, dict) else None
        if (
            verified_projection.job_id != handle["job_id"]
            or verified_projection.job_digest != handle["job_digest"]
            or verified_projection.projection_digest
            != value["observed_projection_digest"]
            or not isinstance(state, dict)
            or state.get("name") != value["state"]
            or state.get("terminal_outcome") != value["terminal_outcome"]
            or state.get("reason_code") != value["reason_code"]
            or projection.get("receipt") != value["receipt"]
        ):
            raise error_type("root-action CLI result binding is invalid")
        return value
    if result == "error":
        if not _ERROR_REQUIRED_KEYS.issubset(value) or set(value) - (
            _ERROR_REQUIRED_KEYS | {"handle"}
        ):
            raise error_type("root-action CLI error field set is invalid")
        reason = value.get("reason_code")
        if not isinstance(reason, str) or _REASON_RE.fullmatch(reason) is None:
            raise error_type("root-action CLI reason code is invalid")
        if "handle" in value:
            _handle(value["handle"], error_type=error_type)
        return value
    raise error_type("root-action CLI result kind is invalid")


def _response(
    server,
    run: dict[str, Any],
    *,
    mutated: bool,
    retry_on_timeout: bool = False,
    fallback_handle: dict[str, str] | None = None,
    submission_acceptance_unknown: bool = False,
) -> dict[str, Any]:
    value = _parse_cli_result(run, error_type=server.tool_error)
    public_run = {**run, "stdout": ""}
    ok = run["returncode"] == 0 and value["result"] == "ok"
    reason = value.get("reason_code")
    outcome_unknown = reason == "outcome_unknown_recovery_needed"
    retryable = retry_on_timeout and reason == "terminal_receipt_polling_timed_out"
    handle = value.get("handle") or fallback_handle
    next_action = None
    if submission_acceptance_unknown:
        next_action = (
            "Submission acceptance is unknown. Call root_action_retrieve with the derived "
            "unchanged handle before considering any new submission. Never change the digest "
            "or create a second execution attempt to resolve this state."
        )
    elif retryable:
        next_action = (
            "Call root_action_wait again with the unchanged returned handle. "
            "Do not ask the user to poll, run a shell, or carry receipt output."
        )
    elif outcome_unknown:
        next_action = (
            "Stop polling: the broker recorded an immutable unknown outcome. Preserve the "
            "unchanged handle for an authorized reconciliation path; do not resubmit the "
            "action or ask the user to carry receipt output."
        )
    elif ok and value.get("state") != "terminal":
        next_action = (
            "Call root_action_wait with the unchanged returned handle and keep the original "
            "request active until its terminal receipt is returned."
        )
    return server._common_response(
        ok=ok,
        mutated=mutated,
        runs=[public_run],
        next_action=next_action,
        extra={
            "root_action": value,
            "handle": handle,
            "retryable": retryable,
            "recovery_required": submission_acceptance_unknown or outcome_unknown,
            "acceptance_state": (
                "unknown"
                if submission_acceptance_unknown
                else "accepted"
                if value["result"] == "ok" or value.get("handle") is not None
                else "not_observed"
            ),
        },
    )


def _submission_recovery_response(
    server,
    *,
    run: dict[str, Any] | None,
    argv: list[str],
    handle: dict[str, str],
) -> dict[str, Any]:
    if run is None:
        public_runs = [
            {
                "command": {
                    "argv": argv,
                    "display": shlex.join(argv),
                    "stdin": "provided",
                },
                "returncode": None,
                "stdout": "",
                "stderr": "",
            }
        ]
    else:
        public_runs = [{**run, "stdout": ""}]
    root_action = {
        "schema": ROOT_ACTION_CLI_RESULT_SCHEMA,
        "result": "error",
        "reason_code": "root_action_submission_result_unavailable",
        "handle": handle,
    }
    return server._common_response(
        ok=False,
        mutated=False,
        runs=public_runs,
        next_action=(
            "Submission acceptance is unknown. Call root_action_retrieve with the derived "
            "unchanged handle before considering any new submission. Never change the digest "
            "or create a second execution attempt to resolve this state."
        ),
        extra={
            "root_action": root_action,
            "handle": handle,
            "retryable": False,
            "recovery_required": True,
            "acceptance_state": "unknown",
        },
    )


def submit(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"manifest"}, error_type=server.tool_error)
    manifest = args.get("manifest")
    if not isinstance(manifest, dict):
        raise server.tool_error("manifest must be an object")
    try:
        sealed = seal_typed_manifest(canonical_manifest_bytes(manifest))
    except (TypeError, ValueError, ManifestValidationError) as exc:
        raise server.tool_error(f"typed root-action manifest rejected: {exc}") from exc
    derived_handle = {
        "job_id": sealed.job_id,
        "job_digest": sealed.job_digest,
        "request_id": sealed.request_id,
        "reply_target": sealed.reply_target,
    }
    argv = [server.opsctl, "root-action", "submit", "--manifest-stdin"]
    try:
        run = server._run(
            argv,
            input_text=sealed.canonical_manifest.decode("utf-8"),
            timeout=15,
        )
    except Exception:
        return _submission_recovery_response(
            server,
            run=None,
            argv=argv,
            handle=derived_handle,
        )
    try:
        value = _parse_cli_result(run, error_type=server.tool_error)
    except Exception:
        return _submission_recovery_response(
            server,
            run=run,
            argv=argv,
            handle=derived_handle,
        )
    accepted = value["result"] == "ok" or value.get("handle") is not None
    return _response(
        server,
        run,
        mutated=accepted,
        fallback_handle=derived_handle,
        submission_acceptance_unknown=not accepted,
    )


def retrieve(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(args, {"handle"}, error_type=server.tool_error)
    handle = _handle(args.get("handle"), error_type=server.tool_error)
    run = server._run(
        [server.opsctl, "root-action", "retrieve", *_handle_argv(handle)],
        timeout=15,
    )
    return _response(server, run, mutated=False)


def wait(server, args: dict[str, Any]) -> dict[str, Any]:
    v.reject_unknown(
        args,
        {"handle", "wait_timeout_seconds", "poll_interval_seconds"},
        error_type=server.tool_error,
    )
    handle = _handle(args.get("handle"), error_type=server.tool_error)
    wait_timeout = _bounded_number(
        args.get("wait_timeout_seconds"),
        field="wait_timeout_seconds",
        default=45.0,
        maximum=MAX_MCP_WAIT_SECONDS,
        error_type=server.tool_error,
    )
    poll_interval = _bounded_number(
        args.get("poll_interval_seconds"),
        field="poll_interval_seconds",
        default=0.5,
        maximum=MAX_MCP_POLL_INTERVAL_SECONDS,
        error_type=server.tool_error,
    )
    run = server._run(
        [
            server.opsctl,
            "root-action",
            "wait",
            *_handle_argv(handle),
            "--wait-timeout",
            str(wait_timeout),
            "--poll-interval",
            str(poll_interval),
        ],
        timeout=math.ceil(wait_timeout) + 10,
    )
    return _response(server, run, mutated=False, retry_on_timeout=True)
