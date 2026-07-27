from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, BinaryIO

from ..root_actions.client import (
    RootActionBrokerClient,
    RootActionClientError,
    RootActionRequestHandle,
    MAX_BROKER_TIMEOUT_SECONDS,
    MAX_POLL_INTERVAL_SECONDS,
    MAX_WAIT_TIMEOUT_SECONDS,
)
from ..root_actions.contracts import MAX_MANIFEST_BYTES, ManifestValidationError


ROOT_ACTION_CLI_RESULT_SCHEMA = "agent-runtime-root-action-cli-result/v1"
MAX_ROOT_ACTION_CLI_RESULT_BYTES = 1024 * 1024


def _bounded_float(value: str, *, maximum: float, label: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0 or parsed > maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be finite and in the range (0, {maximum}]"
        )
    return parsed


def broker_timeout_arg(value: str) -> float:
    return _bounded_float(
        value, maximum=MAX_BROKER_TIMEOUT_SECONDS, label="broker timeout"
    )


def wait_timeout_arg(value: str) -> float:
    return _bounded_float(
        value, maximum=MAX_WAIT_TIMEOUT_SECONDS, label="wait timeout"
    )


def poll_interval_arg(value: str) -> float:
    return _bounded_float(
        value, maximum=MAX_POLL_INTERVAL_SECONDS, label="poll interval"
    )


def _canonical(value: dict[str, Any]) -> bytes:
    raw = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_ROOT_ACTION_CLI_RESULT_BYTES:
        raise RootActionClientError("public_cli_result_exceeds_bound")
    return raw


def _read_bounded(stream: BinaryIO) -> bytes:
    raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestValidationError("manifest byte length is outside the allowed range")
    return raw


def _read_manifest(args: argparse.Namespace) -> bytes:
    if args.manifest_stdin:
        return _read_bounded(sys.stdin.buffer)
    path = Path(args.manifest_file)
    with path.open("rb") as stream:
        return _read_bounded(stream)


def _handle_from_args(args: argparse.Namespace) -> RootActionRequestHandle:
    return RootActionRequestHandle(
        job_id=args.job_id,
        job_digest=args.job_digest,
        request_id=args.request_id,
        reply_target=args.reply_target,
    )


def _public_result(
    handle: RootActionRequestHandle,
    projection: dict[str, Any],
) -> dict[str, Any]:
    status = projection["status"]["state"]
    return {
        "schema": ROOT_ACTION_CLI_RESULT_SCHEMA,
        "result": "ok",
        "handle": {
            "job_id": handle.job_id,
            "job_digest": handle.job_digest,
            "request_id": handle.request_id,
            "reply_target": handle.reply_target,
        },
        "observed_projection_digest": projection["projection_digest"],
        "state": status["name"],
        "terminal_outcome": status["terminal_outcome"],
        "reason_code": status["reason_code"],
        "receipt": projection["receipt"],
    }


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write(_canonical(value))


def _emit_error(reason_code: str) -> int:
    _emit(
        {
            "schema": ROOT_ACTION_CLI_RESULT_SCHEMA,
            "result": "error",
            "reason_code": reason_code,
        }
    )
    return 2


def cmd_root_action_submit(args: argparse.Namespace) -> int:
    try:
        raw = _read_manifest(args)
        client = RootActionBrokerClient()
        handle, projection = client.submit(raw, timeout_seconds=args.broker_timeout)
        if args.wait:
            projection, _receipt = client.poll_terminal(
                handle,
                timeout_seconds=args.wait_timeout,
                interval_seconds=args.poll_interval,
            )
        _emit(_public_result(handle, projection))
        return 0
    except (OSError, ValueError, ManifestValidationError, RootActionClientError) as exc:
        reason = str(exc)
        if reason not in {
            "outcome_unknown_recovery_needed",
            "terminal_receipt_polling_timed_out",
        }:
            reason = "root_action_submission_failed_closed"
        return _emit_error(reason)


def cmd_root_action_retrieve(args: argparse.Namespace) -> int:
    try:
        handle = _handle_from_args(args)
        projection = RootActionBrokerClient().retrieve(
            handle,
            timeout_seconds=args.broker_timeout,
        )
        _emit(_public_result(handle, projection))
        return 0
    except (OSError, ValueError, RootActionClientError):
        return _emit_error("root_action_retrieval_failed_closed")


def cmd_root_action_wait(args: argparse.Namespace) -> int:
    try:
        handle = _handle_from_args(args)
        projection, _receipt = RootActionBrokerClient().poll_terminal(
            handle,
            timeout_seconds=args.wait_timeout,
            interval_seconds=args.poll_interval,
        )
        _emit(_public_result(handle, projection))
        return 0
    except (OSError, ValueError, RootActionClientError) as exc:
        reason = str(exc)
        if reason not in {
            "outcome_unknown_recovery_needed",
            "terminal_receipt_polling_timed_out",
        }:
            reason = "root_action_retrieval_failed_closed"
        return _emit_error(reason)
