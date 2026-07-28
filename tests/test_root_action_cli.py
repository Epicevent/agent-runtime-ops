from __future__ import annotations

import argparse
from io import BytesIO
import json
from pathlib import Path

import pytest

from agent_runtime_ops.commands.root_action import (
    broker_timeout_arg,
    cmd_root_action_retrieve,
    cmd_root_action_submit,
    cmd_root_action_wait,
    poll_interval_arg,
    wait_timeout_arg,
)
from agent_runtime_ops.root_actions.client import (
    RootActionClientError,
    RootActionRequestHandle,
)
from tests.test_root_action_admission import manifest


DIGEST = "sha256:" + "a" * 64
PROJECTION_DIGEST = "sha256:" + "b" * 64


def projection(*, terminal: bool) -> dict:
    return {
        "schema": "agent-runtime-root-action-public-projection/v1",
        "job_id": "job-cli",
        "job_digest": DIGEST,
        "projection_digest": PROJECTION_DIGEST,
        "status": {
            "state": {
                "name": "terminal" if terminal else "pending",
                "terminal_outcome": "succeeded" if terminal else None,
                "reason_code": "completed" if terminal else None,
            }
        },
        "history": {
            "events": [
                {"action": "sealed_pending"},
                *([{"action": "complete_execution"}] if terminal else []),
            ]
        },
        "receipt": (
            {
                "schema": "agent-runtime-root-action-receipt/v1",
                "kind": "terminal_notice",
                "job_id": "job-cli",
                "job_digest": DIGEST,
                "operation_id": "artifact.probe_kwrag_product",
                "request_id": "request-job-cli",
                "reply_target": "reply-job-cli",
                "terminal_outcome": "succeeded",
                "reason_code": "completed",
                "receipt_digest": "sha256:" + "c" * 64,
            }
            if terminal
            else None
        ),
    }


class FakeClient:
    submitted = None
    waited = False

    def submit(self, raw: bytes, *, timeout_seconds: float):
        type(self).submitted = raw
        return (
            RootActionRequestHandle(
                job_id="job-cli",
                job_digest=DIGEST,
                request_id="request-job-cli",
                reply_target="reply-job-cli",
            ),
            projection(terminal=False),
        )

    def retrieve(self, handle, *, timeout_seconds: float):
        return projection(terminal=False)

    def poll_terminal(self, handle, *, timeout_seconds: float, interval_seconds: float):
        type(self).waited = True
        return projection(terminal=True), object()


class PollTimeoutClient(FakeClient):
    def poll_terminal(self, handle, *, timeout_seconds: float, interval_seconds: float):
        raise RootActionClientError("terminal_receipt_polling_timed_out")


class PollTransportFailureClient(FakeClient):
    def poll_terminal(self, handle, *, timeout_seconds: float, interval_seconds: float):
        raise RootActionClientError("broker response failed closed")


class SubmitFailureClient(FakeClient):
    def submit(self, raw: bytes, *, timeout_seconds: float):
        raise RootActionClientError("broker response failed closed")


class BinaryStdin:
    def __init__(self, raw: bytes) -> None:
        self.buffer = BytesIO(raw)


def test_submit_wait_reads_exact_file_bytes_and_emits_bound_terminal_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    raw = manifest("job-cli")
    path = tmp_path / "manifest.json"
    path.write_bytes(raw)
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", FakeClient
    )
    args = argparse.Namespace(
        manifest_file=str(path),
        manifest_stdin=False,
        wait=True,
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_submit(args) == 0
    result = json.loads(capfd.readouterr().out)
    assert FakeClient.submitted == raw
    assert FakeClient.waited is True
    assert result["handle"] == {
        "job_id": "job-cli",
        "job_digest": DIGEST,
        "request_id": "request-job-cli",
        "reply_target": "reply-job-cli",
    }
    assert result["observed_projection_digest"] == PROJECTION_DIGEST
    assert result["state"] == "terminal"
    assert result["receipt"]["request_id"] == "request-job-cli"
    assert result["receipt"]["reply_target"] == "reply-job-cli"
    assert result["projection"] == projection(terminal=True)
    assert result["projection"]["status"]["state"]["name"] == "terminal"
    assert [row["action"] for row in result["projection"]["history"]["events"]] == [
        "sealed_pending",
        "complete_execution",
    ]
    assert "stdout" not in json.dumps(result)
    assert "stderr" not in json.dumps(result)


def test_submit_stdin_is_bounded_and_exact(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    raw = manifest("job-cli")
    FakeClient.submitted = None
    FakeClient.waited = False
    monkeypatch.setattr("sys.stdin", BinaryStdin(raw))
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", FakeClient
    )
    args = argparse.Namespace(
        manifest_file=None,
        manifest_stdin=True,
        wait=False,
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_submit(args) == 0
    result = json.loads(capfd.readouterr().out)
    assert FakeClient.submitted == raw
    assert result["state"] == "pending"
    assert result["receipt"] is None


@pytest.mark.parametrize(
    ("client_type", "reason_code"),
    [
        (PollTimeoutClient, "terminal_receipt_polling_timed_out"),
        (PollTransportFailureClient, "root_action_retrieval_failed_closed"),
    ],
)
def test_submit_wait_failure_preserves_machine_recovery_handle(
    client_type: type[FakeClient],
    reason_code: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    raw = manifest("job-cli")
    path = tmp_path / "manifest.json"
    path.write_bytes(raw)
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", client_type
    )
    args = argparse.Namespace(
        manifest_file=str(path),
        manifest_stdin=False,
        wait=True,
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_submit(args) == 2
    result = json.loads(capfd.readouterr().out)
    assert result == {
        "schema": "agent-runtime-root-action-cli-result/v1",
        "result": "error",
        "reason_code": reason_code,
        "handle": {
            "job_id": "job-cli",
            "job_digest": DIGEST,
            "request_id": "request-job-cli",
            "reply_target": "reply-job-cli",
        },
    }


def test_submit_failure_before_acceptance_has_no_recovery_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "manifest.json"
    path.write_bytes(manifest("job-cli"))
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient",
        SubmitFailureClient,
    )
    args = argparse.Namespace(
        manifest_file=str(path),
        manifest_stdin=False,
        wait=True,
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_submit(args) == 2
    result = json.loads(capfd.readouterr().out)
    assert result == {
        "schema": "agent-runtime-root-action-cli-result/v1",
        "result": "error",
        "reason_code": "root_action_submission_failed_closed",
    }


def test_retrieve_and_wait_carry_complete_identity_bound_handle(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", FakeClient
    )
    common = dict(
        job_id="job-cli",
        job_digest=DIGEST,
        request_id="request-job-cli",
        reply_target="reply-job-cli",
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_retrieve(argparse.Namespace(**common)) == 0
    retrieved = json.loads(capfd.readouterr().out)
    assert retrieved["handle"]["request_id"] == "request-job-cli"
    assert cmd_root_action_wait(argparse.Namespace(**common)) == 0
    waited = json.loads(capfd.readouterr().out)
    assert waited["receipt"]["reply_target"] == "reply-job-cli"


@pytest.mark.parametrize(
    ("command", "reason_code"),
    [
        (cmd_root_action_retrieve, "root_action_retrieval_failed_closed"),
        (cmd_root_action_wait, "terminal_receipt_polling_timed_out"),
    ],
)
def test_retrieve_failures_preserve_valid_machine_recovery_handle(
    command,
    reason_code: str,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    class BrokenClient(FakeClient):
        def retrieve(self, handle, *, timeout_seconds: float):
            raise RootActionClientError("broker response failed closed")

        def poll_terminal(
            self, handle, *, timeout_seconds: float, interval_seconds: float
        ):
            raise RootActionClientError("terminal_receipt_polling_timed_out")

    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", BrokenClient
    )
    args = argparse.Namespace(
        job_id="job-cli",
        job_digest=DIGEST,
        request_id="request-job-cli",
        reply_target="reply-job-cli",
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert command(args) == 2
    result = json.loads(capfd.readouterr().out)
    assert result["reason_code"] == reason_code
    assert result["handle"]["job_digest"] == DIGEST


def test_invalid_recovery_handle_is_never_echoed(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "agent_runtime_ops.commands.root_action.RootActionBrokerClient", FakeClient
    )
    args = argparse.Namespace(
        job_id="../escape",
        job_digest=DIGEST,
        request_id="request-job-cli",
        reply_target="reply-job-cli",
        broker_timeout=5.0,
        wait_timeout=900.0,
        poll_interval=0.25,
    )
    assert cmd_root_action_retrieve(args) == 2
    result = json.loads(capfd.readouterr().out)
    assert result["reason_code"] == "root_action_retrieval_failed_closed"
    assert "handle" not in result


def test_cli_source_has_no_shell_payload_or_configurable_socket_surface() -> None:
    source = Path("opsctl/agent_runtime_ops/commands/root_action.py").read_text(
        encoding="utf-8"
    )
    parser_source = Path("opsctl/agent_runtime_ops/cli.py").read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "shell" not in source
    root_section = parser_source[
        parser_source.index('root_action = sub.add_parser(') : parser_source.index(
            '    config = sub.add_parser("config")'
        )
    ]
    assert '"--manifest-file"' in root_section
    assert '"--manifest-stdin"' in root_section
    assert '"--socket"' not in root_section
    assert 'parser.add_argument("--job-id", required=True)' in root_section
    assert 'parser.add_argument("--job-digest", required=True)' in root_section
    assert 'parser.add_argument("--request-id", required=True)' in root_section
    assert 'parser.add_argument("--reply-target", required=True)' in root_section
    assert '"--projection-digest"' not in root_section


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1", "60.01"])
def test_broker_timeout_parser_rejects_nonfinite_nonpositive_and_over_cap(
    value: str,
) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        broker_timeout_arg(value)


@pytest.mark.parametrize("value", ["nan", "inf", "0", "86400.01"])
def test_wait_timeout_parser_rejects_unbounded_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        wait_timeout_arg(value)


@pytest.mark.parametrize("value", ["nan", "inf", "0", "60.01"])
def test_poll_interval_parser_rejects_unbounded_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        poll_interval_arg(value)
