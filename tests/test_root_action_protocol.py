from __future__ import annotations

from dataclasses import replace
import json

import pytest

from agent_runtime_ops.root_actions import (
    BrokerPeerIdentity,
    RootActionBrokerClient,
    RootActionBrokerEndpoint,
    RootActionClientError,
    SubmissionPolicy,
    TypedRootActionBroker,
    seal_raw_receipt,
)
from agent_runtime_ops.root_actions.protocol import (
    BROKER_REQUEST_SCHEMA,
    BrokerProtocolError,
    canonical_json,
    encode_frame,
    encode_response,
    parse_request_frame,
    parse_response_frame,
    MAX_BROKER_REQUEST_BYTES,
)
from agent_runtime_ops.root_actions.receipts import RECEIPT_SCHEMA, seal_receipt
from agent_runtime_ops.root_actions.state import (
    TerminalOutcome,
    TransitionEvent,
    TransitionKind,
)
from tests.test_root_action_admission import Events, manifest


PEER = BrokerPeerIdentity(uid=1027, gid=1048, pid=301)


def make_broker(store, *, sink=None) -> TypedRootActionBroker:
    return TypedRootActionBroker(
        store,
        events=Events(
            [
                ("event-pending", "2026-07-27T12:00:00Z"),
                ("event-circuit", "2026-07-27T12:00:01Z"),
            ]
        ),
        public_sink=sink,
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({PEER.uid}),
            allowed_gids=frozenset({PEER.gid}),
        ),
    )


def transition_terminal(store, job_id: str, *, outcome: TerminalOutcome) -> None:
    job = store.read_sealed(job_id)
    record = store.read_record(job_id)
    if record.state.value == "pending":
        record = store.compare_and_append(
            TransitionEvent(
                event_id="claim-" + job_id,
                job_id=job.job_id,
                job_digest=job.job_digest,
                expected_revision=record.revision,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at="2026-07-27T12:00:02Z",
            )
        )
    if record.state.value == "unknown":
        kind = TransitionKind.RECONCILE_UNKNOWN
    else:
        kind = TransitionKind.COMPLETE_EXECUTION
    store.compare_and_append(
        TransitionEvent(
            event_id="terminal-" + job_id,
            job_id=job.job_id,
            job_digest=job.job_digest,
            expected_revision=record.revision,
            kind=kind,
            occurred_at="2026-07-27T12:00:04Z",
            outcome=outcome,
            reason_code="completed" if outcome is TerminalOutcome.SUCCEEDED else "handler_failed",
        )
    )


def publish_public_receipt(store, job_id: str) -> None:
    job = store.read_sealed(job_id)
    raw = seal_raw_receipt(
        job_id=job.job_id,
        job_digest=job.job_digest,
        root_storage_id="raw-" + job.job_id,
        raw_bytes=b"private complete output",
    )
    try:
        store.put_raw_if_absent(raw)
    except Exception:
        raw = store.read_raw_root_only(job.job_id)
    artifact = seal_receipt(
        json.dumps(
            {
                "schema": RECEIPT_SCHEMA,
                "kind": "public",
                "job_id": job.job_id,
                "job_digest": job.job_digest,
                "operation_id": job.operation_id,
                "request_id": job.request_id,
                "reply_target": job.reply_target,
                "terminal_outcome": "succeeded",
                "raw_receipt_digest": raw.reference.raw_receipt_digest,
                "started_at": "2026-07-27T12:00:02Z",
                "ended_at": "2026-07-27T12:00:04Z",
                "exit_code": 0,
                "removed_lines": 0,
                "result": {
                    "status": "pass",
                    "facts": [{"name": "verified", "value": "true"}],
                },
            },
            ensure_ascii=False,
        ).encode("utf-8")
    )
    store.publish_if_absent(artifact)


def test_response_drop_after_commit_exact_retry_recovers_same_handle() -> None:
    from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture

    store = LocalRootActionFixture()
    endpoint = RootActionBrokerEndpoint(make_broker(store))
    calls = 0

    def drop_first(frame: bytes, _timeout: float) -> bytes:
        nonlocal calls
        calls += 1
        response = endpoint.handle(frame, peer=PEER)
        if calls == 1:
            raise OSError("simulated response drop")
        return response

    client = RootActionBrokerClient(transport=drop_first)
    raw = manifest("job-idempotent")
    with pytest.raises(RootActionClientError):
        client.submit(raw)
    handle, projection = client.submit(raw)
    assert handle.job_id == "job-idempotent"
    assert projection["status"]["state"]["name"] == "pending"
    assert len(store.read_ledger(handle.job_id)) == 1

    changed = json.loads(raw)
    changed["review"]["purpose"] = "different exact action"
    conflicting = (
        json.dumps(changed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    with pytest.raises(RootActionClientError):
        client.submit(conflicting)


def test_publication_failure_and_broker_restart_do_not_lose_submission() -> None:
    from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture

    class BrokenCatalog:
        def publish(self, _bundle) -> None:
            return None

        def publish_catalog(self, _bundles) -> None:
            raise OSError("catalog unavailable")

    store = LocalRootActionFixture()
    first = RootActionBrokerEndpoint(make_broker(store, sink=BrokenCatalog()))
    raw = manifest("job-publication-recovery")
    client = RootActionBrokerClient(
        transport=lambda frame, _timeout: first.handle(frame, peer=PEER)
    )
    first_handle, _ = client.submit(raw)

    restarted = RootActionBrokerEndpoint(make_broker(store))
    recovered = RootActionBrokerClient(
        transport=lambda frame, _timeout: restarted.handle(frame, peer=PEER)
    )
    second_handle, projection = recovered.submit(raw)
    assert first_handle == second_handle
    assert projection["status"]["state"]["name"] == "pending"
    assert len(store.read_ledger(first_handle.job_id)) == 1


def test_submit_to_terminal_receipt_auto_retrieve_and_binding_controls() -> None:
    from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture

    store = LocalRootActionFixture()
    broker = make_broker(store)
    endpoint = RootActionBrokerEndpoint(broker)
    client = RootActionBrokerClient(
        transport=lambda frame, _timeout: endpoint.handle(frame, peer=PEER)
    )
    handle, initial_projection = client.submit(manifest("job-auto-retrieve"))
    initial_digest = initial_projection["projection_digest"]
    transition_terminal(store, handle.job_id, outcome=TerminalOutcome.SUCCEEDED)
    publish_public_receipt(store, handle.job_id)

    projection, receipt = client.poll_terminal(
        handle,
        timeout_seconds=0.2,
        interval_seconds=0.01,
    )
    assert receipt.kind == "public"
    assert receipt.request_id == handle.request_id
    assert receipt.reply_target == handle.reply_target
    assert projection["projection_digest"] != initial_digest
    assert projection["receipt"]["result"]["facts"] == [
        {"name": "verified", "value": "true"}
    ]
    assert b"private complete output" not in json.dumps(projection).encode()

    with pytest.raises(RootActionClientError):
        client.retrieve(replace(handle, reply_target="reply-wrong"))
    with pytest.raises(RootActionClientError):
        client.retrieve(replace(handle, job_digest="sha256:" + "0" * 64))


def test_corrupt_projection_fails_closed() -> None:
    from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture

    endpoint = RootActionBrokerEndpoint(make_broker(LocalRootActionFixture()))

    def corrupt(frame: bytes, _timeout: float) -> bytes:
        value = parse_response_frame(endpoint.handle(frame, peer=PEER))
        value["projection"]["status"]["job"]["reply_target"] = "reply-swapped"
        return encode_response(value)

    client = RootActionBrokerClient(transport=corrupt)
    with pytest.raises(RootActionClientError):
        client.submit(manifest("job-corrupt"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("job_id", "../escape"),
        ("job_digest", "sha256:bad"),
        ("request_id", ["not", "a", "string"]),
        ("reply_target", "UPPERCASE"),
    ],
)
def test_retrieve_protocol_rejects_untyped_or_unsafe_identity(
    field: str, value: object
) -> None:
    request = {
        "schema": BROKER_REQUEST_SCHEMA,
        "method": "retrieve",
        "job_id": "job-safe",
        "job_digest": "sha256:" + "a" * 64,
        "request_id": "request-safe",
        "reply_target": "reply-safe",
    }
    request[field] = value
    frame = encode_frame(
        canonical_json(request), maximum=MAX_BROKER_REQUEST_BYTES
    )
    with pytest.raises(BrokerProtocolError, match="identity"):
        parse_request_frame(frame)


def test_unknown_is_not_complete_and_reconciled_terminal_can_complete() -> None:
    from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture

    store = LocalRootActionFixture()
    endpoint = RootActionBrokerEndpoint(make_broker(store))
    retrieve_count = 0

    def transport(frame: bytes, _timeout: float) -> bytes:
        nonlocal retrieve_count
        request_method = json.loads(frame[4:])["method"]
        if request_method == "retrieve":
            retrieve_count += 1
            if retrieve_count == 2:
                transition_terminal(
                    store,
                    "job-unknown-reconcile",
                    outcome=TerminalOutcome.SUCCEEDED,
                )
                publish_public_receipt(store, "job-unknown-reconcile")
        return endpoint.handle(frame, peer=PEER)

    client = RootActionBrokerClient(transport=transport)
    handle, _ = client.submit(manifest("job-unknown-reconcile"))
    job = store.read_sealed(handle.job_id)
    running = store.compare_and_append(
        TransitionEvent(
            event_id="claim-unknown",
            job_id=job.job_id,
            job_digest=job.job_digest,
            expected_revision=0,
            kind=TransitionKind.CLAIM_EXECUTION,
            occurred_at="2026-07-27T12:00:02Z",
        )
    )
    store.compare_and_append(
        TransitionEvent(
            event_id="mark-unknown",
            job_id=job.job_id,
            job_digest=job.job_digest,
            expected_revision=running.revision,
            kind=TransitionKind.MARK_UNKNOWN,
            occurred_at="2026-07-27T12:00:03Z",
            reason_code="worker_lost",
        )
    )
    raw = seal_raw_receipt(
        job_id=job.job_id,
        job_digest=job.job_digest,
        root_storage_id="raw-unknown",
        raw_bytes=b"unknown forensic bytes",
    )
    store.put_raw_if_absent(raw)
    store.publish_if_absent(
        seal_receipt(
            json.dumps(
                {
                    "schema": RECEIPT_SCHEMA,
                    "kind": "unknown",
                    "job_id": job.job_id,
                    "job_digest": job.job_digest,
                    "operation_id": job.operation_id,
                    "request_id": job.request_id,
                    "reply_target": job.reply_target,
                    "terminal_outcome": None,
                    "raw_receipt_digest": raw.reference.raw_receipt_digest,
                    "last_known_at": "2026-07-27T12:00:03Z",
                    "reason_code": "worker_lost",
                }
            ).encode("utf-8")
        )
    )
    projection, receipt = client.poll_terminal(
        handle,
        timeout_seconds=0.3,
        interval_seconds=0.01,
    )
    assert retrieve_count >= 2
    assert projection["status"]["state"]["terminal_outcome"] == "succeeded"
    assert receipt.kind == "public"
