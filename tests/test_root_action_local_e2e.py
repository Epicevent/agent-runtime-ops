from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time

from agent_runtime_ops.root_actions.auth_service import RootActionAuthorizationService
from agent_runtime_ops.root_actions.authorization import WebAuthnPolicy, WebAuthnVerifier
from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.endpoint import RootActionBrokerEndpoint
from agent_runtime_ops.root_actions.execution import HandlerResult, OperationHandlerRegistry
from agent_runtime_ops.root_actions.posix_store import PosixRootActionStore
from agent_runtime_ops.root_actions.protocol import (
    auth_request,
    parse_response_frame,
    submit_request,
)
from agent_runtime_ops.root_actions.state import JobState
from agent_runtime_ops.root_actions.submission import BrokerPeerIdentity, SubmissionPolicy
from agent_runtime_ops.root_actions.worker import RootActionExecutionWorker
from tests.test_root_action_admission import Events, MemoryPublicSink, manifest
from tests.test_root_action_authorization import ORIGIN, RP_ID, USER_ID, VirtualAuthenticator


ROOT = BrokerPeerIdentity(uid=0, gid=0, pid=1)
SVCOPS = BrokerPeerIdentity(uid=1002, gid=1002, pid=500)


class E2EHandler:
    operation_id = "artifact.probe_kwrag_product"
    operation_version = 1

    def run(self, _job):
        return HandlerResult(
            raw_bytes=b'{"full":"root-only e2e output"}\n',
            public_status="pass",
            public_facts=(("writes", "0"),),
        )


def test_local_browser_message_to_root_worker_terminal_receipt_e2e() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = PosixRootActionStore(
            Path(temporary) / "root-actions",
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        sink = MemoryPublicSink()
        broker = TypedRootActionBroker(
            store,
            events=Events(
                [
                    ("event-e2e-pending", "2026-07-28T01:00:03Z"),
                    ("event-e2e-circuit", "2026-07-28T01:00:04Z"),
                ]
            ),
            public_sink=sink,
            submission_policy=SubmissionPolicy(
                allowed_uids=frozenset({SVCOPS.uid}),
                allowed_gids=frozenset({SVCOPS.gid}),
                maximum_age_seconds=24 * 60 * 60,
            ),
        )
        worker = RootActionExecutionWorker(
            store,
            handlers=OperationHandlerRegistry((E2EHandler(),)),
            events=Events([("event-e2e-complete", "2026-07-28T01:00:07Z")]),
            repair_public=broker.repair_public_best_effort,
        )
        worker.start()
        authorization = RootActionAuthorizationService(
            store,
            WebAuthnVerifier(
                WebAuthnPolicy(RP_ID, "Root action", (ORIGIN,), USER_ID)
            ),
            dispatch=worker.enqueue,
            events=Events(
                [
                    ("event-e2e-bootstrap", "2026-07-28T01:00:00Z"),
                    ("event-e2e-registration-begin", "2026-07-28T01:00:01Z"),
                    ("event-e2e-registration-finish", "2026-07-28T01:00:02Z"),
                    ("event-e2e-approval-begin", "2026-07-28T01:00:05Z"),
                    ("event-e2e-approval-finish", "2026-07-28T01:00:06Z"),
                ]
            ),
        )
        endpoint = RootActionBrokerEndpoint(broker, authorization=authorization)
        authenticator = VirtualAuthenticator()
        try:
            bootstrap = parse_response_frame(
                endpoint.handle(auth_request("auth_bootstrap_create"), peer=ROOT)
            )
            token = bootstrap["bootstrap_token"]
            registration_begin = parse_response_frame(
                endpoint.handle(
                    auth_request(
                        "auth_registration_begin",
                        bootstrap_token=token,
                        role="approval",
                        label="office_windows_hello",
                    ),
                    peer=SVCOPS,
                )
            )
            registration = store.read_ceremony(registration_begin["ceremony_id"])
            parse_response_frame(
                endpoint.handle(
                    auth_request(
                        "auth_registration_finish",
                        bootstrap_token=token,
                        ceremony_id=registration.ceremony_id,
                        credential=authenticator.registration(registration.challenge),
                    ),
                    peer=SVCOPS,
                )
            )

            submitted = parse_response_frame(
                endpoint.handle(submit_request(manifest("job-local-e2e")), peer=SVCOPS)
            )
            assert submitted["state"] == "pending"
            approval_begin = parse_response_frame(
                endpoint.handle(
                    auth_request(
                        "auth_approval_begin",
                        job_id=submitted["job_id"],
                        job_digest=submitted["job_digest"],
                    ),
                    peer=SVCOPS,
                )
            )
            approval = store.read_ceremony(approval_begin["ceremony_id"])
            finish = parse_response_frame(
                endpoint.handle(
                    auth_request(
                        "auth_approval_finish",
                        ceremony_id=approval.ceremony_id,
                        credential=authenticator.assertion(approval.challenge),
                    ),
                    peer=SVCOPS,
                )
            )
            assert finish["job_digest"] == submitted["job_digest"]

            deadline = time.monotonic() + 2
            while store.read_record(submitted["job_id"]).state is not JobState.TERMINAL:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            receipt = store.retrieve(
                submitted["job_id"], submitted["job_digest"]
            ).receipt_copy()
            assert receipt["terminal_outcome"] == "succeeded"
            assert receipt["result"]["facts"] == [
                {"name": "writes", "value": "0"}
            ]
            assert b"root-only e2e output" in store.read_raw_root_only(
                submitted["job_id"]
            ).raw_bytes
            assert submitted["job_id"] in sink.bundles
            assert [entry.action for entry in store.read_ledger(submitted["job_id"])] == [
                "sealed_pending",
                "claim_execution",
                "complete_execution",
            ]
        finally:
            worker.close()
