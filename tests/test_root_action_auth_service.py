from __future__ import annotations

from pathlib import Path
import tempfile

import pytest

from agent_runtime_ops.root_actions.auth_service import RootActionAuthorizationService
from agent_runtime_ops.root_actions.authorization import (
    CeremonyState,
    CredentialRole,
    WebAuthnPolicy,
    WebAuthnVerifier,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.endpoint import RootActionBrokerEndpoint
from agent_runtime_ops.root_actions.posix_store import PosixRootActionStore
from agent_runtime_ops.root_actions.protocol import auth_request, parse_response_frame
from agent_runtime_ops.root_actions.state import JobState
from agent_runtime_ops.root_actions.submission import BrokerPeerIdentity, SubmissionPolicy
from tests.test_root_action_admission import Events
from tests.test_root_action_authorization import ORIGIN, RP_ID, USER_ID, VirtualAuthenticator
from tests.test_root_action_contracts import encoded, valid_manifest


def test_real_webauthn_registration_then_exact_action_claim() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = PosixRootActionStore(
            Path(temporary) / "root-actions",
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        events = Events(
            [
                ("event-bootstrap", "2026-07-28T01:00:00Z"),
                ("event-registration-begin", "2026-07-28T01:00:01Z"),
                ("event-registration-finish", "2026-07-28T01:00:02Z"),
                ("event-approval-begin", "2026-07-28T01:00:04Z"),
                ("event-approval-finish", "2026-07-28T01:00:05Z"),
            ]
        )
        service = RootActionAuthorizationService(
            store,
            WebAuthnVerifier(
                WebAuthnPolicy(
                    rp_id=RP_ID,
                    rp_name="Root action",
                    allowed_origins=(ORIGIN,),
                    user_id=USER_ID,
                )
            ),
            dispatch=lambda _job_id, _job_digest: None,
            events=events,
        )
        authenticator = VirtualAuthenticator()

        bootstrap, token = service.create_initial_bootstrap()
        registration_options = service.begin_registration(
            encoded_token=token,
            role=CredentialRole.APPROVAL,
            label="office_windows_hello",
        )
        registration = store.read_ceremony(registration_options.ceremony_id)
        result = service.finish_registration(
            encoded_token=token,
            ceremony_id=registration.ceremony_id,
            browser_credential=authenticator.registration(registration.challenge),
        )
        assert result.credential.role is CredentialRole.APPROVAL
        assert result.remaining_registrations == 2
        assert store.read_auth_bootstrap(bootstrap.bootstrap_id).remaining_registrations == 2
        assert service.status()["approval_ready"] is True
        assert service.status()["recovery_ready"] is False

        job = seal_typed_manifest(encoded(valid_manifest()))
        store.seal_pending(
            job,
            event_id="event-job-pending",
            occurred_at="2026-07-28T01:00:03Z",
        )
        approval_options = service.begin_approval(
            job_id=job.job_id,
            job_digest=job.job_digest,
        )
        assert approval_options.job_digest == job.job_digest
        ceremony = store.read_ceremony(approval_options.ceremony_id)
        record = service.finish_approval(
            ceremony_id=ceremony.ceremony_id,
            browser_credential=authenticator.assertion(ceremony.challenge),
        )

        assert record.state is JobState.RUNNING
        assert record.job_digest == job.job_digest
        assert store.read_ceremony(ceremony.ceremony_id).state is CeremonyState.CONSUMED
        assert len(store.approvals(job.job_id)) == 1
        assert store.approvals(job.job_id)[0].origin == ORIGIN


def test_bootstrap_endpoint_requires_kernel_root_peer() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = PosixRootActionStore(
            Path(temporary) / "root-actions",
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        authorization = RootActionAuthorizationService(
            store,
            WebAuthnVerifier(
                WebAuthnPolicy(RP_ID, "Root action", (ORIGIN,), USER_ID)
            ),
            dispatch=lambda _job_id, _job_digest: None,
            events=Events([("event-bootstrap", "2026-07-28T01:00:00Z")]),
        )
        broker = TypedRootActionBroker(
            store,
            submission_policy=SubmissionPolicy(
                allowed_uids=frozenset({1002}),
                allowed_gids=frozenset({1002}),
            ),
        )
        endpoint = RootActionBrokerEndpoint(
            broker,
            authorization=authorization,
        )
        frame = auth_request("auth_bootstrap_create")
        with pytest.raises(ValueError, match="root peer"):
            endpoint.handle(
                frame,
                peer=BrokerPeerIdentity(uid=1002, gid=1002, pid=55),
            )

        response = parse_response_frame(
            endpoint.handle(
                frame,
                peer=BrokerPeerIdentity(uid=0, gid=0, pid=1),
            )
        )
        assert response["method"] == "auth_bootstrap_create"
        assert len(response["bootstrap_token"]) == 43
