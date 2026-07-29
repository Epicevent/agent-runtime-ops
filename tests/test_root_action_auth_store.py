from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile

import pytest

from agent_runtime_ops.root_actions.authorization import (
    ApprovalRecord,
    BootstrapSession,
    BootstrapState,
    CeremonyPurpose,
    CeremonyState,
    CredentialRole,
    PendingCeremony,
    RegisteredCredential,
    VerifiedAssertion,
    action_challenge_bytes,
    bootstrap_token_digest,
    registration_challenge_bytes,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.posix_store import PosixRootActionStore
from agent_runtime_ops.root_actions.state import (
    JobState,
    StaleRevision,
    TransitionEvent,
    TransitionKind,
)
from agent_runtime_ops.root_actions.storage import StorageConflict
from tests.test_root_action_contracts import encoded, valid_manifest


ISSUED = "2026-07-28T01:00:00Z"
REGISTRATION_EXPIRES = "2026-07-28T01:05:00Z"
BOOTSTRAP_EXPIRES = "2026-07-28T01:10:00Z"
APPROVAL_EXPIRES = "2026-07-28T01:02:00Z"
VERIFIED_AT = "2026-07-28T01:01:00Z"


def make_store(root: Path) -> PosixRootActionStore:
    return PosixRootActionStore(
        root,
        create=True,
        required_uid=None,
        required_gid=None,
        require_posix=False,
    )


def make_registration(*, bootstrap_id: str = "bootstrap-test") -> PendingCeremony:
    nonce = bytes.fromhex("31" * 32)
    challenge = registration_challenge_bytes(
        bootstrap_id=bootstrap_id,
        role=CredentialRole.APPROVAL,
        label="office_windows_hello",
        nonce=nonce,
        expires_at=REGISTRATION_EXPIRES,
    )
    return PendingCeremony(
        ceremony_id="ceremony-registration-test",
        purpose=CeremonyPurpose.REGISTRATION,
        challenge=challenge,
        binding_nonce=nonce,
        challenge_digest="sha256:" + hashlib.sha256(challenge).hexdigest(),
        issued_at=ISSUED,
        expires_at=REGISTRATION_EXPIRES,
        bootstrap_id=bootstrap_id,
        role=CredentialRole.APPROVAL,
        label="office_windows_hello",
    )


def make_credential() -> RegisteredCredential:
    return RegisteredCredential(
        credential_id=bytes.fromhex("41" * 32),
        public_key=bytes.fromhex("42" * 64),
        sign_count=0,
        role=CredentialRole.APPROVAL,
        label="office_windows_hello",
        aaguid="00000000-0000-0000-0000-000000000000",
        device_type="single_device",
        backed_up=False,
        registered_at=ISSUED,
    )


def make_approval(job, index: int = 0) -> PendingCeremony:
    nonce = index.to_bytes(1, "big") + bytes.fromhex("51" * 31)
    challenge = action_challenge_bytes(
        job_digest=job.job_digest,
        nonce=nonce,
        expires_at=APPROVAL_EXPIRES,
    )
    return PendingCeremony(
        ceremony_id=f"ceremony-approval-{index}",
        purpose=CeremonyPurpose.APPROVAL,
        challenge=challenge,
        binding_nonce=nonce,
        challenge_digest="sha256:" + hashlib.sha256(challenge).hexdigest(),
        issued_at=ISSUED,
        expires_at=APPROVAL_EXPIRES,
        job_id=job.job_id,
        job_digest=job.job_digest,
    )


def make_approval_record(ceremony: PendingCeremony, credential: RegisteredCredential, index: int = 0) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=f"approval-{index}",
        ceremony_id=ceremony.ceremony_id,
        job_id=ceremony.job_id or "",
        job_digest=ceremony.job_digest or "",
        credential_fingerprint=credential.fingerprint,
        verified_at=VERIFIED_AT,
        origin="https://ops.example.com",
        rp_id="example.com",
        user_verified=True,
        sign_count=1,
    )


def make_claim(job, index: int = 0, *, revision: int = 0) -> TransitionEvent:
    return TransitionEvent(
        event_id=f"event-approved-claim-{index}",
        job_id=job.job_id,
        job_digest=job.job_digest,
        expected_revision=revision,
        kind=TransitionKind.CLAIM_EXECUTION,
        occurred_at=VERIFIED_AT,
    )


def enroll(store: PosixRootActionStore) -> RegisteredCredential:
    token = bytes.fromhex("61" * 32)
    bootstrap = BootstrapSession(
        bootstrap_id="bootstrap-test",
        token_digest=bootstrap_token_digest(token),
        issued_at=ISSUED,
        expires_at=BOOTSTRAP_EXPIRES,
        remaining_registrations=1,
    )
    store.create_auth_bootstrap(bootstrap)
    ceremony = make_registration()
    store.issue_registration_ceremony(
        token_digest=bootstrap.token_digest,
        ceremony=ceremony,
    )
    credential = make_credential()
    store.complete_registration(
        token_digest=bootstrap.token_digest,
        ceremony_id=ceremony.ceremony_id,
        credential=credential,
        consumed_at="2026-07-28T01:00:30Z",
    )
    return credential


def test_initial_bootstrap_cannot_be_recreated_after_consumption() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        enroll(store)
        second_token = bytes.fromhex("62" * 32)
        second = BootstrapSession(
            bootstrap_id="bootstrap-second",
            token_digest=bootstrap_token_digest(second_token),
            issued_at="2026-07-28T02:00:00Z",
            expires_at="2026-07-28T02:10:00Z",
            remaining_registrations=1,
        )

        with pytest.raises(StorageConflict, match="initial bootstrap"):
            store.create_auth_bootstrap(second)


def test_initial_bootstrap_allows_one_pre_enrollment_response_loss_recovery() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        first = BootstrapSession(
            bootstrap_id="bootstrap-expired",
            token_digest=bootstrap_token_digest(bytes.fromhex("63" * 32)),
            issued_at=ISSUED,
            expires_at=BOOTSTRAP_EXPIRES,
            remaining_registrations=1,
        )
        store.create_auth_bootstrap(first)
        second = BootstrapSession(
            bootstrap_id="bootstrap-after-expiry",
            token_digest=bootstrap_token_digest(bytes.fromhex("64" * 32)),
            issued_at="2026-07-28T03:00:00Z",
            expires_at="2026-07-28T03:10:00Z",
            remaining_registrations=1,
        )
        store.create_auth_bootstrap(second)

        assert store.read_auth_bootstrap(first.bootstrap_id).state is BootstrapState.EXPIRED
        assert store.read_auth_bootstrap(second.bootstrap_id) == second
        third = BootstrapSession(
            bootstrap_id="bootstrap-third",
            token_digest=bootstrap_token_digest(bytes.fromhex("65" * 32)),
            issued_at="2026-07-28T04:00:00Z",
            expires_at="2026-07-28T04:10:00Z",
            remaining_registrations=1,
        )
        with pytest.raises(StorageConflict, match="initial bootstrap"):
            store.create_auth_bootstrap(third)


def test_initial_bootstrap_reissue_is_blocked_after_registration_ceremony() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        first = BootstrapSession(
            bootstrap_id="bootstrap-with-ceremony",
            token_digest=bootstrap_token_digest(bytes.fromhex("66" * 32)),
            issued_at=ISSUED,
            expires_at=BOOTSTRAP_EXPIRES,
            remaining_registrations=1,
        )
        store.create_auth_bootstrap(first)
        store.issue_registration_ceremony(
            token_digest=first.token_digest,
            ceremony=make_registration(bootstrap_id=first.bootstrap_id),
        )
        replacement = BootstrapSession(
            bootstrap_id="bootstrap-after-ceremony",
            token_digest=bootstrap_token_digest(bytes.fromhex("67" * 32)),
            issued_at="2026-07-28T02:00:00Z",
            expires_at="2026-07-28T02:10:00Z",
            remaining_registrations=1,
        )

        with pytest.raises(StorageConflict, match="initial bootstrap"):
            store.create_auth_bootstrap(replacement)


def pending_job(store: PosixRootActionStore):
    job = seal_typed_manifest(encoded(valid_manifest()))
    store.seal_pending(
        job,
        event_id="event-auth-sealed",
        occurred_at=ISSUED,
    )
    return job


def verified(credential: RegisteredCredential) -> VerifiedAssertion:
    return VerifiedAssertion(
        credential_id=credential.credential_id,
        new_sign_count=1,
        user_verified=True,
        device_type=credential.device_type,
        backed_up=False,
        origin="https://ops.example.com",
        rp_id="example.com",
    )


def test_registration_and_approval_claim_are_persisted_atomically() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        credential = enroll(store)
        job = pending_job(store)
        ceremony = make_approval(job)
        store.issue_approval_ceremony(ceremony)

        record = store.claim_with_approval(
            ceremony=ceremony,
            credential=credential,
            verified=verified(credential),
            approval=make_approval_record(ceremony, credential),
            claim_event=make_claim(job),
        )

        assert record.state is JobState.RUNNING
        assert record.execution_count == 1
        assert store.read_credential(credential.credential_id).sign_count == 1
        assert store.read_ceremony(ceremony.ceremony_id).state is CeremonyState.CONSUMED
        assert store.approvals(job.job_id) == (
            make_approval_record(ceremony, credential),
        )


def test_failed_state_claim_rolls_back_counter_ceremony_and_approval() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        credential = enroll(store)
        job = pending_job(store)
        ceremony = make_approval(job)
        store.issue_approval_ceremony(ceremony)

        with pytest.raises(StaleRevision):
            store.claim_with_approval(
                ceremony=ceremony,
                credential=credential,
                verified=verified(credential),
                approval=make_approval_record(ceremony, credential),
                claim_event=make_claim(job, revision=9),
            )

        assert store.read_record(job.job_id).state is JobState.PENDING
        assert store.read_credential(credential.credential_id).sign_count == 0
        assert store.read_ceremony(ceremony.ceremony_id) == ceremony
        assert store.approvals(job.job_id) == ()


def test_parallel_valid_approvals_have_one_execution_winner() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        credential = enroll(store)
        job = pending_job(store)
        ceremonies = tuple(make_approval(job, index) for index in range(16))
        for ceremony in ceremonies:
            store.issue_approval_ceremony(ceremony)

        def claim(index: int) -> str:
            ceremony = ceremonies[index]
            try:
                store.claim_with_approval(
                    ceremony=ceremony,
                    credential=credential,
                    verified=verified(credential),
                    approval=make_approval_record(ceremony, credential, index),
                    claim_event=make_claim(job, index),
                )
                return "claimed"
            except StorageConflict:
                return "blocked"

        with ThreadPoolExecutor(max_workers=16) as executor:
            outcomes = tuple(executor.map(claim, range(16)))

        assert outcomes.count("claimed") == 1
        assert outcomes.count("blocked") == 15
        assert store.read_record(job.job_id).execution_count == 1
        assert len(store.approvals(job.job_id)) == 1


def test_v2_database_is_migrated_to_the_explicit_v3_auth_schema() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "root-actions"
        store = make_store(root)
        with store._connect() as connection:
            connection.executescript(
                """
                DROP TABLE root_action_auth_approvals;
                DROP TABLE root_action_auth_ceremonies;
                DROP TABLE root_action_auth_credentials;
                DROP TABLE root_action_auth_bootstrap;
                PRAGMA user_version=2;
                """
            )

        reopened = PosixRootActionStore(
            root,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        with reopened._connect() as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                if row[0].startswith("root_action_")
            }
        assert "root_action_auth_approvals" in tables
        assert "root_action_auth_credentials" in tables


def test_expiry_boundary_is_closed_and_leaves_the_job_pending() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        store = make_store(Path(temporary) / "root-actions")
        credential = enroll(store)
        job = pending_job(store)
        ceremony = make_approval(job)
        store.issue_approval_ceremony(ceremony)
        at_expiry = replace(
            make_approval_record(ceremony, credential),
            verified_at=APPROVAL_EXPIRES,
        )
        with pytest.raises(StorageConflict, match="expired"):
            store.claim_with_approval(
                ceremony=ceremony,
                credential=credential,
                verified=verified(credential),
                approval=at_expiry,
                claim_event=make_claim(job),
            )
        assert store.read_record(job.job_id).state is JobState.PENDING
