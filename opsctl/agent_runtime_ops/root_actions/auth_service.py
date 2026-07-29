from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Callable

from .authorization import (
    APPROVAL_CHALLENGE_SECONDS,
    BOOTSTRAP_SECONDS,
    REGISTRATION_CHALLENGE_SECONDS,
    ApprovalRecord,
    BootstrapSession,
    CeremonyPurpose,
    CredentialRole,
    PendingCeremony,
    RegisteredCredential,
    WebAuthnVerifier,
    action_challenge_bytes,
    bootstrap_token_digest,
    decoded_bootstrap_token,
    encoded_bootstrap_token,
    new_bootstrap_id,
    new_bootstrap_token,
    new_ceremony_id,
    public_credential_summary,
    registration_challenge_bytes,
)
from .broker import BrokerEventSource, SystemBrokerEventSource
from .posix_store import PosixRootActionStore
from .state import JobRecord, TransitionEvent, TransitionKind


@dataclass(frozen=True)
class CeremonyOptions:
    ceremony_id: str
    purpose: CeremonyPurpose
    expires_at: str
    public_key: dict[str, Any]
    job_id: str | None = None
    job_digest: str | None = None


@dataclass(frozen=True)
class RegistrationResult:
    credential: RegisteredCredential
    remaining_registrations: int


class RootActionAuthorizationService:
    """Root-owned WebAuthn ceremony and exact-action claim coordinator.

    The ordinary OPS process may transport browser messages, but only this
    service verifies them against root-owned credentials and consumes an
    approval in the same transaction as the one-shot execution claim.
    """

    def __init__(
        self,
        store: PosixRootActionStore,
        verifier: WebAuthnVerifier,
        *,
        dispatch: Callable[[str, str], None],
        events: BrokerEventSource | None = None,
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._dispatch = dispatch
        self._events = events or SystemBrokerEventSource()

    def create_initial_bootstrap(self) -> tuple[BootstrapSession, str]:
        _event_id, issued_at = self._events.next_event()
        token = new_bootstrap_token()
        session = BootstrapSession(
            bootstrap_id=new_bootstrap_id(),
            token_digest=bootstrap_token_digest(token),
            issued_at=issued_at,
            expires_at=_after(issued_at, BOOTSTRAP_SECONDS),
            remaining_registrations=3,
        )
        self._store.create_auth_bootstrap(session)
        return session, encoded_bootstrap_token(token)

    def status(self) -> dict[str, Any]:
        approval = self._store.active_credentials(CredentialRole.APPROVAL)
        recovery = self._store.active_credentials(CredentialRole.RECOVERY)
        return {
            "configured": bool(approval) and bool(recovery),
            "approval_ready": bool(approval),
            "recovery_ready": bool(recovery),
            "credentials": [
                public_credential_summary(item)
                for item in (*approval, *recovery)
            ],
        }

    def begin_registration(
        self,
        *,
        encoded_token: str,
        role: CredentialRole,
        label: str,
    ) -> CeremonyOptions:
        token_digest = bootstrap_token_digest(decoded_bootstrap_token(encoded_token))
        _event_id, issued_at = self._events.next_event()
        expires_at = _after(issued_at, REGISTRATION_CHALLENGE_SECONDS)
        nonce = secrets.token_bytes(32)
        bootstrap_id = self._bootstrap_id_for_token(token_digest)
        challenge = registration_challenge_bytes(
            bootstrap_id=bootstrap_id,
            role=role,
            label=label,
            nonce=nonce,
            expires_at=expires_at,
        )
        ceremony = PendingCeremony(
            ceremony_id=new_ceremony_id(),
            purpose=CeremonyPurpose.REGISTRATION,
            challenge=challenge,
            binding_nonce=nonce,
            challenge_digest=_sha256(challenge),
            issued_at=issued_at,
            expires_at=expires_at,
            bootstrap_id=bootstrap_id,
            role=role,
            label=label,
        )
        self._store.issue_registration_ceremony(
            token_digest=token_digest,
            ceremony=ceremony,
        )
        credentials = (
            *self._store.active_credentials(CredentialRole.APPROVAL),
            *self._store.active_credentials(CredentialRole.RECOVERY),
        )
        return CeremonyOptions(
            ceremony_id=ceremony.ceremony_id,
            purpose=ceremony.purpose,
            expires_at=ceremony.expires_at,
            public_key=self._verifier.registration_options(
                ceremony,
                exclude_credentials=credentials,
            ),
        )

    def finish_registration(
        self,
        *,
        encoded_token: str,
        ceremony_id: str,
        browser_credential: dict[str, Any],
    ) -> RegistrationResult:
        token_digest = bootstrap_token_digest(decoded_bootstrap_token(encoded_token))
        ceremony = self._store.read_ceremony(ceremony_id)
        _event_id, registered_at = self._events.next_event()
        credential = self._verifier.verify_registration(
            ceremony,
            browser_credential,
            registered_at=registered_at,
        )
        self._store.complete_registration(
            token_digest=token_digest,
            ceremony_id=ceremony_id,
            credential=credential,
            consumed_at=registered_at,
        )
        bootstrap = self._store.read_auth_bootstrap(ceremony.bootstrap_id or "")
        return RegistrationResult(
            credential=credential,
            remaining_registrations=bootstrap.remaining_registrations,
        )

    def begin_approval(self, *, job_id: str, job_digest: str) -> CeremonyOptions:
        job = self._store.read_sealed(job_id)
        if job.job_digest != job_digest:
            raise ValueError("approval request job digest mismatch")
        _event_id, issued_at = self._events.next_event()
        expires_at = _after(issued_at, APPROVAL_CHALLENGE_SECONDS)
        nonce = secrets.token_bytes(32)
        challenge = action_challenge_bytes(
            job_digest=job_digest,
            nonce=nonce,
            expires_at=expires_at,
        )
        ceremony = PendingCeremony(
            ceremony_id=new_ceremony_id(),
            purpose=CeremonyPurpose.APPROVAL,
            challenge=challenge,
            binding_nonce=nonce,
            challenge_digest=_sha256(challenge),
            issued_at=issued_at,
            expires_at=expires_at,
            job_id=job_id,
            job_digest=job_digest,
        )
        self._store.issue_approval_ceremony(ceremony)
        credentials = self._store.active_credentials(CredentialRole.APPROVAL)
        return CeremonyOptions(
            ceremony_id=ceremony.ceremony_id,
            purpose=ceremony.purpose,
            expires_at=ceremony.expires_at,
            public_key=self._verifier.authentication_options(
                ceremony,
                credentials=credentials,
            ),
            job_id=job_id,
            job_digest=job_digest,
        )

    def finish_approval(
        self,
        *,
        ceremony_id: str,
        browser_credential: dict[str, Any],
    ) -> JobRecord:
        ceremony = self._store.read_ceremony(ceremony_id)
        credential_id = self._verifier.credential_id(browser_credential)
        credential = self._store.read_credential(credential_id)
        if credential.role is not CredentialRole.APPROVAL:
            raise ValueError("recovery credential cannot approve an action")
        verified = self._verifier.verify_assertion(
            ceremony,
            browser_credential,
            credential=credential,
        )
        event_id, verified_at = self._events.next_event()
        approval = ApprovalRecord(
            approval_id="approval-" + secrets.token_hex(16),
            ceremony_id=ceremony.ceremony_id,
            job_id=ceremony.job_id or "",
            job_digest=ceremony.job_digest or "",
            credential_fingerprint=credential.fingerprint,
            verified_at=verified_at,
            origin=verified.origin,
            rp_id=verified.rp_id,
            user_verified=verified.user_verified,
            sign_count=verified.new_sign_count,
        )
        record = self._store.claim_with_approval(
            ceremony=ceremony,
            credential=credential,
            verified=verified,
            approval=approval,
            claim_event=TransitionEvent(
                event_id=event_id,
                job_id=approval.job_id,
                job_digest=approval.job_digest,
                expected_revision=0,
                kind=TransitionKind.CLAIM_EXECUTION,
                occurred_at=verified_at,
            ),
        )
        self._dispatch(record.job_id, record.job_digest)
        return record

    def _bootstrap_id_for_token(self, token_digest: str) -> str:
        return self._store.read_auth_bootstrap_by_token(token_digest).bootstrap_id


def _after(value: str, seconds: int) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()
