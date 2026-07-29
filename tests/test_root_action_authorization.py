from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from struct import pack

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from agent_runtime_ops.root_actions.authorization import (
    CeremonyPurpose,
    CredentialRole,
    PendingCeremony,
    WebAuthnAuthorizationError,
    WebAuthnPolicy,
    WebAuthnVerifier,
    action_challenge_bytes,
    registration_challenge_bytes,
)


ORIGIN = "https://ops.example.com"
RP_ID = "example.com"
USER_ID = bytes.fromhex("11" * 32)
ISSUED = "2026-07-28T01:00:00Z"
EXPIRES = "2026-07-28T01:02:00Z"
JOB_DIGEST = "sha256:" + "a" * 64


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def client_data(
    kind: str,
    challenge: bytes,
    *,
    origin: str = ORIGIN,
    cross_origin: bool | None = None,
    top_origin: str | None = None,
) -> bytes:
    value: dict[str, object] = {
        "type": kind,
        "challenge": b64(challenge),
        "origin": origin,
    }
    if cross_origin is not None:
        value["crossOrigin"] = cross_origin
    if top_origin is not None:
        value["topOrigin"] = top_origin
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class VirtualAuthenticator:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public = self.private_key.public_key().public_numbers()
        self.public_key_cose = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: public.x.to_bytes(32, "big"),
                -3: public.y.to_bytes(32, "big"),
            }
        )
        self.credential_id = bytes.fromhex("22" * 32)

    def registration(
        self,
        challenge: bytes,
        *,
        uv: bool = True,
        backed_up: bool = False,
        origin: str = ORIGIN,
        cross_origin: bool | None = None,
        top_origin: str | None = None,
        attachment: str = "platform",
    ) -> dict[str, object]:
        flags = 0x01 | 0x40
        if uv:
            flags |= 0x04
        if backed_up:
            flags |= 0x08 | 0x10
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([flags])
            + pack("!I", 0)
            + bytes(16)
            + pack("!H", len(self.credential_id))
            + self.credential_id
            + self.public_key_cose
        )
        attestation = cbor2.dumps(
            {"fmt": "none", "attStmt": {}, "authData": auth_data}
        )
        collected = client_data(
            "webauthn.create",
            challenge,
            origin=origin,
            cross_origin=cross_origin,
            top_origin=top_origin,
        )
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": attachment,
            "response": {
                "clientDataJSON": b64(collected),
                "attestationObject": b64(attestation),
                "transports": ["internal"],
            },
        }

    def assertion(
        self,
        challenge: bytes,
        *,
        sign_count: int = 1,
        uv: bool = True,
        backed_up: bool = False,
        origin: str = ORIGIN,
        cross_origin: bool | None = None,
        top_origin: str | None = None,
        user_handle: bytes = USER_ID,
    ) -> dict[str, object]:
        flags = 0x01
        if uv:
            flags |= 0x04
        if backed_up:
            flags |= 0x08 | 0x10
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([flags])
            + pack("!I", sign_count)
        )
        collected = client_data(
            "webauthn.get",
            challenge,
            origin=origin,
            cross_origin=cross_origin,
            top_origin=top_origin,
        )
        signature = self.private_key.sign(
            auth_data + hashlib.sha256(collected).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": b64(self.credential_id),
            "rawId": b64(self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(collected),
                "authenticatorData": b64(auth_data),
                "signature": b64(signature),
                "userHandle": b64(user_handle),
            },
        }


@pytest.fixture()
def policy() -> WebAuthnPolicy:
    return WebAuthnPolicy(
        rp_id=RP_ID,
        rp_name="Root action",
        allowed_origins=(ORIGIN,),
        user_id=USER_ID,
    )


@pytest.fixture()
def registration() -> PendingCeremony:
    nonce = bytes.fromhex("33" * 32)
    challenge = registration_challenge_bytes(
        bootstrap_id="bootstrap-one",
        role=CredentialRole.APPROVAL,
        label="office_windows_hello",
        nonce=nonce,
        expires_at=EXPIRES,
    )
    return PendingCeremony(
        ceremony_id="ceremony-registration",
        purpose=CeremonyPurpose.REGISTRATION,
        challenge=challenge,
        binding_nonce=nonce,
        challenge_digest="sha256:" + hashlib.sha256(challenge).hexdigest(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
        bootstrap_id="bootstrap-one",
        role=CredentialRole.APPROVAL,
        label="office_windows_hello",
    )


def approval() -> PendingCeremony:
    nonce = bytes.fromhex("44" * 32)
    challenge = action_challenge_bytes(
        job_digest=JOB_DIGEST,
        nonce=nonce,
        expires_at=EXPIRES,
    )
    return PendingCeremony(
        ceremony_id="ceremony-approval",
        purpose=CeremonyPurpose.APPROVAL,
        challenge=challenge,
        binding_nonce=nonce,
        challenge_digest="sha256:" + hashlib.sha256(challenge).hexdigest(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
        job_id="job-one",
        job_digest=JOB_DIGEST,
    )


def test_action_challenge_commits_digest_nonce_and_expiry() -> None:
    nonce = bytes.fromhex("55" * 32)
    first = action_challenge_bytes(
        job_digest=JOB_DIGEST, nonce=nonce, expires_at=EXPIRES
    )
    assert first == action_challenge_bytes(
        job_digest=JOB_DIGEST, nonce=nonce, expires_at=EXPIRES
    )
    assert first != action_challenge_bytes(
        job_digest="sha256:" + "b" * 64,
        nonce=nonce,
        expires_at=EXPIRES,
    )
    assert first != action_challenge_bytes(
        job_digest=JOB_DIGEST,
        nonce=bytes.fromhex("56" * 32),
        expires_at=EXPIRES,
    )


def test_policy_requires_exact_https_rp_origins() -> None:
    with pytest.raises(WebAuthnAuthorizationError, match="HTTPS"):
        WebAuthnPolicy(RP_ID, "Root", ("http://ops.example.com",), USER_ID)
    with pytest.raises(WebAuthnAuthorizationError, match="RP origin"):
        WebAuthnPolicy(RP_ID, "Root", ("https://attacker.example.net",), USER_ID)


def test_registration_requires_uv_and_rejects_cross_origin(
    policy: WebAuthnPolicy, registration: PendingCeremony
) -> None:
    authenticator = VirtualAuthenticator()
    verifier = WebAuthnVerifier(policy)
    options = verifier.registration_options(registration, exclude_credentials=())
    assert options["authenticatorSelection"]["userVerification"] == "required"

    registered = verifier.verify_registration(
        registration,
        authenticator.registration(registration.challenge),
        registered_at=ISSUED,
    )
    assert registered.credential_id == authenticator.credential_id
    assert registered.device_type == "single_device"
    assert not registered.backed_up

    with pytest.raises(WebAuthnAuthorizationError, match="cross-origin"):
        verifier.verify_registration(
            registration,
            authenticator.registration(registration.challenge, cross_origin=True),
            registered_at=ISSUED,
        )
    with pytest.raises(WebAuthnAuthorizationError, match="cross-origin"):
        verifier.verify_registration(
            registration,
            authenticator.registration(
                registration.challenge,
                top_origin="https://frame.example.com",
            ),
            registered_at=ISSUED,
        )
    with pytest.raises(Exception, match="verified"):
        verifier.verify_registration(
            registration,
            authenticator.registration(registration.challenge, uv=False),
            registered_at=ISSUED,
        )


def test_recovery_registration_rejects_synced_credential(
    policy: WebAuthnPolicy, registration: PendingCeremony
) -> None:
    authenticator = VirtualAuthenticator()
    verifier = WebAuthnVerifier(policy)
    challenge = registration_challenge_bytes(
        bootstrap_id=registration.bootstrap_id or "",
        role=CredentialRole.RECOVERY,
        label="recovery_fido2",
        nonce=registration.binding_nonce,
        expires_at=registration.expires_at,
    )
    recovery = replace(
        registration,
        role=CredentialRole.RECOVERY,
        label="recovery_fido2",
        challenge=challenge,
        challenge_digest="sha256:" + hashlib.sha256(challenge).hexdigest(),
    )
    options = verifier.registration_options(recovery, exclude_credentials=())
    assert options["authenticatorSelection"]["authenticatorAttachment"] == "cross-platform"
    with pytest.raises(WebAuthnAuthorizationError, match="attachment"):
        verifier.verify_registration(
            recovery,
            authenticator.registration(recovery.challenge),
            registered_at=ISSUED,
        )
    with pytest.raises(WebAuthnAuthorizationError, match="device-bound"):
        verifier.verify_registration(
            recovery,
            authenticator.registration(
                recovery.challenge,
                backed_up=True,
                attachment="cross-platform",
            ),
            registered_at=ISSUED,
        )


def test_ceremony_recomputes_the_exact_action_binding() -> None:
    valid = approval()
    with pytest.raises(WebAuthnAuthorizationError, match="binding mismatch"):
        replace(valid, binding_nonce=bytes.fromhex("99" * 32))


def test_assertion_is_uv_origin_user_and_counter_bound(
    policy: WebAuthnPolicy, registration: PendingCeremony
) -> None:
    authenticator = VirtualAuthenticator()
    verifier = WebAuthnVerifier(policy)
    registered = verifier.verify_registration(
        registration,
        authenticator.registration(registration.challenge),
        registered_at=ISSUED,
    )
    ceremony = approval()
    options = verifier.authentication_options(
        ceremony, credentials=(registered,)
    )
    assert options["userVerification"] == "required"
    verified = verifier.verify_assertion(
        ceremony,
        authenticator.assertion(ceremony.challenge),
        credential=registered,
    )
    assert verified.user_verified
    assert verified.new_sign_count == 1

    with pytest.raises(Exception, match="verified"):
        verifier.verify_assertion(
            ceremony,
            authenticator.assertion(ceremony.challenge, uv=False),
            credential=registered,
        )
    with pytest.raises(WebAuthnAuthorizationError, match="userHandle"):
        verifier.verify_assertion(
            ceremony,
            authenticator.assertion(
                ceremony.challenge, user_handle=bytes.fromhex("99" * 32)
            ),
            credential=registered,
        )
    with pytest.raises(WebAuthnAuthorizationError, match="not verified"):
        verifier.verify_assertion(
            ceremony,
            authenticator.assertion(
                ceremony.challenge, origin="https://evil.example.com"
            ),
            credential=registered,
        )
    with pytest.raises(WebAuthnAuthorizationError, match="not verified"):
        verifier.verify_assertion(
            ceremony,
            authenticator.assertion(ceremony.challenge, sign_count=1),
            credential=replace(registered, sign_count=1),
        )


def test_assertion_for_other_action_digest_fails(
    policy: WebAuthnPolicy, registration: PendingCeremony
) -> None:
    authenticator = VirtualAuthenticator()
    verifier = WebAuthnVerifier(policy)
    registered = verifier.verify_registration(
        registration,
        authenticator.registration(registration.challenge),
        registered_at=ISSUED,
    )
    expected = approval()
    other_challenge = action_challenge_bytes(
        job_digest="sha256:" + "b" * 64,
        nonce=bytes.fromhex("44" * 32),
        expires_at=EXPIRES,
    )
    with pytest.raises(WebAuthnAuthorizationError, match="not verified"):
        verifier.verify_assertion(
            expected,
            authenticator.assertion(other_challenge),
            credential=registered,
        )
