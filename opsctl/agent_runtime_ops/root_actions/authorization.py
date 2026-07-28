from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import os
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers.exceptions import WebAuthnException


AUTHORIZATION_SCHEMA = "agent-runtime-root-action-authorization/v1"
APPROVAL_CHALLENGE_SECONDS = 120
REGISTRATION_CHALLENGE_SECONDS = 300
BOOTSTRAP_SECONDS = 600
MAX_CREDENTIAL_BYTES = 4096
MAX_BROWSER_CREDENTIAL_BYTES = 256 * 1024
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_RP_ID_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_TIMESTAMP_RE = re.compile(
    r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
_LABEL_ROLES = {
    "office_windows_hello": "approval",
    "remote_phone_passkey": "approval",
    "recovery_fido2": "recovery",
}


class WebAuthnAuthorizationError(ValueError):
    """A WebAuthn ceremony cannot cross the root authorization boundary."""


class CredentialRole(str, Enum):
    APPROVAL = "approval"
    RECOVERY = "recovery"


class CeremonyPurpose(str, Enum):
    APPROVAL = "approval"
    REGISTRATION = "registration"
    RECOVERY = "recovery"


class CeremonyState(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class BootstrapState(str, Enum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"


def _timestamp(value: str, field: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise WebAuthnAuthorizationError(f"{field} must be an RFC3339 UTC second timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise WebAuthnAuthorizationError(f"{field} is not a real timestamp") from exc
    return value


def _safe_id(value: str, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise WebAuthnAuthorizationError(f"{field} must be a safe identifier")
    return value


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise WebAuthnAuthorizationError(f"{field} must be a sha256 digest")
    return value


def _bounded_bytes(value: bytes, field: str, maximum: int = MAX_CREDENTIAL_BYTES) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > maximum:
        raise WebAuthnAuthorizationError(f"{field} byte length is invalid")
    return value


def _canonical_browser_credential(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WebAuthnAuthorizationError("browser credential must be an object")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WebAuthnAuthorizationError("browser credential is not JSON") from exc
    if not encoded or len(encoded) > MAX_BROWSER_CREDENTIAL_BYTES:
        raise WebAuthnAuthorizationError("browser credential byte length is invalid")
    return json.loads(encoded.decode("utf-8"))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class WebAuthnPolicy:
    rp_id: str
    rp_name: str
    allowed_origins: tuple[str, ...]
    user_id: bytes
    user_name: str = "root-action-owner"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.rp_id, str)
            or self.rp_id != self.rp_id.lower()
            or _RP_ID_RE.fullmatch(self.rp_id) is None
        ):
            raise WebAuthnAuthorizationError("rp_id must be a canonical lower-case domain")
        if not isinstance(self.rp_name, str) or not 1 <= len(self.rp_name.encode("utf-8")) <= 128:
            raise WebAuthnAuthorizationError("rp_name must be bounded")
        if not isinstance(self.allowed_origins, tuple) or not self.allowed_origins:
            raise WebAuthnAuthorizationError("at least one allowed origin is required")
        if len(set(self.allowed_origins)) != len(self.allowed_origins):
            raise WebAuthnAuthorizationError("allowed origins must be unique")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or origin.endswith("/")
                or (
                    parsed.hostname != self.rp_id
                    and not parsed.hostname.endswith("." + self.rp_id)
                )
            ):
                raise WebAuthnAuthorizationError("allowed origin is not a canonical HTTPS RP origin")
        _bounded_bytes(self.user_id, "user_id", 64)
        _safe_id(self.user_name, "user_name")

    @classmethod
    def from_environment(cls) -> "WebAuthnPolicy":
        rp_id = os.environ.get("ROOT_ACTION_WEBAUTHN_RP_ID", "").strip()
        raw_origins = os.environ.get("ROOT_ACTION_WEBAUTHN_ORIGINS", "")
        origins = tuple(item.strip() for item in raw_origins.split(",") if item.strip())
        user_id_hex = os.environ.get("ROOT_ACTION_WEBAUTHN_USER_ID", "").strip()
        try:
            user_id = bytes.fromhex(user_id_hex)
        except ValueError as exc:
            raise WebAuthnAuthorizationError(
                "ROOT_ACTION_WEBAUTHN_USER_ID must be hex"
            ) from exc
        return cls(
            rp_id=rp_id,
            rp_name=os.environ.get(
                "ROOT_ACTION_WEBAUTHN_RP_NAME", "JI TECH root action"
            ).strip(),
            allowed_origins=origins,
            user_id=user_id,
        )


@dataclass(frozen=True)
class RegisteredCredential:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    role: CredentialRole
    label: str
    aaguid: str
    device_type: str
    backed_up: bool
    registered_at: str
    revoked_at: str | None = None

    def __post_init__(self) -> None:
        _bounded_bytes(self.credential_id, "credential_id")
        _bounded_bytes(self.public_key, "public_key", 16 * 1024)
        if isinstance(self.sign_count, bool) or not isinstance(self.sign_count, int) or self.sign_count < 0:
            raise WebAuthnAuthorizationError("sign_count must be a non-negative integer")
        if not isinstance(self.role, CredentialRole):
            raise WebAuthnAuthorizationError("credential role is invalid")
        if _LABEL_ROLES.get(self.label) != self.role.value:
            raise WebAuthnAuthorizationError("credential label does not match its role")
        _safe_id(self.aaguid, "aaguid")
        if self.device_type not in {"single_device", "multi_device"}:
            raise WebAuthnAuthorizationError("credential device type is invalid")
        if not isinstance(self.backed_up, bool):
            raise WebAuthnAuthorizationError("credential backed_up flag is invalid")
        _timestamp(self.registered_at, "registered_at")
        if self.revoked_at is not None:
            _timestamp(self.revoked_at, "revoked_at")
            if self.revoked_at < self.registered_at:
                raise WebAuthnAuthorizationError("revocation precedes registration")
        if self.role is CredentialRole.RECOVERY and (
            self.device_type != "single_device" or self.backed_up
        ):
            raise WebAuthnAuthorizationError(
                "recovery credential must be device-bound and not backed up"
            )

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(
            b"agent-runtime-root-action-credential/v1\x00" + self.credential_id
        ).hexdigest()


@dataclass(frozen=True)
class BootstrapSession:
    bootstrap_id: str
    token_digest: str
    issued_at: str
    expires_at: str
    remaining_registrations: int
    state: BootstrapState = BootstrapState.ISSUED

    def __post_init__(self) -> None:
        _safe_id(self.bootstrap_id, "bootstrap_id")
        _digest(self.token_digest, "token_digest")
        _timestamp(self.issued_at, "issued_at")
        _timestamp(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise WebAuthnAuthorizationError("bootstrap must expire after issue")
        if (
            isinstance(self.remaining_registrations, bool)
            or not isinstance(self.remaining_registrations, int)
            or not 0 <= self.remaining_registrations <= 3
        ):
            raise WebAuthnAuthorizationError(
                "bootstrap remaining registration count is invalid"
            )
        if not isinstance(self.state, BootstrapState):
            raise WebAuthnAuthorizationError("bootstrap state is invalid")
        if self.state is BootstrapState.ISSUED and self.remaining_registrations < 1:
            raise WebAuthnAuthorizationError(
                "issued bootstrap must have a remaining registration"
            )
        if self.state is BootstrapState.CONSUMED and self.remaining_registrations != 0:
            raise WebAuthnAuthorizationError(
                "consumed bootstrap cannot have remaining registrations"
            )


@dataclass(frozen=True)
class PendingCeremony:
    ceremony_id: str
    purpose: CeremonyPurpose
    challenge: bytes
    binding_nonce: bytes
    challenge_digest: str
    issued_at: str
    expires_at: str
    job_id: str | None = None
    job_digest: str | None = None
    bootstrap_id: str | None = None
    role: CredentialRole | None = None
    label: str | None = None
    state: CeremonyState = CeremonyState.ISSUED
    consumed_at: str | None = None
    credential_fingerprint: str | None = None

    def __post_init__(self) -> None:
        _safe_id(self.ceremony_id, "ceremony_id")
        if not isinstance(self.purpose, CeremonyPurpose):
            raise WebAuthnAuthorizationError("ceremony purpose is invalid")
        _bounded_bytes(self.challenge, "challenge", 64)
        if not isinstance(self.binding_nonce, bytes) or len(self.binding_nonce) != 32:
            raise WebAuthnAuthorizationError("ceremony binding nonce must contain 32 bytes")
        _digest(self.challenge_digest, "challenge_digest")
        if self.challenge_digest != "sha256:" + hashlib.sha256(self.challenge).hexdigest():
            raise WebAuthnAuthorizationError("challenge digest mismatch")
        _timestamp(self.issued_at, "issued_at")
        _timestamp(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise WebAuthnAuthorizationError("ceremony must expire after issue")
        if not isinstance(self.state, CeremonyState):
            raise WebAuthnAuthorizationError("ceremony state is invalid")
        if self.state is CeremonyState.ISSUED:
            if self.consumed_at is not None or self.credential_fingerprint is not None:
                raise WebAuthnAuthorizationError("issued ceremony has consumption metadata")
        else:
            _timestamp(self.consumed_at or "", "consumed_at")
            if self.consumed_at and self.consumed_at < self.issued_at:
                raise WebAuthnAuthorizationError("ceremony consumption precedes issue")
            if self.credential_fingerprint is not None:
                _digest(self.credential_fingerprint, "credential_fingerprint")
        if self.purpose is CeremonyPurpose.APPROVAL:
            _safe_id(self.job_id or "", "job_id")
            _digest(self.job_digest or "", "job_digest")
            if any(value is not None for value in (self.bootstrap_id, self.role, self.label)):
                raise WebAuthnAuthorizationError("approval ceremony has registration fields")
            if self.challenge != action_challenge_bytes(
                job_digest=self.job_digest or "",
                nonce=self.binding_nonce,
                expires_at=self.expires_at,
            ):
                raise WebAuthnAuthorizationError("approval challenge binding mismatch")
        elif self.purpose is CeremonyPurpose.REGISTRATION:
            _safe_id(self.bootstrap_id or "", "bootstrap_id")
            if not isinstance(self.role, CredentialRole) or _LABEL_ROLES.get(self.label or "") != self.role.value:
                raise WebAuthnAuthorizationError("registration role or label is invalid")
            if self.job_id is not None or self.job_digest is not None:
                raise WebAuthnAuthorizationError("registration ceremony has job fields")
            if self.challenge != registration_challenge_bytes(
                bootstrap_id=self.bootstrap_id or "",
                role=self.role,
                label=self.label or "",
                nonce=self.binding_nonce,
                expires_at=self.expires_at,
            ):
                raise WebAuthnAuthorizationError("registration challenge binding mismatch")
        else:
            raise WebAuthnAuthorizationError(
                "recovery ceremony remains fail-closed until its replacement scope is implemented"
            )


@dataclass(frozen=True)
class VerifiedAssertion:
    credential_id: bytes
    new_sign_count: int
    user_verified: bool
    device_type: str
    backed_up: bool
    origin: str
    rp_id: str

    def __post_init__(self) -> None:
        _bounded_bytes(self.credential_id, "credential_id")
        if (
            isinstance(self.new_sign_count, bool)
            or not isinstance(self.new_sign_count, int)
            or self.new_sign_count < 0
        ):
            raise WebAuthnAuthorizationError("assertion sign count is invalid")
        if self.user_verified is not True:
            raise WebAuthnAuthorizationError("assertion did not verify the user")
        if self.device_type not in {"single_device", "multi_device"}:
            raise WebAuthnAuthorizationError("assertion device type is invalid")
        if not isinstance(self.backed_up, bool):
            raise WebAuthnAuthorizationError("assertion backup state is invalid")
        if not isinstance(self.origin, str) or len(self.origin) > 512:
            raise WebAuthnAuthorizationError("assertion origin is invalid")
        if not isinstance(self.rp_id, str) or _RP_ID_RE.fullmatch(self.rp_id) is None:
            raise WebAuthnAuthorizationError("assertion RP ID is invalid")


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    ceremony_id: str
    job_id: str
    job_digest: str
    credential_fingerprint: str
    verified_at: str
    origin: str
    rp_id: str
    user_verified: bool
    sign_count: int

    def __post_init__(self) -> None:
        _safe_id(self.approval_id, "approval_id")
        _safe_id(self.ceremony_id, "ceremony_id")
        _safe_id(self.job_id, "job_id")
        _digest(self.job_digest, "job_digest")
        _digest(self.credential_fingerprint, "credential_fingerprint")
        _timestamp(self.verified_at, "verified_at")
        if not isinstance(self.origin, str) or len(self.origin) > 512:
            raise WebAuthnAuthorizationError("approval origin is invalid")
        if not isinstance(self.rp_id, str) or _RP_ID_RE.fullmatch(self.rp_id) is None:
            raise WebAuthnAuthorizationError("approval RP ID is invalid")
        if self.user_verified is not True:
            raise WebAuthnAuthorizationError("approval must record user verification")
        if isinstance(self.sign_count, bool) or not isinstance(self.sign_count, int) or self.sign_count < 0:
            raise WebAuthnAuthorizationError("approval sign count is invalid")


def credential_fingerprint(credential_id: bytes) -> str:
    _bounded_bytes(credential_id, "credential_id")
    return "sha256:" + hashlib.sha256(
        b"agent-runtime-root-action-credential/v1\x00" + credential_id
    ).hexdigest()


def bootstrap_token_digest(token: bytes) -> str:
    _bounded_bytes(token, "bootstrap_token", 64)
    return "sha256:" + hashlib.sha256(
        b"agent-runtime-root-action-bootstrap/v1\x00" + token
    ).hexdigest()


def action_challenge_bytes(
    *, job_digest: str, nonce: bytes, expires_at: str
) -> bytes:
    _digest(job_digest, "job_digest")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise WebAuthnAuthorizationError("approval nonce must contain 32 bytes")
    _timestamp(expires_at, "expires_at")
    return hashlib.sha256(
        b"agent-runtime-root-action-approval/v1\x00"
        + job_digest.encode("ascii")
        + b"\x00"
        + nonce
        + b"\x00"
        + expires_at.encode("ascii")
    ).digest()


def registration_challenge_bytes(
    *,
    bootstrap_id: str,
    role: CredentialRole,
    label: str,
    nonce: bytes,
    expires_at: str,
) -> bytes:
    _safe_id(bootstrap_id, "bootstrap_id")
    if not isinstance(role, CredentialRole) or _LABEL_ROLES.get(label) != role.value:
        raise WebAuthnAuthorizationError("registration role or label is invalid")
    if not isinstance(nonce, bytes) or len(nonce) != 32:
        raise WebAuthnAuthorizationError("registration nonce must contain 32 bytes")
    _timestamp(expires_at, "expires_at")
    return hashlib.sha256(
        b"agent-runtime-root-action-registration/v1\x00"
        + bootstrap_id.encode("ascii")
        + b"\x00"
        + role.value.encode("ascii")
        + b"\x00"
        + label.encode("ascii")
        + b"\x00"
        + nonce
        + b"\x00"
        + expires_at.encode("ascii")
    ).digest()


def new_ceremony_id() -> str:
    return "ceremony-" + secrets.token_hex(16)


def new_bootstrap_id() -> str:
    return "bootstrap-" + secrets.token_hex(16)


def new_bootstrap_token() -> bytes:
    return secrets.token_bytes(32)


def _client_data_json(browser_credential: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = browser_credential["response"]["clientDataJSON"]
        raw = base64url_to_bytes(encoded)
        value = json.loads(raw.decode("utf-8"))
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnAuthorizationError("clientDataJSON is malformed") from exc
    if not isinstance(value, dict):
        raise WebAuthnAuthorizationError("clientDataJSON must be an object")
    if value.get("crossOrigin") is True or "topOrigin" in value:
        raise WebAuthnAuthorizationError("cross-origin WebAuthn ceremonies are forbidden")
    return value


def _credential_id(browser_credential: dict[str, Any]) -> bytes:
    try:
        raw_id = base64url_to_bytes(browser_credential["rawId"])
        identifier = base64url_to_bytes(browser_credential["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WebAuthnAuthorizationError("credential identity is malformed") from exc
    if raw_id != identifier:
        raise WebAuthnAuthorizationError("credential id and rawId differ")
    return _bounded_bytes(raw_id, "credential_id")


def _verify_user_handle(
    browser_credential: dict[str, Any], expected_user_id: bytes
) -> None:
    raw = browser_credential.get("response", {}).get("userHandle")
    if raw is None:
        return
    try:
        user_handle = base64url_to_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise WebAuthnAuthorizationError("userHandle is malformed") from exc
    if user_handle != expected_user_id:
        raise WebAuthnAuthorizationError("userHandle does not identify the root-action owner")


class WebAuthnVerifier:
    """Thin strict adapter around py_webauthn for the root-owned verifier."""

    def __init__(self, policy: WebAuthnPolicy) -> None:
        self.policy = policy

    def registration_options(
        self,
        ceremony: PendingCeremony,
        *,
        exclude_credentials: tuple[RegisteredCredential, ...],
    ) -> dict[str, Any]:
        if ceremony.purpose is not CeremonyPurpose.REGISTRATION:
            raise WebAuthnAuthorizationError("registration options require a registration ceremony")
        attachment = (
            AuthenticatorAttachment.CROSS_PLATFORM
            if ceremony.role is CredentialRole.RECOVERY
            else AuthenticatorAttachment.PLATFORM
        )
        options = generate_registration_options(
            rp_id=self.policy.rp_id,
            rp_name=self.policy.rp_name,
            user_name=self.policy.user_name,
            user_id=self.policy.user_id,
            user_display_name="Root action owner",
            challenge=ceremony.challenge,
            timeout=REGISTRATION_CHALLENGE_SECONDS * 1000,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=attachment,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=item.credential_id)
                for item in exclude_credentials
                if item.revoked_at is None
            ],
        )
        return json.loads(options_to_json(options))

    def verify_registration(
        self,
        ceremony: PendingCeremony,
        browser_credential: dict[str, Any],
        *,
        registered_at: str,
    ) -> RegisteredCredential:
        if ceremony.purpose is not CeremonyPurpose.REGISTRATION:
            raise WebAuthnAuthorizationError("registration verification requires a registration ceremony")
        credential = _canonical_browser_credential(browser_credential)
        _client_data_json(credential)
        expected_attachment = (
            "cross-platform"
            if ceremony.role is CredentialRole.RECOVERY
            else "platform"
        )
        if credential.get("authenticatorAttachment") != expected_attachment:
            raise WebAuthnAuthorizationError(
                "registration authenticator attachment does not match its fixed role"
            )
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=ceremony.challenge,
                expected_rp_id=self.policy.rp_id,
                expected_origin=list(self.policy.allowed_origins),
                require_user_presence=True,
                require_user_verification=True,
            )
        except WebAuthnException as exc:
            raise WebAuthnAuthorizationError(
                "registration response was not verified"
            ) from exc
        role = ceremony.role
        assert role is not None and ceremony.label is not None
        device_type = verified.credential_device_type.value
        return RegisteredCredential(
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            role=role,
            label=ceremony.label,
            aaguid=verified.aaguid,
            device_type=device_type,
            backed_up=verified.credential_backed_up,
            registered_at=_timestamp(registered_at, "registered_at"),
        )

    def authentication_options(
        self,
        ceremony: PendingCeremony,
        *,
        credentials: tuple[RegisteredCredential, ...],
    ) -> dict[str, Any]:
        if ceremony.purpose not in {CeremonyPurpose.APPROVAL, CeremonyPurpose.RECOVERY}:
            raise WebAuthnAuthorizationError("authentication options require an assertion ceremony")
        active = tuple(item for item in credentials if item.revoked_at is None)
        if not active:
            raise WebAuthnAuthorizationError("no active credential is available")
        options = generate_authentication_options(
            rp_id=self.policy.rp_id,
            challenge=ceremony.challenge,
            timeout=APPROVAL_CHALLENGE_SECONDS * 1000,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=item.credential_id) for item in active
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options))

    def credential_id(self, browser_credential: dict[str, Any]) -> bytes:
        credential = _canonical_browser_credential(browser_credential)
        return _credential_id(credential)

    def verify_assertion(
        self,
        ceremony: PendingCeremony,
        browser_credential: dict[str, Any],
        *,
        credential: RegisteredCredential,
    ) -> VerifiedAssertion:
        if ceremony.purpose not in {CeremonyPurpose.APPROVAL, CeremonyPurpose.RECOVERY}:
            raise WebAuthnAuthorizationError("assertion verification requires an authentication ceremony")
        if credential.revoked_at is not None:
            raise WebAuthnAuthorizationError("credential is revoked")
        browser = _canonical_browser_credential(browser_credential)
        client_data = _client_data_json(browser)
        _verify_user_handle(browser, self.policy.user_id)
        if _credential_id(browser) != credential.credential_id:
            raise WebAuthnAuthorizationError("assertion credential does not match the stored record")
        try:
            verified = verify_authentication_response(
                credential=browser,
                expected_challenge=ceremony.challenge,
                expected_rp_id=self.policy.rp_id,
                expected_origin=list(self.policy.allowed_origins),
                credential_public_key=credential.public_key,
                credential_current_sign_count=credential.sign_count,
                require_user_verification=True,
            )
        except WebAuthnException as exc:
            raise WebAuthnAuthorizationError(
                "assertion response was not verified"
            ) from exc
        return VerifiedAssertion(
            credential_id=verified.credential_id,
            new_sign_count=verified.new_sign_count,
            user_verified=verified.user_verified,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
            origin=client_data["origin"],
            rp_id=self.policy.rp_id,
        )


def public_credential_summary(credential: RegisteredCredential) -> dict[str, Any]:
    return {
        "fingerprint": credential.fingerprint,
        "role": credential.role.value,
        "label": credential.label,
        "device_type": credential.device_type,
        "backed_up": credential.backed_up,
        "registered_at": credential.registered_at,
        "revoked_at": credential.revoked_at,
    }


def encoded_bootstrap_token(token: bytes) -> str:
    _bounded_bytes(token, "bootstrap_token", 64)
    return _b64url(token)


def decoded_bootstrap_token(value: str) -> bytes:
    try:
        token = base64url_to_bytes(value)
    except (TypeError, ValueError) as exc:
        raise WebAuthnAuthorizationError("bootstrap token is malformed") from exc
    if len(token) != 32:
        raise WebAuthnAuthorizationError("bootstrap token length is invalid")
    return token
