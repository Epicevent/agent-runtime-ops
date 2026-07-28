from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Callable, Sequence
from urllib.parse import urlsplit


ROOT_ACTION_WEBAUTHN_ENV = Path(
    "/etc/agent-runtime-ops/root-action-webauthn.env"
)
ROOT_ACTION_BROKER_SERVICE = "agent-runtime-root-action-broker.service"
ROOT_ACTION_RP_NAME = "JI TECH root action"
ROOT_ACTION_ACTIVATION_SCHEMA = "agent-runtime-root-action-activation/v1"
_ENV_KEYS = {
    "ROOT_ACTION_WEBAUTHN_RP_ID",
    "ROOT_ACTION_WEBAUTHN_ORIGINS",
    "ROOT_ACTION_WEBAUTHN_USER_ID",
    "ROOT_ACTION_WEBAUTHN_RP_NAME",
}
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


class RootActionActivationError(ValueError):
    pass


@dataclass(frozen=True)
class RootActionActivationConfig:
    rp_id: str
    origin: str

    def __post_init__(self) -> None:
        if self.rp_id != self.rp_id.lower() or not _DOMAIN_RE.fullmatch(self.rp_id):
            raise RootActionActivationError("rp_id must be a canonical lowercase domain")
        parsed = urlsplit(self.origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != self.rp_id
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path != ""
            or parsed.query
            or parsed.fragment
            or self.origin != f"https://{self.rp_id}"
        ):
            raise RootActionActivationError(
                "origin must be the exact portless HTTPS origin for rp_id"
            )


RunCommand = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _run_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _parse_env(raw: bytes) -> dict[str, str]:
    if not raw or len(raw) > 4096:
        raise RootActionActivationError("existing WebAuthn environment is invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RootActionActivationError(
            "existing WebAuthn environment is invalid"
        ) from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RootActionActivationError("existing WebAuthn environment is invalid")
        key, value = line.split("=", 1)
        if key not in _ENV_KEYS or key in values or not value:
            raise RootActionActivationError("existing WebAuthn environment is invalid")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise RootActionActivationError("existing WebAuthn environment is invalid")
        values[key] = value
    if set(values) != _ENV_KEYS:
        raise RootActionActivationError("existing WebAuthn environment is invalid")
    if not re.fullmatch(
        r"[0-9a-f]{64}", values["ROOT_ACTION_WEBAUTHN_USER_ID"]
    ):
        raise RootActionActivationError("existing WebAuthn environment is invalid")
    return values


def _expected_values(
    config: RootActionActivationConfig, user_id: str
) -> dict[str, str]:
    return {
        "ROOT_ACTION_WEBAUTHN_RP_ID": config.rp_id,
        "ROOT_ACTION_WEBAUTHN_ORIGINS": config.origin,
        "ROOT_ACTION_WEBAUTHN_USER_ID": user_id,
        "ROOT_ACTION_WEBAUTHN_RP_NAME": ROOT_ACTION_RP_NAME,
    }


def _render_env(values: dict[str, str]) -> bytes:
    ordered = [
        "ROOT_ACTION_WEBAUTHN_RP_ID",
        "ROOT_ACTION_WEBAUTHN_ORIGINS",
        "ROOT_ACTION_WEBAUTHN_USER_ID",
        "ROOT_ACTION_WEBAUTHN_RP_NAME",
    ]
    return ("".join(f"{key}={values[key]}\n" for key in ordered)).encode("utf-8")


def _verify_parent(
    parent: Path,
    *,
    expected_owner_uid: int,
    enforce_posix_permissions: bool,
) -> None:
    parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    metadata = parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RootActionActivationError(
            "WebAuthn environment directory is not trusted"
        )
    if enforce_posix_permissions and (
        metadata.st_uid != expected_owner_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RootActionActivationError(
            "WebAuthn environment directory is not trusted"
        )


def _read_existing(
    path: Path,
    config: RootActionActivationConfig,
    *,
    expected_owner_uid: int,
    enforce_posix_permissions: bool,
) -> str | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RootActionActivationError(
            "existing WebAuthn environment ownership or mode is invalid"
        )
    if enforce_posix_permissions and (
        metadata.st_uid != expected_owner_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RootActionActivationError(
            "existing WebAuthn environment ownership or mode is invalid"
        )
    values = _parse_env(path.read_bytes())
    user_id = values["ROOT_ACTION_WEBAUTHN_USER_ID"]
    if values != _expected_values(config, user_id):
        raise RootActionActivationError(
            "existing WebAuthn environment does not match requested RP"
        )
    return user_id


def _write_new_env(
    path: Path,
    config: RootActionActivationConfig,
    *,
    expected_owner_uid: int,
    enforce_posix_permissions: bool,
) -> str:
    _verify_parent(
        path.parent,
        expected_owner_uid=expected_owner_uid,
        enforce_posix_permissions=enforce_posix_permissions,
    )
    user_id = secrets.token_hex(32)
    raw = _render_env(_expected_values(config, user_id))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = -1
        if path.exists() or path.is_symlink():
            raise RootActionActivationError(
                "WebAuthn environment appeared during creation"
            )
        os.replace(temporary, path)
        if enforce_posix_permissions:
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    observed = _read_existing(
        path,
        config,
        expected_owner_uid=expected_owner_uid,
        enforce_posix_permissions=enforce_posix_permissions,
    )
    if observed != user_id:
        raise RootActionActivationError("WebAuthn environment verification failed")
    return user_id


def activate_root_action_broker(
    config: RootActionActivationConfig,
    *,
    env_path: Path = ROOT_ACTION_WEBAUTHN_ENV,
    expected_owner_uid: int = 0,
    enforce_posix_permissions: bool = True,
    run_command: RunCommand = _run_command,
) -> dict[str, object]:
    existing_user_id = _read_existing(
        env_path,
        config,
        expected_owner_uid=expected_owner_uid,
        enforce_posix_permissions=enforce_posix_permissions,
    )
    created = existing_user_id is None
    user_id = existing_user_id or _write_new_env(
        env_path,
        config,
        expected_owner_uid=expected_owner_uid,
        enforce_posix_permissions=enforce_posix_permissions,
    )
    commands = [
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", "--now", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-enabled", "--quiet", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "is-active", "--quiet", ROOT_ACTION_BROKER_SERVICE),
    ]
    for command in commands:
        completed = run_command(command)
        if completed.returncode != 0:
            raise RootActionActivationError(
                "root-action broker activation failed closed"
            )
    return {
        "schema": ROOT_ACTION_ACTIVATION_SCHEMA,
        "rp_id": config.rp_id,
        "origin": config.origin,
        "environment": str(env_path),
        "environment_created": created,
        "user_id_fingerprint": "sha256:"
        + hashlib.sha256(bytes.fromhex(user_id)).hexdigest(),
        "service": ROOT_ACTION_BROKER_SERVICE,
        "enabled": True,
        "active": True,
    }
