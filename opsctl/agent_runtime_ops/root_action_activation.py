from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Sequence
from urllib.parse import urlsplit


ROOT_ACTION_WEBAUTHN_ENV = Path("/etc/agent-runtime-ops/root-action-webauthn.env")
ROOT_ACTION_BROKER_SERVICE = "agent-runtime-root-action-broker.service"
ROOT_ACTION_RP_NAME = "JI TECH root action"
ROOT_ACTION_ACTIVATION_SCHEMA = "agent-runtime-root-action-activation/v1"
ROOT_ACTION_RUNNING_RELEASE_ENV = "AGENT_RUNTIME_OPS_RELEASE"
ROOT_ACTION_PROCESS_ENV_MAX_BYTES = 64 * 1024
ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS = 40
ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS = 0.25
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
            raise RootActionActivationError(
                "rp_id must be a canonical lowercase domain"
            )
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
ReadRunningEnvironment = Callable[[int], bytes]
Sleep = Callable[[float], None]


def _run_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _read_running_environment(pid: int) -> bytes:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise RootActionActivationError("root-action broker MainPID is invalid")
    try:
        with Path(f"/proc/{pid}/environ").open("rb") as stream:
            raw = stream.read(ROOT_ACTION_PROCESS_ENV_MAX_BYTES + 1)
    except OSError as exc:
        raise RootActionActivationError(
            "root-action broker running release could not be verified"
        ) from exc
    if not raw or len(raw) > ROOT_ACTION_PROCESS_ENV_MAX_BYTES:
        raise RootActionActivationError(
            "root-action broker running release could not be verified"
        )
    return raw


def _installed_release() -> Path:
    try:
        release = Path(sys.prefix).resolve(strict=True).parent
    except OSError as exc:
        raise RootActionActivationError(
            "installed root-action release could not be resolved"
        ) from exc
    if not release.is_absolute() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in str(release)
    ):
        raise RootActionActivationError(
            "installed root-action release could not be resolved"
        )
    return release


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
    if not re.fullmatch(r"[0-9a-f]{64}", values["ROOT_ACTION_WEBAUTHN_USER_ID"]):
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
        raise RootActionActivationError("WebAuthn environment directory is not trusted")
    if enforce_posix_permissions and (
        metadata.st_uid != expected_owner_uid or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RootActionActivationError("WebAuthn environment directory is not trusted")


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
        metadata.st_uid != expected_owner_uid or stat.S_IMODE(metadata.st_mode) != 0o600
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
    expected_release: Path | None = None,
    read_running_environment: ReadRunningEnvironment = _read_running_environment,
    attestation_attempts: int = ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS,
    attestation_interval_seconds: float = (
        ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS
    ),
    sleep: Sleep = time.sleep,
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
    release = (
        Path(expected_release) if expected_release is not None else _installed_release()
    )
    if not release.is_absolute():
        raise RootActionActivationError("expected root-action release is invalid")
    if (
        isinstance(attestation_attempts, bool)
        or not isinstance(attestation_attempts, int)
        or not 1 <= attestation_attempts <= ROOT_ACTION_POST_RESTART_ATTESTATION_ATTEMPTS
        or isinstance(attestation_interval_seconds, bool)
        or not isinstance(attestation_interval_seconds, (int, float))
        or not 0 <= attestation_interval_seconds
        <= ROOT_ACTION_POST_RESTART_ATTESTATION_INTERVAL_SECONDS
    ):
        raise RootActionActivationError("post-restart attestation bounds are invalid")
    mutation_commands = [
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", ROOT_ACTION_BROKER_SERVICE),
        ("systemctl", "restart", ROOT_ACTION_BROKER_SERVICE),
    ]
    for command in mutation_commands:
        completed = run_command(command)
        if completed.returncode != 0:
            raise RootActionActivationError(
                "root-action broker activation failed closed"
            )
    marker = f"{ROOT_ACTION_RUNNING_RELEASE_ENV}={release}".encode("utf-8")
    attested = False
    for attempt in range(attestation_attempts):
        enabled = run_command(
            ("systemctl", "is-enabled", "--quiet", ROOT_ACTION_BROKER_SERVICE)
        )
        active = run_command(
            ("systemctl", "is-active", "--quiet", ROOT_ACTION_BROKER_SERVICE)
        )
        main_pid_result = run_command(
            (
                "systemctl",
                "show",
                "--property=MainPID",
                "--value",
                ROOT_ACTION_BROKER_SERVICE,
            )
        )
        stdout = main_pid_result.stdout
        main_pid = (
            int(stdout.strip())
            if main_pid_result.returncode == 0
            and isinstance(stdout, str)
            and re.fullmatch(r"[1-9][0-9]{0,9}\n?", stdout)
            else None
        )
        raw_environment: bytes | None = None
        if main_pid is not None:
            try:
                candidate_environment = read_running_environment(main_pid)
            except (OSError, RootActionActivationError):
                candidate_environment = None
            if isinstance(candidate_environment, bytes):
                raw_environment = candidate_environment
        if (
            enabled.returncode == 0
            and active.returncode == 0
            and main_pid is not None
            and raw_environment is not None
            and marker in raw_environment.split(b"\x00")
        ):
            attested = True
            break
        if attempt + 1 < attestation_attempts:
            sleep(float(attestation_interval_seconds))
    if not attested:
        raise RootActionActivationError(
            "root-action broker post-restart attestation failed closed"
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
        "restart_performed": True,
        "running_release": str(release),
    }
