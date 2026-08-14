from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
import unicodedata
from typing import Any


ASSIGNMENT_SCHEMA = "root-review-assignment/v3"
HANDLE_SCHEMA = "agent-runtime-root-review-handle/v1"
MAX_ASSIGNMENT_BYTES = 8 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_COMMAND_BYTES = 32 * 1024
MAX_TRANSCRIPT_APPEND_BYTES = 1024 * 1024
MAX_WAIT_SECONDS = 50.0
MAX_POLL_SECONDS = 5.0
_AGENT_SLUG_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_PANE_RE = re.compile(r"%[0-9]+")
_HANDLE_RE = re.compile(r"rr1\.[A-Za-z0-9_-]+\.[0-9a-f]{64}")
_REQUIRED_ASSIGNMENT_KEYS = {
    "assignment_schema",
    "agent_tmux_session",
    "agent_pane",
    "agent_pane_pid",
    "agent_codex_executable",
    "root_session",
    "root_session_id",
    "root_pane",
    "viewer_pane",
    "transcript",
    "request",
}
_OPTIONAL_ASSIGNMENT_KEYS = {"requesting_codex_task"}
_INITIAL_NO_PENDING = (
    "# 아직 실행 요청 없음\n"
    "# 이 pane은 표시 전용이며 아래 root pane에서 사용자만 실행합니다.\n"
).encode("utf-8")
_CANONICAL_NO_PENDING = (
    "STATUS=NO_PENDING_ROOT_COMMAND\n"
    "PURPOSE=Previous root-review card was observed and cleared; no next root command is pending.\n"
    "TRANSCRIPT_VERIFIED=YES\n"
    "POST_STATE_VERIFIED=YES\n"
).encode("utf-8")


class RootReviewError(RuntimeError):
    """The existing root-review file boundary failed closed."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int


@dataclass(frozen=True)
class RootReviewAssignment:
    agent_session: str
    agent_pane: str
    request_path: Path
    transcript_path: Path


@dataclass(frozen=True)
class RootReviewHandle:
    agent_session: str
    agent_pane: str
    request_sha256: str
    transcript_device: int
    transcript_inode: int
    transcript_offset: int

    def encode(self) -> str:
        payload = _canonical_json(
            {
                "schema": HANDLE_SCHEMA,
                "agent_session": self.agent_session,
                "agent_pane": self.agent_pane,
                "request_sha256": self.request_sha256,
                "transcript_device": self.transcript_device,
                "transcript_inode": self.transcript_inode,
                "transcript_offset": self.transcript_offset,
            }
        )
        body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        return f"rr1.{body}.{hashlib.sha256(payload).hexdigest()}"

    @classmethod
    def decode(cls, raw: str) -> RootReviewHandle:
        if not isinstance(raw, str) or _HANDLE_RE.fullmatch(raw) is None:
            raise RootReviewError("root_review_handle_invalid")
        _prefix, body, expected_digest = raw.split(".", 2)
        try:
            padding = "=" * (-len(body) % 4)
            payload = base64.urlsafe_b64decode((body + padding).encode("ascii"))
            value = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RootReviewError("root_review_handle_invalid") from exc
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise RootReviewError("root_review_handle_invalid")
        expected_keys = {
            "schema",
            "agent_session",
            "agent_pane",
            "request_sha256",
            "transcript_device",
            "transcript_inode",
            "transcript_offset",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected_keys
            or value.get("schema") != HANDLE_SCHEMA
            or payload != _canonical_json(value)
            or not isinstance(value.get("agent_session"), str)
            or _AGENT_SLUG_RE.fullmatch(value["agent_session"]) is None
            or not isinstance(value.get("agent_pane"), str)
            or _PANE_RE.fullmatch(value["agent_pane"]) is None
            or not isinstance(value.get("request_sha256"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["request_sha256"]) is None
            or any(
                isinstance(value.get(field), bool)
                or not isinstance(value.get(field), int)
                or value[field] < 0
                for field in (
                    "transcript_device",
                    "transcript_inode",
                    "transcript_offset",
                )
            )
        ):
            raise RootReviewError("root_review_handle_invalid")
        return cls(
            agent_session=value["agent_session"],
            agent_pane=value["agent_pane"],
            request_sha256=value["request_sha256"],
            transcript_device=value["transcript_device"],
            transcript_inode=value["transcript_inode"],
            transcript_offset=value["transcript_offset"],
        )


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_single_line(value: Any, *, field: str, maximum_chars: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum_chars:
        raise RootReviewError(f"root_review_{field}_invalid")
    if any(
        character in "\r\n\t" or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    ):
        raise RootReviewError(f"root_review_{field}_invalid")
    return value


def _safe_command(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RootReviewError("root_review_command_invalid")
    if len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise RootReviewError("root_review_command_invalid")
    if any(
        character == "\r"
        or (
            character != "\n"
            and unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        )
        for character in value
    ):
        raise RootReviewError("root_review_command_invalid")
    for line in value.splitlines():
        if line in {"COMMAND_BEGIN", "COMMAND_END"} or line.startswith(
            ("STATUS=", "command=", "PURPOSE=", "# 목적:")
        ):
            raise RootReviewError("root_review_command_invalid")
    return value


class RootReviewStore:
    """Thin adapter over the existing assignment/request/transcript files."""

    def __init__(
        self,
        *,
        assignment_dir: Path,
        request_dir: Path,
        transcript_dir: Path,
        pane_id: str,
        agent_uid: int,
        agent_gid: int,
        root_uid: int = 0,
        enforce_posix_metadata: bool = True,
    ) -> None:
        self.assignment_dir = Path(assignment_dir)
        self.request_dir = Path(request_dir)
        self.transcript_dir = Path(transcript_dir)
        self.pane_id = pane_id
        self.agent_uid = agent_uid
        self.agent_gid = agent_gid
        self.root_uid = root_uid
        self.enforce_posix_metadata = enforce_posix_metadata

    @classmethod
    def current(cls) -> RootReviewStore:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise RootReviewError("root_review_posix_runtime_required")
        uid = os.getuid()
        try:
            import pwd

            gid = pwd.getpwuid(uid).pw_gid
        except (ImportError, KeyError) as exc:
            raise RootReviewError("root_review_agent_identity_unavailable") from exc
        pane_id = os.environ.get("TMUX_PANE", "")
        if _PANE_RE.fullmatch(pane_id) is None:
            raise RootReviewError("root_review_agent_pane_unavailable")
        return cls(
            assignment_dir=Path("/run/codex-root-review/assignments"),
            request_dir=Path(f"/run/user/{uid}/codex-root-review/requests"),
            transcript_dir=Path("/run/codex-root-review/output"),
            pane_id=pane_id,
            agent_uid=uid,
            agent_gid=gid,
        )

    def publish(
        self,
        *,
        purpose: str,
        command: str,
        previous_handle: str | None = None,
    ) -> dict[str, Any]:
        purpose_value = _safe_single_line(purpose, field="purpose", maximum_chars=240)
        command_value = _safe_command(command)
        assignment = self._discover_assignment()
        current_request, current_identity = self._read_request(assignment)
        transcript_identity = self._transcript_identity(assignment)

        if previous_handle is None:
            if not self._is_no_pending(current_request):
                raise RootReviewError("root_review_pending_card_exists")
        else:
            handle = self._validate_handle(
                previous_handle,
                assignment=assignment,
                request_bytes=current_request,
                transcript_identity=transcript_identity,
            )
            if transcript_identity.size <= handle.transcript_offset:
                raise RootReviewError("root_review_transcript_unchanged")

        command_projection = (
            f"command={command_value}\n"
            if "\n" not in command_value
            else f"COMMAND_BEGIN\n{command_value}\nCOMMAND_END\n"
        )
        request_bytes = (
            "STATUS=WAITING_FOR_USER_REVIEW_AND_APPROVAL_NOT_EXECUTED\n"
            f"CARD_ID={secrets.token_hex(16)}\n"
            f"# 목적: {purpose_value}\n"
            f"{command_projection}"
        ).encode("utf-8")
        if len(request_bytes) > MAX_REQUEST_BYTES:
            raise RootReviewError("root_review_request_too_large")
        published = self._replace_request(
            assignment,
            request_bytes,
            expected_identity=current_identity,
            expected_sha256=_sha256(current_request),
        )
        handle = RootReviewHandle(
            agent_session=assignment.agent_session,
            agent_pane=assignment.agent_pane,
            request_sha256=_sha256(published),
            transcript_device=transcript_identity.device,
            transcript_inode=transcript_identity.inode,
            transcript_offset=transcript_identity.size,
        ).encode()
        return {
            "handle": handle,
            "state": "pending",
            "request_sha256": _sha256(published),
            "command": command_value,
            "command_sha256": _sha256(command_value.encode("utf-8")),
            "command_bytes": len(command_value.encode("utf-8")),
        }

    def wait(
        self,
        *,
        raw_handle: str,
        timeout_seconds: float,
        poll_interval_seconds: float,
    ) -> dict[str, Any]:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or not math.isfinite(float(poll_interval_seconds))
            or timeout_seconds < 0
            or timeout_seconds > MAX_WAIT_SECONDS
            or poll_interval_seconds <= 0
            or poll_interval_seconds > MAX_POLL_SECONDS
        ):
            raise RootReviewError("root_review_wait_bounds_invalid")
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            assignment = self._discover_assignment()
            request_bytes, _request_identity = self._read_request(assignment)
            transcript_identity = self._transcript_identity(assignment)
            handle = self._validate_handle(
                raw_handle,
                assignment=assignment,
                request_bytes=request_bytes,
                transcript_identity=transcript_identity,
            )
            if transcript_identity.size > handle.transcript_offset:
                appended = self._read_transcript_append(
                    assignment,
                    handle=handle,
                    expected_identity=transcript_identity,
                )
                return {
                    "handle": raw_handle,
                    "state": "transcript_appended",
                    "request_sha256": handle.request_sha256,
                    "transcript_append_sha256": _sha256(appended),
                    "transcript_appended_bytes": len(appended),
                    "retryable": False,
                }
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "handle": raw_handle,
                    "state": "pending",
                    "request_sha256": handle.request_sha256,
                    "transcript_append_sha256": None,
                    "transcript_appended_bytes": 0,
                    "retryable": True,
                }
            time.sleep(min(float(poll_interval_seconds), remaining))

    def resolve(self, *, raw_handle: str) -> dict[str, Any]:
        assignment = self._discover_assignment()
        request_bytes, request_identity = self._read_request(assignment)
        transcript_identity = self._transcript_identity(assignment)
        handle = self._validate_handle(
            raw_handle,
            assignment=assignment,
            request_bytes=request_bytes,
            transcript_identity=transcript_identity,
        )
        if transcript_identity.size <= handle.transcript_offset:
            raise RootReviewError("root_review_transcript_unchanged")
        appended = self._read_transcript_append(
            assignment,
            handle=handle,
            expected_identity=transcript_identity,
        )
        published = self._replace_request(
            assignment,
            _CANONICAL_NO_PENDING,
            expected_identity=request_identity,
            expected_sha256=handle.request_sha256,
        )
        return {
            "handle": raw_handle,
            "state": "no_pending",
            "request_sha256": _sha256(published),
            "transcript_append_sha256": _sha256(appended),
            "transcript_appended_bytes": len(appended),
        }

    def _discover_assignment(self) -> RootReviewAssignment:
        self._validate_directory(
            self.assignment_dir,
            expected_uid=self.root_uid,
            expected_gid=self.agent_gid,
            expected_mode=0o750,
        )
        self._validate_directory(
            self.request_dir,
            expected_uid=self.agent_uid,
            expected_gid=self.agent_gid,
            expected_mode=0o700,
        )
        self._validate_directory(
            self.transcript_dir,
            expected_uid=self.root_uid,
            expected_gid=self.agent_gid,
            expected_mode=0o750,
        )
        matches: list[RootReviewAssignment] = []
        try:
            candidates = sorted(self.assignment_dir.glob("*.env"))
        except OSError as exc:
            raise RootReviewError("root_review_assignment_unavailable") from exc
        for candidate in candidates:
            try:
                raw, _identity = self._read_regular(
                    candidate,
                    expected_uid=self.root_uid,
                    expected_gid=self.agent_gid,
                    expected_mode=0o640,
                    maximum=MAX_ASSIGNMENT_BYTES,
                )
                value = self._parse_assignment(raw)
            except RootReviewError:
                continue
            if value["agent_pane"] != self.pane_id:
                continue
            session = value["agent_tmux_session"]
            if candidate.stem != session:
                raise RootReviewError("root_review_assignment_mismatch")
            request_path = self.request_dir / f"{session}.txt"
            transcript_path = self.transcript_dir / f"{session}.log"
            if (
                Path(value["request"]) != request_path
                or Path(value["transcript"]) != transcript_path
            ):
                raise RootReviewError("root_review_assignment_mismatch")
            matches.append(
                RootReviewAssignment(
                    agent_session=session,
                    agent_pane=value["agent_pane"],
                    request_path=request_path,
                    transcript_path=transcript_path,
                )
            )
        if len(matches) != 1:
            raise RootReviewError("root_review_assignment_not_unique")
        return matches[0]

    @staticmethod
    def _parse_assignment(raw: bytes) -> dict[str, str]:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RootReviewError("root_review_assignment_invalid") from exc
        value: dict[str, str] = {}
        for line in text.splitlines():
            if not line or "=" not in line:
                raise RootReviewError("root_review_assignment_invalid")
            key, item = line.split("=", 1)
            if not key or key in value:
                raise RootReviewError("root_review_assignment_invalid")
            value[key] = item
        if (
            not _REQUIRED_ASSIGNMENT_KEYS.issubset(value)
            or set(value) - (_REQUIRED_ASSIGNMENT_KEYS | _OPTIONAL_ASSIGNMENT_KEYS)
            or value.get("assignment_schema") != ASSIGNMENT_SCHEMA
            or _AGENT_SLUG_RE.fullmatch(value.get("agent_tmux_session", "")) is None
            or _PANE_RE.fullmatch(value.get("agent_pane", "")) is None
            or not value.get("agent_pane_pid", "").isdigit()
        ):
            raise RootReviewError("root_review_assignment_invalid")
        return value

    def _read_request(
        self, assignment: RootReviewAssignment
    ) -> tuple[bytes, FileIdentity]:
        return self._read_regular(
            assignment.request_path,
            expected_uid=self.agent_uid,
            expected_gid=self.agent_gid,
            expected_mode=0o600,
            maximum=MAX_REQUEST_BYTES,
        )

    def _transcript_identity(self, assignment: RootReviewAssignment) -> FileIdentity:
        return self._stat_regular(
            assignment.transcript_path,
            expected_uid=self.root_uid,
            expected_gid=self.agent_gid,
            expected_mode=0o640,
        )

    def _validate_handle(
        self,
        raw_handle: str,
        *,
        assignment: RootReviewAssignment,
        request_bytes: bytes,
        transcript_identity: FileIdentity,
    ) -> RootReviewHandle:
        handle = RootReviewHandle.decode(raw_handle)
        if (
            handle.agent_session != assignment.agent_session
            or handle.agent_pane != assignment.agent_pane
            or handle.request_sha256 != _sha256(request_bytes)
            or handle.transcript_device != transcript_identity.device
            or handle.transcript_inode != transcript_identity.inode
            or transcript_identity.size < handle.transcript_offset
        ):
            raise RootReviewError("root_review_handle_stale_or_mismatched")
        return handle

    def _read_transcript_append(
        self,
        assignment: RootReviewAssignment,
        *,
        handle: RootReviewHandle,
        expected_identity: FileIdentity,
    ) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(assignment.transcript_path, flags)
        except OSError as exc:
            raise RootReviewError("root_review_transcript_unavailable") from exc
        try:
            opened = self._validated_stat(
                os.fstat(fd),
                expected_uid=self.root_uid,
                expected_gid=self.agent_gid,
                expected_mode=0o640,
            )
            if opened != expected_identity:
                raise RootReviewError("root_review_transcript_identity_changed")
            os.lseek(fd, handle.transcript_offset, os.SEEK_SET)
            value = bytearray()
            while len(value) <= MAX_TRANSCRIPT_APPEND_BYTES:
                chunk = os.read(
                    fd,
                    min(65536, MAX_TRANSCRIPT_APPEND_BYTES + 1 - len(value)),
                )
                if not chunk:
                    break
                value.extend(chunk)
            if not value:
                raise RootReviewError("root_review_transcript_unchanged")
            if len(value) > MAX_TRANSCRIPT_APPEND_BYTES:
                raise RootReviewError("root_review_transcript_append_too_large")
            if self._identity(os.fstat(fd)) != expected_identity:
                raise RootReviewError("root_review_transcript_identity_changed")
            return bytes(value)
        finally:
            os.close(fd)

    @staticmethod
    def _is_no_pending(raw: bytes) -> bool:
        if raw == _INITIAL_NO_PENDING or raw == _CANONICAL_NO_PENDING:
            return True
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return False
        return (
            bool(lines)
            and lines[0] == "STATUS=NO_PENDING_ROOT_COMMAND"
            and not any(line.startswith("command=") for line in lines)
        )

    def _replace_request(
        self,
        assignment: RootReviewAssignment,
        new_bytes: bytes,
        *,
        expected_identity: FileIdentity,
        expected_sha256: str,
    ) -> bytes:
        current, current_identity = self._read_request(assignment)
        if current_identity != expected_identity or _sha256(current) != expected_sha256:
            raise RootReviewError("root_review_request_changed_before_publish")
        temporary = assignment.request_path.with_name(
            f".{assignment.request_path.name}.{secrets.token_hex(12)}.tmp"
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = -1
        try:
            fd = os.open(temporary, flags, 0o600)
            offset = 0
            while offset < len(new_bytes):
                written = os.write(fd, new_bytes[offset:])
                if written <= 0:
                    raise RootReviewError("root_review_request_publish_failed")
                offset += written
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            current_again, identity_again = self._read_request(assignment)
            if (
                identity_again != expected_identity
                or _sha256(current_again) != expected_sha256
            ):
                raise RootReviewError("root_review_request_changed_before_publish")
            os.replace(temporary, assignment.request_path)
            if os.name == "posix":
                directory_fd = os.open(
                    self.request_dir,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            published, _published_identity = self._read_request(assignment)
            if published != new_bytes:
                raise RootReviewError("root_review_request_publish_mismatch")
            return published
        except OSError as exc:
            raise RootReviewError("root_review_request_publish_failed") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _read_regular(
        self,
        path: Path,
        *,
        expected_uid: int,
        expected_gid: int,
        expected_mode: int,
        maximum: int,
    ) -> tuple[bytes, FileIdentity]:
        before = self._stat_regular(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=expected_mode,
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise RootReviewError("root_review_file_unavailable") from exc
        try:
            opened = self._validated_stat(
                os.fstat(fd),
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                expected_mode=expected_mode,
            )
            if opened != before:
                raise RootReviewError("root_review_file_identity_changed")
            value = bytearray()
            while len(value) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(value)))
                if not chunk:
                    break
                value.extend(chunk)
            if len(value) > maximum:
                raise RootReviewError("root_review_file_too_large")
            if self._identity(os.fstat(fd)) != before:
                raise RootReviewError("root_review_file_identity_changed")
            return bytes(value), before
        finally:
            os.close(fd)

    def _stat_regular(
        self,
        path: Path,
        *,
        expected_uid: int,
        expected_gid: int,
        expected_mode: int,
    ) -> FileIdentity:
        try:
            return self._validated_stat(
                path.lstat(),
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                expected_mode=expected_mode,
            )
        except OSError as exc:
            raise RootReviewError("root_review_file_unavailable") from exc

    def _validated_stat(
        self,
        value: os.stat_result,
        *,
        expected_uid: int,
        expected_gid: int,
        expected_mode: int,
    ) -> FileIdentity:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise RootReviewError("root_review_file_identity_unsafe")
        if self.enforce_posix_metadata and (
            value.st_uid != expected_uid
            or value.st_gid != expected_gid
            or stat.S_IMODE(value.st_mode) != expected_mode
        ):
            raise RootReviewError("root_review_file_identity_unsafe")
        return self._identity(value)

    @staticmethod
    def _identity(value: os.stat_result) -> FileIdentity:
        return FileIdentity(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
        )

    def _validate_directory(
        self,
        path: Path,
        *,
        expected_uid: int,
        expected_gid: int,
        expected_mode: int,
    ) -> None:
        try:
            value = path.lstat()
        except OSError as exc:
            raise RootReviewError("root_review_directory_unavailable") from exc
        if not stat.S_ISDIR(value.st_mode):
            raise RootReviewError("root_review_directory_identity_unsafe")
        if self.enforce_posix_metadata and (
            value.st_uid != expected_uid
            or value.st_gid != expected_gid
            or stat.S_IMODE(value.st_mode) != expected_mode
        ):
            raise RootReviewError("root_review_directory_identity_unsafe")
