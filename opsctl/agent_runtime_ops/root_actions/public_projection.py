from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

from .receipts import ReceiptArtifact, seal_receipt


PUBLIC_PROJECTION_SCHEMA = "agent-runtime-root-action-public-projection/v1"
PUBLIC_PROJECTION_MAX_BYTES = 3 * 1024 * 1024
_SAFE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


class PublicProjectionError(RuntimeError):
    """A public projection could not be built or published safely."""


@dataclass(frozen=True)
class PublicProjectionArtifact:
    job_id: str
    job_digest: str
    projection_digest: str
    canonical_bytes: bytes


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _load_canonical(raw: bytes, field: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicProjectionError(f"{field} is not UTF-8 JSON") from exc
    if not isinstance(value, dict) or raw != _canonical(value):
        raise PublicProjectionError(f"{field} is not canonical JSON")
    return value


def build_public_projection(
    *,
    job_id: str,
    job_digest: str,
    status_bytes: bytes,
    history_bytes: bytes,
    receipt: ReceiptArtifact | None,
) -> PublicProjectionArtifact:
    status = _load_canonical(status_bytes, "status")
    history = _load_canonical(history_bytes, "history")
    if (
        status.get("job", {}).get("job_id") != job_id
        or status.get("job", {}).get("job_digest") != job_digest
        or history.get("job_id") != job_id
        or history.get("job_digest") != job_digest
    ):
        raise PublicProjectionError("public projection identity mismatch")
    receipt_value: dict[str, Any] | None = None
    if receipt is not None:
        verified = seal_receipt(receipt.canonical_receipt)
        if verified != receipt:
            raise PublicProjectionError("public receipt metadata mismatch")
        status_job = status.get("job", {})
        if (
            receipt.job_id != job_id
            or receipt.job_digest != job_digest
            or receipt.request_id != status_job.get("request_id")
            or receipt.reply_target != status_job.get("reply_target")
        ):
            raise PublicProjectionError("public receipt identity mismatch")
        receipt_value = _load_canonical(receipt.canonical_receipt, "receipt")
    payload = {
        "schema": PUBLIC_PROJECTION_SCHEMA,
        "job_id": job_id,
        "job_digest": job_digest,
        "status": status,
        "history": history,
        "receipt": receipt_value,
    }
    payload_bytes = _canonical(payload)
    projection_digest = (
        "sha256:"
        + hashlib.sha256(
            b"agent-runtime-root-action-public-projection/v1\x00" + payload_bytes
        ).hexdigest()
    )
    canonical = _canonical({**payload, "projection_digest": projection_digest})
    if len(canonical) > PUBLIC_PROJECTION_MAX_BYTES:
        raise PublicProjectionError("public projection exceeds its byte limit")
    return PublicProjectionArtifact(
        job_id=job_id,
        job_digest=job_digest,
        projection_digest=projection_digest,
        canonical_bytes=canonical,
    )


class AtomicPublicProjectionPublisher:
    """Publish one canonical projection envelope by atomic same-dir replace.

    The fixed constructor root is installer policy. A job request cannot choose
    a filesystem path, filename, uid, or mode.
    """

    def __init__(
        self,
        root: Path,
        *,
        create: bool = False,
        required_uid: int | None = 0,
        required_gid: int | None = None,
        require_posix: bool = True,
    ) -> None:
        self.root = Path(root)
        self._required_uid = required_uid
        self._required_gid = required_gid
        self._posix = os.name == "posix"
        if require_posix and not self._posix:
            raise PublicProjectionError(
                "production projection publisher requires POSIX"
            )
        if require_posix and required_gid is None:
            raise PublicProjectionError(
                "production projection publisher requires a trusted read gid"
            )
        if create:
            self.root.mkdir(mode=0o750, parents=True, exist_ok=True)
            os.chmod(self.root, 0o750)
            if self._posix and required_uid is not None and required_gid is not None:
                os.chown(self.root, required_uid, required_gid)
        self._verify_directory(self.root, "public projection root", 0o750)

    def publish(self, bundle: Any) -> None:
        artifact = PublicProjectionArtifact(
            job_id=bundle.job_id,
            job_digest=bundle.job_digest,
            projection_digest=bundle.projection_digest,
            canonical_bytes=bundle.projection_bytes,
        )
        verified = validate_public_projection(artifact.canonical_bytes)
        if verified != artifact:
            raise PublicProjectionError("projection bundle metadata mismatch")
        try:
            if self._posix:
                self._publish_posix(artifact)
            else:
                self._publish_portable(artifact)
        except PublicProjectionError:
            raise
        except OSError as exc:
            raise PublicProjectionError(
                "public projection path operation failed"
            ) from exc

    def publish_catalog(
        self,
        bundles: tuple[Any, ...],
        *,
        authority_job_count: int | None = None,
    ) -> None:
        from .catalog import build_public_catalog

        artifact = build_public_catalog(
            bundles,
            authority_job_count=authority_job_count,
        )
        generations = self.root / "catalog-generations"
        generation = generations / artifact.generation
        if self._posix:
            self._ensure_public_directory(generations)
            self._ensure_public_directory(generation)
        else:
            generations.mkdir(mode=0o750, exist_ok=True)
            generation.mkdir(mode=0o750, exist_ok=True)
        for path, _digest, raw in artifact.pages:
            destination = self.root / path
            self._publish_immutable_file(destination, raw)
        prior_generation = self._publish_current_catalog(artifact.catalog_bytes)
        self._prune_catalog_generations(
            {artifact.generation, prior_generation} - {None}
        )

    def _ensure_public_directory(self, path: Path) -> None:
        try:
            path.mkdir(mode=0o750)
            if self._required_uid is not None and self._required_gid is not None:
                os.chown(path, self._required_uid, self._required_gid)
            os.chmod(path, 0o750)
            self._fsync_path(path.parent)
        except FileExistsError:
            pass
        self._verify_directory(path, "public catalog directory", 0o750)

    def _publish_immutable_file(self, path: Path, raw: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(path, flags, 0o640)
        except FileExistsError:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or path.is_symlink()
                or info.st_nlink != 1
                or (self._posix and stat.S_IMODE(info.st_mode) != 0o640)
            ):
                raise PublicProjectionError("immutable catalog page is unsafe")
            if self._posix:
                self._verify_owner(info, "immutable catalog page")
            if path.read_bytes() != raw:
                raise PublicProjectionError("immutable catalog page changed")
            return
        try:
            if self._posix:
                os.fchmod(fd, 0o640)
                if self._required_uid is not None and self._required_gid is not None:
                    os.fchown(fd, self._required_uid, self._required_gid)
            self._write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_path(path.parent)

    def _publish_current_catalog(self, raw: bytes) -> str | None:
        prior_generation = self._validated_current_generation()
        temp = self.root / f".catalog-{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(temp, flags, 0o640)
        try:
            if self._posix:
                os.fchmod(fd, 0o640)
                if self._required_uid is not None and self._required_gid is not None:
                    os.fchown(fd, self._required_uid, self._required_gid)
            self._write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.replace(temp, self.root / "catalog.json")
            self._fsync_path(self.root)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        return prior_generation

    def _validated_current_generation(self) -> str | None:
        from .catalog import validate_public_catalog

        current = self.root / "catalog.json"
        try:
            raw = current.read_bytes()
        except FileNotFoundError:
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
            references = value["pages"]
            page_values = {
                reference["path"]: (self.root / reference["path"]).read_bytes()
                for reference in references
            }
            artifact = validate_public_catalog(raw, page_values)
        except (KeyError, TypeError, OSError, ValueError, PublicProjectionError):
            return None
        return artifact.generation

    def _prune_catalog_generations(self, keep: set[str]) -> None:
        generations = self.root / "catalog-generations"
        if not generations.exists():
            return
        generation_re = re.compile(r"generation-[0-9a-f]{32}")
        page_re = re.compile(r"page-[0-9]{8}\.json")
        for candidate in generations.iterdir():
            if candidate.name in keep:
                continue
            info = candidate.lstat()
            if (
                generation_re.fullmatch(candidate.name) is None
                or not stat.S_ISDIR(info.st_mode)
                or candidate.is_symlink()
                or (self._posix and stat.S_IMODE(info.st_mode) != 0o750)
            ):
                raise PublicProjectionError(
                    "catalog retention found an untrusted generation"
                )
            if self._posix:
                self._verify_owner(info, "catalog retained generation")
            pages = list(candidate.iterdir())
            for page in pages:
                page_info = page.lstat()
                if (
                    page_re.fullmatch(page.name) is None
                    or not stat.S_ISREG(page_info.st_mode)
                    or page.is_symlink()
                    or page_info.st_nlink != 1
                    or (self._posix and stat.S_IMODE(page_info.st_mode) != 0o640)
                ):
                    raise PublicProjectionError(
                        "catalog retention found an untrusted page"
                    )
                if self._posix:
                    self._verify_owner(page_info, "catalog retained page")
            for page in pages:
                page.unlink()
            candidate.rmdir()
        self._fsync_path(generations)

    @staticmethod
    def _fsync_path(path: Path) -> None:
        if os.name != "posix":
            return
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _publish_posix(self, artifact: PublicProjectionArtifact) -> None:
        root_fd = os.open(self.root, self._directory_flags())
        job_fd = -1
        temp_name = ""
        try:
            self._verify_directory_fd(root_fd, "public projection root", 0o750)
            created = False
            try:
                os.mkdir(artifact.job_id, 0o750, dir_fd=root_fd)
                created = True
                os.fsync(root_fd)
            except FileExistsError:
                pass
            job_fd = os.open(artifact.job_id, self._directory_flags(), dir_fd=root_fd)
            if created:
                os.fchmod(job_fd, 0o750)
                if self._required_uid is not None and self._required_gid is not None:
                    os.fchown(job_fd, self._required_uid, self._required_gid)
            self._verify_directory_fd(job_fd, "public projection job", 0o750)
            temp_name = f".projection-{secrets.token_hex(16)}.tmp"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            fd = os.open(temp_name, flags, 0o640, dir_fd=job_fd)
            try:
                os.fchmod(fd, 0o640)
                if self._required_uid is not None and self._required_gid is not None:
                    os.fchown(fd, self._required_uid, self._required_gid)
                self._write_all(fd, artifact.canonical_bytes)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise PublicProjectionError("projection temporary file is unsafe")
                self._verify_owner(info, "projection temporary file")
                if stat.S_IMODE(info.st_mode) != 0o640:
                    raise PublicProjectionError(
                        "projection temporary file mode drifted"
                    )
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(
                temp_name,
                "projection.json",
                src_dir_fd=job_fd,
                dst_dir_fd=job_fd,
            )
            temp_name = ""
            os.fsync(job_fd)
        finally:
            if temp_name and job_fd >= 0:
                try:
                    os.unlink(temp_name, dir_fd=job_fd)
                except FileNotFoundError:
                    pass
            if job_fd >= 0:
                os.close(job_fd)
            os.close(root_fd)

    def _publish_portable(self, artifact: PublicProjectionArtifact) -> None:
        job = self.root / artifact.job_id
        job.mkdir(mode=0o750, exist_ok=True)
        temp = job / f".projection-{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(temp, flags, 0o640)
        try:
            self._write_all(fd, artifact.canonical_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, job / "projection.json")

    @staticmethod
    def _write_all(fd: int, value: bytes) -> None:
        view = memoryview(value)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise PublicProjectionError("projection write made no progress")
            offset += written

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

    def _verify_directory(self, path: Path, field: str, expected_mode: int) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise PublicProjectionError(f"{field} is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            raise PublicProjectionError(f"{field} is not a real directory")
        if self._posix:
            self._verify_owner(info, field)
            if stat.S_IMODE(info.st_mode) != expected_mode:
                raise PublicProjectionError(f"{field} mode is invalid")

    def _verify_directory_fd(self, fd: int, field: str, expected_mode: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise PublicProjectionError(f"{field} is not a directory")
        self._verify_owner(info, field)
        if stat.S_IMODE(info.st_mode) != expected_mode:
            raise PublicProjectionError(f"{field} mode is invalid")

    def _verify_owner(self, info: os.stat_result, field: str) -> None:
        if self._required_uid is not None and info.st_uid != self._required_uid:
            raise PublicProjectionError(f"{field} uid is not trusted")
        if self._required_gid is not None and info.st_gid != self._required_gid:
            raise PublicProjectionError(f"{field} gid is not trusted")


def validate_public_projection(raw: bytes) -> PublicProjectionArtifact:
    if not raw or len(raw) > PUBLIC_PROJECTION_MAX_BYTES:
        raise PublicProjectionError("public projection byte length is invalid")
    value = _load_canonical(raw, "public projection")
    expected = {
        "schema",
        "job_id",
        "job_digest",
        "projection_digest",
        "status",
        "history",
        "receipt",
    }
    if set(value) != expected or value["schema"] != PUBLIC_PROJECTION_SCHEMA:
        raise PublicProjectionError("public projection field set or schema is invalid")
    if (
        not isinstance(value["job_id"], str)
        or _SAFE_ID_RE.fullmatch(value["job_id"]) is None
        or not isinstance(value["job_digest"], str)
        or _DIGEST_RE.fullmatch(value["job_digest"]) is None
    ):
        raise PublicProjectionError("public projection job identity is invalid")
    payload = {key: value[key] for key in value if key != "projection_digest"}
    payload_bytes = _canonical(payload)
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"agent-runtime-root-action-public-projection/v1\x00" + payload_bytes
        ).hexdigest()
    )
    if value["projection_digest"] != digest:
        raise PublicProjectionError("public projection digest mismatch")
    status = value["status"]
    history = value["history"]
    if (
        not isinstance(status, dict)
        or not isinstance(history, dict)
        or status.get("job", {}).get("job_id") != value["job_id"]
        or status.get("job", {}).get("job_digest") != value["job_digest"]
        or history.get("job_id") != value["job_id"]
        or history.get("job_digest") != value["job_digest"]
    ):
        raise PublicProjectionError("public projection nested identity mismatch")
    if value["receipt"] is not None:
        receipt = seal_receipt(_canonical(value["receipt"]))
        status_job = status.get("job", {})
        if (
            receipt.job_id != value["job_id"]
            or receipt.job_digest != value["job_digest"]
            or receipt.request_id != status_job.get("request_id")
            or receipt.reply_target != status_job.get("reply_target")
        ):
            raise PublicProjectionError("public projection receipt identity mismatch")
    return PublicProjectionArtifact(
        job_id=value["job_id"],
        job_digest=value["job_digest"],
        projection_digest=digest,
        canonical_bytes=raw,
    )
