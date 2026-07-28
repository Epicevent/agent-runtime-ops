from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import struct
import threading

from .endpoint import RootActionBrokerEndpoint
from .protocol import MAX_BROKER_REQUEST_BYTES, BrokerProtocolError
from .submission import BrokerPeerIdentity
from .storage import StorageConflict
from .worker import RootActionWorkerError


DEFAULT_RUNTIME_ROOT = Path("/run/agent-runtime-ops")
DEFAULT_SOCKET_PATH = DEFAULT_RUNTIME_ROOT / "root-action-broker.sock"


class RootActionListenerError(RuntimeError):
    """The trusted local listener path or peer identity is not provable."""


class RootActionUnixListener:
    """Linux SO_PEERCRED listener for one request frame per connection."""

    def __init__(
        self,
        endpoint: RootActionBrokerEndpoint,
        *,
        socket_path: Path = DEFAULT_SOCKET_PATH,
        required_uid: int = 0,
        trusted_gid: int,
        create_parent: bool = False,
    ) -> None:
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise RootActionListenerError("trusted broker listener requires Linux SO_PEERCRED")
        self.endpoint = endpoint
        self.socket_path = Path(socket_path)
        self.required_uid = required_uid
        self.trusted_gid = trusted_gid
        self._socket: socket.socket | None = None
        self._lock_fd: int | None = None
        if not self.socket_path.is_absolute():
            raise RootActionListenerError("broker socket path must be absolute")
        self._prepare_parent(create=create_parent)

    def _prepare_parent(self, *, create: bool) -> None:
        parent = self.socket_path.parent
        if create:
            parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            os.chmod(parent, 0o750)
            os.chown(parent, self.required_uid, self.trusted_gid)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or parent.is_symlink()
            or info.st_uid != self.required_uid
            or info.st_gid != self.trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o750
        ):
            raise RootActionListenerError("broker socket parent is not trusted")

    def open(self) -> None:
        if self._socket is not None:
            raise RootActionListenerError("broker listener is already open")
        self._acquire_lock()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound = False
        try:
            try:
                existing = self.socket_path.lstat()
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if (
                    not stat.S_ISSOCK(existing.st_mode)
                    or existing.st_uid != self.required_uid
                    or existing.st_gid != self.trusted_gid
                    or stat.S_IMODE(existing.st_mode) != 0o660
                ):
                    raise RootActionListenerError(
                        "broker socket path is occupied unsafely"
                    )
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.settimeout(0.2)
                    probe.connect(str(self.socket_path))
                except (ConnectionRefusedError, FileNotFoundError):
                    self.socket_path.unlink()
                else:
                    raise RootActionListenerError(
                        "broker socket already has a live listener"
                    )
                finally:
                    probe.close()
            listener.bind(str(self.socket_path))
            bound = True
            os.chown(self.socket_path, self.required_uid, self.trusted_gid)
            os.chmod(self.socket_path, 0o660)
            info = self.socket_path.lstat()
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != self.required_uid
                or info.st_gid != self.trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o660
            ):
                raise RootActionListenerError("broker socket identity drifted")
            listener.listen(32)
            self._socket = listener
        except Exception:
            listener.close()
            if bound:
                try:
                    self.socket_path.unlink()
                except FileNotFoundError:
                    pass
            self._release_lock()
            raise

    def close(self) -> None:
        listener = self._socket
        self._socket = None
        if listener is not None:
            listener.close()
        try:
            info = self.socket_path.lstat()
        except FileNotFoundError:
            self._release_lock()
            return
        if (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == self.required_uid
            and info.st_gid == self.trusted_gid
        ):
            self.socket_path.unlink()
        self._release_lock()

    def _acquire_lock(self) -> None:
        import fcntl

        path = self.socket_path.parent / ".root-action-broker.lock"
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(path, flags, 0o640)
        try:
            os.fchmod(fd, 0o640)
            os.fchown(fd, self.required_uid, self.trusted_gid)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.required_uid
                or info.st_gid != self.trusted_gid
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise RootActionListenerError("broker listener lock is unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RootActionListenerError(
                    "broker listener lock is already held"
                ) from exc
        except Exception:
            os.close(fd)
            raise
        self._lock_fd = fd

    def _release_lock(self) -> None:
        fd = self._lock_fd
        self._lock_fd = None
        if fd is None:
            return
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def serve_once(self) -> None:
        if self._socket is None:
            raise RootActionListenerError("broker listener is not open")
        connection, _ = self._socket.accept()
        with connection:
            try:
                connection.settimeout(2.0)
                peer = self._peer_identity(connection)
                frame = self._read_one_frame(connection)
                response = self.endpoint.handle(frame, peer=peer)
                connection.sendall(response)
            except OSError:
                # A reset or timeout belongs to this accepted connection.  It
                # must not terminate the broker whether it happens before the
                # full frame arrives or after the request has committed.
                return

    def serve_forever(self, stop: threading.Event | None = None) -> None:
        if self._socket is None:
            self.open()
        assert self._socket is not None
        self._socket.settimeout(0.5)
        while stop is None or not stop.is_set():
            try:
                self.serve_once()
            except socket.timeout:
                continue
            except (
                BrokerProtocolError,
                ValueError,
                KeyError,
                StorageConflict,
                RootActionWorkerError,
            ):
                # Fail closed by closing this one connection without a response.
                continue

    @staticmethod
    def _peer_identity(connection: socket.socket) -> BrokerPeerIdentity:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        pid, uid, gid = struct.unpack("3i", raw)
        return BrokerPeerIdentity(uid=uid, gid=gid, pid=pid)

    @staticmethod
    def _recv_exact(connection: socket.socket, size: int) -> bytes:
        value = bytearray()
        while len(value) < size:
            chunk = connection.recv(size - len(value))
            if not chunk:
                raise BrokerProtocolError("broker request is truncated")
            value.extend(chunk)
        return bytes(value)

    @classmethod
    def _read_one_frame(cls, connection: socket.socket) -> bytes:
        header = cls._recv_exact(connection, 4)
        (length,) = struct.unpack("!I", header)
        if length < 1 or length > MAX_BROKER_REQUEST_BYTES:
            raise BrokerProtocolError("broker request length is invalid")
        payload = cls._recv_exact(connection, length)
        if connection.recv(1) != b"":
            raise BrokerProtocolError("broker connection contains more than one frame")
        return header + payload
