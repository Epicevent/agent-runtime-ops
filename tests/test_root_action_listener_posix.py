from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import threading

import pytest

from agent_runtime_ops.root_actions import (
    BrokerPeerIdentity,
    RootActionBrokerClient,
    RootActionBrokerEndpoint,
    RootActionListenerError,
    RootActionUnixListener,
    SubmissionPolicy,
    TypedRootActionBroker,
)
from agent_runtime_ops.root_actions.protocol import BrokerProtocolError, submit_request
from agent_runtime_ops.root_actions.public_projection import AtomicPublicProjectionPublisher
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from tests.test_root_action_admission import Events, manifest


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED"),
    reason="Linux SO_PEERCRED observation requires a POSIX runtime",
)


def root_broker() -> TypedRootActionBroker:
    return TypedRootActionBroker(
        LocalRootActionFixture(),
        events=Events(
            [
                ("event-listener-pending", "2026-07-27T12:00:00Z"),
                ("event-listener-circuit", "2026-07-27T12:00:01Z"),
            ]
        ),
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({os.getuid()}),
            allowed_gids=frozenset({os.getgid()}),
        ),
    )


def serve_one(listener: RootActionUnixListener, errors: list[BaseException]) -> threading.Thread:
    def target() -> None:
        try:
            listener.serve_once()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread


def test_real_unix_listener_uses_peer_credentials_and_blocks_split_brain(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    socket_path = runtime / "broker.sock"
    listener = RootActionUnixListener(
        RootActionBrokerEndpoint(root_broker()),
        socket_path=socket_path,
        required_uid=os.getuid(),
        trusted_gid=os.getgid(),
        create_parent=True,
    )
    listener.open()
    second = RootActionUnixListener(
        RootActionBrokerEndpoint(root_broker()),
        socket_path=socket_path,
        required_uid=os.getuid(),
        trusted_gid=os.getgid(),
    )
    with pytest.raises(RootActionListenerError, match="lock is already held"):
        second.open()
    errors: list[BaseException] = []
    thread = serve_one(listener, errors)
    client = RootActionBrokerClient(socket_path=socket_path)
    handle, projection = client.submit(manifest("job-listener"))
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert handle.job_id == "job-listener"
    assert projection["status"]["state"]["name"] == "pending"
    info = socket_path.lstat()
    assert stat.S_ISSOCK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o660

    thread = serve_one(listener, errors)
    retrieved = client.retrieve(handle)
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert retrieved["status"]["job"]["request_id"] == handle.request_id
    listener.close()
    assert not socket_path.exists()


def test_listener_rejects_multiple_frames_on_one_connection(tmp_path: Path) -> None:
    socket_path = tmp_path / "runtime" / "broker.sock"
    listener = RootActionUnixListener(
        RootActionBrokerEndpoint(root_broker()),
        socket_path=socket_path,
        required_uid=os.getuid(),
        trusted_gid=os.getgid(),
        create_parent=True,
    )
    listener.open()
    errors: list[BaseException] = []
    thread = serve_one(listener, errors)
    frame = submit_request(manifest("job-multi-frame"))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall(frame + frame)
        client.shutdown(socket.SHUT_WR)
        try:
            response = client.recv(1)
        except ConnectionResetError:
            # Linux may reset a connection closed with unread extra request
            # bytes.  EOF and reset both prove that no response frame escaped.
            response = b""
        assert response == b""
    thread.join(timeout=3)
    listener.close()
    assert len(errors) == 1
    assert isinstance(errors[0], BrokerProtocolError)


def test_production_projection_permissions_are_root_trusted_group_only(
    tmp_path: Path,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("root ownership observation requires a disposable root test runtime")
    public = tmp_path / "public"
    publisher = AtomicPublicProjectionPublisher(
        public,
        create=True,
        required_uid=0,
        required_gid=os.getgid(),
    )
    broker = root_broker()
    submitted = broker.submit(manifest("job-posix-mode"), peer=BrokerPeerIdentity(0, os.getgid(), os.getpid()))
    publisher.publish(broker.public_projection(submitted.job_id))
    job_dir = public / submitted.job_id
    projection = job_dir / "projection.json"
    assert stat.S_IMODE(public.lstat().st_mode) == 0o750
    assert stat.S_IMODE(job_dir.lstat().st_mode) == 0o750
    assert stat.S_IMODE(projection.lstat().st_mode) == 0o640
    assert projection.lstat().st_uid == 0
    assert projection.lstat().st_gid == os.getgid()
    value = json.loads(projection.read_bytes())
    assert "stdout" not in value
    assert "stderr" not in value
