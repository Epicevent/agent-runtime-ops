from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd

from .broker import TypedRootActionBroker
from .endpoint import RootActionBrokerEndpoint
from .listener import DEFAULT_RUNTIME_ROOT, DEFAULT_SOCKET_PATH, RootActionUnixListener
from .posix_store import PosixRootActionStore
from .public_projection import AtomicPublicProjectionPublisher
from .submission import SubmissionPolicy


STATE_ROOT = Path("/var/lib/agent-runtime-ops/root-actions")
STORE_ROOT = STATE_ROOT / "private"
PUBLIC_ROOT = STATE_ROOT / "public"
TRUSTED_READER_ACCOUNT = "svcops"


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("root-action broker service must run as root")
    account = pwd.getpwnam(TRUSTED_READER_ACCOUNT)
    group = grp.getgrnam(TRUSTED_READER_ACCOUNT)
    if account.pw_gid != group.gr_gid:
        raise SystemExit("trusted reader primary group mismatch")
    runtime_root = DEFAULT_RUNTIME_ROOT
    runtime_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(runtime_root, 0, group.gr_gid)
    os.chmod(runtime_root, 0o750)
    STATE_ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(STATE_ROOT, 0, group.gr_gid)
    os.chmod(STATE_ROOT, 0o750)
    store = PosixRootActionStore(
        STORE_ROOT,
        create=True,
        required_uid=0,
        required_gid=0,
    )
    publisher = AtomicPublicProjectionPublisher(
        PUBLIC_ROOT,
        create=True,
        required_uid=0,
        required_gid=group.gr_gid,
    )
    broker = TypedRootActionBroker(
        store,
        public_sink=publisher,
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({account.pw_uid}),
            allowed_gids=frozenset({group.gr_gid}),
        ),
    )
    broker.reconcile_public()
    listener = RootActionUnixListener(
        RootActionBrokerEndpoint(broker),
        socket_path=DEFAULT_SOCKET_PATH,
        required_uid=0,
        trusted_gid=group.gr_gid,
        create_parent=False,
    )
    try:
        listener.open()
        listener.serve_forever()
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
