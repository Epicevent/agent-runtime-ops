from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd

from .auth_service import RootActionAuthorizationService
from .authorization import WebAuthnPolicy, WebAuthnVerifier
from .broker import TypedRootActionBroker
from .endpoint import RootActionBrokerEndpoint
from .listener import DEFAULT_RUNTIME_ROOT, DEFAULT_SOCKET_PATH, RootActionUnixListener
from .posix_store import PosixRootActionStore
from .public_projection import AtomicPublicProjectionPublisher
from .submission import SubmissionPolicy
from .worker import RootActionExecutionWorker


STATE_ROOT = Path("/var/lib/agent-runtime-ops/root-actions")
STORE_ROOT = STATE_ROOT / "private"
PUBLIC_ROOT = STATE_ROOT / "public"
TRUSTED_READER_ACCOUNT_ENV = "AGENT_RUNTIME_OPS_TRUSTED_ACCOUNT"
TRUSTED_READER_ACCOUNT_FALLBACK = "svcops"


def trusted_reader_account() -> str:
    account = os.environ.get(TRUSTED_READER_ACCOUNT_ENV, TRUSTED_READER_ACCOUNT_FALLBACK)
    if not account or not account.isidentifier() or len(account) > 32:
        raise SystemExit("trusted reader account configuration is invalid")
    return account


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("root-action broker service must run as root")
    trusted_account = trusted_reader_account()
    account = pwd.getpwnam(trusted_account)
    group = grp.getgrnam(trusted_account)
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
    webauthn_policy = WebAuthnPolicy.from_environment()
    worker = RootActionExecutionWorker(
        store,
        repair_public=broker.repair_public_best_effort,
    )
    worker.recover_orphaned_claims()
    broker.reconcile_public()
    worker.start()
    authorization = RootActionAuthorizationService(
        store,
        WebAuthnVerifier(webauthn_policy),
        dispatch=worker.enqueue,
    )
    listener = RootActionUnixListener(
        RootActionBrokerEndpoint(broker, authorization=authorization),
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
        worker.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
