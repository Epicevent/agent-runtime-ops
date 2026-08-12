from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

import pytest

from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.client import (
    RootActionBrokerClient,
    RootActionRequestHandle,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.endpoint import RootActionBrokerEndpoint
from agent_runtime_ops.root_actions.execution import DEFAULT_EXECUTION_POLICIES
from agent_runtime_ops.root_actions.groupware_reobservation import (
    MAX_GROUPWARE_SLOTS_PER_CYCLE,
    TERMINAL_WAIT_SECONDS_PER_SLOT,
    GroupwareReobservationError,
    build_groupware_reobservation_manifest,
    declared_groupware_slots,
    main,
    plan_groupware_reobservations,
    submit_groupware_reobservations,
)
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.submission import (
    BrokerPeerIdentity,
    SubmissionPolicy,
)
from agent_runtime_ops.routing import RuntimeBinding


MODULE = "agent_runtime_ops.root_actions.groupware_reobservation"
PEER = BrokerPeerIdentity(uid=1002, gid=1002, pid=4242)


def _binding(
    slot: str,
    index: int,
    *,
    enabled: bool = True,
    upstream_kind: str = "managed-rootful",
) -> RuntimeBinding:
    return RuntimeBinding(
        instance_id=str(uuid.UUID(int=index + 1)),
        linux_account=slot,
        public_host=f"{slot}.example.com",
        family="openclaw",
        runtime_class="customer",
        gateway_port=20000 + index * 2,
        bridge_port=20001 + index * 2,
        enabled=enabled,
        upstream_kind=upstream_kind,
        upstream_owner="owner" if upstream_kind == "developer-rootless" else "",
        upstream_container="runtime" if upstream_kind == "developer-rootless" else "",
    )


def _views(slots: tuple[str, ...], *, record: object | None = None) -> dict:
    return {
        "views": {},
        "corpus_views": {
            slot: {
                "groupware": (
                    {"share": "//nas.example/hanpass_groupware", "paths": ["mail"]}
                    if record is None
                    else record
                )
            }
            for slot in slots
        },
    }


class _Events:
    def __init__(self, bucket: datetime) -> None:
        self.bucket = bucket
        self.calls = 0

    def next_event(self) -> tuple[str, str]:
        self.calls += 1
        occurred_at = self.bucket + timedelta(seconds=self.calls)
        return (
            f"event-groupware-{self.calls}",
            occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


class _FailingClient:
    def __init__(
        self,
        *,
        fail_at: int | None = None,
        terminal_state: str = "terminal",
    ) -> None:
        self.fail_at = fail_at
        self.terminal_state = terminal_state
        self.manifests: list[bytes] = []
        self.calls: list[tuple[str, str]] = []

    def submit(self, manifest: bytes):
        self.manifests.append(manifest)
        job = seal_typed_manifest(manifest)
        self.calls.append(("submit", job.job_id))
        if self.fail_at == len(self.manifests):
            raise OSError("broker unavailable")
        return (
            RootActionRequestHandle(
                job.job_id,
                job.job_digest,
                job.request_id,
                job.reply_target,
            ),
            {},
        )

    def poll_terminal(self, handle, *, timeout_seconds: float):
        assert timeout_seconds == TERMINAL_WAIT_SECONDS_PER_SLOT
        self.calls.append(("poll", handle.job_id))
        return (
            {"status": {"state": {"name": self.terminal_state}}},
            object(),
        )


class _TerminalProxy:
    def __init__(self, client: RootActionBrokerClient) -> None:
        self.client = client

    def submit(self, manifest: bytes):
        return self.client.submit(manifest)

    def poll_terminal(self, _handle, *, timeout_seconds: float):
        assert timeout_seconds == TERMINAL_WAIT_SECONDS_PER_SLOT
        return {"status": {"state": {"name": "terminal"}}}, object()


def test_manifest_is_exactly_deterministic_per_slot_and_15_minute_bucket(
    tmp_path: Path,
) -> None:
    first_now = datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc)
    second_now = datetime(2026, 8, 12, 9, 13, 59, tzinfo=timezone.utc)
    with patch(f"{MODULE}.declared_groupware_slots", return_value=("oc16",)):
        first = plan_groupware_reobservations(tmp_path, now=first_now)
        second = plan_groupware_reobservations(tmp_path, now=second_now)
    assert first == second
    job = seal_typed_manifest(first[0].manifest)
    value = job.manifest_copy()
    assert job.job_id == "groupware-reobserve.oc16.20260812t0900z"
    assert value["operation_id"] == "nas.observe_groupware_runtime"
    assert value["operation_version"] == 1
    assert value["request"] == {
        "request_id": job.job_id,
        "lineage_id": "groupware-reobserve.oc16",
        "reply_target": "ops-groupware-reobserver",
        "submitted_at": "2026-08-12T09:00:00Z",
    }
    assert value["parameters"] == {"slot": "oc16"}
    assert value["expected_pre_state"] == {"kind": "none", "digest": None}
    assert value["review"]["changes"] == ["No runtime repair or product-state change"]
    next_bucket = build_groupware_reobservation_manifest(
        "oc16", datetime(2026, 8, 12, 9, 15, tzinfo=timezone.utc)
    )
    assert next_bucket != first[0].manifest


def test_declared_slots_are_sorted_and_require_enabled_bindings() -> None:
    slots = ("oc20", "oc6", "oc16")
    bindings = [_binding(slot, index) for index, slot in enumerate(slots)]
    with (
        patch(f"{MODULE}.load_runtime_bindings", return_value=bindings),
        patch(f"{MODULE}.load_yaml", return_value=_views(slots)),
    ):
        assert declared_groupware_slots(Path("/state")) == ("oc16", "oc20", "oc6")

    bindings[0] = _binding("oc20", 0, enabled=False)
    with (
        patch(f"{MODULE}.load_runtime_bindings", return_value=bindings),
        patch(f"{MODULE}.load_yaml", return_value=_views(slots)),
        pytest.raises(GroupwareReobservationError, match="groupware_slot_not_enabled"),
    ):
        declared_groupware_slots(Path("/state"))


def test_slot_cap_and_malformed_record_fail_before_any_broker_submission(
    tmp_path: Path,
) -> None:
    too_many = tuple(
        f"oc{index + 1}" for index in range(MAX_GROUPWARE_SLOTS_PER_CYCLE + 1)
    )
    bindings = [_binding(slot, index) for index, slot in enumerate(too_many)]
    client = _FailingClient()
    with (
        patch(f"{MODULE}.load_runtime_bindings", return_value=bindings),
        patch(f"{MODULE}.load_yaml", return_value=_views(too_many)),
        pytest.raises(GroupwareReobservationError, match="groupware_slot_cap_exceeded"),
    ):
        submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc),
            client=client,
        )
    assert client.manifests == []

    with (
        patch(f"{MODULE}.load_runtime_bindings", return_value=[_binding("oc6", 0)]),
        patch(f"{MODULE}.load_yaml", return_value=_views(("oc6",), record=[])),
        pytest.raises(GroupwareReobservationError, match="groupware_inventory_invalid"),
    ):
        submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc),
            client=client,
        )
    assert client.manifests == []


def test_unknown_disabled_and_rootless_inventory_fail_before_submission(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc)
    cases = (
        ([], _views(("oc6",)), "groupware_slot_not_enabled"),
        (
            [_binding("oc6", 0, enabled=False)],
            _views(("oc6",)),
            "groupware_slot_not_enabled",
        ),
        (
            [_binding("oc6", 0, upstream_kind="developer-rootless")],
            _views(("oc6",)),
            "groupware_slot_not_rootful",
        ),
        (
            [_binding("oc6", 0)],
            {"views": {}, "corpus_views": []},
            "groupware_inventory_invalid",
        ),
    )
    for bindings, views, reason in cases:
        client = _FailingClient()
        with (
            patch(f"{MODULE}.load_runtime_bindings", return_value=bindings),
            patch(f"{MODULE}.load_yaml", return_value=views),
            pytest.raises(GroupwareReobservationError, match=reason),
        ):
            submit_groupware_reobservations(tmp_path, now=now, client=client)
        assert client.calls == []


def test_slots_submit_and_reach_terminal_strictly_sequentially(tmp_path: Path) -> None:
    client = _FailingClient()
    with patch(
        f"{MODULE}.declared_groupware_slots",
        return_value=("oc1", "oc6", "oc16"),
    ):
        cycle = submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc),
            client=client,
        )
    ids = [handle.job_id for handle in cycle.handles]
    assert client.calls == [
        (action, job_id) for job_id in ids for action in ("submit", "poll")
    ]


def test_unknown_terminal_state_stops_before_the_next_slot(tmp_path: Path) -> None:
    client = _FailingClient(terminal_state="unknown")
    with (
        patch(
            f"{MODULE}.declared_groupware_slots",
            return_value=("oc1", "oc6"),
        ),
        pytest.raises(
            GroupwareReobservationError, match="broker_terminal_state_unknown"
        ),
    ):
        submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc),
            client=client,
        )
    assert len(client.manifests) == 1
    assert [action for action, _job_id in client.calls] == ["submit", "poll"]


def test_persistent_catchup_uses_current_quarter_and_naive_clock_fails_closed(
    tmp_path: Path,
) -> None:
    client = _FailingClient()
    with patch(f"{MODULE}.declared_groupware_slots", return_value=("oc6",)):
        cycle = submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 37, tzinfo=timezone.utc),
            client=client,
        )
    assert cycle.bucket == "2026-08-12T09:30:00Z"
    assert cycle.handles[0].job_id.endswith(".20260812t0930z")
    naive_client = _FailingClient()
    with pytest.raises(GroupwareReobservationError, match="clock_not_timezone_aware"):
        submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9),
            client=naive_client,
        )
    assert naive_client.manifests == []


def test_exact_duplicate_submission_does_not_redispatch(tmp_path: Path) -> None:
    bucket = datetime(2026, 8, 12, 9, tzinfo=timezone.utc)
    store = LocalRootActionFixture()
    dispatched: list[tuple[str, str]] = []
    broker = TypedRootActionBroker(
        store,
        events=_Events(bucket),
        policies=DEFAULT_EXECUTION_POLICIES,
        submission_policy=SubmissionPolicy(
            allowed_uids=frozenset({PEER.uid}),
            allowed_gids=frozenset(),
        ),
        dispatch=lambda job_id, job_digest: dispatched.append((job_id, job_digest)),
    )
    endpoint = RootActionBrokerEndpoint(broker)
    client = RootActionBrokerClient(
        transport=lambda frame, _timeout: endpoint.handle(frame, peer=PEER)
    )
    producer_client = _TerminalProxy(client)
    now = bucket + timedelta(seconds=30)
    with patch(f"{MODULE}.declared_groupware_slots", return_value=("oc16",)):
        first = submit_groupware_reobservations(
            tmp_path, now=now, client=producer_client
        )
        second = submit_groupware_reobservations(
            tmp_path, now=now, client=producer_client
        )
    assert first == second
    assert len(dispatched) == 1
    assert [item.action for item in store.read_ledger(first.handles[0].job_id)] == [
        "sealed_pending",
        "claim_execution",
    ]


def test_broker_failure_stops_cycle_without_submitting_later_slots(
    tmp_path: Path,
) -> None:
    client = _FailingClient(fail_at=2)
    with (
        patch(
            f"{MODULE}.declared_groupware_slots",
            return_value=("oc1", "oc6", "oc16"),
        ),
        pytest.raises(GroupwareReobservationError, match="broker_submission_failed"),
    ):
        submit_groupware_reobservations(
            tmp_path,
            now=datetime(2026, 8, 12, 9, 1, tzinfo=timezone.utc),
            client=client,
        )
    assert [
        seal_typed_manifest(raw).manifest_copy()["parameters"]["slot"]
        for raw in client.manifests
    ] == ["oc1", "oc6"]


def test_module_rejects_every_argument_without_contacting_broker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch.object(sys, "argv", ["groupware_reobservation", "--slot", "oc16"]),
        patch(f"{MODULE}.submit_groupware_reobservations") as submit,
    ):
        assert main() == 2
    submit.assert_not_called()
    assert "reason=arguments_not_supported" in capsys.readouterr().err


def test_install_contract_is_fixed_read_only_oneshot_and_persistent_timer() -> None:
    install = Path("install.sh").read_text(encoding="utf-8")
    start = install.index("install_groupware_reobservation_timer()")
    end = install.index("\n}\n", start) + 3
    function = install[start:end]
    package_start = install.index("install_package()")
    package_end = install.index("\n}\n", package_start) + 3
    package = install[package_start:package_end]
    check_start = install.index("check_install()")
    check_end = install.index("\n}\n", check_start) + 3
    check = install[check_start:check_end]

    assert "Type=oneshot" in function
    assert "User=$OPS_USER" in function
    assert "Group=$OPS_GROUP" in function
    assert (
        "ExecStart=$CURRENT_LINK/.venv/bin/python -I -B -m "
        "agent_runtime_ops.root_actions.groupware_reobservation"
    ) in function
    assert "Environment=AGENT_RUNTIME_STATE_ROOT=$STATE_ROOT" in function
    assert "TimeoutStartSec=1200" in function
    assert "NoNewPrivileges=true" in function
    assert "ProtectSystem=strict" in function
    assert "ReadOnlyPaths=$STATE_ROOT $CURRENT_LINK" in function
    assert "RestrictAddressFamilies=AF_UNIX" in function
    assert "OnCalendar=*-*-* *:00:00 UTC" in function
    assert "Persistent=true" in function
    assert "RandomizedDelaySec" not in function
    assert "systemctl enable --now" in function
    assert "systemctl is-enabled --quiet" in function
    assert "systemctl is-active --quiet" in function
    assert "|| true" not in function
    assert "Requires=agent-runtime-root-action-broker.service" not in function
    assert "sudo" not in function.lower()
    assert package.index("install_root_action_broker_or_restore") < package.index(
        "install_groupware_reobservation_timer"
    )
    assert package.index("install_usage_collect_timer") < package.index(
        "install_groupware_reobservation_timer"
    )
    assert "GROUPWARE_REOBSERVATION_SERVICE_FILE" in check
    assert "GROUPWARE_REOBSERVATION_TIMER_FILE" in check
    assert "groupware reobservation timer is not enabled" in check
    assert "groupware reobservation timer is not active" in check
