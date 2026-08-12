from __future__ import annotations

import errno
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.groupware_runtime_observation import (
    DeclaredPathProbe,
    GroupwareRuntimeObservationError,
    ResolvedRuntime,
    RuntimeObservation,
    ServicePrincipal,
    groupware_runtime_desired_contract,
    _assume_service_principal,
    _matches_service,
    _resolve_runtime,
    observe_groupware_runtime,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.execution import (
    DEFAULT_EXECUTION_POLICIES,
    DEFAULT_OPERATION_HANDLERS,
    ExecutionPolicy,
    ExecutionPolicyRegistry,
    OperationAvailability,
    OperationHandlerRegistry,
)
from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.submission import (
    BrokerPeerIdentity,
    SubmissionPolicy,
)
from agent_runtime_ops.root_actions.groupware_runtime_observation import (
    GroupwareRuntimeObservationHandler,
)
from agent_runtime_ops.root_actions.posix_store import PosixRootActionStore
from agent_runtime_ops.root_actions.registry import DEFAULT_REGISTRY
from agent_runtime_ops.root_actions.state import TransitionEvent, TransitionKind
from agent_runtime_ops.root_actions.worker import RootActionExecutionWorker
from agent_runtime_ops.routing import RuntimeBinding
from tests.test_root_action_admission import Events
from tests.test_root_action_contracts import encoded, valid_manifest


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
PROFILE_DIGEST = "sha256:" + "d" * 64


def groupware_job():
    value = valid_manifest()
    value["operation_id"] = "nas.observe_groupware_runtime"
    value["parameters"] = {"slot": "oc16"}
    value["expected_pre_state"] = {"kind": "none", "digest": None}
    return seal_typed_manifest(encoded(value))


def principal() -> ServicePrincipal:
    return ServicePrincipal(9001, 1022, 1043, (1043, 1060), DIGEST_C)


def resolved() -> ResolvedRuntime:
    binding = RuntimeBinding(
        instance_id="11111111-1111-4111-8111-111111111111",
        linux_account="oc16",
        public_host="oc16.example.com",
        family="hermes",
        runtime_class="customer",
        gateway_port=30001,
        bridge_port=30002,
    )
    return ResolvedRuntime(
        binding,
        "0123456789ab",
        777,
        "hermes-runtime-customer",
        PROFILE_DIGEST,
        "/workspace/nas_docs",
        "/home/oc16/nas_docs/groupware",
        ("groupware/mails/example",),
        ("groupware/mails/example",),
        ("groupware_mails_example",),
        ("//nas.example/groupware[/groupware/mails/example]",),
        DIGEST_A,
        DIGEST_B,
    )


def observation() -> RuntimeObservation:
    return RuntimeObservation(
        "oc16",
        PROFILE_DIGEST,
        1,
        1,
        DIGEST_A,
        DIGEST_B,
        "healthy",
        "runtime_observation_healthy",
        principal(),
        (
            DeclaredPathProbe(
                0, True, True, True, True, True, True, True, True, None, "regular_file"
            ),
        ),
    )


def observe_with(
    result: dict[str, object],
    *,
    runtime: ResolvedRuntime | None = None,
    host_present: bool = True,
    container_present: bool = True,
    host_source_match: bool = True,
    host_readonly: bool = True,
    host_observed: bool = True,
    host_target: str = "/home/oc16/nas_docs/groupware/groupware_mails_example",
    mountinfo_calls: list[tuple[int, str]] | None = None,
) -> RuntimeObservation:
    expected_source = "//nas.example/groupware[/groupware/mails/example]"
    host_rows = []
    container_rows = []
    if host_present:
        host_rows.append(
            {
                "target": host_target,
                "source": (
                    expected_source
                    if host_source_match
                    else "//other.example/groupware[/groupware/mails/example]"
                ),
                "fstype": "cifs",
                "options": f"{'ro' if host_readonly else 'rw'},nosuid,nodev",
            }
        )
    if container_present:
        container_rows.append(
            {
                "target": "/workspace/nas_docs/groupware/groupware_mails_example",
                "source": expected_source,
                "fstype": "cifs",
                "options": "ro,nosuid,nodev",
            }
        )
    def mountinfo(pid: int, target: str):
        if mountinfo_calls is not None:
            mountinfo_calls.append((pid, target))
        if pid == 1:
            return (0, "", host_rows) if host_observed else (1, "unavailable", [])
        return 0, "", container_rows

    with (
        patch(
            "agent_runtime_ops.domain.groupware_runtime_observation._resolve_runtime",
            return_value=runtime or resolved(),
        ),
        patch(
            "agent_runtime_ops.domain.groupware_runtime_observation._service_principal",
            return_value=principal(),
        ),
        patch(
            "agent_runtime_ops.domain.groupware_runtime_observation._probe_namespace",
            return_value=(result,),
        ),
        patch(
            "agent_runtime_ops.domain.groupware_runtime_observation.mountinfo_under",
            side_effect=mountinfo,
        ),
    ):
        return observe_groupware_runtime("oc16")


class GroupwareRuntimeObservationTests(unittest.TestCase):
    def test_status_contract_builder_matches_observer_digest_payload(self) -> None:
        binding = resolved().binding
        record = {
            "share": "//10.10.10.2/hanpass_groupware",
            "paths": ["groupware/mails/example"],
        }
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.get_runtime_binding",
                return_value=binding,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_views_state",
                return_value={},
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.get_view_record",
                return_value=record,
            ),
        ):
            contract = groupware_runtime_desired_contract(
                "oc16",
                Path("/unused"),
                "/workspace/nas_docs",
                "hermes-runtime-customer",
                PROFILE_DIGEST,
            )
        self.assertEqual(contract.host_nas_root, "/home/oc16/nas_docs/groupware")
        self.assertEqual(contract.aliases, ("groupware_mails_example",))
        self.assertEqual(contract.runtime_profile_digest, PROFILE_DIGEST)
        self.assertEqual(contract.requested_paths, ("groupware/mails/example",))
        self.assertEqual(contract.effective_paths, ("groupware/mails/example",))
        self.assertEqual(
            contract.desired_digest,
            "sha256:ce7e75d5ebd561b6d87f118fb32a2a17c8b0a22e6c64da263f11ea75530da934",
        )

    def test_desired_digest_binds_profile_digest_and_requested_effective_sets(
        self,
    ) -> None:
        binding = resolved().binding
        record = {
            "share": "//10.10.10.2/hanpass_groupware",
            "paths": ["groupware/mails/example", "groupware/approval/example"],
            "rooms_missing_media": ["groupware/approval/example"],
        }
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.get_runtime_binding",
                return_value=binding,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_views_state",
                return_value={},
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.get_view_record",
                return_value=record,
            ),
        ):
            first = groupware_runtime_desired_contract(
                "oc16",
                Path("/unused"),
                "/workspace/nas_docs",
                "hermes-runtime-customer",
                PROFILE_DIGEST,
            )
            second = groupware_runtime_desired_contract(
                "oc16",
                Path("/unused"),
                "/workspace/nas_docs",
                "hermes-runtime-customer",
                DIGEST_C,
            )
        self.assertEqual(len(first.requested_paths), 2)
        self.assertEqual(len(first.effective_paths), 1)
        self.assertNotEqual(first.desired_digest, second.desired_digest)

    def test_requested_effective_shortfall_cannot_be_healthy(self) -> None:
        runtime = replace(
            resolved(),
            requested_paths=(
                "groupware/mails/example",
                "groupware/approval/example",
            ),
        )
        value = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            runtime=runtime,
        )
        facts = dict(value.public_facts())
        self.assertEqual(value.status, "unhealthy")
        self.assertEqual(value.reason_code, "runtime_path_cardinality_mismatch")
        self.assertEqual(facts["failure_class"], "PATH_CARDINALITY_MISMATCH")
        self.assertEqual(facts["requested_path_count"], "2")
        self.assertEqual(facts["effective_path_count"], "1")
        self.assertEqual(facts["declared_path_count"], "1")

    def test_host_mount_uses_canonical_slot_target_in_host_namespace(self) -> None:
        calls: list[tuple[int, str]] = []
        value = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            mountinfo_calls=calls,
        )
        self.assertEqual(value.status, "healthy")
        self.assertEqual(
            calls,
            [
                (1, "/home/oc16/nas_docs/groupware"),
                (777, "/workspace/nas_docs/groupware"),
            ],
        )

    def test_wrong_host_target_fails_closed_without_path_fallback(self) -> None:
        value = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            host_target="/home/oc20/nas_docs/groupware/groupware_mails_example",
        )
        facts = dict(value.public_facts())
        self.assertEqual(value.reason_code, "runtime_mount_missing")
        self.assertEqual(facts["host_mount_present_count"], "0")
        self.assertEqual(facts["container_mount_verified_count"], "1")
        self.assertEqual(facts["bounded_probe_open_read_count"], "1")

    def test_enabled_observation_policy_claims_and_dispatches_once_on_submit(
        self,
    ) -> None:
        policies = ExecutionPolicyRegistry(
            (
                ExecutionPolicy(
                    "audit.verify",
                    1,
                    OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
                    "disabled",
                ),
                ExecutionPolicy(
                    "projection.staging_selftest",
                    1,
                    OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
                    "disabled",
                ),
                ExecutionPolicy(
                    "agent_loop.campaign_run",
                    1,
                    OperationAvailability.DISABLED_UNVERIFIED_AUTHORITY,
                    "disabled",
                ),
                ExecutionPolicy(
                    "nas.observe_groupware_runtime",
                    1,
                    OperationAvailability.ENABLED,
                    None,
                    True,
                ),
            )
        )
        store = LocalRootActionFixture()
        dispatched: list[tuple[str, str]] = []
        broker = TypedRootActionBroker(
            store,
            events=Events(
                [
                    ("event-observe-submit", "2026-07-27T05:00:01Z"),
                    ("event-observe-circuit", "2026-07-27T05:00:01Z"),
                    ("event-observe-claim", "2026-07-27T05:00:02Z"),
                ]
            ),
            policies=policies,
            submission_policy=SubmissionPolicy(
                allowed_uids=frozenset({1002}), allowed_gids=frozenset()
            ),
            dispatch=lambda job_id, job_digest: dispatched.append((job_id, job_digest)),
        )
        value = valid_manifest()
        value["operation_id"] = "nas.observe_groupware_runtime"
        value["parameters"] = {"slot": "oc16"}
        value["expected_pre_state"] = {"kind": "none", "digest": None}
        job = seal_typed_manifest(encoded(value))
        submitted = broker.submit(
            job.canonical_manifest, peer=BrokerPeerIdentity(1002, 1002, 1)
        )
        self.assertEqual(submitted.status["state"]["name"], "running")
        self.assertEqual(dispatched, [(job.job_id, job.job_digest)])
        self.assertEqual(store.read_record(job.job_id).execution_count, 1)
        retry = broker.submit(
            job.canonical_manifest, peer=BrokerPeerIdentity(1002, 1002, 1)
        )
        self.assertEqual(retry.status["state"]["name"], "running")
        self.assertEqual(dispatched, [(job.job_id, job.job_digest)])

    def test_registry_exposes_only_slot_and_fixed_handler(self) -> None:
        spec = DEFAULT_REGISTRY.spec("nas.observe_groupware_runtime")
        self.assertEqual(spec.parameter_names, ("slot",))
        self.assertEqual(
            DEFAULT_EXECUTION_POLICIES.enabled_operation_ids,
            ("nas.observe_groupware_runtime",),
        )
        self.assertIsInstance(
            DEFAULT_OPERATION_HANDLERS.handler("nas.observe_groupware_runtime"),
            GroupwareRuntimeObservationHandler,
        )
        self.assertFalse(
            {"path", "argv", "command", "env", "payload"}.intersection(
                spec.parameter_names
            )
        )

    def test_principal_transition_preserves_groups_before_gid_uid(self) -> None:
        calls: list[tuple[str, object]] = []
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.os.setgroups",
                side_effect=lambda value: calls.append(("groups", value)),
                create=True,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.os.setgid",
                side_effect=lambda value: calls.append(("gid", value)),
                create=True,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.os.setuid",
                side_effect=lambda value: calls.append(("uid", value)),
                create=True,
            ),
        ):
            _assume_service_principal(principal())
        self.assertEqual(
            calls,
            [("groups", [1043, 1060]), ("gid", 1043), ("uid", 1022)],
        )

    def test_service_match_is_fixed_and_family_specific(self) -> None:
        self.assertTrue(
            _matches_service(
                "openclaw",
                ("node", "dist/index.js", "gateway", "--port", "18789"),
            )
        )
        self.assertTrue(
            _matches_service(
                "hermes", ("node", "/opt/hermes-workspace/server-entry.js")
            )
        )
        self.assertFalse(_matches_service("openclaw", ("sh", "-c", "id")))
        self.assertFalse(
            _matches_service("hermes", ("node", "/tmp/caller-selected.js"))
        )

    def test_runtime_resolution_binds_applied_profile_to_container_identity(
        self,
    ) -> None:
        runtime = resolved()
        target = SimpleNamespace(
            route=runtime.binding,
            runtime_profile=runtime.runtime_profile,
            runtime_profile_digest=runtime.runtime_profile_digest,
        )
        contract = SimpleNamespace(
            runtime_profile=runtime.runtime_profile,
            runtime_profile_digest=runtime.runtime_profile_digest,
            container_nas_root=runtime.container_nas_root,
            host_nas_root=runtime.host_nas_root,
            requested_paths=runtime.requested_paths,
            effective_paths=runtime.effective_paths,
            aliases=runtime.aliases,
            expected_sources=runtime.expected_sources,
            desired_digest=runtime.desired_digest,
        )
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_runtime_target",
                return_value=target,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.find_gateway_container_by_binding",
                return_value=(runtime.container, "instance_label"),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation._container_state",
                return_value=(runtime.container_pid, runtime.runtime_profile),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_profile",
                return_value=SimpleNamespace(
                    name=runtime.runtime_profile,
                    digest=runtime.runtime_profile_digest,
                    metadata={
                        "family": "hermes",
                        "slot_class": "customer",
                        "container_nas_root": runtime.container_nas_root,
                    },
                ),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation._groupware_desired_contract",
                return_value=contract,
            ),
        ):
            actual = _resolve_runtime("oc16", Path("/state"))
        self.assertEqual(actual.runtime_profile_digest, PROFILE_DIGEST)
        self.assertNotEqual(actual.container_identity_digest, DIGEST_B)

    def test_runtime_resolution_rejects_profile_name_and_digest_drift(self) -> None:
        runtime = resolved()
        target = SimpleNamespace(
            route=runtime.binding,
            runtime_profile=runtime.runtime_profile,
            runtime_profile_digest=runtime.runtime_profile_digest,
        )
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_runtime_target",
                return_value=target,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.find_gateway_container_by_binding",
                return_value=(runtime.container, "instance_label"),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation._container_state",
                return_value=(runtime.container_pid, "different-profile"),
            ),
        ):
            with self.assertRaisesRegex(
                GroupwareRuntimeObservationError, "container_profile_mismatch"
            ):
                _resolve_runtime("oc16", Path("/state"))
        with (
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_runtime_target",
                return_value=target,
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.find_gateway_container_by_binding",
                return_value=(runtime.container, "instance_label"),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation._container_state",
                return_value=(runtime.container_pid, runtime.runtime_profile),
            ),
            patch(
                "agent_runtime_ops.domain.groupware_runtime_observation.load_profile",
                return_value=SimpleNamespace(
                    name=runtime.runtime_profile,
                    digest=DIGEST_C,
                    metadata={
                        "family": "hermes",
                        "slot_class": "customer",
                    },
                ),
            ),
        ):
            with self.assertRaisesRegex(
                GroupwareRuntimeObservationError, "runtime_profile_digest_mismatch"
            ):
                _resolve_runtime("oc16", Path("/state"))

    def test_evidence_axes_are_distinct_and_required_for_healthy(self) -> None:
        result = {
            "index": 0,
            "list_ok": True,
            "open_read_ok": True,
            "errno": None,
            "representative": "regular_file",
        }
        healthy = observe_with(result)
        missing_host = observe_with(result, host_present=False)
        self.assertEqual(healthy.status, "healthy")
        healthy_facts = dict(healthy.public_facts())
        self.assertEqual(healthy_facts["failure_class"], "HEALTHY")
        self.assertEqual(healthy_facts["host_mount_present_count"], "1")
        self.assertEqual(healthy_facts["host_mount_source_match_count"], "1")
        self.assertEqual(healthy_facts["host_mount_readonly_count"], "1")
        self.assertEqual(healthy_facts["bounded_probe_open_read_count"], "1")
        self.assertTrue(healthy.probes[0].container_mount_present)
        self.assertTrue(healthy.probes[0].open_read_ok)
        self.assertEqual(missing_host.status, "unhealthy")
        self.assertEqual(missing_host.reason_code, "runtime_mount_missing")
        missing_facts = dict(missing_host.public_facts())
        self.assertEqual(missing_facts["failure_class"], "MOUNT_MISSING")
        self.assertEqual(missing_facts["mount_missing_count"], "1")
        self.assertFalse(missing_host.probes[0].host_mount_present)
        self.assertTrue(missing_host.probes[0].open_read_ok)

    def test_bounded_search_without_file_is_unknown_not_denied(self) -> None:
        value = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": False,
                "errno": None,
                "representative": "no_regular_file_within_bound",
            }
        )
        self.assertEqual(value.status, "unknown")
        self.assertEqual(value.reason_code, "runtime_empty_readable")
        facts = dict(value.public_facts())
        self.assertEqual(facts["failure_class"], "EMPTY_READABLE")
        self.assertEqual(facts["bounded_probe_empty_readable_count"], "1")

    def test_source_mismatch_is_explicit_without_publishing_source(self) -> None:
        value = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            host_source_match=False,
        )
        facts = dict(value.public_facts())
        self.assertEqual(value.status, "unhealthy")
        self.assertEqual(value.reason_code, "runtime_source_mismatch")
        self.assertEqual(facts["failure_class"], "SOURCE_MISMATCH")
        self.assertEqual(facts["host_mount_present_count"], "1")
        self.assertEqual(facts["host_mount_source_match_count"], "0")
        self.assertNotIn("nas.example", json.dumps(facts))

    def test_access_denied_and_contract_mismatch_are_distinct(self) -> None:
        denied = observe_with(
            {
                "index": 0,
                "list_ok": False,
                "open_read_ok": False,
                "errno": errno.EACCES,
                "representative": "directory_open_failed",
            }
        )
        contract = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            host_readonly=False,
        )
        unobserved = observe_with(
            {
                "index": 0,
                "list_ok": True,
                "open_read_ok": True,
                "errno": None,
                "representative": "regular_file",
            },
            host_observed=False,
        )
        denied_facts = dict(denied.public_facts())
        contract_facts = dict(contract.public_facts())
        self.assertEqual(denied.reason_code, "runtime_access_denied")
        self.assertEqual(denied_facts["access_denied_count"], "1")
        self.assertEqual(contract.status, "unknown")
        self.assertEqual(
            contract.reason_code, "runtime_observer_contract_mismatch"
        )
        self.assertEqual(contract_facts["host_mount_readonly_count"], "0")
        self.assertEqual(
            contract_facts["observer_contract_mismatch_count"], "1"
        )
        self.assertEqual(unobserved.reason_code, "runtime_observer_contract_mismatch")
        self.assertNotEqual(unobserved.reason_code, "runtime_mount_missing")

    def test_handler_receipt_is_redacted_and_binds_principal(self) -> None:

        with patch(
            "agent_runtime_ops.root_actions.groupware_runtime_observation.observe_groupware_runtime",
            return_value=observation(),
        ):
            result = GroupwareRuntimeObservationHandler().run(groupware_job())
        raw = json.loads(result.raw_bytes)
        facts = dict(result.public_facts)
        self.assertEqual(result.terminal_outcome, "succeeded")
        self.assertEqual(
            raw["schema"], "agent-runtime-groupware-runtime-observation/v2"
        )
        self.assertEqual(raw["runtime_profile_digest"], PROFILE_DIGEST)
        self.assertEqual(raw["requested_path_count"], 1)
        self.assertEqual(raw["effective_path_count"], 1)
        self.assertEqual(raw["principal"]["uid"], 1022)
        self.assertEqual(raw["principal"]["supplementary_group_count"], 2)
        self.assertEqual(facts["open_read_verified_count"], "1")
        self.assertEqual(facts["failure_class"], "HEALTHY")
        self.assertEqual(facts["container_mount_present_count"], "1")
        self.assertEqual(facts["container_mount_source_match_count"], "1")
        self.assertEqual(facts["bounded_probe_open_read_count"], "1")
        self.assertEqual(facts["runtime_profile_digest"], PROFILE_DIGEST)
        self.assertEqual(facts["requested_path_count"], "1")
        self.assertEqual(facts["effective_path_count"], "1")
        text = result.raw_bytes.decode()
        self.assertNotIn("groupware/mails/example", text)
        self.assertNotIn("0123456789ab", text)
        self.assertNotIn("argv", text)

    def test_worker_persists_raw_and_public_receipts(self) -> None:
        handlers = OperationHandlerRegistry((GroupwareRuntimeObservationHandler(),))
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "agent_runtime_ops.root_actions.groupware_runtime_observation.observe_groupware_runtime",
                return_value=observation(),
            ),
        ):
            store = PosixRootActionStore(
                Path(temporary) / "root-actions",
                create=True,
                required_uid=None,
                required_gid=None,
                require_posix=False,
            )
            job = groupware_job()
            store.seal_pending(
                job,
                event_id="event-groupware-pending",
                occurred_at="2026-08-11T01:00:00Z",
            )
            store.compare_and_append(
                TransitionEvent(
                    event_id="event-groupware-claim",
                    job_id=job.job_id,
                    job_digest=job.job_digest,
                    expected_revision=0,
                    kind=TransitionKind.CLAIM_EXECUTION,
                    occurred_at="2026-08-11T01:00:01Z",
                )
            )
            repaired = threading.Event()
            worker = RootActionExecutionWorker(
                store,
                handlers=handlers,
                events=Events([("event-groupware-complete", "2026-08-11T01:00:02Z")]),
                repair_public=lambda _job_id: repaired.set(),
            )
            worker.start()
            try:
                worker.enqueue(job.job_id, job.job_digest)
                self.assertTrue(repaired.wait(2))
            finally:
                worker.close()
            raw = json.loads(store.read_raw_root_only(job.job_id).raw_bytes)
            receipt = store.retrieve(job.job_id, job.job_digest).receipt_copy()
        self.assertEqual(
            raw["schema"], "agent-runtime-groupware-runtime-observation/v2"
        )
        self.assertEqual(receipt["operation_id"], "nas.observe_groupware_runtime")
        self.assertEqual(receipt["result"]["status"], "healthy")

    def test_unavailable_runtime_is_durable_redacted_unknown(self) -> None:
        with patch(
            "agent_runtime_ops.root_actions.groupware_runtime_observation.observe_groupware_runtime",
            side_effect=GroupwareRuntimeObservationError("container_not_found"),
        ):
            result = GroupwareRuntimeObservationHandler().run(groupware_job())
        raw = json.loads(result.raw_bytes)
        self.assertEqual(result.terminal_outcome, "failed")
        self.assertEqual(result.public_status, "unknown")
        self.assertEqual(
            dict(result.public_facts)["failure_class"], "OBSERVER_CONTRACT_MISMATCH"
        )
        self.assertEqual(raw["reason_code"], "container_not_found")
        self.assertEqual(raw["runtime_profile_digest"], "unavailable")
        self.assertIsNone(raw["requested_path_count"])
        self.assertIsNone(raw["effective_path_count"])
        self.assertEqual(raw["declared_paths"], [])
        self.assertEqual(raw["writes"], 0)


if __name__ == "__main__":
    unittest.main()
