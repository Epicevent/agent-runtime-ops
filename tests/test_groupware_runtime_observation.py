from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_runtime_ops.domain.groupware_runtime_observation import (
    DeclaredPathProbe,
    GroupwareRuntimeObservationError,
    ResolvedRuntime,
    RuntimeObservation,
    ServicePrincipal,
    _assume_service_principal,
    _matches_service,
    observe_groupware_runtime,
)
from agent_runtime_ops.root_actions.contracts import seal_typed_manifest
from agent_runtime_ops.root_actions.execution import (
    DEFAULT_EXECUTION_POLICIES,
    DEFAULT_OPERATION_HANDLERS,
    OperationHandlerRegistry,
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
        "/workspace/nas_docs",
        ("groupware_mails_example",),
        DIGEST_A,
        DIGEST_B,
    )


def observation() -> RuntimeObservation:
    return RuntimeObservation(
        "oc16",
        DIGEST_A,
        DIGEST_B,
        "healthy",
        "runtime_observation_healthy",
        principal(),
        (
            DeclaredPathProbe(
                0, True, True, True, True, True, True, None, "regular_file"
            ),
        ),
    )


def observe_with(
    result: dict[str, object],
    *,
    host_present: bool = True,
    container_present: bool = True,
) -> RuntimeObservation:
    host_rows = []
    container_rows = []
    if host_present:
        host_rows.append(
            {
                "target": "/home/oc16/nas_docs/groupware/groupware_mails_example",
                "fstype": "cifs",
                "options": "ro,nosuid,nodev",
            }
        )
    if container_present:
        container_rows.append(
            {
                "target": "/workspace/nas_docs/groupware/groupware_mails_example",
                "fstype": "cifs",
                "options": "ro,nosuid,nodev",
            }
        )
    with patch(
        "agent_runtime_ops.domain.groupware_runtime_observation._resolve_runtime",
        return_value=resolved(),
    ), patch(
        "agent_runtime_ops.domain.groupware_runtime_observation._service_principal",
        return_value=principal(),
    ), patch(
        "agent_runtime_ops.domain.groupware_runtime_observation._probe_namespace",
        return_value=(result,),
    ), patch(
        "agent_runtime_ops.domain.groupware_runtime_observation.findmnt_under",
        return_value=(0, "", host_rows),
    ), patch(
        "agent_runtime_ops.domain.groupware_runtime_observation.mountinfo_under",
        return_value=(0, "", container_rows),
    ):
        return observe_groupware_runtime("oc16")


class GroupwareRuntimeObservationTests(unittest.TestCase):
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
        with patch(
            "agent_runtime_ops.domain.groupware_runtime_observation.os.setgroups",
            side_effect=lambda value: calls.append(("groups", value)),
        ), patch(
            "agent_runtime_ops.domain.groupware_runtime_observation.os.setgid",
            side_effect=lambda value: calls.append(("gid", value)),
        ), patch(
            "agent_runtime_ops.domain.groupware_runtime_observation.os.setuid",
            side_effect=lambda value: calls.append(("uid", value)),
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
        self.assertTrue(healthy.probes[0].container_mount_present)
        self.assertTrue(healthy.probes[0].open_read_ok)
        self.assertEqual(missing_host.status, "unhealthy")
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
        self.assertEqual(value.reason_code, "runtime_observation_incomplete")

    def test_handler_receipt_is_redacted_and_binds_principal(self) -> None:
        with patch(
            "agent_runtime_ops.root_actions.groupware_runtime_observation.observe_groupware_runtime",
            return_value=observation(),
        ):
            result = GroupwareRuntimeObservationHandler().run(groupware_job())
        raw = json.loads(result.raw_bytes)
        facts = dict(result.public_facts)
        self.assertEqual(result.terminal_outcome, "succeeded")
        self.assertEqual(raw["principal"]["uid"], 1022)
        self.assertEqual(raw["principal"]["supplementary_group_count"], 2)
        self.assertEqual(facts["open_read_verified_count"], "1")
        text = result.raw_bytes.decode()
        self.assertNotIn("groupware/mails/example", text)
        self.assertNotIn("0123456789ab", text)
        self.assertNotIn("argv", text)

    def test_worker_persists_raw_and_public_receipts(self) -> None:
        handlers = OperationHandlerRegistry((GroupwareRuntimeObservationHandler(),))
        with tempfile.TemporaryDirectory() as temporary, patch(
            "agent_runtime_ops.root_actions.groupware_runtime_observation.observe_groupware_runtime",
            return_value=observation(),
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
                events=Events(
                    [("event-groupware-complete", "2026-08-11T01:00:02Z")]
                ),
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
        self.assertEqual(raw["schema"], "agent-runtime-groupware-runtime-observation/v1")
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
        self.assertEqual(raw["reason_code"], "container_not_found")
        self.assertEqual(raw["declared_paths"], [])
        self.assertEqual(raw["writes"], 0)


if __name__ == "__main__":
    unittest.main()
