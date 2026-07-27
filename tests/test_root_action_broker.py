from __future__ import annotations

import json
import unittest

from agent_runtime_ops.root_actions import BrokerPeerIdentity, SubmissionPolicy
from agent_runtime_ops.root_actions.broker import (
    PUBLIC_CATALOG_JOB_LIMIT,
    TypedRootActionBroker,
)
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.registry import REGISTRY_VERSION
from agent_runtime_ops.root_actions.storage import StorageConflict, StorageNotFound


def manifest(*, job_id: str = "job-broker-1") -> bytes:
    return json.dumps(
        {
            "schema": "agent-runtime-root-action-manifest/v1",
            "registry_version": REGISTRY_VERSION,
            "job_id": job_id,
            "operation_id": "artifact.probe_kwrag_product",
            "operation_version": 1,
            "request": {
                "request_id": "request-broker-1",
                "lineage_id": "lineage-broker-1",
                "reply_target": "task-019f-root",
                "submitted_at": "2026-07-27T08:00:00Z",
            },
            "parameters": {
                "revision": "1" * 40,
            },
            "expected_pre_state": {"kind": "none", "digest": None},
            "review": {
                "purpose": "Read one bounded candidate proof.",
                "premises": [
                    {
                        "claim": "The probe reads only the named proof fields.",
                        "basis": "direct_observation",
                        "anchor": {
                            "source": "opsctl artifact probe source",
                            "quote": "writes=0",
                        },
                        "falsifier": "Any host write or unbounded output invalidates the premise.",
                    }
                ],
                "targets": ["kwrag candidate proof"],
                "changes": ["No persistent change"],
                "recovery": ["No rollback is required for a read-only operation"],
                "risk_delta": {
                    "baseline": "The artifact is not observed by this job.",
                    "added": [],
                    "removed": [],
                    "maximum_consequence": "The bounded observation may fail closed.",
                },
            },
        },
        ensure_ascii=False,
    ).encode("utf-8")


TEST_PEER = BrokerPeerIdentity(uid=1002, gid=1002, pid=4242)
TEST_SUBMISSION_POLICY = SubmissionPolicy(
    allowed_uids=frozenset({1002}),
    allowed_gids=frozenset(),
)


class FixedEvents:
    def __init__(self) -> None:
        self.calls = 0

    def next_event(self) -> tuple[str, str]:
        self.calls += 1
        return f"event-sealed-{self.calls}", f"2026-07-27T08:00:0{self.calls}Z"


class CapturingSink:
    def __init__(self) -> None:
        self.bundles = []

    def publish(self, bundle) -> None:
        self.bundles.append(bundle)


class FailingSink:
    def publish(self, bundle) -> None:
        raise OSError("projection storage unavailable")


class BoundedCatalogStore(LocalRootActionFixture):
    def __init__(self) -> None:
        super().__init__()
        self.observed_limit = None

    def catalog_job_ids(self, *, limit: int):
        self.observed_limit = limit
        ids, _count = super().catalog_job_ids(limit=limit)
        return ids, 5000


class CatalogCoverageSink(CapturingSink):
    def __init__(self) -> None:
        super().__init__()
        self.catalog = None

    def publish_catalog(self, bundles, *, authority_job_count=None) -> None:
        self.catalog = (bundles, authority_job_count)


class TypedRootActionBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = LocalRootActionFixture()
        self.events = FixedEvents()
        self.sink = CapturingSink()
        self.broker = TypedRootActionBroker(
            self.store,
            events=self.events,
            public_sink=self.sink,
            submission_policy=TEST_SUBMISSION_POLICY,
        )

    def test_submit_seals_pending_and_projects_exact_public_status(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        self.assertEqual(submitted.job_id, "job-broker-1")
        self.assertEqual(submitted.status["state"]["name"], "pending")
        self.assertEqual(
            submitted.status["job"]["reply_target"],
            "task-019f-root",
        )
        self.assertEqual(self.broker.status(submitted.job_id), submitted.status)
        history = self.broker.history(submitted.job_id)
        self.assertEqual(
            [row["action"] for row in history["events"]], ["sealed_pending"]
        )
        self.assertEqual(len(self.sink.bundles), 1)
        self.assertEqual(self.sink.bundles[0].job_digest, submitted.job_digest)

    def test_exact_duplicate_is_idempotent_and_does_not_replace_sealed_job(self) -> None:
        first = self.broker.submit(manifest(), peer=TEST_PEER)
        second = self.broker.submit(manifest(), peer=TEST_PEER)
        self.assertEqual(second, first)
        self.assertEqual(self.broker.status(first.job_id), first.status)
        self.assertEqual(len(self.store.read_ledger(first.job_id)), 1)

    def test_receipt_lookup_is_bound_to_exact_job_digest(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        with self.assertRaises(StorageNotFound):
            self.broker.receipt("job-broker-1", "sha256:" + "0" * 64)
        with self.assertRaises(StorageNotFound):
            self.broker.receipt("job-missing", submitted.job_digest)

    def test_public_projection_is_canonical_and_identity_bound(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        bundle = self.broker.public_projection(submitted.job_id)
        self.assertEqual(bundle.job_id, submitted.job_id)
        self.assertEqual(bundle.job_digest, submitted.job_digest)
        self.assertTrue(bundle.status_bytes.endswith(b"\n"))
        self.assertTrue(bundle.history_bytes.endswith(b"\n"))
        self.assertNotIn(b"stdout", bundle.status_bytes + bundle.history_bytes)
        self.assertNotIn(b"stderr", bundle.status_bytes + bundle.history_bytes)
        self.assertEqual(
            json.loads(bundle.status_bytes)["job"]["job_digest"],
            submitted.job_digest,
        )

    def test_catalog_rebuild_fetches_only_explicit_bounded_recent_ids(self) -> None:
        store = BoundedCatalogStore()
        sink = CatalogCoverageSink()
        broker = TypedRootActionBroker(
            store,
            events=FixedEvents(),
            public_sink=sink,
            submission_policy=TEST_SUBMISSION_POLICY,
        )
        broker.submit(manifest(), peer=TEST_PEER)
        self.assertEqual(store.observed_limit, PUBLIC_CATALOG_JOB_LIMIT)
        self.assertIsNotNone(sink.catalog)
        bundles, authority_count = sink.catalog
        self.assertEqual(len(bundles), 1)
        self.assertEqual(authority_count, 5000)

    def test_public_broker_exposes_no_authentication_or_dispatch_surface(self) -> None:
        self.assertFalse(hasattr(self.broker, "authenticate"))
        self.assertFalse(hasattr(self.broker, "approve"))
        self.assertFalse(hasattr(self.broker, "dispatch"))
        self.assertFalse(hasattr(self.broker, "execute"))

    def test_submitter_cannot_supply_audit_event_identity_or_time(self) -> None:
        with self.assertRaises(TypeError):
            self.broker.submit(  # type: ignore[call-arg]
                manifest(job_id="job-forged-event"),
                peer=TEST_PEER,
                event_id="event-from-submitter",
                occurred_at="2026-07-27T00:00:00Z",
            )

    def test_disabled_historical_family_is_rejected_without_execution(self) -> None:
        value = json.loads(manifest(job_id="job-disabled-network"))
        value["operation_id"] = "kwrag.network_ensure"
        value["parameters"] = {
            "network_plan_digest": "sha256:" + "a" * 64,
            "expected_state": "absent",
            "expected_identity_digest": None,
        }
        submitted = self.broker.submit(
            json.dumps(value).encode("utf-8"), peer=TEST_PEER
        )
        self.assertEqual(submitted.status["state"]["name"], "terminal")
        self.assertEqual(submitted.status["state"]["execution_count"], 0)
        self.assertEqual(
            submitted.status["state"]["reason_code"],
            "disabled_by_product_boundary",
        )
        self.assertEqual(submitted.status["receipt"]["kind"], "terminal_notice")
        self.assertEqual(
            [row["action"] for row in self.broker.history(submitted.job_id)["events"]],
            ["sealed_pending", "close_pending"],
        )

    def test_public_projection_failure_is_recoverable_from_authoritative_store(
        self,
    ) -> None:
        failing = TypedRootActionBroker(
            self.store,
            events=self.events,
            public_sink=FailingSink(),
            submission_policy=TEST_SUBMISSION_POLICY,
        )
        submitted = failing.submit(
            manifest(job_id="job-projection-recovery"), peer=TEST_PEER
        )
        self.assertEqual(submitted.job_id, "job-projection-recovery")
        self.assertEqual(self.store.list_job_ids(), ("job-projection-recovery",))

        recovered_sink = CapturingSink()
        recovered = TypedRootActionBroker(
            self.store,
            events=self.events,
            public_sink=recovered_sink,
            submission_policy=TEST_SUBMISSION_POLICY,
        ).reconcile_public()
        self.assertEqual(
            [item.job_id for item in recovered], ["job-projection-recovery"]
        )
        self.assertEqual(len(recovered_sink.bundles), 1)


if __name__ == "__main__":
    unittest.main()
