from __future__ import annotations

import json
import unittest

from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.registry import REGISTRY_VERSION
from agent_runtime_ops.root_actions.storage import StorageConflict, StorageNotFound


def manifest(*, job_id: str = "job-broker-1") -> bytes:
    return json.dumps(
        {
            "schema": "agent-runtime-root-action-manifest/v1",
            "registry_version": REGISTRY_VERSION,
            "job_id": job_id,
            "operation_id": "audit.verify",
            "operation_version": 1,
            "request": {
                "request_id": "request-broker-1",
                "lineage_id": "lineage-broker-1",
                "reply_target": "task-019f-root",
                "submitted_at": "2026-07-27T08:00:00Z",
            },
            "parameters": {
                "target_identity": "kwrag-candidate",
                "expected_schema": "kwrag-proof-v1",
                "freshness_seconds": 300,
                "allowlisted_fields": ["source_revision", "artifact_digest"],
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
            },
        },
        ensure_ascii=False,
    ).encode("utf-8")


class TypedRootActionBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = LocalRootActionFixture()
        self.broker = TypedRootActionBroker(self.store)

    def test_submit_seals_pending_and_projects_exact_public_status(self) -> None:
        submitted = self.broker.submit(
            manifest(),
            event_id="event-sealed-1",
            occurred_at="2026-07-27T08:00:01Z",
        )
        self.assertEqual(submitted.job_id, "job-broker-1")
        self.assertEqual(submitted.status["state"]["name"], "pending")
        self.assertEqual(
            submitted.status["job"]["reply_target"],
            "task-019f-root",
        )
        self.assertEqual(self.broker.status(submitted.job_id), submitted.status)
        history = self.broker.history(submitted.job_id)
        self.assertEqual([row["action"] for row in history["events"]], ["sealed_pending"])

    def test_duplicate_job_id_does_not_replace_the_first_sealed_job(self) -> None:
        first = self.broker.submit(
            manifest(),
            event_id="event-sealed-1",
            occurred_at="2026-07-27T08:00:01Z",
        )
        with self.assertRaisesRegex(StorageConflict, "already sealed"):
            self.broker.submit(
                manifest(),
                event_id="event-sealed-2",
                occurred_at="2026-07-27T08:00:02Z",
            )
        self.assertEqual(self.broker.status(first.job_id), first.status)

    def test_receipt_lookup_is_bound_to_exact_job_digest(self) -> None:
        submitted = self.broker.submit(
            manifest(),
            event_id="event-sealed-1",
            occurred_at="2026-07-27T08:00:01Z",
        )
        with self.assertRaises(StorageNotFound):
            self.broker.receipt("job-broker-1", "sha256:" + "0" * 64)
        with self.assertRaises(StorageNotFound):
            self.broker.receipt("job-missing", submitted.job_digest)

    def test_public_projection_is_canonical_and_identity_bound(self) -> None:
        submitted = self.broker.submit(
            manifest(),
            event_id="event-sealed-1",
            occurred_at="2026-07-27T08:00:01Z",
        )
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

    def test_public_broker_exposes_no_authentication_or_dispatch_surface(self) -> None:
        self.assertFalse(hasattr(self.broker, "authenticate"))
        self.assertFalse(hasattr(self.broker, "approve"))
        self.assertFalse(hasattr(self.broker, "dispatch"))
        self.assertFalse(hasattr(self.broker, "execute"))


if __name__ == "__main__":
    unittest.main()
