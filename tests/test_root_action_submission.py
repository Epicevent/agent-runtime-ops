from __future__ import annotations

import json
import struct
import unittest

from agent_runtime_ops.root_actions import (
    BrokerPeerIdentity,
    RootActionSubmissionEndpoint,
    SUBMISSION_RESPONSE_SCHEMA,
    SubmissionPolicy,
    SubmissionRejected,
    decode_submission_frame,
    encode_submission_frame,
    seal_typed_manifest,
)
from agent_runtime_ops.root_actions.broker import TypedRootActionBroker
from agent_runtime_ops.root_actions.contracts import MAX_MANIFEST_BYTES
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from agent_runtime_ops.root_actions.storage import StorageConflict, SubmissionLimits
from tests.test_root_action_broker import FixedEvents, TEST_PEER, manifest
from tests.root_action_support import TEST_EXECUTION_POLICIES


class RootActionSubmissionTests(unittest.TestCase):
    def test_binary_frame_is_exact_and_has_no_extra_method_or_path_surface(
        self,
    ) -> None:
        raw = manifest()
        frame = encode_submission_frame(raw)
        self.assertEqual(decode_submission_frame(frame), raw)
        with self.assertRaisesRegex(SubmissionRejected, "does not match"):
            decode_submission_frame(frame + b"extra")
        with self.assertRaisesRegex(SubmissionRejected, "length is invalid"):
            decode_submission_frame(struct.pack("!I", MAX_MANIFEST_BYTES + 1))
        with self.assertRaisesRegex(SubmissionRejected, "truncated"):
            decode_submission_frame(b"\x00\x00")

    def test_explicit_peer_allowlist_and_manifest_time_window_fail_closed(self) -> None:
        job = seal_typed_manifest(manifest())
        policy = SubmissionPolicy(
            allowed_uids=frozenset({1002}),
            allowed_gids=frozenset(),
        )
        metadata = policy.authorize(
            job,
            peer=TEST_PEER,
            broker_received_at="2026-07-27T08:00:01Z",
        )
        self.assertEqual(metadata.peer_uid, 1002)
        with self.assertRaisesRegex(SubmissionRejected, "not allowlisted"):
            policy.authorize(
                job,
                peer=BrokerPeerIdentity(uid=2002, gid=2002, pid=1),
                broker_received_at="2026-07-27T08:00:01Z",
            )
        with self.assertRaisesRegex(SubmissionRejected, "stale"):
            policy.authorize(
                job,
                peer=TEST_PEER,
                broker_received_at="2026-07-27T09:00:00Z",
            )
        with self.assertRaisesRegex(SubmissionRejected, "future"):
            policy.authorize(
                job,
                peer=TEST_PEER,
                broker_received_at="2026-07-27T07:00:00Z",
            )

    def test_lineage_and_uid_circuit_breakers_are_atomic_store_guards(self) -> None:
        store = LocalRootActionFixture()
        policy = SubmissionPolicy(
            allowed_uids=frozenset({1002}),
            allowed_gids=frozenset(),
            limits=SubmissionLimits(
                max_open_per_uid=8,
                max_open_per_lineage=1,
                max_jobs_per_uid_window=32,
                window_seconds=3600,
            ),
        )
        broker = TypedRootActionBroker(
            store,
            events=FixedEvents(),
            policies=TEST_EXECUTION_POLICIES,
            submission_policy=policy,
        )
        broker.submit(manifest(job_id="job-lineage-1"), peer=TEST_PEER)
        second = json.loads(manifest(job_id="job-lineage-2"))
        with self.assertRaisesRegex(StorageConflict, "lineage circuit breaker"):
            broker.submit(json.dumps(second).encode("utf-8"), peer=TEST_PEER)
        self.assertEqual(store.list_job_ids(), ("job-lineage-1",))

    def test_policy_cannot_be_constructed_without_a_peer_allowlist(self) -> None:
        with self.assertRaisesRegex(SubmissionRejected, "explicit peer allowlist"):
            SubmissionPolicy(allowed_uids=frozenset(), allowed_gids=frozenset())

    def test_endpoint_accepts_only_exact_frame_and_returns_bounded_identity(
        self,
    ) -> None:
        broker = TypedRootActionBroker(
            LocalRootActionFixture(),
            events=FixedEvents(),
            policies=TEST_EXECUTION_POLICIES,
            submission_policy=SubmissionPolicy(
                allowed_uids=frozenset({1002}),
                allowed_gids=frozenset(),
            ),
        )
        endpoint = RootActionSubmissionEndpoint(broker)
        response = endpoint.handle(
            encode_submission_frame(manifest()),
            peer=TEST_PEER,
        )
        value = json.loads(response)
        self.assertEqual(
            set(value),
            {
                "schema",
                "job_id",
                "job_digest",
                "state",
                "terminal_outcome",
                "reason_code",
                "projection_digest",
            },
        )
        self.assertEqual(value["schema"], SUBMISSION_RESPONSE_SCHEMA)
        self.assertEqual(value["job_id"], "job-broker-1")
        self.assertEqual(value["state"], "pending")
        self.assertNotIn(b"parameters", response)
        self.assertNotIn(b"review", response)
        self.assertLessEqual(len(response), 4096)

    def test_endpoint_has_no_approval_authentication_or_execution_surface(self) -> None:
        endpoint = RootActionSubmissionEndpoint(object())
        self.assertFalse(hasattr(endpoint, "authenticate"))
        self.assertFalse(hasattr(endpoint, "approve"))
        self.assertFalse(hasattr(endpoint, "dispatch"))
        self.assertFalse(hasattr(endpoint, "execute"))


if __name__ == "__main__":
    unittest.main()
