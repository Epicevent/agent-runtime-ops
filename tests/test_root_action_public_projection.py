from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from agent_runtime_ops.root_actions import (
    AtomicPublicProjectionPublisher,
    PublicProjectionError,
    TypedRootActionBroker,
    validate_public_projection,
)
from agent_runtime_ops.root_actions.local_fixture import LocalRootActionFixture
from tests.test_root_action_broker import (
    FixedEvents,
    TEST_PEER,
    TEST_SUBMISSION_POLICY,
    manifest,
)


class RootActionPublicProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "public"
        self.publisher = AtomicPublicProjectionPublisher(
            self.root,
            create=True,
            required_uid=None,
            required_gid=None,
            require_posix=False,
        )
        self.store = LocalRootActionFixture()
        self.broker = TypedRootActionBroker(
            self.store,
            events=FixedEvents(),
            public_sink=self.publisher,
            submission_policy=TEST_SUBMISSION_POLICY,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_submit_publishes_one_atomic_canonical_envelope(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        path = self.root / submitted.job_id / "projection.json"
        self.assertTrue(path.is_file())
        artifact = validate_public_projection(path.read_bytes())
        self.assertEqual(artifact.job_id, submitted.job_id)
        self.assertEqual(artifact.job_digest, submitted.job_digest)
        value = json.loads(artifact.canonical_bytes)
        self.assertEqual(value["status"]["state"]["name"], "pending")
        self.assertEqual(value["history"]["events"][-1]["next_state"], "pending")
        self.assertIsNone(value["receipt"])
        self.assertEqual(list(path.parent.glob(".projection-*.tmp")), [])

    def test_committed_golden_fixture_is_exact_broker_output(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        actual = self.broker.public_projection(submitted.job_id).projection_bytes
        expected = (
            Path(__file__).parent / "fixtures" / "root_action_public_projection_v1.json"
        ).read_bytes()
        self.assertEqual(actual, expected)

    def test_republish_replaces_the_complete_envelope_not_individual_parts(
        self,
    ) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        path = self.root / submitted.job_id / "projection.json"
        before = validate_public_projection(path.read_bytes())
        self.broker.publish_public(submitted.job_id)
        after = validate_public_projection(path.read_bytes())
        self.assertEqual(after, before)
        self.assertEqual(list(path.parent.glob(".projection-*.tmp")), [])

    def test_unsafe_job_identity_is_rejected_before_path_use(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        value = json.loads(
            (self.root / submitted.job_id / "projection.json").read_bytes()
        )
        value["job_id"] = "../escape"
        value["status"]["job"]["job_id"] = "../escape"
        value["history"]["job_id"] = "../escape"
        # Digest invalidity is enough; no code may turn this identity into a path.
        raw = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        with self.assertRaises(PublicProjectionError):
            validate_public_projection(raw)
        self.assertFalse((self.root.parent / "escape").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow policy requires POSIX")
    def test_symlink_job_directory_is_rejected(self) -> None:
        other = self.root / "other"
        other.mkdir()
        link = self.root / "job-broker-1"
        link.symlink_to(other, target_is_directory=True)
        with self.assertRaises(PublicProjectionError):
            self.broker.submit(manifest(), peer=TEST_PEER)
        self.assertFalse((other / "projection.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX owner/mode policy requires POSIX")
    def test_projection_file_has_fixed_public_mode_and_single_link(self) -> None:
        submitted = self.broker.submit(manifest(), peer=TEST_PEER)
        path = self.root / submitted.job_id / "projection.json"
        info = path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)


if __name__ == "__main__":
    unittest.main()
