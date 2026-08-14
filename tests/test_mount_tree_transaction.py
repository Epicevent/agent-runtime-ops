import contextlib
import ctypes
import errno
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agent_runtime_ops.commands import groupware_view_replace as replace_view
from agent_runtime_ops.commands import nas_view
from agent_runtime_ops.domain import groupware_runtime_observation as observation
from agent_runtime_ops.host import mount_tree_transaction as transaction


CANDIDATE = Path("C:/run/generation/candidate")
ANCHOR = Path("C:/run/generation/rollback")
LIVE = Path("C:/srv/kw-nas/slots/oc6/groupware")


class MountTreeTransactionTests(unittest.TestCase):
    def test_syscall_arguments_include_recursive_private_mount_setattr(self) -> None:
        calls = []
        with patch.object(
            transaction, "_syscall", lambda number, *args: calls.append((number, args)) or 41
        ):
            self.assertEqual(transaction._open_tree(LIVE, clone=True), 41)
            self.assertEqual(transaction._clone_tree_from_fd(41), 41)
            transaction._move_mount(41, LIVE, beneath=True)
            transaction._make_private_tree(41)

        self.assertEqual([number for number, _ in calls], [428, 428, 429, 442])
        self.assertEqual(type(calls[0][1][0]), ctypes.c_long)
        self.assertEqual(calls[0][1][2].value, 0x88001)
        self.assertEqual(calls[1][1][2].value, 0x89001)
        self.assertEqual(calls[2][1][-1].value, 0x204)
        self.assertEqual(calls[3][1][2].value, 0x9000)
        attributes = ctypes.cast(
            calls[3][1][3], ctypes.POINTER(transaction._MountAttr)
        ).contents
        self.assertEqual(attributes.propagation, 0x40000)

    def test_prepare_privatizes_both_clones_before_attaching_or_detaching(self) -> None:
        events = []
        descriptors = iter((10, 11))
        with (
            patch.object(transaction, "_require_safe_paths", lambda *args: None),
            patch.object(
                transaction,
                "_open_tree",
                lambda path, *, clone: events.append(("open", path.name, clone))
                or next(descriptors),
            ),
            patch.object(
                transaction,
                "_make_private_tree",
                lambda fd: events.append(("private", fd)),
            ),
            patch.object(
                transaction,
                "_move_mount",
                lambda fd, path, *, beneath: events.append(("move", path.name, beneath)),
            ),
            patch.object(
                transaction, "detach_top", lambda path: events.append(("detach", path.name))
            ),
            patch.object(transaction, "findmnt_one", lambda path: (1, "", [])),
        ):
            self.assertEqual(
                transaction.prepare_transaction(CANDIDATE, LIVE, ANCHOR), (10, 11)
            )

        self.assertEqual(
            events,
            [
                ("open", "groupware", True),
                ("private", 10),
                ("move", "rollback", False),
                ("open", "candidate", True),
                ("private", 11),
                ("detach", "candidate"),
            ],
        )

    def test_prepare_cleanup_failure_still_closes_both_descriptors(self) -> None:
        closed = []
        descriptors = iter((10, 11))

        def detach(path: Path) -> None:
            raise OSError(errno.EBUSY, "busy")

        with (
            patch.object(transaction, "_require_safe_paths", lambda *args: None),
            patch.object(
                transaction, "_open_tree", lambda path, *, clone: next(descriptors)
            ),
            patch.object(transaction, "_make_private_tree", lambda fd: None),
            patch.object(transaction, "_move_mount", lambda *args, **kwargs: None),
            patch.object(transaction, "detach_top", detach),
            patch.object(transaction.os, "close", closed.append),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "prepare_undo_failed:16:16"
            ):
                transaction.prepare_transaction(CANDIDATE, LIVE, ANCHOR)

        self.assertEqual(closed, [10, 11])

    def test_prepare_failure_matrix_closes_every_open_fd_without_touching_live(self) -> None:
        for failure in (
            "open-old",
            "private-old",
            "attach-anchor",
            "open-candidate",
            "private-candidate",
            "detach-candidate",
            "vacancy",
        ):
            with self.subTest(failure=failure):
                events = []

                def open_tree(path, *, clone):
                    step = "open-old" if path == LIVE else "open-candidate"
                    events.append(step)
                    if failure == step:
                        raise OSError(errno.EIO, step)
                    return 10 if path == LIVE else 11

                def make_private(fd):
                    step = "private-old" if fd == 10 else "private-candidate"
                    events.append(step)
                    if failure == step:
                        raise OSError(errno.EIO, step)

                def move_mount(fd, path, *, beneath):
                    events.append("attach-anchor")
                    if failure == "attach-anchor":
                        raise OSError(errno.EIO, "attach-anchor")

                def detach(path):
                    step = "detach-candidate" if path == CANDIDATE else "detach-anchor"
                    events.append(("detach", path))
                    if failure == "detach-candidate" and path == CANDIDATE:
                        raise OSError(errno.EBUSY, step)

                with (
                    patch.object(transaction, "_require_safe_paths", lambda *args: None),
                    patch.object(transaction, "_open_tree", open_tree),
                    patch.object(transaction, "_make_private_tree", make_private),
                    patch.object(transaction, "_move_mount", move_mount),
                    patch.object(transaction, "detach_top", detach),
                    patch.object(
                        transaction,
                        "findmnt_one",
                        lambda path: (
                            (0, "", [{"target": path.as_posix()}])
                            if failure == "vacancy"
                            else (1, "", [])
                        ),
                    ),
                    patch.object(
                        transaction.os,
                        "close",
                        lambda fd: events.append(("close", fd)),
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "prepare_failed"):
                        transaction.prepare_transaction(CANDIDATE, LIVE, ANCHOR)

                self.assertNotIn(("detach", LIVE), events)
                opened = []
                if "open-old" in events and failure != "open-old":
                    opened.append(10)
                if "open-candidate" in events and failure != "open-candidate":
                    opened.append(11)
                self.assertEqual(
                    [
                        item[1]
                        for item in events
                        if isinstance(item, tuple) and item[0] == "close"
                    ],
                    opened,
                )

    def test_mount_layer_graph_counts_only_one_linear_root_stack(self) -> None:
        rows = [
            {"mount_id": "30", "parent_id": "20", "target": LIVE.as_posix()},
            {"mount_id": "20", "parent_id": "1", "target": LIVE.as_posix()},
            {"mount_id": "31", "parent_id": "30", "target": f"{LIVE.as_posix()}/x"},
        ]
        with patch.object(transaction, "mountinfo_under", lambda *args: (0, "", rows)):
            self.assertEqual(transaction.root_mount_layers(LIVE), 2)
        rows[1]["parent_id"] = "30"
        with patch.object(transaction, "mountinfo_under", lambda *args: (0, "", rows)):
            with self.assertRaisesRegex(RuntimeError, "mount_layer_graph_invalid"):
                transaction.root_mount_layers(LIVE)


def _tree_rows(root: str, paths: tuple[str, ...], propagation: str = "private"):
    rows = [
        {
            "mount_id": "10",
            "parent_id": "1",
            "major_minor": "0:1",
            "root": "/view",
            "target": root,
            "source": "/view",
            "fstype": "tmpfs",
            "options": "ro,nosuid,nodev",
            "propagation": propagation,
        }
    ]
    for index, path in enumerate(paths, start=11):
        alias = observation.path_alias(path)
        rows.append(
            {
                "mount_id": str(index),
                "parent_id": "10",
                "major_minor": f"0:{index}",
                "root": f"/{path}",
                "target": f"{root}/{alias}",
                "source": f"//nas/groupware[/{path}]",
                "fstype": "cifs",
                "options": "ro,nosuid,nodev",
                "propagation": propagation,
            }
        )
    return rows


class GroupwareTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = {
            "share": "//nas/groupware",
            "paths": ["groupware/mails/user", "groupware/approval/user"],
            "rooms_missing_media": [],
        }
        self.root = "/run/stage/candidate"

    def test_digest_ignores_propagation_but_private_policy_is_explicit(self) -> None:
        paths = tuple(self.record["paths"])
        with patch.object(
            observation, "mountinfo_under", lambda *args: (0, "", _tree_rows(self.root, paths))
        ):
            _, private_digest = observation.groupware_mount_tree(
                self.root, self.record, require_complete=True, require_private=True
            )
        with patch.object(
            observation,
            "mountinfo_under",
            lambda *args: (0, "", _tree_rows(self.root, paths, "shared")),
        ):
            _, shared_digest = observation.groupware_mount_tree(self.root, self.record)
            with self.assertRaisesRegex(
                observation.GroupwareRuntimeObservationError, "mount_tree_mismatch"
            ):
                observation.groupware_mount_tree(
                    self.root, self.record, require_private=True
                )
        self.assertEqual(private_digest, shared_digest)

    def test_extra_mount_and_wrong_parent_fail_closed(self) -> None:
        rows = _tree_rows(self.root, tuple(self.record["paths"]))
        rows.append(dict(rows[-1], mount_id="99", target=f"{self.root}/extra"))
        with patch.object(observation, "mountinfo_under", lambda *args: (0, "", rows)):
            with self.assertRaisesRegex(
                observation.GroupwareRuntimeObservationError, "mount_tree_mismatch"
            ):
                observation.groupware_mount_tree(self.root, self.record)
        rows = _tree_rows(self.root, tuple(self.record["paths"]))
        rows[1]["parent_id"] = "1"
        with patch.object(observation, "mountinfo_under", lambda *args: (0, "", rows)):
            with self.assertRaisesRegex(
                observation.GroupwareRuntimeObservationError, "mount_tree_mismatch"
            ):
                observation.groupware_mount_tree(self.root, self.record)


class ReplaceRecoveryTests(unittest.TestCase):
    def _state(self, phase: str, *, current_is_candidate: bool = False):
        old = {
            "share": "//nas/groupware",
            "user_id": "user",
            "paths": ["old"],
            "rooms_missing_media": [],
        }
        candidate = dict(old, paths=["new"])
        current = candidate if current_is_candidate else old
        pending = {
            "schema": replace_view._PENDING_SCHEMA,
            "phase": phase,
            "slot": "oc6",
            "generation": "a" * 32,
            "boot_id": "boot",
            "candidate_record": candidate,
            "old_tree_digest": "old-tree",
            "candidate_tree_digest": "new-tree",
            "old_runtime_contract": replace_view._digest(
                {"desired": "old-desired", "profile": "profile", "principal": "principal"}
            ),
            "candidate_runtime_contract": replace_view._digest(
                {"desired": "new-desired", "profile": "profile", "principal": "principal"}
            ),
        }
        pending["authority_digest"] = replace_view._digest(
            {"pending": dict(pending), "record": current}
        )
        return {
            "corpus_views": {"oc6": {"groupware": current}},
            "views": {},
            "pending_replace": pending,
        }, old, candidate

    def _base(self, state: dict, *, anchor: bool = True):
        observation_result = Mock(
            status="unhealthy",
            reason_code="runtime_path_cardinality_mismatch",
            desired_digest="old-desired",
            runtime_profile_digest="profile",
            principal=Mock(identity_digest="principal"),
        )
        stack = contextlib.ExitStack()
        stack.enter_context(
            patch.object(replace_view.nas_views, "load_views_state", lambda root: state)
        )
        stack.enter_context(
            patch.object(Path, "read_text", lambda path, **kwargs: "boot\n")
        )
        stack.enter_context(
            patch.object(
                replace_view.legacy,
                "_findmnt_one",
                lambda path: (0, "", [{"target": path.as_posix()}])
                if anchor
                else (1, "", []),
            )
        )
        stack.enter_context(
            patch.object(
                replace_view.observation,
                "observe_groupware_runtime",
                lambda *args, **kwargs: observation_result,
            )
        )
        return stack

    def test_anchor_absent_old_runtime_clears_precommit_state(self) -> None:
        state, old, _ = self._state("prepared")
        writes = []
        with self._base(state, anchor=False), patch.object(
            replace_view, "_tree", lambda root, record, **kwargs: ((), "old-tree")
        ), patch.object(replace_view, "_persist", lambda *args, **kwargs: writes.append(args)):
            replace_view.recover_pending(Path("C:/state"))
        self.assertEqual(len(writes), 1)

    def test_hidden_candidate_rolls_back_via_anchor_without_move_back(self) -> None:
        state, old, candidate = self._state("rollback_authoritative")
        events = []
        layers = iter((2, 2))
        top = iter(("old-tree", "new-tree", "new-tree"))

        def tree(root, record, **kwargs):
            return (), "old-tree"

        with (
            self._base(state),
            patch.object(replace_view, "_tree", tree),
            patch.object(replace_view, "_top_tree_digest", lambda *args: next(top)),
            patch.object(
                replace_view.mount_tx, "root_mount_layers", lambda path: next(layers)
            ),
            patch.object(
                replace_view.mount_tx,
                "detach_top",
                lambda path: events.append(("detach", path.name)),
            ),
            patch.object(replace_view.mount_tx, "_open_tree", lambda *args, **kwargs: 10),
            patch.object(replace_view.mount_tx, "_clone_tree_from_fd", lambda fd: 11),
            patch.object(
                replace_view.mount_tx,
                "_make_private_tree",
                lambda fd: events.append(("private", fd)),
            ),
            patch.object(
                replace_view.mount_tx,
                "_move_mount",
                lambda fd, path, *, beneath: events.append(("move", path.name, beneath)),
            ),
            patch.object(replace_view.os, "close", lambda fd: None),
            patch.object(
                replace_view,
                "_persist",
                lambda *args, **kwargs: events.append(
                    ("persist", args[3] if len(args) > 3 else "clear")
                ),
            ),
        ):
            replace_view.recover_pending(Path("C:/state"))

        self.assertIn(("persist", "rollback_beneath"), events)
        self.assertEqual(
            [event for event in events if event[0] == "move"],
            [("move", "groupware", True)],
        )
        self.assertEqual(
            [event for event in events if event[0] == "detach"],
            [("detach", "groupware"), ("detach", "groupware"), ("detach", "rollback")],
        )

    def test_rollback_beneath_crash_detaches_candidate_without_second_move(self) -> None:
        state, _, _ = self._state("rollback_beneath")
        events = []
        top_digest = Mock(side_effect=["new-tree", "old-tree"])
        with (
            self._base(state),
            patch.object(replace_view, "_tree", lambda *args, **kwargs: ((), "old-tree")),
            patch.object(replace_view, "_top_tree_digest", top_digest),
            patch.object(replace_view.mount_tx, "root_mount_layers", lambda path: 2),
            patch.object(
                replace_view.mount_tx,
                "detach_top",
                lambda path: events.append(path.name),
            ),
            patch.object(replace_view.mount_tx, "_move_mount") as move,
            patch.object(replace_view, "_persist"),
        ):
            replace_view.recover_pending(Path("C:/state"))
        move.assert_not_called()
        self.assertEqual(events, ["groupware", "rollback"])
        self.assertEqual(top_digest.call_count, 2)

    def test_commit_decided_only_verifies_forward_and_cleans_anchor(self) -> None:
        state, _, candidate = self._state("commit_decided", current_is_candidate=True)
        events = []
        stable = Mock(
            status="unhealthy",
            reason_code="runtime_access_denied",
            desired_digest="new-desired",
            runtime_profile_digest="profile",
            principal=Mock(identity_digest="principal"),
        )
        with (
            self._base(state),
            patch.object(replace_view, "_tree", lambda *args, **kwargs: ((), "new-tree")),
            patch.object(replace_view.mount_tx, "root_mount_layers", lambda path: 1),
            patch.object(
                replace_view.observation,
                "observe_groupware_runtime",
                lambda *args, **kwargs: stable,
            ),
            patch.object(
                replace_view.mount_tx,
                "detach_top",
                lambda path: events.append(path.name),
            ),
            patch.object(replace_view, "_persist", lambda *args, **kwargs: events.append("clear")),
            patch.object(replace_view.mount_tx, "_move_mount") as move,
        ):
            replace_view.recover_pending(Path("C:/state"))
        move.assert_not_called()
        self.assertEqual(events, ["rollback", "clear"])

    def test_commit_decided_rejects_live_tree_not_matching_sealed_candidate(self) -> None:
        state, _, _ = self._state("commit_decided", current_is_candidate=True)
        with (
            self._base(state),
            patch.object(replace_view, "_tree", lambda *args, **kwargs: ((), "wrong-tree")),
            patch.object(replace_view.mount_tx, "root_mount_layers", lambda path: 1),
        ):
            with self.assertRaisesRegex(RuntimeError, "committed_live_mismatch"):
                replace_view.recover_pending(Path("C:/state"))

    def test_boot_change_requires_restore_readiness_before_clearing_pending(self) -> None:
        state, _, _ = self._state("prepared")
        state["pending_replace"]["boot_id"] = "old-boot"
        pending = state["pending_replace"]
        pending["authority_digest"] = replace_view._digest(
            {
                "pending": {
                    key: value
                    for key, value in pending.items()
                    if key != "authority_digest"
                },
                "record": state["corpus_views"]["oc6"]["groupware"],
            }
        )
        events = []
        with (
            self._base(state),
            patch.object(
                replace_view.legacy,
                "_restore_views",
                lambda *args, **kwargs: events.append("restore") or 0,
            ),
            patch.object(
                replace_view,
                "_persist",
                lambda *args, **kwargs: events.append("clear"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "boot_restore_required"):
                replace_view.recover_pending(Path("C:/state"))
            self.assertTrue(
                replace_view.recover_pending(
                    Path("C:/state"), boot_restore_ready=True
                )
            )
        self.assertEqual(events, ["restore", "clear"])

    def test_boot_restore_failure_retains_pending_authority(self) -> None:
        state, _, _ = self._state("commit_decided", current_is_candidate=True)
        state["pending_replace"]["boot_id"] = "old-boot"
        pending = state["pending_replace"]
        pending["authority_digest"] = replace_view._digest(
            {
                "pending": {
                    key: value
                    for key, value in pending.items()
                    if key != "authority_digest"
                },
                "record": state["corpus_views"]["oc6"]["groupware"],
            }
        )
        persist = Mock()
        with (
            self._base(state),
            patch.object(replace_view.legacy, "_restore_views", return_value=1),
            patch.object(replace_view, "_persist", persist),
        ):
            with self.assertRaisesRegex(RuntimeError, "boot_restore_failed"):
                replace_view.recover_pending(
                    Path("C:/state"), boot_restore_ready=True
                )
        persist.assert_not_called()

    def test_replace_persists_each_authority_gate_before_the_next_mount_step(self) -> None:
        old = {
            "share": "//nas/groupware",
            "user_id": "user",
            "paths": ["old"],
            "rooms_missing_media": [],
        }
        state = {
            "views": {},
            "corpus_views": {"oc6": {"groupware": old}},
        }
        args = SimpleNamespace(
            slot="oc6",
            user_id="user",
            share="//nas/groupware",
            path=["new"],
            require_content_ready=True,
            expected_runtime_desired_digest="cas",
        )
        plan = nas_view.ViewPlan(
            "oc6",
            "user",
            Mock(),
            Path("/master"),
            Path("/view"),
            LIVE,
            room_binds=[(Path("/master/new"), Path("/view/new"))],
            corpus="groupware",
            paths=["new"],
        )
        principal = SimpleNamespace(identity_digest="principal")
        runtime = SimpleNamespace(
            container_identity_digest="container",
            runtime_profile_digest="profile",
        )
        before = SimpleNamespace(
            status="unhealthy",
            reason_code="runtime_path_cardinality_mismatch",
            desired_digest="old-desired",
            runtime_profile_digest="profile",
            container_identity_digest="container",
            principal=principal,
        )
        candidate = SimpleNamespace(
            status="healthy",
            reason_code="runtime_observation_healthy",
            desired_digest="new-desired",
            runtime_profile_digest="profile",
            container_identity_digest="container",
            principal=principal,
        )
        events = []

        def persist(root, current_state, pending=None, phase="", stage=None):
            current = replace_view.nas_views.get_view_record(
                current_state, "oc6", "groupware"
            )
            events.append(
                (
                    "persist",
                    phase,
                    tuple(current.get("paths") or []),
                    str((pending or {}).get("candidate_runtime_contract") or ""),
                )
            )

        def tree(root, record, **kwargs):
            return (), "new-tree" if record.get("paths") == ["new"] else "old-tree"

        with (
            patch.object(replace_view.nas_views, "load_views_state", return_value=state),
            patch.object(
                replace_view.legacy,
                "_groupware_runtime_desired_digest",
                return_value="cas",
            ),
            patch.object(replace_view.observation, "_resolve_runtime", return_value=runtime),
            patch.object(
                replace_view.observation,
                "_service_principal",
                return_value=principal,
            ),
            patch.object(
                replace_view.observation,
                "observe_groupware_runtime",
                side_effect=(before, candidate),
            ),
            patch.object(replace_view, "_master", return_value=Path("/master")),
            patch.object(replace_view.nas_views, "build_view_plan", return_value=plan),
            patch.object(replace_view, "_tree", side_effect=tree),
            patch.object(replace_view, "_persist", side_effect=persist),
            patch.object(
                replace_view,
                "_prepare_stage",
                side_effect=lambda path: events.append(("stage",)),
            ),
            patch.object(
                replace_view.legacy,
                "_apply_binds",
                side_effect=lambda staged: events.append(("bind",))
                or (True, "ok", 1),
            ),
            patch.object(replace_view, "_probe_candidate", return_value="new-tree"),
            patch.object(
                replace_view.mount_tx,
                "prepare_transaction",
                side_effect=lambda *args: events.append(("prepare",)) or (10, 11),
            ),
            patch.object(
                replace_view.mount_tx,
                "_move_mount",
                side_effect=lambda *args, **kwargs: events.append(("beneath",)),
            ),
            patch.object(
                replace_view.mount_tx,
                "detach_top",
                side_effect=lambda *args: events.append(("reveal",)),
            ),
            patch.object(replace_view.mount_tx, "root_mount_layers", return_value=1),
            patch.object(replace_view.os, "urandom", return_value=b"x" * 16),
            patch.object(replace_view.os, "close"),
            patch.object(Path, "read_text", return_value="boot\n"),
            patch.object(replace_view.legacy, "_now_iso", return_value="now"),
            patch.object(
                replace_view,
                "recover_pending",
                side_effect=lambda root: events.append(("recover",)) or False,
            ),
        ):
            replace_view._replace(args, Path("/state"))

        labels = [event[0] for event in events]
        self.assertLess(labels.index("persist"), labels.index("stage"))
        self.assertLess(labels.index("bind"), labels.index("prepare"))
        self.assertLess(labels.index("prepare"), labels.index("beneath"))
        rollback_gate = next(
            index
            for index, event in enumerate(events)
            if event[:2] == ("persist", "rollback_authoritative")
        )
        self.assertLess(rollback_gate, labels.index("beneath"))
        commit = next(
            event for event in events if event[:2] == ("persist", "commit_decided")
        )
        self.assertEqual(commit[2], ("new",))
        self.assertTrue(commit[3].startswith("sha256:"))
        self.assertEqual(events[-1], ("recover",))


class CommandContractTests(unittest.TestCase):
    def test_serialized_mutation_recovers_before_calling_command(self) -> None:
        events = []

        @contextlib.contextmanager
        def lock(root):
            events.append("lock")
            yield
            events.append("unlock")

        wrapped = nas_view._serialized_view_mutation(
            lambda args: events.append("command") or 0
        )
        with (
            patch.object(nas_view, "_is_root", lambda: True),
            patch.object(nas_view, "_state_root", lambda args: Path("C:/state")),
            patch.object(nas_view, "runtime_host_mutation_lock", lock),
            patch.object(replace_view, "recover_pending", lambda root: events.append("recover")),
        ):
            self.assertEqual(wrapped(Mock()), 0)
        self.assertEqual(events, ["lock", "recover", "command", "unlock"])

    def test_failure_reports_recovery_failure_without_raw_exception(self) -> None:
        args = Mock(slot="oc6", path=["secret/customer/path"])
        output = io.StringIO()
        with (
            patch.object(replace_view.legacy, "_require_root", lambda command: True),
            patch.object(replace_view.legacy, "_state_root", lambda args: Path("C:/state")),
            patch.object(replace_view, "_replace", side_effect=ValueError("/secret path")),
            patch.object(replace_view, "recover_pending", side_effect=RuntimeError("fail")),
            patch.object(nas_view, "_is_root", lambda: False),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(replace_view.cmd_nas_view_replace(args), 1)
        self.assertIn("reason=unexpected_error", output.getvalue())
        self.assertIn("recovery_status=failed", output.getvalue())
        self.assertNotIn("secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
