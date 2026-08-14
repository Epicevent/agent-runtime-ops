from __future__ import annotations

import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.commands.nas_view import cmd_nas_view_restore
from agent_runtime_ops.host.nas_ready import failed_cifs_mount_units, wait_for_nas_ready


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class WaitForNasReadyTest(unittest.TestCase):
    def test_ready_after_retries_with_backoff(self) -> None:
        clock = FakeClock()
        attempts = {"n": 0}

        def probe(host: str) -> bool:
            attempts["n"] += 1
            return attempts["n"] >= 3

        result = wait_for_nas_ready(
            ["192.168.0.222"], total_seconds=600, probe=probe, sleep=clock.sleep, monotonic=clock.monotonic
        )
        self.assertEqual(result, {"192.168.0.222": True})
        self.assertEqual(clock.sleeps, [5.0, 10.0])

    def test_dead_host_times_out_bounded(self) -> None:
        clock = FakeClock()
        result = wait_for_nas_ready(
            ["10.0.0.9"], total_seconds=30, probe=lambda h: False, sleep=clock.sleep, monotonic=clock.monotonic
        )
        self.assertEqual(result, {"10.0.0.9": False})
        self.assertLessEqual(clock.now, 31.0)

    def test_zero_wait_is_single_probe_pass(self) -> None:
        clock = FakeClock()
        result = wait_for_nas_ready(
            ["a", "a", "b"], total_seconds=0, probe=lambda h: h == "a", sleep=clock.sleep, monotonic=clock.monotonic
        )
        self.assertEqual(result, {"a": True, "b": False})
        self.assertEqual(clock.sleeps, [])

    def test_empty_hosts(self) -> None:
        self.assertEqual(wait_for_nas_ready([], total_seconds=600), {})


def _fake_runner(list_output: str, what_by_unit: dict[str, str]):
    def runner(command, **kwargs):
        if command[:2] == ["systemctl", "list-units"]:
            return SimpleNamespace(returncode=0, stdout=list_output, stderr="")
        if command[:2] == ["systemctl", "show"]:
            return SimpleNamespace(returncode=0, stdout=what_by_unit.get(command[2], "") + "\n", stderr="")
        raise AssertionError(command)

    return runner


class FailedCifsMountUnitsTest(unittest.TestCase):
    def test_only_smb_sourced_units_counted(self) -> None:
        listing = "mnt-nas-kakao\\x2dwork.mount loaded failed failed /mnt/nas/kakao-work\nboot.mount loaded failed failed /boot\n"
        units, error = failed_cifs_mount_units(
            _fake_runner(listing, {"mnt-nas-kakao\\x2dwork.mount": "//192.168.0.222/kakao-work", "boot.mount": "/dev/sda1"})
        )
        self.assertIsNone(error)
        self.assertEqual(units, ["mnt-nas-kakao\\x2dwork.mount"])

    def test_no_failed_units(self) -> None:
        units, error = failed_cifs_mount_units(_fake_runner("", {}))
        self.assertIsNone(error)
        self.assertEqual(units, [])

    def test_systemctl_missing_reports_error(self) -> None:
        def runner(command, **kwargs):
            raise FileNotFoundError("systemctl")

        units, error = failed_cifs_mount_units(runner)
        self.assertEqual(units, [])
        self.assertIn("systemctl", error)

    def test_systemctl_failure_reports_error(self) -> None:
        def runner(command, **kwargs):
            return SimpleNamespace(returncode=4, stdout="", stderr="boom")

        units, error = failed_cifs_mount_units(runner)
        self.assertEqual(units, [])
        self.assertEqual(error, "boom")


def _run_restore(*, readiness: dict, mount_all_rc: int = 0, nas_wait_seconds: float = 42.0):
    records = {"views": {"oc1": {"user_id": "7362168", "share": "//192.168.0.222/kakao-work", "package": "p"}}}
    stdout = io.StringIO()
    with (
        patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
        patch(
            "agent_runtime_ops.commands.nas_view.runtime_host_mutation_lock",
            return_value=contextlib.nullcontext(),
        ),
        patch(
            "agent_runtime_ops.commands.groupware_view_replace.recover_pending",
            return_value=False,
        ),
        patch("agent_runtime_ops.commands.nas_view.load_views_state", return_value=records),
        patch("agent_runtime_ops.commands.nas_view.wait_for_nas_ready", return_value=readiness) as wait,
        patch(
            "agent_runtime_ops.commands.nas_view._run_text",
            return_value=SimpleNamespace(returncode=mount_all_rc, stdout="", stderr=""),
        ) as run_text,
        patch("agent_runtime_ops.commands.nas_view._ensure_hidden_dirs"),
        patch("agent_runtime_ops.commands.nas_view._mount_master", return_value=(True, "ok")),
        patch(
            "agent_runtime_ops.commands.nas_view.build_view_plan",
            return_value=SimpleNamespace(user_id="7362168", missing_rooms=[]),
        ),
        patch("agent_runtime_ops.commands.nas_view._apply_binds", return_value=(True, "ok", 13)),
        patch("agent_runtime_ops.commands.nas_view.save_views_state") as save_state,
        patch("agent_runtime_ops.commands.nas_view._append_action_log"),
        contextlib.redirect_stdout(stdout),
    ):
        rc = cmd_nas_view_restore(SimpleNamespace(state_root="/unused", nas_wait_seconds=nas_wait_seconds))
    return rc, stdout.getvalue(), wait, run_text, save_state


class RestoreWaitsForNasTest(unittest.TestCase):
    def test_pending_recovery_runs_only_after_nas_readiness_and_mount_all(self) -> None:
        records = {
            "views": {
                "oc1": {
                    "user_id": "7362168",
                    "share": "//192.168.0.222/kakao-work",
                }
            }
        }
        events: list[str] = []
        with (
            patch("agent_runtime_ops.commands.nas_view._is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.nas_view.runtime_host_mutation_lock",
                return_value=contextlib.nullcontext(),
            ),
            patch(
                "agent_runtime_ops.commands.nas_view.load_views_state",
                return_value=records,
            ),
            patch(
                "agent_runtime_ops.commands.nas_view.wait_for_nas_ready",
                side_effect=lambda *args, **kwargs: events.append("ready") or {},
            ),
            patch(
                "agent_runtime_ops.commands.nas_view._run_text",
                side_effect=lambda *args, **kwargs: events.append("mount-all")
                or SimpleNamespace(returncode=0),
            ),
            patch(
                "agent_runtime_ops.commands.groupware_view_replace.recover_pending",
                side_effect=lambda *args, **kwargs: events.append("recover") or False,
            ),
            patch(
                "agent_runtime_ops.commands.nas_view._restore_views",
                side_effect=lambda *args, **kwargs: events.append("restore") or 0,
            ),
            patch("agent_runtime_ops.commands.nas_view.save_views_state"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                cmd_nas_view_restore(
                    SimpleNamespace(state_root="/unused", nas_wait_seconds=0)
                ),
                0,
            )
        self.assertEqual(events, ["ready", "mount-all", "recover", "restore"])

    def test_restore_probes_nas_and_remounts_fstab(self) -> None:
        rc, output, wait, run_text, save_state = _run_restore(readiness={"192.168.0.222": True})
        self.assertEqual(rc, 0, output)
        self.assertEqual(wait.call_args.kwargs["total_seconds"], 42.0)
        self.assertEqual(wait.call_args.args[0], ["192.168.0.222"])
        self.assertIn("nas_ready host=192.168.0.222 ready=yes", output)
        self.assertIn("cifs_mount_all=ok", output)
        self.assertEqual(run_text.call_args.args[0], ["mount", "-a", "-t", "cifs"])
        save_state.assert_called_once()
        self.assertIn("view_restore_status=ok", output)

    def test_nas_timeout_fails_loudly(self) -> None:
        rc, output, _, _, _ = _run_restore(readiness={"192.168.0.222": False})
        self.assertEqual(rc, 1, output)
        self.assertIn("nas_ready host=192.168.0.222 ready=timeout", output)
        self.assertIn("view_restore_status=fail", output)

    def test_mount_all_failure_fails_loudly(self) -> None:
        rc, output, _, _, _ = _run_restore(readiness={"192.168.0.222": True}, mount_all_rc=32)
        self.assertEqual(rc, 1, output)
        self.assertIn("cifs_mount_all=rc=32", output)
        self.assertIn("view_restore_status=fail", output)


if __name__ == "__main__":
    unittest.main()
