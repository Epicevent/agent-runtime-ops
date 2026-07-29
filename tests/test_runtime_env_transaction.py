from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.commands.apply import _cmd_rollback_locked, cmd_rollback
from agent_runtime_ops.domain.runtime_apply import (
    _restore_and_verify_backup,
    apply_desired_slot,
)
from agent_runtime_ops.domain.runtime_backup import (
    _next_backup_path,
    backup_agent_runtime_state,
    consume_legacy_retrieval_projection_exemption,
    finish_rollback_transaction,
    legacy_retrieval_projection_failures_may_be_expected,
    latest_backup,
    pending_rollback_backup,
    restore_backup,
    restore_backup_env,
    runtime_host_mutation_lock,
    runtime_transaction_lock,
)
from agent_runtime_ops.domain.runtime_paths import (
    agent_compose_path,
    agent_manifest_path,
    state_manifest_path,
)


def recovery_backup_root(state_root: Path, slot: str = "oc20") -> Path:
    return state_root / "runtime-recovery" / slot / "backups"


def rollback_transaction_path(state_root: Path, slot: str = "oc20") -> Path:
    return (
        state_root
        / "runtime-recovery"
        / slot
        / ".agent-runtime-rollback-transaction.json"
    )


def runtime_transaction_lock_path(state_root: Path, slot: str = "oc20") -> Path:
    return (
        state_root
        / "runtime-recovery"
        / slot
        / ".agent-runtime-transaction.lock"
    )


def runtime_host_mutation_lock_path(state_root: Path) -> Path:
    return state_root / "runtime-recovery" / ".agent-runtime-host-mutation.lock"


def legacy_migration_path(state_root: Path, slot: str = "oc20") -> Path:
    return (
        state_root
        / "runtime-recovery"
        / slot
        / ".agent-runtime-legacy-retrieval-migration.json"
    )


def test_runtime_env_backup_is_private_and_restores_exact_prior_bytes(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    original = b"API_SERVER_KEY=secret\nJITECH_RETRIEVAL_ENABLED=false\n"
    env_path.write_bytes(original)
    env_path.chmod(0o640)

    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    env_path.write_text("JITECH_RETRIEVAL_ENABLED=true\n", encoding="utf-8")
    restore_backup_env(runtime_dir, backup_dir)

    assert env_path.read_bytes() == original
    if os.name != "nt":
        assert backup_dir.stat().st_mode & 0o777 == 0o700
        assert (backup_dir / ".env").stat().st_mode & 0o777 == 0o600
        assert env_path.stat().st_mode & 0o777 == 0o640


def test_backup_publication_syncs_files_and_directories_before_return(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    (runtime_dir / ".env").write_text("VALUE=old\n", encoding="utf-8")
    events: list[tuple[str, str]] = []
    original_rename = Path.rename

    def rename(source: Path, target: Path) -> Path:
        events.append(("rename", source.name))
        return original_rename(source, target)

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup._fsync_regular_file",
            side_effect=lambda path: events.append(("file", path.name)),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_backup._fsync_directory",
            side_effect=lambda path: events.append(("directory", path.name)),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_backup.fsync_parent",
            side_effect=lambda path: events.append(("parent", path.parent.name)),
        ),
        patch.object(Path, "rename", rename),
    ):
        backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)

    staging_name = next(value for event, value in events if event == "rename")
    assert staging_name.startswith(".staging-")
    assert events == [
        ("parent", "state"),
        ("parent", "runtime-recovery"),
        ("parent", "oc20"),
        ("file", ".env"),
        ("file", "backup.json"),
        ("directory", staging_name),
        ("rename", staging_name),
        ("directory", "backups"),
    ]
    assert backup_dir.is_dir()


def test_backup_and_recovery_identity_live_only_under_controlled_state_root(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "slot-owned-runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "root-controlled-state"
    state_root.mkdir()

    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)

    assert backup_dir.parent == recovery_backup_root(state_root)
    assert not (runtime_dir / ".agent-runtime-backups").exists()
    assert not (runtime_dir / ".agent-runtime-rollback-transaction.json").exists()
    if os.name != "nt":
        expected_uid = os.geteuid()
        for path in (
            state_root / "runtime-recovery",
            state_root / "runtime-recovery" / "oc20",
            recovery_backup_root(state_root),
            backup_dir,
        ):
            assert path.stat().st_uid == expected_uid
            assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_runtime_transaction_lock_serializes_same_slot_and_persists_inode(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()

    with runtime_transaction_lock(state_root, "oc20") as lock_path:
        assert lock_path == runtime_transaction_lock_path(state_root)
        assert lock_path.is_file()
        first_inode = lock_path.stat().st_ino
        with pytest.raises(RuntimeError, match="another runtime transaction is active"):
            with runtime_transaction_lock(state_root, "oc20"):
                pass
        with pytest.raises(RuntimeError, match="another runtime transaction is active"):
            with runtime_transaction_lock(state_root, "oc20"):
                pass

    with runtime_transaction_lock(state_root, "oc20") as lock_path:
        assert lock_path.stat().st_ino == first_inode
        if os.name != "nt":
            assert lock_path.stat().st_uid == os.geteuid()
            assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_runtime_host_mutation_lock_serializes_different_slots_and_persists_inode(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()

    with runtime_host_mutation_lock(state_root) as lock_path:
        assert lock_path == runtime_host_mutation_lock_path(state_root)
        first_inode = lock_path.stat().st_ino
        with pytest.raises(RuntimeError, match="another runtime host mutation"):
            with runtime_host_mutation_lock(state_root):
                pass

    with runtime_host_mutation_lock(state_root) as lock_path:
        assert lock_path.stat().st_ino == first_inode
        if os.name != "nt":
            assert lock_path.stat().st_uid == os.geteuid()
            assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_apply_holds_runtime_transaction_lock_for_the_entire_slot_operation(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    desired = SimpleNamespace(slot="oc20")

    def observe_locked_operation(**_: object) -> int:
        with pytest.raises(RuntimeError, match="another runtime host mutation"):
            with runtime_host_mutation_lock(state_root):
                pass
        with pytest.raises(RuntimeError, match="another runtime transaction is active"):
            with runtime_transaction_lock(state_root, "oc20"):
                pass
        return 0

    with patch(
        "agent_runtime_ops.domain.runtime_apply._apply_desired_slot_locked",
        side_effect=observe_locked_operation,
    ) as locked_apply:
        rc = apply_desired_slot(
            desired=desired,
            profile=SimpleNamespace(),
            state_root=state_root,
            allow_first_apply=False,
        )

    assert rc == 0
    locked_apply.assert_called_once()


def test_apply_runs_admission_while_host_and_slot_locks_are_held(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    desired = SimpleNamespace(slot="oc20")
    events: list[str] = []

    def admission() -> None:
        with pytest.raises(RuntimeError, match="another runtime host mutation"):
            with runtime_host_mutation_lock(state_root):
                pass
        with pytest.raises(RuntimeError, match="another runtime transaction is active"):
            with runtime_transaction_lock(state_root, "oc20"):
                pass
        events.append("admitted")

    def mutate(**_: object) -> int:
        events.append("mutated")
        return 0

    with patch(
        "agent_runtime_ops.domain.runtime_apply._apply_desired_slot_locked",
        side_effect=mutate,
    ):
        rc = apply_desired_slot(
            desired=desired,
            profile=SimpleNamespace(),
            state_root=state_root,
            allow_first_apply=False,
            pre_apply_admission=admission,
        )

    assert rc == 0
    assert events == ["admitted", "mutated"]


def test_manual_rollback_holds_the_same_runtime_transaction_lock(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()

    def observe_locked_operation(*_: object) -> int:
        with pytest.raises(RuntimeError, match="another runtime host mutation"):
            with runtime_host_mutation_lock(state_root):
                pass
        with pytest.raises(RuntimeError, match="another runtime transaction is active"):
            with runtime_transaction_lock(state_root, "oc20"):
                pass
        return 0

    with (
        patch("agent_runtime_ops.commands.apply._is_root", return_value=True),
        patch("agent_runtime_ops.commands.apply._state_root", return_value=state_root),
        patch(
            "agent_runtime_ops.commands.apply._cmd_rollback_locked",
            side_effect=observe_locked_operation,
        ) as locked_rollback,
    ):
        rc = cmd_rollback(SimpleNamespace(slot="oc20"))

    assert rc == 0
    locked_rollback.assert_called_once()


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode contract")
def test_recovery_parent_owner_and_mode_drift_fail_closed(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_agent_runtime_state("oc20", runtime_dir, state_root)
    recovery_dir = state_root / "runtime-recovery" / "oc20"
    recovery_dir.chmod(0o770)

    with pytest.raises(
        ValueError,
        match="mode mismatch|must not be group/other writable",
    ):
        pending_rollback_backup(state_root, "oc20")

    recovery_dir.chmod(0o700)
    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.os.geteuid",
            return_value=os.geteuid() + 1,
        ),
        pytest.raises(ValueError, match="owner mismatch"),
    ):
        pending_rollback_backup(state_root, "oc20")


def test_restore_backup_replays_exact_transaction_after_mid_restore_crash(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    env_path = runtime_dir / ".env"
    state_manifest_file = state_manifest_path(state_root, "oc20", create_parent=True)
    old_values = {
        compose_path: "services:\n  old: {}\n",
        manifest_path: "old-manifest\n",
        env_path: "VALUE=old\n",
        state_manifest_file: "slot: oc20\nvalue: old\n",
    }
    for path, value in old_values.items():
        path.write_text(value, encoding="utf-8")
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    for path in old_values:
        path.write_text("candidate\n", encoding="utf-8")

    from agent_runtime_ops.domain import runtime_backup

    original_restore = runtime_backup._restore_regular_file
    restore_calls = 0

    def crash_after_first_restore(source: Path, target: Path, **kwargs: object) -> None:
        nonlocal restore_calls
        restore_calls += 1
        assert (
            rollback_transaction_path(state_root)
        ).is_file()
        if restore_calls == 2:
            raise OSError("simulated host crash boundary")
        original_restore(source, target, **kwargs)

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup._restore_regular_file",
            side_effect=crash_after_first_restore,
        ),
        pytest.raises(OSError, match="simulated host crash boundary"),
    ):
        restore_backup("oc20", runtime_dir, backup_dir, state_root)

    transaction_path = rollback_transaction_path(state_root)
    assert transaction_path.is_file()
    assert pending_rollback_backup(state_root, "oc20") == backup_dir
    assert env_path.read_text(encoding="utf-8") == old_values[env_path]
    assert compose_path.read_text(encoding="utf-8") == "candidate\n"
    with pytest.raises(RuntimeError, match="rollback transaction must be completed"):
        backup_agent_runtime_state("oc20", runtime_dir, state_root)

    completed = subprocess.CompletedProcess(["docker"], 0, "", "")
    with patch(
        "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
        return_value=completed,
    ):
        ok, reason = restore_backup("oc20", runtime_dir, backup_dir, state_root)

    assert ok is True
    assert reason == "rollback_applied"
    assert transaction_path.is_file()
    assert pending_rollback_backup(state_root, "oc20") == backup_dir
    for path, value in old_values.items():
        assert path.read_text(encoding="utf-8") == value
    finish_rollback_transaction("oc20", state_root, backup_dir)
    assert not transaction_path.exists()
    assert pending_rollback_backup(state_root, "oc20") is None


def test_restore_transaction_finishes_only_after_live_and_probe_pass(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    compose_path = agent_compose_path(runtime_dir)
    manifest_path = agent_manifest_path(runtime_dir)
    state_manifest_file = state_manifest_path(state_root, "oc20", create_parent=True)
    compose_path.write_text("services: {}\n", encoding="utf-8")
    manifest_path.write_text("old-manifest\n", encoding="utf-8")
    state_manifest_file.write_text("slot: oc20\n", encoding="utf-8")
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    compose_path.write_text("candidate\n", encoding="utf-8")
    previous_desired = SimpleNamespace(
        image_spec={"retrieval_contract": {"schema": "fixture"}},
        route=SimpleNamespace(linux_account="oc20"),
    )
    previous_profile = SimpleNamespace(name="profile")
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")
    transaction_path = rollback_transaction_path(state_root)

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=[(False, "restored_runtime_unhealthy", "fixture")],
        ),
        patch("agent_runtime_ops.domain.runtime_apply.run_retrieval_status_probe") as probe,
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is False
    assert reason == "rollback_live_failed:restored_runtime_unhealthy"
    assert transaction_path.is_file()
    assert pending_rollback_backup(state_root, "oc20") == backup_dir
    probe.assert_not_called()

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=[(True, "restored_runtime_healthy", "fixture")],
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.find_gateway_container",
            return_value=("container-1", "instance_label"),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_retrieval_status_probe",
            side_effect=ValueError("probe failed"),
        ),
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is False
    assert reason == "rollback_verification_failed:probe failed"
    assert transaction_path.is_file()
    assert pending_rollback_backup(state_root, "oc20") == backup_dir

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=[(True, "restored_runtime_healthy", "fixture")],
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.find_gateway_container",
            return_value=("container-1", "instance_label"),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_retrieval_status_probe",
            return_value={"bindingDigest": "sha256:" + "1" * 64},
        ),
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is True
    assert reason == "rollback_applied_verified"
    assert not transaction_path.exists()
    assert pending_rollback_backup(state_root, "oc20") is None


def test_failed_first_apply_restores_verified_empty_baseline_and_finishes(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    active_paths = [
        runtime_dir / ".env",
        agent_compose_path(runtime_dir),
        agent_manifest_path(runtime_dir),
        state_manifest_path(state_root, "oc20", create_parent=True),
    ]
    for path in active_paths:
        path.write_text("candidate\n", encoding="utf-8")
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ) as compose,
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text",
            return_value=completed,
        ) as residue,
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is True
    assert reason == "rollback_empty_baseline_restored_verified"
    assert all(not path.exists() for path in active_paths)
    assert pending_rollback_backup(state_root, "oc20") is None
    compose.assert_called_once()
    assert "down" in compose.call_args.args[0]
    assert residue.call_count == 3


def test_empty_baseline_residue_preserves_transaction_then_same_backup_resumes(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    agent_compose_path(runtime_dir).write_text("candidate\n", encoding="utf-8")
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")
    residue = subprocess.CompletedProcess(["docker"], 0, "container-id\n", "")

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text",
            return_value=residue,
        ),
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is False
    assert reason == "empty_baseline_containers_remain:1"
    assert pending_rollback_backup(state_root, "oc20") == backup_dir
    assert not agent_compose_path(runtime_dir).exists()

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd"
        ) as compose,
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text",
            return_value=completed,
        ),
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is True
    assert reason == "rollback_empty_baseline_restored_verified"
    compose.assert_not_called()
    assert pending_rollback_backup(state_root, "oc20") is None


def test_manual_rollback_finishes_verified_empty_baseline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    agent_compose_path(runtime_dir).write_text("candidate\n", encoding="utf-8")
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")

    with (
        patch(
            "agent_runtime_ops.commands.apply.slot_runtime_dir",
            return_value=runtime_dir,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text",
            return_value=completed,
        ),
        patch("agent_runtime_ops.commands.apply._append_action_log"),
    ):
        rc = _cmd_rollback_locked(SimpleNamespace(slot="oc20"), state_root)

    assert rc == 0
    assert pending_rollback_backup(state_root, "oc20") is None
    output = capsys.readouterr().out
    assert "rollback_status=ok" in output
    assert "rollback_empty_baseline=yes" in output
    assert str(backup_dir) in output


@pytest.mark.parametrize(
    ("compose_text", "expected_ok", "expected_reason"),
    [
        (
            "services:\n  gateway:\n    image: legacy-wrapper@sha256:old\n",
            True,
            "rollback_applied_verified_legacy_projection_absence",
        ),
        (
            "services:\n  gateway:\n    labels:\n      agent-runtime.retrieval-enabled: 'false'\n",
            False,
            "rollback_live_failed:truth_retrieval_binding_matches_expected,"
            "truth_retrieval_enabled_declared,"
            "truth_retrieval_projection_complete_and_consistent",
        ),
    ],
)
def test_legacy_projection_absence_is_only_accepted_for_exact_pre_feature_backup(
    tmp_path: Path,
    compose_text: str,
    expected_ok: bool,
    expected_reason: str,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    agent_compose_path(runtime_dir).write_text(compose_text, encoding="utf-8")
    agent_manifest_path(runtime_dir).write_text(
        "slot=oc20\nfamily=hermes\nruntime_profile=hermes-runtime-customer\n",
        encoding="utf-8",
    )
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    agent_compose_path(runtime_dir).write_text("candidate\n", encoding="utf-8")
    previous_desired = SimpleNamespace(image_spec={}, route=None)
    previous_profile = SimpleNamespace(name="profile")
    retrieval_failures = [
        (False, "truth_retrieval_projection_complete_and_consistent", "missing"),
        (False, "truth_retrieval_binding_matches_expected", "missing"),
        (False, "truth_retrieval_enabled_declared", "missing"),
    ]
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")
    truth = {
        "truth_status": "ok",
        "retrieval_labels_present": "false",
        "retrieval_projection_labels_present": "false",
    }

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=retrieval_failures,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.live_runtime_truth",
            return_value=(truth, []),
        ) as live_truth,
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=backup_dir,
            state_root=state_root,
        )

    assert ok is expected_ok
    assert reason == expected_reason
    if expected_ok:
        live_truth.assert_called_once_with("oc20", state_root)
        assert pending_rollback_backup(state_root, "oc20") is None
        assert legacy_migration_path(state_root).is_file()
        receipt = json.loads(
            legacy_migration_path(state_root).read_text(encoding="utf-8")
        )
        assert receipt["backup_name"] == backup_dir.name
        assert receipt["slot"] == "oc20"
        if os.name != "nt":
            assert stat.S_IMODE(legacy_migration_path(state_root).stat().st_mode) == 0o600
    else:
        live_truth.assert_not_called()
        assert pending_rollback_backup(state_root, "oc20") == backup_dir
        assert not legacy_migration_path(state_root).exists()


def test_legacy_projection_exemption_is_one_time_but_same_transaction_resumes(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    legacy_compose = "services:\n  gateway:\n    image: legacy-wrapper@sha256:old\n"
    agent_compose_path(runtime_dir).write_text(legacy_compose, encoding="utf-8")
    agent_manifest_path(runtime_dir).write_text(
        "slot=oc20\nfamily=hermes\nruntime_profile=hermes-runtime-customer\n",
        encoding="utf-8",
    )
    first_backup = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    agent_compose_path(runtime_dir).write_text("candidate\n", encoding="utf-8")
    previous_desired = SimpleNamespace(image_spec={}, route=None)
    previous_profile = SimpleNamespace(name="profile")
    retrieval_failures = [
        (False, "truth_retrieval_projection_complete_and_consistent", "missing"),
        (False, "truth_retrieval_binding_matches_expected", "missing"),
        (False, "truth_retrieval_enabled_declared", "missing"),
    ]
    truth = {
        "truth_status": "ok",
        "retrieval_labels_present": "false",
        "retrieval_projection_labels_present": "false",
    }
    completed = subprocess.CompletedProcess(["docker"], 0, "", "")
    finish_calls = 0

    def crash_once(slot: str, root: Path, backup: Path) -> None:
        nonlocal finish_calls
        finish_calls += 1
        if finish_calls == 1:
            raise OSError("simulated crash after migration receipt")
        finish_rollback_transaction(slot, root, backup)

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=retrieval_failures,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.live_runtime_truth",
            return_value=(truth, []),
        ) as live_truth,
        patch(
            "agent_runtime_ops.domain.runtime_apply.finish_rollback_transaction",
            side_effect=crash_once,
        ),
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=first_backup,
            state_root=state_root,
        )
        assert ok is False
        assert reason == (
            "rollback_verification_failed:simulated crash after migration receipt"
        )
        assert legacy_migration_path(state_root).is_file()
        assert pending_rollback_backup(state_root, "oc20") == first_backup

        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=first_backup,
            state_root=state_root,
        )

    assert ok is True
    assert reason == "rollback_applied_verified_legacy_projection_absence"
    assert pending_rollback_backup(state_root, "oc20") is None
    assert live_truth.call_count == 2

    # A later upgrade from the restored legacy bytes gets a new backup identity.
    second_backup = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    assert second_backup != first_backup
    agent_compose_path(runtime_dir).write_text("candidate-2\n", encoding="utf-8")
    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.run_text_cwd",
            return_value=completed,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.load_backup_runtime_contract",
            return_value=(previous_desired, previous_profile),
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds",
            return_value=1,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait",
            return_value=retrieval_failures,
        ),
        patch(
            "agent_runtime_ops.domain.runtime_apply.live_runtime_truth"
        ) as later_truth,
    ):
        ok, reason = _restore_and_verify_backup(
            slot="oc20",
            runtime_dir=runtime_dir,
            backup_dir=second_backup,
            state_root=state_root,
        )

    assert ok is False
    assert reason.startswith("rollback_live_failed:")
    later_truth.assert_not_called()
    assert pending_rollback_backup(state_root, "oc20") == second_backup


def test_legacy_projection_exemption_requires_exact_pending_backup(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    agent_compose_path(runtime_dir).write_text(
        "services:\n  gateway:\n    image: legacy-wrapper@sha256:old\n",
        encoding="utf-8",
    )
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    failures = set(
        [
            "truth_retrieval_projection_complete_and_consistent",
            "truth_retrieval_binding_matches_expected",
            "truth_retrieval_enabled_declared",
        ]
    )
    from agent_runtime_ops.domain.runtime_backup import _begin_rollback_transaction

    _begin_rollback_transaction("oc20", state_root, backup_dir)
    consume_legacy_retrieval_projection_exemption(
        state_root,
        "oc20",
        backup_dir,
    )
    assert legacy_retrieval_projection_failures_may_be_expected(
        state_root,
        "oc20",
        backup_dir,
        failures,
    )
    finish_rollback_transaction("oc20", state_root, backup_dir)
    assert not legacy_retrieval_projection_failures_may_be_expected(
        state_root,
        "oc20",
        backup_dir,
        failures,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode contract")
def test_legacy_projection_migration_receipt_mode_drift_fails_closed(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    agent_compose_path(runtime_dir).write_text(
        "services:\n  gateway:\n    image: legacy-wrapper@sha256:old\n",
        encoding="utf-8",
    )
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    failures = {
        "truth_retrieval_projection_complete_and_consistent",
        "truth_retrieval_binding_matches_expected",
        "truth_retrieval_enabled_declared",
    }
    from agent_runtime_ops.domain.runtime_backup import _begin_rollback_transaction

    _begin_rollback_transaction("oc20", state_root, backup_dir)
    receipt_path = consume_legacy_retrieval_projection_exemption(
        state_root,
        "oc20",
        backup_dir,
    )
    receipt_path.chmod(0o640)

    with pytest.raises(ValueError, match="mode must be 0600"):
        legacy_retrieval_projection_failures_may_be_expected(
            state_root,
            "oc20",
            backup_dir,
            failures,
        )


def test_pending_transaction_rejects_changed_backup_identity(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    compose_path = agent_compose_path(runtime_dir)
    compose_path.write_text("services: {}\n", encoding="utf-8")
    first = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    from agent_runtime_ops.domain.runtime_backup import _begin_rollback_transaction

    _begin_rollback_transaction("oc20", state_root, first)
    second = first.parent / "20260729T235959+0000"
    shutil.copytree(first, second)
    second.chmod(0o700)

    assert pending_rollback_backup(state_root, "oc20") == first
    with pytest.raises(RuntimeError, match="another rollback transaction is pending"):
        _begin_rollback_transaction("oc20", state_root, second)


def test_pending_transaction_rejects_backup_artifact_digest_drift(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    compose_path = agent_compose_path(runtime_dir)
    compose_path.write_text("services: {}\n", encoding="utf-8")
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)

    from agent_runtime_ops.domain.runtime_backup import _begin_rollback_transaction

    _begin_rollback_transaction("oc20", state_root, backup_dir)
    (backup_dir / "docker-compose.agent-runtime.yml").write_text(
        "tampered\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="artifact digest mismatch"):
        pending_rollback_backup(state_root, "oc20")
    with pytest.raises(ValueError, match="artifact digest mismatch"):
        restore_backup("oc20", runtime_dir, backup_dir, state_root)


def test_env_restore_syncs_parent_after_atomic_replace(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    env_path.write_text("VALUE=old\n", encoding="utf-8")
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    env_path.write_text("VALUE=new\n", encoding="utf-8")
    events: list[str] = []
    original_replace = os.replace

    def replace(source: Path, target: Path) -> None:
        events.append("replace")
        original_replace(source, target)

    with (
        patch("agent_runtime_ops.domain.runtime_backup.os.replace", side_effect=replace),
        patch(
            "agent_runtime_ops.domain.runtime_backup.fsync_parent",
            side_effect=lambda path: events.append("parent_sync"),
        ),
    ):
        restore_backup_env(runtime_dir, backup_dir)

    assert events == ["replace", "parent_sync"]
    assert env_path.read_text(encoding="utf-8") == "VALUE=old\n"


def test_legacy_backup_without_env_metadata_leaves_live_env_untouched(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    env_path = runtime_dir / ".env"
    current = b"API_SERVER_KEY=current-secret\n"
    env_path.write_bytes(current)
    backup_dir = tmp_path / "legacy-backup"
    backup_dir.mkdir()
    (backup_dir / "backup.json").write_text(
        json.dumps({"had_compose": True, "had_manifest": True}),
        encoding="utf-8",
    )

    restore_backup_env(runtime_dir, backup_dir)

    assert env_path.read_bytes() == current


def test_new_backup_explicitly_without_env_removes_candidate_env_on_restore(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()

    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    env_path = runtime_dir / ".env"
    env_path.write_text("JITECH_RETRIEVAL_ENABLED=false\n", encoding="utf-8")
    restore_backup_env(runtime_dir, backup_dir)

    assert not env_path.exists()


def test_env_absence_restore_syncs_parent_only_after_actual_deletion(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)
    env_path = runtime_dir / ".env"
    env_path.write_text("JITECH_RETRIEVAL_ENABLED=false\n", encoding="utf-8")
    events: list[str] = []

    def sync_parent(path: Path) -> None:
        assert path == env_path
        assert not env_path.exists()
        events.append("parent_sync")

    with patch(
        "agent_runtime_ops.domain.runtime_backup.fsync_parent",
        side_effect=sync_parent,
    ):
        restore_backup_env(runtime_dir, backup_dir)

    assert events == ["parent_sync"]


def test_env_absence_restore_does_not_sync_when_already_absent(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)

    with patch("agent_runtime_ops.domain.runtime_backup.fsync_parent") as sync_parent:
        restore_backup_env(runtime_dir, backup_dir)

    sync_parent.assert_not_called()


@pytest.mark.parametrize("marker", [None, 0, "false"])
def test_malformed_env_marker_never_deletes_live_env(
    tmp_path: Path, marker: object
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    env_path = runtime_dir / ".env"
    current = b"API_SERVER_KEY=current-secret\n"
    env_path.write_bytes(current)
    backup_dir = tmp_path / "malformed-backup"
    backup_dir.mkdir()
    (backup_dir / "backup.json").write_text(
        json.dumps({"had_env": marker}), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="must be boolean"):
        restore_backup_env(runtime_dir, backup_dir)

    assert env_path.read_bytes() == current


def test_env_restore_copy_failure_preserves_live_bytes_and_removes_temporary(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    env_path = runtime_dir / ".env"
    current = b"API_SERVER_KEY=current-secret\n"
    env_path.write_bytes(current)
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    (backup_dir / "backup.json").write_text(
        json.dumps(
            {
                "had_env": True,
                "env_mode": 0o600,
                "env_uid": env_path.stat().st_uid,
                "env_gid": env_path.stat().st_gid,
            }
        ),
        encoding="utf-8",
    )
    (backup_dir / ".env").write_bytes(b"API_SERVER_KEY=restored-secret\n")

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.shutil.copy2",
            side_effect=OSError("restore copy failed"),
        ),
        pytest.raises(OSError, match="restore copy failed"),
    ):
        restore_backup_env(runtime_dir, backup_dir)

    assert env_path.read_bytes() == current
    assert list(runtime_dir.glob(".env.restore-*")) == []


def test_incomplete_backup_is_not_published_or_selected(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    (runtime_dir / ".env").write_text("VALUE=old\n", encoding="utf-8")

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup.shutil.copy2",
            side_effect=OSError("copy failed"),
        ),
        pytest.raises(OSError, match="copy failed"),
    ):
        backup_agent_runtime_state("oc20", runtime_dir, state_root)

    backup_root = recovery_backup_root(state_root)
    assert list(backup_root.iterdir()) == []
    assert latest_backup(state_root, "oc20") is None


def test_latest_backup_ignores_incomplete_visible_directory(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_root = recovery_backup_root(state_root)
    backup_root.mkdir(parents=True)
    (state_root / "runtime-recovery").chmod(0o700)
    (state_root / "runtime-recovery" / "oc20").chmod(0o700)
    backup_root.chmod(0o700)
    valid = backup_root / "20260729T000000+0000"
    valid.mkdir(parents=True)
    (valid / "backup.json").write_text("{}", encoding="utf-8")
    incomplete = backup_root / "20260729T000001+0000"
    incomplete.mkdir()

    assert latest_backup(state_root, "oc20") == valid


def test_latest_backup_ignores_staging_directory_with_backup_metadata(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_root = recovery_backup_root(state_root)
    backup_root.mkdir(parents=True)
    (state_root / "runtime-recovery").chmod(0o700)
    (state_root / "runtime-recovery" / "oc20").chmod(0o700)
    backup_root.chmod(0o700)
    valid = backup_root / "20260729T000000+0000"
    valid.mkdir(parents=True)
    (valid / "backup.json").write_text("{}", encoding="utf-8")
    staging = backup_root / ".staging-interrupted"
    staging.mkdir()
    (staging / "backup.json").write_text("{", encoding="utf-8")

    assert latest_backup(state_root, "oc20") == valid


def test_latest_backup_orders_same_second_collision_suffix_numerically(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_root = recovery_backup_root(state_root)
    backup_root.mkdir(parents=True)
    (state_root / "runtime-recovery").chmod(0o700)
    (state_root / "runtime-recovery" / "oc20").chmod(0o700)
    backup_root.chmod(0o700)
    for suffix in ("", ".2", ".9", ".10"):
        candidate = backup_root / f"20260729T000000+0000{suffix}"
        candidate.mkdir(parents=True)
        (candidate / "backup.json").write_text("{}", encoding="utf-8")

    assert latest_backup(state_root, "oc20") == backup_root / "20260729T000000+0000.10"


def test_new_backup_suffix_starts_above_highest_same_second_collision(
    tmp_path: Path,
) -> None:
    backup_root = tmp_path / ".agent-runtime-backups"
    backup_root.mkdir()
    original = backup_root / "20260729T000000+0000"
    for suffix in ("", ".2", ".10"):
        (backup_root / f"{original.name}{suffix}").mkdir()

    assert _next_backup_path(backup_root, original) == Path(f"{original}.11")


def test_apply_backs_up_env_before_prepare_and_restores_on_pre_dispatch_failure(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    original = "UNCHANGED=old\n"
    env_path.write_text(original, encoding="utf-8")
    desired = SimpleNamespace(
        slot="oc20",
        route=None,
        image_spec={},
        image_name="direct-image",
    )
    profile = SimpleNamespace(name="hermes-runtime-customer", digest="sha256:" + "a" * 64)
    rendered = SimpleNamespace(text="services: {}\n", sha256="sha256:" + "b" * 64)
    observed: dict[str, object] = {}

    def prepare() -> None:
        backups = list(recovery_backup_root(state_root).iterdir())
        assert len(backups) == 1
        observed["backup_bytes"] = (backups[0] / ".env").read_text(encoding="utf-8")
        env_path.write_text("JITECH_RETRIEVAL_ENABLED=false\n", encoding="utf-8")

    with (
        patch("agent_runtime_ops.domain.runtime_apply.render_compose", return_value=rendered),
        patch("agent_runtime_ops.domain.runtime_apply.run_static_slot_checks", return_value=[]),
        patch("agent_runtime_ops.domain.runtime_apply.slot_runtime_dir", return_value=runtime_dir),
        patch("agent_runtime_ops.domain.runtime_apply.ensure_nas_workspace_dir", return_value=tmp_path / "nas"),
        patch("agent_runtime_ops.domain.runtime_apply.ensure_runtime_workspace_guidance", return_value={}),
        patch("agent_runtime_ops.domain.runtime_apply.image_spec_config_contract", return_value=None),
        patch("agent_runtime_ops.domain.runtime_apply.required_compose_variables", return_value=set()),
        patch("agent_runtime_ops.domain.runtime_apply.atomic_write", side_effect=RuntimeError("pre-dispatch-stop")),
        patch("agent_runtime_ops.domain.runtime_apply.append_action_log"),
    ):
        rc = apply_desired_slot(
            desired=desired,
            profile=profile,
            state_root=state_root,
            allow_first_apply=True,
            prepare_runtime_env=prepare,
        )

    assert rc == 1
    assert observed["backup_bytes"] == original
    assert env_path.read_text(encoding="utf-8") == original


def test_apply_keeps_prepared_env_after_successful_dispatch(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    env_path.write_text("UNCHANGED=old\n", encoding="utf-8")
    desired = SimpleNamespace(
        slot="oc20",
        route=None,
        image_spec={},
        image_name="direct-image",
    )
    profile = SimpleNamespace(name="hermes-runtime-customer", digest="sha256:" + "a" * 64)
    rendered = SimpleNamespace(text="services: {}\n", sha256="sha256:" + "b" * 64)

    def prepare() -> None:
        env_path.write_text("JITECH_RETRIEVAL_ENABLED=false\n", encoding="utf-8")

    with (
        patch("agent_runtime_ops.domain.runtime_apply.render_compose", return_value=rendered),
        patch("agent_runtime_ops.domain.runtime_apply.run_static_slot_checks", return_value=[]),
        patch("agent_runtime_ops.domain.runtime_apply.slot_runtime_dir", return_value=runtime_dir),
        patch("agent_runtime_ops.domain.runtime_apply.ensure_nas_workspace_dir", return_value=tmp_path / "nas"),
        patch("agent_runtime_ops.domain.runtime_apply.ensure_runtime_workspace_guidance", return_value={}),
        patch("agent_runtime_ops.domain.runtime_apply.image_spec_config_contract", return_value=None),
        patch("agent_runtime_ops.domain.runtime_apply.required_compose_variables", return_value=set()),
        patch(
            "agent_runtime_ops.domain.runtime_apply.run_text_cwd",
            return_value=subprocess.CompletedProcess(["docker"], 0, "", ""),
        ),
        patch("agent_runtime_ops.domain.runtime_apply.run_live_slot_checks_with_wait", return_value=[]),
        patch("agent_runtime_ops.domain.runtime_apply.profile_startup_timeout_seconds", return_value=1),
        patch("agent_runtime_ops.domain.runtime_apply.FINAL_WORKSPACE_GUIDANCE_STABILIZE_DELAYS_SECONDS", []),
        patch("agent_runtime_ops.domain.runtime_apply.write_slot_manifests"),
        patch("agent_runtime_ops.domain.runtime_apply.append_action_log"),
    ):
        rc = apply_desired_slot(
            desired=desired,
            profile=profile,
            state_root=state_root,
            allow_first_apply=True,
            prepare_runtime_env=prepare,
        )

    assert rc == 0
    assert env_path.read_text(encoding="utf-8") == "JITECH_RETRIEVAL_ENABLED=false\n"
