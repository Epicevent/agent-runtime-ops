from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.domain.runtime_apply import apply_desired_slot
from agent_runtime_ops.domain.runtime_backup import (
    _next_backup_path,
    backup_agent_runtime_state,
    latest_backup,
    restore_backup_env,
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
        patch.object(Path, "rename", rename),
    ):
        backup_dir = backup_agent_runtime_state("oc20", runtime_dir, state_root)

    staging_name = events[-2][1]
    assert staging_name.startswith(".staging-")
    assert events == [
        ("file", ".env"),
        ("file", "backup.json"),
        ("directory", staging_name),
        ("rename", staging_name),
        ("directory", ".agent-runtime-backups"),
    ]
    assert backup_dir.is_dir()


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

    backup_root = runtime_dir / ".agent-runtime-backups"
    assert list(backup_root.iterdir()) == []
    assert latest_backup(runtime_dir) is None


def test_latest_backup_ignores_incomplete_visible_directory(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    backup_root = runtime_dir / ".agent-runtime-backups"
    valid = backup_root / "20260729T000000+0000"
    valid.mkdir(parents=True)
    (valid / "backup.json").write_text("{}", encoding="utf-8")
    incomplete = backup_root / "20260729T000001+0000"
    incomplete.mkdir()

    assert latest_backup(runtime_dir) == valid


def test_latest_backup_ignores_staging_directory_with_backup_metadata(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    backup_root = runtime_dir / ".agent-runtime-backups"
    valid = backup_root / "20260729T000000+0000"
    valid.mkdir(parents=True)
    (valid / "backup.json").write_text("{}", encoding="utf-8")
    staging = backup_root / ".staging-interrupted"
    staging.mkdir()
    (staging / "backup.json").write_text("{", encoding="utf-8")

    assert latest_backup(runtime_dir) == valid


def test_latest_backup_orders_same_second_collision_suffix_numerically(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    backup_root = runtime_dir / ".agent-runtime-backups"
    for suffix in ("", ".2", ".9", ".10"):
        candidate = backup_root / f"20260729T000000+0000{suffix}"
        candidate.mkdir(parents=True)
        (candidate / "backup.json").write_text("{}", encoding="utf-8")

    assert latest_backup(runtime_dir) == backup_root / "20260729T000000+0000.10"


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
        backups = list((runtime_dir / ".agent-runtime-backups").iterdir())
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
