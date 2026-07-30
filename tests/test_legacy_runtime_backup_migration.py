from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_runtime_ops.commands.apply import _cmd_rollback_locked
from agent_runtime_ops.commands.diagnostics import _resolve_diagnostics_dir
from agent_runtime_ops.domain import runtime_backup
from agent_runtime_ops.domain.runtime_backup import (
    finish_rollback_transaction,
    import_legacy_agent_runtime_backups,
    pending_rollback_backup,
    restore_backup,
    restore_backup_env,
)
from agent_runtime_ops.install_migrations import migrate_legacy_runtime_backups


POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="legacy importer requires POSIX fd-relative no-follow semantics",
)


def _legacy_backup(
    runtime_dir: Path,
    *,
    name: str = "20260728T120000+0000",
    diagnostics: bool = True,
) -> Path:
    root = runtime_dir / ".agent-runtime-backups"
    root.mkdir(mode=0o755, exist_ok=True)
    root.chmod(0o755)
    backup = root / name
    backup.mkdir(mode=0o755)
    backup.chmod(0o755)
    artifacts = {
        "docker-compose.agent-runtime.yml": b"services: {}\n",
        ".agent-runtime-manifest": b"image_name=old\n",
        "manifest.yaml": b"schema: fixture\n",
    }
    for artifact_name, value in artifacts.items():
        path = backup / artifact_name
        path.write_bytes(value)
        path.chmod(0o644)
    metadata = {
        "created_at": "2026-07-28T12:00:00+00:00",
        "had_compose": True,
        "had_manifest": True,
        "had_state_manifest": True,
        "state_manifest_path": "/srv/openclaw-ops/runtime/oc20/manifest.yaml",
    }
    metadata_path = backup / "backup.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_path.chmod(0o644)
    if diagnostics:
        diag = backup / "failed-container"
        diag.mkdir(mode=0o700)
        diag.chmod(0o700)
        lookup = diag / "lookup.txt"
        lookup.write_text("container=old\nlookup=label\n", encoding="utf-8")
        lookup.chmod(0o600)
    return backup


def _earliest_legacy_backup(
    runtime_dir: Path,
    *,
    name: str = "20260608T151423+0900",
    had_runtime: bool = True,
) -> Path:
    source = _legacy_backup(runtime_dir, name=name, diagnostics=False)
    metadata_path = source / "backup.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.pop("had_state_manifest")
    metadata.pop("state_manifest_path")
    metadata["had_compose"] = had_runtime
    metadata["had_manifest"] = had_runtime
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_path.chmod(0o644)
    (source / "manifest.yaml").unlink()
    if not had_runtime:
        for artifact_name in (
            "docker-compose.agent-runtime.yml",
            ".agent-runtime-manifest",
        ):
            (source / artifact_name).unlink()
    return source


@POSIX_ONLY
def test_valid_legacy_backup_is_durably_adopted_once_without_removing_source(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir)
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    env_path.write_text("API_SERVER_KEY=current-secret\n", encoding="utf-8")

    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert len(imported) == 1
    adopted = imported[0]
    assert source.is_dir()
    assert (source / "backup.json").is_file()
    assert adopted.parent == state_root / "runtime-recovery" / "oc20" / "backups"
    assert stat_mode(adopted) == 0o700
    assert stat_mode(adopted / "backup.json") == 0o600
    assert stat_mode(adopted / "docker-compose.agent-runtime.yml") == 0o600
    assert (adopted / "failed-container" / "lookup.txt").read_text(
        encoding="utf-8"
    ) == "container=old\nlookup=label\n"
    metadata = json.loads((adopted / "backup.json").read_text(encoding="utf-8"))
    assert metadata["schema"] == "agent-runtime-backup/v2"
    assert "had_env" not in metadata
    assert metadata["artifact_sha256"][".env"] is None
    assert metadata["legacy_source"]["backup_name"] == source.name
    assert metadata["legacy_source"]["schema"] == (
        "agent-runtime-legacy-backup-import/v1"
    )

    restore_backup_env(runtime_dir, adopted)
    assert env_path.read_text(encoding="utf-8") == "API_SERVER_KEY=current-secret\n"
    assert import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root) == []


@POSIX_ONLY
def test_earliest_three_key_backup_with_compose_and_manifest_imports(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _earliest_legacy_backup(runtime_dir)
    state_root = tmp_path / "state"
    state_root.mkdir()

    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert len(imported) == 1
    adopted = imported[0]
    assert (adopted / "docker-compose.agent-runtime.yml").read_bytes() == (
        source / "docker-compose.agent-runtime.yml"
    ).read_bytes()
    assert (adopted / ".agent-runtime-manifest").read_bytes() == (
        source / ".agent-runtime-manifest"
    ).read_bytes()
    metadata = json.loads((adopted / "backup.json").read_text(encoding="utf-8"))
    assert metadata["had_compose"] is True
    assert metadata["had_manifest"] is True
    assert metadata["schema"] == "agent-runtime-backup/v2"
    assert metadata["had_state_manifest"] is False
    assert metadata["state_manifest_path"] == str(
        state_root / "runtime" / "oc20" / "manifest.yaml"
    )
    assert metadata["artifact_sha256"]["manifest.yaml"] is None
    assert "had_env" not in metadata


@POSIX_ONLY
def test_earliest_three_key_backup_removes_impossible_state_and_preserves_env(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _earliest_legacy_backup(runtime_dir, had_runtime=False)
    state_root = tmp_path / "state"
    state_root.mkdir()
    state_manifest = state_root / "runtime" / "oc20" / "manifest.yaml"
    state_manifest.parent.mkdir(parents=True)
    state_manifest.write_text("schema: current-state\n", encoding="utf-8")
    env_path = runtime_dir / ".env"
    env_path.write_text("API_SERVER_KEY=current-secret\n", encoding="utf-8")

    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert len(imported) == 1
    adopted = imported[0]
    assert source.is_dir()
    metadata = json.loads((adopted / "backup.json").read_text(encoding="utf-8"))
    assert metadata["schema"] == "agent-runtime-backup/v2"
    assert metadata["had_state_manifest"] is False
    assert metadata["state_manifest_path"] == str(state_manifest)
    assert "had_env" not in metadata
    assert metadata["artifact_sha256"]["manifest.yaml"] is None
    assert metadata["artifact_sha256"][".env"] is None

    with patch(
        "agent_runtime_ops.domain.runtime_backup._empty_baseline_project_residue",
        return_value=(True, "empty_baseline_project_absent"),
    ):
        ok, reason = restore_backup("oc20", runtime_dir, adopted, state_root)

    assert ok is True
    assert reason == "rollback_empty_baseline_restored"
    assert not state_manifest.exists()
    assert env_path.read_text(encoding="utf-8") == "API_SERVER_KEY=current-secret\n"


@POSIX_ONLY
def test_earliest_backup_rejects_unmeasured_state_manifest_artifact(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _earliest_legacy_backup(runtime_dir)
    unexpected = source / "manifest.yaml"
    unexpected.write_text("schema: must-not-be-guessed\n", encoding="utf-8")
    unexpected.chmod(0o644)
    state_root = tmp_path / "state"
    state_root.mkdir()

    with pytest.raises(ValueError, match="artifact marker mismatch"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert not (state_root / "runtime-recovery").exists()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_earliest_metadata_keyset_is_exact_and_rejects_extensions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "backup.json"
    v0 = {
        "created_at": "2026-06-08T15:14:23+09:00",
        "had_compose": True,
        "had_manifest": True,
    }
    v1 = {
        **v0,
        "had_state_manifest": False,
        "state_manifest_path": "/srv/openclaw-ops/runtime/oc20/manifest.yaml",
    }
    v1_env = {
        **v1,
        "env_gid": None,
        "env_mode": None,
        "env_uid": None,
        "had_env": False,
    }

    for accepted in (v0, v1, v1_env):
        assert runtime_backup._strict_legacy_metadata(
            json.dumps(accepted).encode("utf-8"),
            path,
        ) == accepted

    invalid = (
        {**v0, "unexpected": False},
        {
            **v0,
            "env_gid": None,
            "env_mode": None,
            "env_uid": None,
            "had_env": False,
        },
        {**v1_env, "unexpected": False},
    )
    for rejected in invalid:
        with pytest.raises(ValueError, match="metadata keys are invalid"):
            runtime_backup._strict_legacy_metadata(
                json.dumps(rejected).encode("utf-8"),
                path,
            )


def _add_legacy_env_metadata(source: Path, value: bytes | None) -> None:
    metadata_path = source / "backup.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "env_gid": os.getgid(),
            "env_mode": 0o640,
            "env_uid": os.getuid(),
            "had_env": value is not None,
        }
    )
    if value is None:
        metadata.update({"env_gid": None, "env_mode": None, "env_uid": None})
    else:
        env_path = source / ".env"
        env_path.write_bytes(value)
        env_path.chmod(0o600)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_path.chmod(0o644)


@POSIX_ONLY
def test_intermediate_legacy_env_snapshot_is_imported_and_restored(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    prior = b"API_SERVER_KEY=prior-secret\nJITECH_RETRIEVAL_ENABLED=false\n"
    _add_legacy_env_metadata(source, prior)
    state_root = tmp_path / "state"
    state_root.mkdir()
    env_path = runtime_dir / ".env"
    env_path.write_text("API_SERVER_KEY=candidate-secret\n", encoding="utf-8")

    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    adopted = imported[0]
    adopted_metadata = json.loads((adopted / "backup.json").read_text(encoding="utf-8"))
    assert adopted_metadata["had_env"] is True
    assert adopted_metadata["env_mode"] == 0o640
    assert adopted_metadata["artifact_sha256"][".env"].startswith("sha256:")
    assert stat_mode(adopted / ".env") == 0o600

    restore_backup_env(runtime_dir, adopted)

    assert env_path.read_bytes() == prior
    assert stat_mode(env_path) == 0o640


@POSIX_ONLY
def test_intermediate_explicit_env_absence_retains_delete_on_rollback(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    _add_legacy_env_metadata(source, None)
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    env_path = runtime_dir / ".env"
    env_path.write_text("JITECH_RETRIEVAL_ENABLED=true\n", encoding="utf-8")

    restore_backup_env(runtime_dir, imported[0])

    assert not env_path.exists()


@POSIX_ONLY
def test_earliest_empty_baseline_preserves_unmeasured_env_and_can_finish(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    metadata_path = source / "backup.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "had_compose": False,
            "had_manifest": False,
            "had_state_manifest": False,
        }
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_path.chmod(0o644)
    for name in (
        "docker-compose.agent-runtime.yml",
        ".agent-runtime-manifest",
        "manifest.yaml",
    ):
        (source / name).unlink()
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    env_path = runtime_dir / ".env"
    current = b"API_SERVER_KEY=unmeasured-existing-secret\n"
    env_path.write_bytes(current)

    with patch(
        "agent_runtime_ops.domain.runtime_backup._empty_baseline_project_residue",
        return_value=(True, "empty_baseline_project_absent"),
    ):
        ok, reason = restore_backup("oc20", runtime_dir, imported[0], state_root)

    assert ok is True
    assert reason == "rollback_empty_baseline_restored"
    assert env_path.read_bytes() == current
    assert pending_rollback_backup(state_root, "oc20") == imported[0]
    finish_rollback_transaction("oc20", state_root, imported[0])
    assert pending_rollback_backup(state_root, "oc20") is None


@POSIX_ONLY
@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_legacy_artifact_fails_before_publication(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    artifact = source / "docker-compose.agent-runtime.yml"
    artifact.unlink()
    external = tmp_path / "external"
    external.write_text("services: {}\n", encoding="utf-8")
    if unsafe_kind == "symlink":
        artifact.symlink_to(external)
    elif unsafe_kind == "hardlink":
        os.link(external, artifact)
    else:
        os.mkfifo(artifact)
    state_root = tmp_path / "state"
    state_root.mkdir()

    with pytest.raises(ValueError, match="opened safely|regular file|one link"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert not (state_root / "runtime-recovery").exists()


@POSIX_ONLY
def test_unexpected_legacy_entry_fails_before_publication(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    extra = source / ".env"
    extra.write_text("SECRET=must-not-be-imported\n", encoding="utf-8")
    extra.chmod(0o600)
    state_root = tmp_path / "state"
    state_root.mkdir()

    with pytest.raises(ValueError, match="artifact marker mismatch"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert not (state_root / "runtime-recovery").exists()


@POSIX_ONLY
def test_legacy_artifact_mutation_during_read_is_rejected(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    artifact = source / "docker-compose.agent-runtime.yml"
    state_root = tmp_path / "state"
    state_root.mkdir()
    original_read = os.read
    mutated = False

    def read_and_mutate(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        value = original_read(descriptor, size)
        if not mutated and os.fstat(descriptor).st_ino == artifact.stat().st_ino:
            artifact.write_text("services: {changed: {}}\n", encoding="utf-8")
            mutated = True
        return value

    with (
        patch.object(runtime_backup.os, "read", side_effect=read_and_mutate),
        pytest.raises(ValueError, match="changed while reading"),
    ):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert mutated is True
    assert not (state_root / "runtime-recovery").exists()


@POSIX_ONLY
def test_slot_owned_parent_cannot_swap_legacy_root_during_import(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    _legacy_backup(runtime_dir, diagnostics=False)
    legacy_root = runtime_dir / ".agent-runtime-backups"
    displaced = runtime_dir / ".agent-runtime-backups.displaced"
    state_root = tmp_path / "state"
    state_root.mkdir()
    original_reader = runtime_backup._read_legacy_backup_directory
    swapped = False

    def read_and_swap(*args, **kwargs):
        nonlocal swapped
        value = original_reader(*args, **kwargs)
        legacy_root.rename(displaced)
        legacy_root.mkdir(mode=0o755)
        legacy_root.chmod(0o755)
        swapped = True
        return value

    with (
        patch.object(
            runtime_backup,
            "_read_legacy_backup_directory",
            side_effect=read_and_swap,
        ),
        pytest.raises(ValueError, match="root changed while reading"),
    ):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert swapped is True
    assert not (state_root / "runtime-recovery").exists()


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires a root-run Linux ownership fixture",
)
def test_legacy_file_owned_by_another_uid_fails_closed(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    metadata_path = source / "backup.json"
    os.chown(metadata_path, 1, metadata_path.stat().st_gid)
    state_root = tmp_path / "state"
    state_root.mkdir()

    with pytest.raises(ValueError, match="owner mismatch"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert not (state_root / "runtime-recovery").exists()


@POSIX_ONLY
def test_imported_failed_container_is_visible_to_diagnostics_resolution(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    _legacy_backup(runtime_dir)
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert (
        _resolve_diagnostics_dir(state_root, "oc20")
        == (imported[0] / "failed-container").resolve()
    )


@POSIX_ONLY
def test_changed_legacy_source_after_import_fails_closed(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    state_root = tmp_path / "state"
    state_root.mkdir()
    assert import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    artifact = source / "docker-compose.agent-runtime.yml"
    artifact.write_text("services: {changed: {}}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after import"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)


@POSIX_ONLY
def test_partial_prior_imports_are_idempotent_and_sources_remain(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    first_source = _legacy_backup(
        runtime_dir,
        name="20260713T234729+0900",
        diagnostics=False,
    )
    state_root = tmp_path / "state"
    state_root.mkdir()

    first_import = import_legacy_agent_runtime_backups(
        "oc20", runtime_dir, state_root
    )
    assert len(first_import) == 1
    first_metadata = (first_import[0] / "backup.json").read_bytes()

    second_source = _legacy_backup(
        runtime_dir,
        name="20260713T234730+0900",
        diagnostics=False,
    )
    second_import = import_legacy_agent_runtime_backups(
        "oc20", runtime_dir, state_root
    )

    assert len(second_import) == 1
    assert first_import[0].is_dir()
    assert (first_import[0] / "backup.json").read_bytes() == first_metadata
    assert first_source.is_dir()
    assert second_source.is_dir()
    assert import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root) == []


@POSIX_ONLY
def test_source_collision_chain_publishes_only_canonical_names(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    timestamp = "20260713T234730+0900"
    sources = [
        _legacy_backup(
            runtime_dir,
            name=f"{timestamp}{suffix}",
            diagnostics=False,
        )
        for suffix in ("", ".2", ".3")
    ]
    state_root = tmp_path / "state"
    state_root.mkdir()

    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert [item.name for item in imported] == [
        timestamp,
        f"{timestamp}.2",
        f"{timestamp}.3",
    ]
    assert all(".2.2" not in item.name for item in imported)
    assert all(source.is_dir() for source in sources)
    assert import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root) == []


@POSIX_ONLY
def test_nested_suffix_residue_is_renamed_canonically_without_reimport(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    timestamp = "20260713T234730+0900"
    source = _legacy_backup(
        runtime_dir,
        name=f"{timestamp}.2",
        diagnostics=False,
    )
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    assert len(imported) == 1
    malformed = imported[0].with_name(f"{timestamp}.2.2")
    imported[0].rename(malformed)
    before_digest = hashlib.sha256(
        (malformed / "backup.json").read_bytes()
    ).hexdigest()

    repeated = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    recovered = malformed.parent / timestamp
    assert repeated == []
    assert recovered.is_dir()
    assert not malformed.exists()
    assert hashlib.sha256((recovered / "backup.json").read_bytes()).hexdigest() == (
        before_digest
    )
    assert source.is_dir()
    assert import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root) == []


@POSIX_ONLY
def test_nested_suffix_residue_with_wrong_source_identity_is_not_adopted(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    timestamp = "20260713T234730+0900"
    _legacy_backup(
        runtime_dir,
        name=f"{timestamp}.3",
        diagnostics=False,
    )
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    malformed = imported[0].with_name(f"{timestamp}.2.2")
    imported[0].rename(malformed)

    with pytest.raises(ValueError, match="source identity mismatch"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert malformed.is_dir()
    assert not (malformed.parent / timestamp).exists()


@POSIX_ONLY
def test_invalid_nested_suffix_residue_rolls_back_to_original_name(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    _legacy_backup(runtime_dir, diagnostics=False)
    state_root = tmp_path / "state"
    state_root.mkdir()
    backup_root = state_root / "runtime-recovery" / "oc20" / "backups"
    backup_root.mkdir(parents=True, mode=0o700)
    (state_root / "runtime-recovery").chmod(0o700)
    (state_root / "runtime-recovery" / "oc20").chmod(0o700)
    backup_root.chmod(0o700)
    malformed = backup_root / "20260713T234730+0900.2.2"
    malformed.mkdir(mode=0o700)
    metadata = malformed / "backup.json"
    metadata.write_text("{}\n", encoding="utf-8")
    metadata.chmod(0o600)

    with pytest.raises(ValueError, match="metadata schema is invalid"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert malformed.is_dir()
    assert not (backup_root / "20260713T234730+0900").exists()


@POSIX_ONLY
def test_unknown_managed_backup_entry_fails_closed_without_source_removal(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    state_root = tmp_path / "state"
    state_root.mkdir()
    imported = import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)
    backup_root = imported[0].parent
    unknown = backup_root / ".unexpected-managed-entry"
    unknown.mkdir(mode=0o700)
    unknown.chmod(0o700)

    with pytest.raises(ValueError, match="unexpected managed backup entry"):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    assert unknown.is_dir()
    assert source.is_dir()


@POSIX_ONLY
def test_post_rename_validation_failure_removes_only_the_import_copy(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source = _legacy_backup(runtime_dir, diagnostics=False)
    state_root = tmp_path / "state"
    state_root.mkdir()
    observed: list[Path] = []

    def reject_published(
        _state_root: Path,
        _slot: str,
        backup_dir: Path,
    ) -> tuple[dict, str]:
        observed.append(backup_dir)
        raise ValueError("forced post-rename validation failure")

    with (
        patch(
            "agent_runtime_ops.domain.runtime_backup._validate_backup_integrity",
            side_effect=reject_published,
        ),
        pytest.raises(ValueError, match="forced post-rename validation failure"),
    ):
        import_legacy_agent_runtime_backups("oc20", runtime_dir, state_root)

    backup_root = state_root / "runtime-recovery" / "oc20" / "backups"
    assert len(observed) == 1
    assert not observed[0].exists()
    assert list(backup_root.iterdir()) == []
    assert source.is_dir()


def test_install_migration_uses_binding_account_and_reports_import_count(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    (state_root / "runtime-bindings.json").write_text("{}", encoding="utf-8")
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    legacy_root = runtime_dir / ".agent-runtime-backups"
    legacy_root.mkdir()
    binding = SimpleNamespace(linux_account="oc20")
    imported = [state_root / "runtime-recovery" / "oc20" / "backups" / "one"]

    with (
        patch(
            "agent_runtime_ops.install_migrations.load_runtime_bindings",
            return_value=[binding],
        ),
        patch(
            "agent_runtime_ops.install_migrations.legacy_agent_backup_root",
            return_value=legacy_root,
        ),
        patch(
            "agent_runtime_ops.install_migrations.slot_runtime_dir",
            return_value=runtime_dir,
        ),
        patch(
            "agent_runtime_ops.install_migrations.import_legacy_agent_runtime_backups",
            return_value=imported,
        ) as importer,
    ):
        assert migrate_legacy_runtime_backups(state_root) == (1, 1)

    importer.assert_called_once_with("oc20", runtime_dir, state_root)
    output = capsys.readouterr().out
    assert "legacy_runtime_backup_target=oc20 observed=yes imported=1" in output
    assert "targets_observed=1 backups_imported=1" in output


def test_install_runs_legacy_backup_migration_before_release_activation() -> None:
    text = Path("install.sh").read_text(encoding="utf-8")
    call = 'migrate_legacy_runtime_backups "$release_dir"'
    call_offset = text.index(
        call, text.index('chown -R root:"$OPS_GROUP" "$release_dir"')
    )
    activate_offset = text.index('activate_release "$release_dir"', call_offset)
    prune_offset = text.index("prune_old_release_code", activate_offset)

    assert call_offset < activate_offset < prune_offset
    assert (
        '"$release_dir/.venv/bin/python" -m agent_runtime_ops.install_migrations'
        in text
    )


def test_rollback_attempts_legacy_import_before_reporting_no_backup(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_root = tmp_path / "state"
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    args = argparse.Namespace(slot="oc20")

    with (
        patch(
            "agent_runtime_ops.commands.apply.slot_runtime_dir",
            return_value=runtime_dir,
        ),
        patch(
            "agent_runtime_ops.commands.apply.pending_rollback_backup",
            return_value=None,
        ),
        patch(
            "agent_runtime_ops.commands.apply.latest_backup",
            side_effect=[None, None],
        ),
        patch(
            "agent_runtime_ops.commands.apply.import_legacy_agent_runtime_backups",
            return_value=[],
        ) as importer,
        patch("agent_runtime_ops.commands.apply._append_action_log"),
    ):
        assert _cmd_rollback_locked(args, state_root) == 1

    importer.assert_called_once_with("oc20", runtime_dir, state_root)
    output = capsys.readouterr().out
    assert "legacy_backups_imported=0" in output
    assert "reason=no agent-runtime backup" in output
