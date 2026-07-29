from __future__ import annotations

import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from agent_runtime_ops.domain.runtime_apply import apply_desired_slot
from agent_runtime_ops.domain.runtime_backup import (
    backup_agent_runtime_state,
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
