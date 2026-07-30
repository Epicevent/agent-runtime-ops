from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess

import pytest


INSTALL = Path("install.sh").read_text(encoding="utf-8")
TARGET = "b" * 40
PREVIOUS = "a" * 40
REPO = "https://github.com/Epicevent/agent-runtime-ops.git"


def _function(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _bash() -> str:
    bash = shutil.which("bash")
    if bash is not None:
        return bash
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    pytest.skip("bash is required for the installer contract harness")


def _run_bash(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "contract.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n" + body,
        encoding="utf-8",
        newline="\n",
    )
    return subprocess.run(
        [_bash(), str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )


def _status(*, installed: str | None, current: bool, extra: str = "") -> str:
    lines = [f"update_status={'current' if current else 'ready'}"]
    if installed is not None:
        lines.append(f"installed_ref={installed}")
    lines.extend(
        [
            f"repo_url={REPO}",
            f"approved_ref={TARGET}",
            f"approved_matches_installed={'yes' if current else 'no'}",
        ]
    )
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def test_install_normalizes_generated_runtime_trees_before_candidate_attestation() -> None:
    normalizer = _function("normalize_generated_runtime_tree_permissions")
    prepare = _function("prepare_release_for_activation")
    package = _function("install_package")
    assert '! -type d ! -type f ! -type l -print -quit' in normalizer
    assert '-type d -exec chmod 0750 {} +' in normalizer
    assert '-type f -perm /0111 -exec chmod 0750 {} +' in normalizer
    assert '-type f ! -perm /0111 -exec chmod 0640 {} +' in normalizer
    assert "chmod -R" not in normalizer
    assert package.index('chown -R root:"$OPS_GROUP" "$release_dir"') < package.index(
        'prepare_release_for_activation "$release_dir" "$commit"'
    )
    assert prepare.index(
        'normalize_generated_runtime_tree_permissions "$release_dir/.venv"'
    ) < prepare.index('attest_candidate_cli_as_ops "$release_dir" "$commit"')
    assert '"$release_dir/agent-clis/gemini-cli/node_modules"' in prepare
    assert package.index('prepare_release_for_activation "$release_dir" "$commit"') < package.index(
        'migrate_legacy_runtime_backups "$release_dir"'
    )
    assert package.index('migrate_legacy_runtime_backups "$release_dir"') < package.index(
        'activate_release "$release_dir"'
    )


def test_svcops_attestations_are_bounded_minimal_and_prune_is_last() -> None:
    runner = _function("run_cli_as_ops")
    candidate = _function("attest_candidate_cli_as_ops")
    active = _function("attest_active_cli_as_ops")
    finalizer = _function("attest_active_cli_or_restore")
    restorer = _function("restore_previous_active_identity")
    broker_restart = _function("restart_root_action_broker_for_release")
    package = _function("install_package")
    assert "/usr/bin/timeout --kill-after=1" in runner
    assert "runuser -u \"$OPS_USER\" -- env -i" in runner
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in runner
    assert '"$release_dir/.venv/bin/opsctl"' in candidate
    assert '"$release_dir/agent-clis/gemini-cli/node_modules/.bin/gemini"' in candidate
    assert 'run_cli_as_ops "$BIN_LINK" --state-root "$STATE_ROOT" update status' in active
    assert "restore_previous_active_identity" in finalizer
    assert '"$release_dir" "$commit" "$previous_release" "$broker_state"' in finalizer
    assert "previous active identity restored" in finalizer
    assert 'activate_release "$previous_release"' in restorer
    assert 'attest_restored_cli_as_ops "$previous_release" "$expected_ref"' in restorer
    assert 'restart_root_action_broker_for_release "$service_name" "$previous_release"' in restorer
    assert '/usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS"' in broker_restart
    assert 'systemctl restart "$service_name"' in broker_restart
    assert broker_restart.index('systemctl restart "$service_name"') < broker_restart.index(
        'wait_for_root_action_broker_release "$service_name" "$release_dir"'
    )
    assert package.index('previous_active_release="$(capture_previous_active_release "$commit")"') < package.index(
        'activate_release "$release_dir"'
    )
    assert package.index('activate_release "$release_dir"') < package.index(
        '"$release_dir" "$commit" "$previous_active_release" "$previous_broker_state"'
    )
    assert package.index('"$release_dir" "$commit" "$previous_active_release" "$previous_broker_state"') < package.index(
        'install_root_action_broker_contract "$release_dir"'
    )
    assert package.index('install_root_action_broker_contract "$release_dir"') < package.index(
        "prune_old_release_code"
    )
    assert '[[ -x /usr/bin/timeout ]] || die "missing executable: /usr/bin/timeout"' in _function(
        "require_commands"
    )


def test_pre_activation_failure_removes_only_candidate_and_stops(tmp_path: Path) -> None:
    release = tmp_path / "candidate"
    release.mkdir()
    survivor = tmp_path / "previous"
    survivor.mkdir()
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + f"RELEASE={str(release)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "normalize_generated_runtime_tree_permissions() { return 0; }\n"
        + "attest_candidate_cli_as_ops() { return 1; }\n"
        + _function("prepare_release_for_activation")
        + f"\nprepare_release_for_activation \"$RELEASE\" {TARGET}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert not release.exists()
    assert survivor.is_dir()
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "die:generated runtime permissions or pre-activation svcops attestation failed"
    ]


def test_pre_activation_success_preserves_candidate(tmp_path: Path) -> None:
    release = tmp_path / "candidate"
    release.mkdir()
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + f"RELEASE={str(release)!r}\n"
        + "die() { exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "normalize_generated_runtime_tree_permissions() { return 0; }\n"
        + "attest_candidate_cli_as_ops() { return 0; }\n"
        + _function("prepare_release_for_activation")
        + f"\nprepare_release_for_activation \"$RELEASE\" {TARGET}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert release.is_dir()
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "info:ops_cli_pre_activation=svcops_verified"
    ]


@pytest.mark.parametrize(
    ("output", "require_current"),
    [
        (_status(installed=PREVIOUS, current=False), "no"),
        (_status(installed=TARGET, current=True), "no"),
        (_status(installed=None, current=False), "no"),
        (_status(installed=TARGET, current=True), "yes"),
    ],
)
def test_update_status_validator_accepts_exact_ready_current_and_retry(
    tmp_path: Path, output: str, require_current: str
) -> None:
    body = (
        f"REPO_URL={REPO!r}\n"
        + _function("validate_update_status_output")
        + "\n"
        + "output=$(cat <<'EOF'\n"
        + output
        + "\nEOF\n)\n"
        + f"validate_update_status_output \"$output\" {TARGET} {require_current}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "output",
    [
        _status(installed=PREVIOUS, current=False, extra="unexpected=value"),
        _status(installed=PREVIOUS, current=False) + "\napproved_ref=" + TARGET,
        _status(installed=PREVIOUS, current=False).replace(
            f"approved_ref={TARGET}", f"approved_ref={'c' * 40}"
        ),
        _status(installed=PREVIOUS, current=False).replace(
            "approved_matches_installed=no", "approved_matches_installed=yes"
        ),
        _status(installed=PREVIOUS, current=False).replace(
            "repo_url=https://github.com/Epicevent/agent-runtime-ops.git",
            "repo_url=https://example.invalid/repo.git",
        ),
    ],
)
def test_update_status_validator_rejects_unknown_duplicate_and_mismatch(
    tmp_path: Path, output: str
) -> None:
    body = (
        f"REPO_URL={REPO!r}\n"
        + _function("validate_update_status_output")
        + "\n"
        + "output=$(cat <<'EOF'\n"
        + output
        + "\nEOF\n)\n"
        + f"validate_update_status_output \"$output\" {TARGET} no\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode != 0


def test_post_activation_failure_restores_before_returning_failure(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 1; }\n"
        + "restore_previous_active_identity() { printf 'restore:%s:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >>\"$TRACE\"; }\n"
        + _function("attest_active_cli_or_restore")
        + f"\nattest_active_cli_or_restore /release {TARGET} /previous active\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        f"restore:/release:{TARGET}:/previous:active",
        "die:post-activation svcops CLI attestation failed; previous active identity restored",
    ]


def test_post_activation_success_does_not_enter_restore(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 0; }\n"
        + "restore_previous_active_identity() { printf 'restore\\n' >>\"$TRACE\"; return 1; }\n"
        + _function("attest_active_cli_or_restore")
        + f"\nattest_active_cli_or_restore /release {TARGET} /previous active\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "info:ops_cli_post_activation=svcops_verified",
    ]


def test_restore_repoints_wrappers_and_restarts_exact_previous_broker(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "attest_restored_cli_as_ops() { printf 'cli:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
        + "deactivate_first_release() { printf 'deactivate:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { printf 'inactive:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} /previous active\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "activate:/previous",
        f"cli:/previous:{TARGET}",
        "broker:agent-runtime-root-action-broker.service:/previous",
        "info:activation_rollback=previous_identity_restored",
    ]


def test_first_install_restore_removes_candidate_and_keeps_broker_inactive(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "attest_restored_cli_as_ops() { printf 'cli\\n' >>\"$TRACE\"; }\n"
        + "deactivate_first_release() { printf 'deactivate:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker\\n' >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { printf 'inactive:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} '' inactive\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "deactivate:/candidate",
        "inactive:agent-runtime-root-action-broker.service",
        "info:activation_rollback=previous_identity_restored",
    ]


def test_restore_failure_never_reports_restored_identity(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "attest_restored_cli_as_ops() { return 1; }\n"
        + "deactivate_first_release() { return 1; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker\\n' >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { return 0; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} /previous active\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode != 0
    assert trace.read_text(encoding="utf-8").splitlines() == ["activate:/previous"]
