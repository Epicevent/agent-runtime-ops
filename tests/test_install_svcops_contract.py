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


def _shell_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    drive, tail = os.path.splitdrive(str(resolved))
    return f"/{drive[0].lower()}{tail.replace(chr(92), '/')}"


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
        "activate_and_attest_cli_or_restore"
    )


def test_svcops_attestations_are_bounded_minimal_and_prune_is_last() -> None:
    runner = _function("run_cli_as_ops")
    candidate = _function("attest_candidate_cli_as_ops")
    active = _function("attest_active_cli_as_ops")
    finalizer = _function("activate_and_attest_cli_or_restore")
    broker_finalizer = _function("install_root_action_broker_or_restore")
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
    assert '"$release_dir" "$commit" "$previous_release" "$broker_state" "$backup_dir"' in finalizer
    assert "previous active identity restored" in finalizer
    assert "restore_previous_activation_identity" in restorer
    assert 'activate_release "$previous_release"' not in restorer
    assert 'attest_restored_cli_as_ops "$previous_release" "$expected_ref"' in restorer
    assert 'restart_root_action_broker_for_release "$service_name" "$previous_release"' in restorer
    assert '/usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS"' in broker_restart
    assert 'systemctl restart "$service_name"' in broker_restart
    assert broker_restart.index('systemctl restart "$service_name"') < broker_restart.index(
        'wait_for_root_action_broker_release "$service_name" "$release_dir"'
    )
    assert "capture_root_action_broker_unit_backup" in broker_finalizer
    assert "restore_root_action_broker_unit_backup" in broker_finalizer
    unit_restore = broker_finalizer.index("restore_root_action_broker_unit_backup")
    assert unit_restore < broker_finalizer.index(
        "restore_previous_active_identity", unit_restore
    )
    assert package.index('previous_active_release="$(capture_previous_active_release "$commit")"') < package.index(
        "capture_previous_activation_identity"
    )
    assert package.index("capture_previous_activation_identity") < package.index(
        "activate_and_attest_cli_or_restore"
    )
    assert package.index("activate_and_attest_cli_or_restore") < package.index(
        "install_root_action_broker_or_restore"
    )
    assert package.index("install_root_action_broker_or_restore") < package.index(
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
        + "activate_release() { printf 'activate\\n' >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 1; }\n"
        + "restore_previous_active_identity() { printf 'restore:%s:%s:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" >>\"$TRACE\"; }\n"
        + "cleanup_activation_identity_backup() { printf 'cleanup:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("activate_and_attest_cli_or_restore")
        + f"\nactivate_and_attest_cli_or_restore /release {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "activate",
        f"restore:/release:{TARGET}:/previous:active:/backup",
        "cleanup:/backup",
        "die:post-activation svcops CLI attestation failed; previous active identity restored",
    ]


def test_post_activation_success_does_not_enter_restore(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate\\n' >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 0; }\n"
        + "restore_previous_active_identity() { printf 'restore\\n' >>\"$TRACE\"; return 1; }\n"
        + "cleanup_activation_identity_backup() { printf 'cleanup\\n' >>\"$TRACE\"; }\n"
        + _function("activate_and_attest_cli_or_restore")
        + f"\nactivate_and_attest_cli_or_restore /release {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "activate",
        "info:ops_cli_post_activation=svcops_verified",
    ]


def test_restore_repoints_wrappers_and_restarts_exact_previous_broker(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "restore_previous_activation_identity() { printf 'identity:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; }\n"
        + "attest_restored_cli_as_ops() { printf 'cli:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { printf 'inactive:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "identity:/candidate:/previous:/backup",
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
        + "restore_previous_activation_identity() { printf 'identity:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; }\n"
        + "attest_restored_cli_as_ops() { printf 'cli\\n' >>\"$TRACE\"; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker\\n' >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { printf 'inactive:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "root_action_broker_absent_attested() { printf 'absent:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} '' absent /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "identity:/candidate::/backup",
        "absent:agent-runtime-root-action-broker.service",
        "info:activation_rollback=previous_identity_restored",
    ]


@pytest.mark.parametrize(("systemctl_rc", "expected"), [(3, "inactive"), (4, "absent")])
def test_broker_pre_activation_distinguishes_inactive_from_absent(
    tmp_path: Path, systemctl_rc: int, expected: str
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        f"#!/usr/bin/env bash\nexit {systemctl_rc}\n",
        encoding="utf-8",
        newline="\n",
    )
    systemctl.chmod(0o755)
    body = (
        f"PATH={_shell_path(fake_bin)!r}:$PATH\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
        + "die() { printf 'die:%s\\n' \"$*\"; exit 23; }\n"
        + _function("capture_root_action_broker_state")
        + "\ncapture_root_action_broker_state ''\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == f"{expected}\n"


def test_restore_failure_never_reports_restored_identity(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "restore_previous_activation_identity() { printf 'identity\\n' >>\"$TRACE\"; return 1; }\n"
        + "attest_restored_cli_as_ops() { return 1; }\n"
        + "restart_root_action_broker_for_release() { printf 'broker\\n' >>\"$TRACE\"; }\n"
        + "root_action_broker_inactive_attested() { return 0; }\n"
        + _function("restore_previous_active_identity")
        + f"\nrestore_previous_active_identity /candidate {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode != 0
    assert trace.read_text(encoding="utf-8").splitlines() == ["identity"]


def test_broker_partial_failure_restores_unit_then_exact_active_identity(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "capture_root_action_broker_unit_backup() { printf 'capture-unit:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "install_root_action_broker_contract() { printf 'broker-partial:%s\\n' \"$1\" >>\"$TRACE\"; return 1; }\n"
        + "restore_root_action_broker_unit_backup() { printf 'restore-unit:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + "restore_previous_active_identity() { printf 'restore-identity:%s:%s:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\" >>\"$TRACE\"; }\n"
        + "cleanup_activation_identity_backup() { printf 'cleanup:%s\\n' \"$1\" >>\"$TRACE\"; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "capture-unit:/backup",
        "broker-partial:/candidate",
        "restore-unit:/backup",
        f"restore-identity:/candidate:{TARGET}:/previous:active:/backup",
        "cleanup:/backup",
        "die:root-action broker setup failed; previous active identity restored",
    ]


def test_broker_success_never_enters_restore_and_cleans_backup(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "capture_root_action_broker_unit_backup() { printf 'capture-unit\\n' >>\"$TRACE\"; }\n"
        + "install_root_action_broker_contract() { printf 'broker-ok\\n' >>\"$TRACE\"; }\n"
        + "restore_root_action_broker_unit_backup() { printf 'restore-unit\\n' >>\"$TRACE\"; return 1; }\n"
        + "restore_previous_active_identity() { printf 'restore-identity\\n' >>\"$TRACE\"; return 1; }\n"
        + "cleanup_activation_identity_backup() { printf 'cleanup\\n' >>\"$TRACE\"; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous active /backup\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "capture-unit",
        "broker-ok",
        "cleanup",
    ]


def test_real_broker_unit_write_failure_reaches_restore_boundary(tmp_path: Path) -> None:
    release = tmp_path / "release"
    unit_dir = release / "systemd"
    unit_dir.mkdir(parents=True)
    (unit_dir / "agent-runtime-root-action-broker.service").write_text(
        "ExecStart=@@CURRENT_LINK@@/bin\nEnvironment=AGENT_RUNTIME_OPS_RELEASE=@@RELEASE_DIR@@\n",
        encoding="utf-8",
    )
    trace = tmp_path / "trace"
    body = (
        "ROOT=$(cd \"$(dirname \"$0\")\" && pwd -P)\n"
        + f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_TRUSTED_ACCOUNT=svcops\n"
        + "INSTALL_ROOT=$ROOT/install\n"
        + "ROOT_ACTION_STATE_ROOT=$ROOT/state\n"
        + "ROOT_ACTION_PRIVATE_ROOT=$ROOT/state/private\n"
        + "ROOT_ACTION_PUBLIC_ROOT=$ROOT/state/public\n"
        + "ROOT_ACTION_RUNTIME_ROOT=$ROOT/run\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=$ROOT/broker.service\n"
        + "getent() { return 0; }\n"
        + "id() { if [[ \"${1:-}\" == '-gn' ]]; then printf 'svcops\\n'; else command id \"$@\"; fi; }\n"
        + "command() { if [[ \"${1:-}\" == '-v' && \"${2:-}\" == 'systemctl' ]]; then return 1; fi; builtin command \"$@\"; }\n"
        + "install() { local last=\"${!#}\"; if [[ \"$last\" == \"$ROOT_ACTION_BROKER_SERVICE_FILE\" ]]; then printf 'unit-write-failed\\n' >>\"$TRACE\"; return 19; fi; return 0; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "capture_root_action_broker_unit_backup() { printf 'capture\\n' >>\"$TRACE\"; }\n"
        + "restore_root_action_broker_unit_backup() { printf 'restore-unit\\n' >>\"$TRACE\"; }\n"
        + "restore_previous_active_identity() { printf 'restore-identity\\n' >>\"$TRACE\"; }\n"
        + "cleanup_activation_identity_backup() { printf 'cleanup\\n' >>\"$TRACE\"; }\n"
        + _function("install_root_action_broker_contract")
        + _function("install_root_action_broker_or_restore")
        + "\ninstall_root_action_broker_or_restore \"$ROOT/release\" "
        + f"{TARGET} /previous active \"$ROOT/backup\"\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "capture",
        "unit-write-failed",
        "restore-unit",
        "restore-identity",
        "cleanup",
        "die:root-action broker setup failed; previous active identity restored",
    ]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX links and modes")
def test_restore_previous_activation_identity_uses_exact_wrapper_bytes(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "install"
    releases = install_root / "releases"
    previous = releases / "previous"
    candidate = releases / "candidate"
    backup = tmp_path / "backup"
    bin_dir = tmp_path / "bin"
    for path in (previous, candidate, backup, bin_dir):
        path.mkdir(parents=True, exist_ok=True)
    current = install_root / "current"
    current.symlink_to("releases/candidate")
    paths = {
        "opsctl": bin_dir / "opsctl",
        "mcp": bin_dir / "agent-runtime-ops-mcp",
        "gemini": bin_dir / "gemini",
    }
    for name, path in paths.items():
        path.write_text(f"candidate-{name}\n", encoding="utf-8")
        path.chmod(0o755)
        (backup / name).write_text(f"previous-{name}\n", encoding="utf-8")
        (backup / name).chmod(0o600)
    (backup / "state").write_text("previous\n", encoding="utf-8")
    (backup / "manifest-target").write_text(
        "current/.agent-runtime-ops-manifest\n", encoding="utf-8"
    )
    (backup / "state").chmod(0o600)
    (backup / "manifest-target").chmod(0o600)
    backup.chmod(0o700)
    manifest = install_root / ".agent-runtime-ops-manifest"
    manifest.symlink_to("current/.agent-runtime-ops-manifest")
    body = (
        f"INSTALL_ROOT={str(install_root)!r}\n"
        + f"RELEASES_DIR={str(releases)!r}\n"
        + f"CURRENT_LINK={str(current)!r}\n"
        + f"BIN_LINK={str(paths['opsctl'])!r}\n"
        + f"MCP_BIN_LINK={str(paths['mcp'])!r}\n"
        + f"GEMINI_BIN_LINK={str(paths['gemini'])!r}\n"
        + f"MANIFEST={str(manifest)!r}\n"
        + "OPS_GROUP=$(id -gn)\n"
        + "chown() { :; }\n"
        + _function("restore_previous_activation_identity")
        + f"\nrestore_previous_activation_identity {str(candidate)!r} {str(previous)!r} {str(backup)!r}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert current.resolve() == previous.resolve()
    for name, path in paths.items():
        assert path.read_text(encoding="utf-8") == f"previous-{name}\n"
    assert manifest.readlink() == Path("current/.agent-runtime-ops-manifest")


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX links")
def test_first_install_partial_wrapper_removal_is_failure(tmp_path: Path) -> None:
    release = tmp_path / "candidate"
    release.mkdir()
    current = tmp_path / "current"
    current.symlink_to(release)
    paths = [tmp_path / name for name in ("opsctl", "mcp", "gemini", "manifest")]
    paths[0].write_text(
        "#!/usr/bin/env bash\n"
        f'exec "{current}/.venv/bin/opsctl" "$@"\n',
        encoding="utf-8",
    )
    paths[1].write_text(
        "#!/usr/bin/env bash\n"
        f'exec "{current}/.venv/bin/agent-runtime-ops-mcp" "$@"\n',
        encoding="utf-8",
    )
    paths[2].write_text(
        "agent-runtime-ops managed gemini wrapper\n", encoding="utf-8"
    )
    paths[3].symlink_to("current/.agent-runtime-ops-manifest")
    body = (
        f"CURRENT_LINK={str(current)!r}\n"
        + f"BIN_LINK={str(paths[0])!r}\n"
        + f"MCP_BIN_LINK={str(paths[1])!r}\n"
        + f"GEMINI_BIN_LINK={str(paths[2])!r}\n"
        + f"MANIFEST={str(paths[3])!r}\n"
        + "rm() { if [[ \"${3:-}\" == \"$MCP_BIN_LINK\" ]]; then return 1; fi; command rm \"$@\"; }\n"
        + _function("deactivate_first_release")
        + f"\ndeactivate_first_release {str(release)!r}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode != 0
    assert not paths[0].exists()
    assert paths[1].exists()
    assert current.is_symlink()
