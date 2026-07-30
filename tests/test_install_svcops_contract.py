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


def _function_block(name: str, next_name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index(f"\n{next_name}() {{", start)
    return INSTALL[start:end] + "\n"


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
    recovery = _function("recover_and_attest_activation_baseline")
    broker_recovery_policy = _function(
        "restore_broker_service_after_baseline_validation"
    )
    broker_restart = _function("restart_root_action_broker_for_release")
    quiesce = _function("quiesce_root_action_broker_for_publication")
    recovery_quiesce = _function("quiesce_root_action_broker_before_recovery")
    transaction_quiesce = _function("quiesce_root_action_broker_for_transaction")
    tuple_reader = _function("read_root_action_broker_systemd_tuple")
    terminal_attestation = _function("root_action_broker_terminal_tuple_attested")
    inactive_attestation = _function("root_action_broker_inactive_attested")
    absent_attestation = _function("root_action_broker_absent_attested")
    quiesced_attestation = _function("root_action_broker_quiesced_attested")
    package = _function("install_package")
    assert "/usr/bin/timeout --kill-after=1" in runner
    assert "runuser -u \"$OPS_USER\" -- env -i" in runner
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in runner
    assert '"$release_dir/.venv/bin/opsctl"' in candidate
    assert '"$release_dir/agent-clis/gemini-cli/node_modules/.bin/gemini"' in candidate
    assert 'run_cli_as_ops "$BIN_LINK" --state-root "$STATE_ROOT" update status' in active
    assert "recover_and_attest_activation_baseline" in finalizer
    assert '"$helper" "$commit" "$previous_release"' in finalizer
    assert "baseline_cli_state=$RESTORED_CLI_RESULT" in finalizer
    assert "baseline_broker_state=$RESTORED_BROKER_RESULT" in finalizer
    assert 'RESTORED_CLI_RESULT="unchanged_prepublication"' in finalizer
    assert 'RESTORED_BROKER_RESULT="unchanged_prepublication"' in finalizer
    assert 'run_activation_transaction "$helper" recover' in recovery
    assert recovery.index('quiesce_root_action_broker_before_recovery "$helper"') < recovery.index(
        'run_activation_transaction "$helper" recover'
    )
    assert (
        'restore_broker_service_after_baseline_validation \\\n    "$helper" "$previous_release"'
        in recovery
    )
    assert "attest_restored_cli_or_exact_preexisting_legacy" in recovery
    assert '"$previous_release" "$expected_commit"' in recovery
    assert recovery.index("attest_restored_cli_or_exact_preexisting_legacy") < recovery.index(
        "restore_broker_service_after_baseline_validation"
    )
    assert 'info "ops_cli_restoration=$RESTORED_CLI_RESULT"' in recovery
    assert 'info "broker_restoration=$RESTORED_BROKER_RESULT"' in recovery
    assert 'run_activation_transaction "$helper" finalize --expect baseline' in recovery
    assert "restored_exact_but_preexisting_unrunnable" in broker_recovery_policy
    assert "restored_admissible_preexisting_runnable_unexecuted" in broker_recovery_policy
    assert '[[ "$desired_state" == active' in broker_recovery_policy
    assert 'root_action_broker_inactive_attested "$service_name" disabled' in broker_recovery_policy
    assert (
        'RESTORED_BROKER_RESULT="restored_unit_active_intent_carried_candidate_only"'
        in broker_recovery_policy
    )
    assert broker_recovery_policy.index(
        'root_action_broker_inactive_attested "$service_name" disabled'
    ) < broker_recovery_policy.index(
        'defer-broker-reactivation'
    )
    assert broker_recovery_policy.index(
        'RESTORED_BROKER_RESULT="restored_unit_active_intent_carried_candidate_only"'
    ) < broker_recovery_policy.index(
        'restore_broker_service_from_transaction "$helper" "$previous_release"'
    )
    assert '/usr/bin/timeout --kill-after=1 "$ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS"' in broker_restart
    assert 'systemctl restart "$service_name"' in broker_restart
    assert broker_restart.index('systemctl restart "$service_name"') < broker_restart.index(
        'wait_for_root_action_broker_release "$service_name" "$release_dir"'
    )
    assert 'quiesce_root_action_broker_for_transaction "$1"' in quiesce
    assert 'quiesce_root_action_broker_for_transaction "$1"' in recovery_quiesce
    assert 'systemctl stop "$service_name"' in transaction_quiesce
    assert "root_action_broker_quiesced_attested" in transaction_quiesce
    assert tuple_reader.count("systemctl show") == 1
    for property_name in ("LoadState", "ActiveState", "SubState", "MainPID", "Job", "UnitFileState"):
        assert f"--property={property_name}" in tuple_reader
    assert "--value" not in tuple_reader
    assert terminal_attestation.count("read_root_action_broker_systemd_tuple") == 1
    assert "systemctl show" not in terminal_attestation
    assert "ActiveState=inactive" in terminal_attestation
    assert "SubState=dead" in terminal_attestation
    assert "MainPID=0" in terminal_attestation
    assert "JobPresent=no" in terminal_attestation
    assert 'root_action_broker_terminal_tuple_attested "$1" loaded "$2"' in inactive_attestation
    assert 'root_action_broker_terminal_tuple_attested "$1" not-found absent' in absent_attestation
    assert 'LoadState=loaded:UnitFileState=disabled' in quiesced_attestation
    assert 'LoadState=not-found:UnitFileState=absent' in quiesced_attestation
    assert "recover_and_attest_activation_baseline" in broker_finalizer
    assert "finalize --expect candidate" in broker_finalizer
    assert package.index('previous_active_release="$(capture_previous_active_release "$commit")"') < package.index(
        "materialize_exact_source_tree"
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


def test_exact_legacy_baseline_exception_is_passive_and_candidate_gate_remains() -> None:
    discriminator = _function("legacy_baseline_requires_exact_admission")
    identity = _function_block(
        "exact_preexisting_legacy_cli_baseline_identity",
        "attest_exact_preexisting_unrunnable_cli_baseline",
    )
    degraded = _function("attest_exact_preexisting_unrunnable_cli_baseline")
    runnable = _function(
        "attest_exact_preexisting_runnable_cli_baseline_without_execution"
    )
    combined = _function("attest_restored_cli_or_exact_preexisting_legacy")
    capture = _function("capture_previous_active_release")
    recovery = _function("recover_and_attest_activation_baseline")
    prepare = _function("prepare_release_for_activation")
    package = _function("install_package")

    assert "LEGACY_RESTRICTIVE_UMASK_BASELINE_REF" in identity
    assert "os.O_NOFOLLOW" in discriminator
    assert "st_mtime_ns" in discriminator and "st_ctime_ns" in discriminator
    assert 'mode_profile not in ("restrictive", "runnable")' in identity
    assert 'generated_dir_mode = 0o700 if mode_profile == "restrictive" else 0o755' in identity
    assert 'generated_data_mode = 0o600 if mode_profile == "restrictive" else 0o644' in identity
    assert 'generated_exec_mode = 0o700 if mode_profile == "restrictive" else 0o755' in identity
    assert "stat.S_IMODE(venv_meta.st_mode) != generated_dir_mode" in identity
    assert "stat.S_IMODE(venv_bin_meta.st_mode) != generated_dir_mode" in identity
    assert "venv_opsctl_meta" not in identity
    assert "venv_opsctl_text = require_console_entrypoint(" in identity
    assert "venv_mcp_text = require_console_entrypoint(" in identity
    assert "os.O_NOFOLLOW" in identity
    assert "st_mtime_ns" in identity and "st_ctime_ns" in identity
    assert '"updates:",' in identity
    assert '"  agent-runtime-ops:",' in identity
    assert "len(policy_lines) != 10" in identity
    assert '"\\r" in policy_text' in identity
    assert 'not policy_text.endswith("\\n")' in identity
    assert 'policy_text.count("\\n") != 10' in identity
    assert "canonical_approved_by_scalar" in identity
    assert "approved_by_allows_block_plain" in identity
    assert "implicit_non_string_patterns" in identity
    assert "gemini_wrapper != expected_gemini_wrapper" in identity
    assert '"codex/kwrag-legacy-backup-collision-recovery "' in identity
    assert 'path_is_not_executable_as_ops "$release_dir/.venv/bin/opsctl"' in degraded
    assert 'run_cli_as_ops "$release_dir/.venv/bin/opsctl"' not in degraded
    assert "c615067ad8d61a09f116bd9f9e22d949d45b9603af8de184fd90718ebf27765e" in INSTALL
    assert 'source_files != expected_source_files' in identity
    assert 'source_dirs != expected_source_dirs' in identity
    assert 'source_bytes != expected_source_bytes' in identity
    assert 'venv_mcp = os.path.join(venv, "bin", "agent-runtime-ops-mcp")' in identity
    assert 'require_symlink(gemini_link, "../@google/gemini-cli/bundle/gemini.js")' in identity
    assert 'source_projection = validate_source_projection()' in identity
    assert "payload = read_regular(path, 0o755" in identity
    assert "body not in (distlib_template, legacy_template)" in identity
    assert 'gemini_package_data.get("bin") != {"gemini": "bundle/gemini.js"}' in identity
    assert "gemini_package, generated_data_mode" in identity
    assert "gemini_bundle, generated_exec_mode" in identity
    assert degraded.count("exact_preexisting_legacy_cli_baseline_identity") == 2
    assert '"$release_dir" "$expected_ref" restrictive' in degraded
    assert runnable.count("exact_preexisting_legacy_cli_baseline_identity") == 2
    assert '"$release_dir" "$expected_ref" runnable' in runnable
    assert 'path_is_executable_as_ops "$release_dir/.venv/bin/opsctl"' in runnable
    assert runnable.index("exact_preexisting_legacy_cli_baseline_identity") < runnable.index(
        "path_is_executable_as_ops"
    )
    assert "attest_restored_cli_as_ops" not in runnable
    assert 'RESTORED_CLI_RESULT="svcops_verified"' in combined
    assert (
        'RESTORED_CLI_RESULT="restored_admissible_preexisting_runnable_unexecuted"'
        in combined
    )
    assert (
        'RESTORED_CLI_RESULT="restored_exact_but_preexisting_unrunnable"'
        in combined
    )
    assert combined.index("legacy_baseline_requires_exact_admission") < combined.index(
        "attest_restored_cli_as_ops"
    )
    assert combined.index("attest_exact_preexisting_unrunnable_cli_baseline") < combined.index(
        "attest_exact_preexisting_runnable_cli_baseline_without_execution"
    )
    assert combined.index(
        "attest_exact_preexisting_runnable_cli_baseline_without_execution"
    ) < combined.index("attest_restored_cli_as_ops")
    assert "attest_restored_cli_or_exact_preexisting_legacy" in capture
    assert "attest_restored_cli_or_exact_preexisting_legacy" in recovery
    assert "attest_restored_cli_as_ops" not in recovery
    assert 'attest_candidate_cli_as_ops "$release_dir" "$commit"' in prepare
    assert package.index("capture_previous_active_release") < package.index(
        "materialize_exact_source_tree"
    )
    assert package.index('prepare_release_for_activation "$release_dir" "$commit"') < package.index(
        "activate_and_attest_cli_or_restore"
    )


def test_legacy_shaped_altered_opsctl_is_rejected_before_live_wrapper_execution(
    tmp_path: Path,
) -> None:
    sentinel = tmp_path / "altered-wrapper-executed"
    wrapper = tmp_path / "opsctl"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        f"printf 'executed\\n' > {_shell_path(sentinel)!r}\n"
        "exit 0\n",
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(0o755)
    body = (
        f"BIN_LINK={_shell_path(wrapper)!r}\n"
        + "RESTORED_CLI_RESULT=''\n"
        + "legacy_baseline_requires_exact_admission() { return 0; }\n"
        + "attest_exact_preexisting_unrunnable_cli_baseline() { return 1; }\n"
        + "attest_exact_preexisting_runnable_cli_baseline_without_execution() { return 1; }\n"
        + "attest_restored_cli_as_ops() { \"$BIN_LINK\" profile list >/dev/null; }\n"
        + _function("attest_restored_cli_or_exact_preexisting_legacy")
        + f"\nif attest_restored_cli_or_exact_preexisting_legacy /legacy {TARGET}; then\n"
        + "  exit 91\n"
        + "fi\n"
        + "[[ -z \"$RESTORED_CLI_RESULT\" ]]\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert not sentinel.exists()


def test_pending_recovery_is_commit_bound_first_gate_after_lock() -> None:
    package = _function("install_package")
    helper_runner = _function("run_trusted_activation_helper")
    cleanup = _function("cleanup_abandoned_activation_staging")
    assert package.index('commit="$(source_commit "$src")"') < package.index("with_install_lock")
    assert package.index("verify_activation_helper_identity") < package.index("with_install_lock")
    assert package.index("with_install_lock") < package.index(
        'recover_pending_activation_transaction "$activation_helper" "$commit"'
    )
    recovery = package.index('recover_pending_activation_transaction "$activation_helper" "$commit"')
    assert recovery < package.index("cleanup_abandoned_activation_staging")
    assert recovery < package.index("capture_previous_active_release")
    assert recovery < package.index("ensure_base_packages")
    assert package.index("capture_previous_active_release") < package.index(
        "materialize_exact_source_tree"
    )
    for suffix in (
        '"$ACTIVATION_TRANSACTION_DIR"',
        '"${ACTIVATION_TRANSACTION_DIR}.new"',
        '"${ACTIVATION_TRANSACTION_DIR}.complete"',
        '"${ACTIVATION_TRANSACTION_DIR}.recovered.complete"',
        '"${ACTIVATION_TRANSACTION_DIR}.recovered.acknowledged"',
        '"${ACTIVATION_TRANSACTION_DIR}.recovered.retired"',
        '"$ACTIVATION_CANDIDATE_DIR"',
    ):
        assert suffix in package
    assert "ack-recovered" in cleanup
    assert '--expected-commit "$expected_commit"' in cleanup
    assert "recovered_completion_acknowledged=yes) return 2" in cleanup
    assert "recovered_completion_cleaned=yes) return 2" in cleanup
    assert package.index("activation_cleanup_rc") < package.index("capture_previous_active_release")
    assert "completed activation recovery retired; rerun install" in package
    assert "/usr/bin/python3 -I -" in helper_runner
    assert "env -i PATH=/usr/local/bin:/usr/bin:/bin" in helper_runner
    assert "O_NOFOLLOW" in helper_runner
    assert "activation helper bytes do not match the exact source blob" in helper_runner


def test_carried_broker_revocation_is_an_installer_lock_owned_exact_action() -> None:
    revoke = _function("revoke_carried_broker_reactivation")
    lock = revoke.index("with_install_lock")
    first_read = revoke.index("show-recovered --field candidate_commit")
    mutation = revoke.index('revoke-broker-reactivation \\\n')
    retirement = revoke.index('ack-recovered \\\n')
    assert lock < first_read < mutation < retirement
    for field in (
        "candidate_commit",
        "previous_release",
        "broker_service_name",
        "broker_reactivation_origin_sha256",
    ):
        assert f"--field {field}" in revoke
    for binding in (
        '--expected-commit "$expected_commit"',
        '--expected-previous-release "$expected_previous_release"',
        '--expected-service-name "$expected_service_name"',
        '--expected-origin-sha256 "$expected_origin_sha256"',
    ):
        assert binding in revoke
    assert '[[ "$carrier_commit" == "$expected_commit"' in revoke
    assert '"$previous_release" == "$expected_previous_release"' in revoke
    assert '"$service_name" == "$expected_service_name"' in revoke
    assert '"$origin_sha256" == "$expected_origin_sha256"' in revoke
    assert '[[ "$retire_output" == broker_reactivation_intent=revoked ]]' in revoke
    assert "revoke-broker-reactivation)" in INSTALL
    assert "revoke_carried_broker_reactivation" in INSTALL.rsplit(
        'case "${1:-install}" in', 1
    )[1]


def test_bootstrap_installs_python_before_python_backed_parent_validation() -> None:
    bootstrap = _function("bootstrap_from_git")
    package = _function("install_package")
    lexical = _function("validate_activation_path_strings")
    assert "python3" not in lexical
    assert bootstrap.index("validate_activation_path_strings") < bootstrap.index(
        "ensure_base_packages"
    )
    assert bootstrap.index("ensure_base_packages") < bootstrap.index(
        "validate_install_root"
    )
    assert bootstrap.index("validate_install_root") < bootstrap.index('tmp="$(mktemp -d)"')
    assert package.index("validate_activation_path_strings") < package.index(
        'if ! src="$(repo_root)"'
    )
    assert package.index("validate_install_root") > package.index("bootstrap_from_git")


def test_recovered_completion_acknowledgement_is_a_terminal_cleanup_gate(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "run_activation_transaction() { printf 'recovered_completion_acknowledged=yes\\n'; }\n"
        + "run_trusted_activation_helper() { printf 'generic-cleanup\\n' >>\"$TRACE\"; }\n"
        + _function("cleanup_abandoned_activation_staging")
        + f"\ncleanup_abandoned_activation_staging /helper {TARGET}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 2
    assert not trace.exists()


def test_activation_source_contains_no_retired_unjournaled_publisher() -> None:
    assert "_retired_activate_release" not in INSTALL
    activation = _function("activate_release")
    assert "mktemp" not in activation
    assert ".next.$$" not in activation
    assert "fsync-tree" in activation
    assert "--broker-state" in activation
    assert activation.index("quiesce_root_action_broker_for_publication") < activation.index(
        'run_activation_transaction "$helper" publish'
    )
    assert "run_activation_transaction \"$helper\" publish" in activation
    broker = _function("install_root_action_broker_contract")
    assert 'run_activation_transaction "$helper" publish-broker' in broker


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
        + "ACTIVATION_TRANSACTION_DIR=$(cd \"$(dirname \"$0\")\" && pwd -P)/pending\n"
        + "touch \"$ACTIVATION_TRANSACTION_DIR\"\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate\\n' >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 1; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_active; }\n"
        + _function("activate_and_attest_cli_or_restore")
        + f"\nactivate_and_attest_cli_or_restore /release {TARGET} /previous active enabled /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "activate",
        f"recover:/helper:{TARGET}:/previous",
        "die:post-activation svcops CLI attestation failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_active",
    ]


def test_post_activation_success_does_not_enter_restore(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "activate_release() { printf 'activate\\n' >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 0; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover\\n' >>\"$TRACE\"; return 1; }\n"
        + _function("activate_and_attest_cli_or_restore")
        + f"\nactivate_and_attest_cli_or_restore /release {TARGET} /previous active enabled /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "activate",
        "info:ops_cli_post_activation=svcops_verified",
    ]


@pytest.mark.parametrize(("load_state", "expected"), [("loaded", "inactive"), ("not-found", "absent")])
def test_broker_pre_activation_distinguishes_inactive_from_absent(
    tmp_path: Path, load_state: str, expected: str
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/usr/bin/env bash\n"
        "[[ \"$1\" == show ]] || exit 19\n"
        "printf 'LoadState=%s\\n' \"$LOAD_STATE\"\n"
        "printf 'ActiveState=inactive\\n'\n"
        "printf 'SubState=dead\\n'\n"
        "printf 'MainPID=0\\n'\n"
        "printf 'Job=\\n'\n"
        "[[ \"$LOAD_STATE\" == loaded ]] && printf 'UnitFileState=disabled\\n' || printf 'UnitFileState=\\n'\n"
        "exit 0\n",
        encoding="utf-8",
        newline="\n",
    )
    systemctl.chmod(0o755)
    body = (
        f"PATH={_shell_path(fake_bin)!r}:$PATH\n"
        + f"LOAD_STATE={load_state!r}\nexport LOAD_STATE\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=5\n"
        + "die() { printf 'die:%s\\n' \"$*\"; exit 23; }\n"
        + _function("read_root_action_broker_systemd_tuple")
        + _function("capture_root_action_broker_snapshot")
        + "\ncapture_root_action_broker_snapshot ''\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    expected_unit = "disabled" if expected == "inactive" else "absent"
    assert completed.stdout == f"{expected} {expected_unit}\n"


@pytest.mark.parametrize("load_state", ("loaded", "not-found"))
def test_broker_pre_activation_rejects_queued_auto_restart(
    tmp_path: Path, load_state: str
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/usr/bin/env bash\n"
        "[[ \"$1\" == show ]] || exit 19\n"
        "printf 'LoadState=%s\\n' \"$LOAD_STATE\"\n"
        "printf 'ActiveState=activating\\n'\n"
        "printf 'SubState=auto-restart\\n'\n"
        "printf 'MainPID=0\\n'\n"
        "printf 'Job=77\\n'\n"
        "[[ \"$LOAD_STATE\" == loaded ]] && printf 'UnitFileState=enabled\\n' || printf 'UnitFileState=\\n'\n"
        "exit 0\n",
        encoding="utf-8",
        newline="\n",
    )
    systemctl.chmod(0o755)
    body = (
        f"PATH={_shell_path(fake_bin)!r}:$PATH\n"
        + f"LOAD_STATE={load_state!r}\nexport LOAD_STATE\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=5\n"
        + "die() { printf 'die:%s\\n' \"$*\"; exit 23; }\n"
        + _function("read_root_action_broker_systemd_tuple")
        + _function("capture_root_action_broker_snapshot")
        + "\ncapture_root_action_broker_snapshot /previous\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert (
        f"state is transient or unsafe: {load_state}/activating/auto-restart"
        in completed.stdout
    )


def test_broker_partial_failure_restores_unit_then_exact_active_identity(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "run_activation_transaction() { [[ \"$2\" == show ]] && { printf 'active\\n'; return; }; return 1; }\n"
        + "install_root_action_broker_contract() { printf 'broker-partial:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; return 1; }\n"
        + "attest_candidate_root_action_broker_state() { printf 'unexpected-attest\\n' >>\"$TRACE\"; return 1; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_active; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous active /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "broker-partial:/candidate:/helper",
        f"recover:/helper:{TARGET}:/previous",
        "die:root-action broker setup failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_active",
    ]


def test_broker_success_never_enters_restore_and_cleans_backup(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "install_root_action_broker_contract() { printf 'broker-ok:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
        + "attest_candidate_root_action_broker_state() { printf 'attest:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; }\n"
        + "run_activation_transaction() { if [[ \"$2\" == show ]]; then printf 'active\\n'; else printf 'tx:%s:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >>\"$TRACE\"; fi; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover\\n' >>\"$TRACE\"; return 1; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous active /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "broker-ok:/candidate:/helper",
        "attest:/candidate:/helper:active",
        "tx:/helper:finalize:--expect:candidate",
    ]

def test_real_broker_publish_failure_reaches_durable_recovery_boundary(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "run_activation_transaction() { [[ \"$2\" == show ]] && { printf 'active\\n'; return; }; return 1; }\n"
        + "install_root_action_broker_contract() { printf 'publish-broker:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; return 19; }\n"
        + "attest_candidate_root_action_broker_state() { printf 'unexpected-attest\\n' >>\"$TRACE\"; return 1; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_active; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous active /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "publish-broker:/candidate:/helper",
        f"recover:/helper:{TARGET}:/previous",
        "die:root-action broker setup failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_active",
    ]


def test_recorded_inactive_broker_drift_to_active_recovers_without_finalize(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "run_activation_transaction() { if [[ \"$2\" == show ]]; then printf 'inactive\\n'; else printf 'unexpected-finalize\\n' >>\"$TRACE\"; fi; }\n"
        + "install_root_action_broker_contract() { printf 'drift:inactive-to-active\\n' >>\"$TRACE\"; return 1; }\n"
        + "attest_candidate_root_action_broker_state() { printf 'unexpected-attest\\n' >>\"$TRACE\"; return 1; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_inactive; }\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous inactive /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "drift:inactive-to-active",
        f"recover:/helper:{TARGET}:/previous",
        "die:root-action broker setup failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_inactive",
    ]


def test_broker_contract_revalidates_recorded_inactive_before_publication(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "ROOT_ACTION_TRUSTED_ACCOUNT=svcops\n"
        + "ROOT_ACTION_STATE_ROOT=/state\n"
        + "ROOT_ACTION_PRIVATE_ROOT=/state/private\n"
        + "ROOT_ACTION_PUBLIC_ROOT=/state/public\n"
        + "ROOT_ACTION_RUNTIME_ROOT=/run/root-action\n"
        + "ROOT_ACTION_BROKER_SERVICE_FILE=/etc/systemd/system/agent-runtime-root-action-broker.service\n"
        + "getent() { return 0; }\n"
        + "id() { [[ \"$1\" == -gn ]] && printf 'svcops\\n'; }\n"
        + "install() { return 0; }\n"
        + "run_activation_transaction() {\n"
        + "  if [[ \"$2\" == show && \"$3\" == --field ]]; then\n"
        + "    case \"$4\" in\n"
        + "      broker_state) printf 'inactive\\n' ;;\n"
        + "      previous_release) printf '/previous\\n' ;;\n"
        + "      broker_service_name) printf 'agent-runtime-root-action-broker.service\\n' ;;\n"
        + "    esac\n"
        + "    return 0\n"
        + "  fi\n"
        + "  printf 'unexpected-publish\\n' >>\"$TRACE\"\n"
        + "}\n"
        + "attest_quiesced_root_action_broker_state() { printf 'quiesce-attest:active\\n' >>\"$TRACE\"; return 1; }\n"
        + _function("install_root_action_broker_contract")
        + "\ninstall_root_action_broker_contract /candidate /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode != 0
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "quiesce-attest:active"
    ]


def test_post_publish_inactive_broker_drift_recovers_without_candidate_finalize(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "run_activation_transaction() {\n"
        + "  if [[ \"$2\" == show ]]; then\n"
        + "    case \"$4\" in\n"
        + "      broker_state|broker_desired_state) printf 'inactive\\n' ;;\n"
        + "      broker_desired_unit_file_state) printf 'disabled\\n' ;;\n"
        + "      broker_activation_phase) printf 'none\\n' ;;\n"
        + "      broker_service_name) printf 'agent-runtime-root-action-broker.service\\n' ;;\n"
        + "      *) return 87 ;;\n"
        + "    esac\n"
        + "  else printf 'unexpected-finalize\\n' >>\"$TRACE\"; fi\n"
        + "}\n"
        + "install_root_action_broker_contract() { printf 'broker-published\\n' >>\"$TRACE\"; }\n"
        + "root_action_broker_release_attested() { printf 'unexpected-release-attest\\n' >>\"$TRACE\"; return 1; }\n"
        + "root_action_broker_inactive_attested() { printf 'observed-live-active\\n' >>\"$TRACE\"; return 1; }\n"
        + "recover_and_attest_activation_baseline() { printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_inactive; }\n"
        + _function("attest_candidate_root_action_broker_state")
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous inactive /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "broker-published",
        "observed-live-active",
        f"recover:/helper:{TARGET}:/previous",
        "die:root-action broker setup failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_inactive",
    ]


@pytest.mark.parametrize("journal_state,caller_state", (("inactive", "active"), ("active", "inactive")))
def test_caller_broker_state_cannot_override_durable_journal(
    tmp_path: Path, journal_state: str, caller_state: str
) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + f"run_activation_transaction() {{ [[ \"$2\" == show ]] && printf '{journal_state}\\n' || printf 'unexpected-finalize\\n' >>\"$TRACE\"; }}\n"
        + "install_root_action_broker_contract() { printf 'unexpected-install\\n' >>\"$TRACE\"; }\n"
        + "attest_candidate_root_action_broker_state() { printf 'unexpected-attest\\n' >>\"$TRACE\"; }\n"
        + f"recover_and_attest_activation_baseline() {{ printf 'recover:%s:%s:%s\\n' \"$1\" \"$2\" \"$3\" >>\"$TRACE\"; RESTORED_CLI_RESULT=svcops_verified; RESTORED_BROKER_RESULT=restored_recorded_{journal_state}; }}\n"
        + _function("install_root_action_broker_or_restore")
        + f"\ninstall_root_action_broker_or_restore /candidate {TARGET} /previous {caller_state} /helper\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        f"recover:/helper:{TARGET}:/previous",
        f"die:root-action broker setup failed; baseline_cli_state=svcops_verified; baseline_broker_state=restored_recorded_{journal_state}",
    ]
