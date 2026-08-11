from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "systemd" / "install-agent-runtime-root-action-broker-standalone.sh"
UNIT = ROOT / "systemd" / "agent-runtime-root-action-broker-standalone.service"
LOCK = ROOT / "requirements.lock"


def _source() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_standalone_installer_has_one_exact_artifact_contract() -> None:
    source = _source()
    assert '[[ "$#" -eq 3 ]] || die usage_wheel_wheel_sha_source_commit' in source
    assert "WHEEL=$1" in source
    assert "WHEEL_SHA256=$2" in source
    assert "SOURCE_COMMIT=$3" in source
    assert "usage_wheel_wheel_sha_source_commit" in source
    assert "curl " not in source
    assert "wget " not in source
    assert "git " not in source
    assert "opsctl" not in source
    assert "install.sh" not in source
    assert "/opt/agent-runtime-ops/current" not in source


def test_standalone_installer_is_offline_and_phase_specific() -> None:
    source = _source()
    assert "WHEELHOUSE=$SCRIPT_DIR/wheelhouse" in source
    assert "wheelhouse_identity_invalid" in source
    assert "wheelhouse_entry_invalid" in source
    assert "wheelhouse_file_count_invalid" in source
    assert "wheelhouse_too_large" in source
    assert '--no-index --only-binary=:all: --find-links "$WHEELHOUSE"' in source
    assert "venv_creation_failed" in source
    assert "dependency_install_failed" in source
    assert "source_wheel_install_failed" in source
    assert "staged_release_chown_failed" in source
    assert "release_parent_fsync_failed" in source
    assert "rendered_unit_write_failed" in source
    assert "standalone_unit_publish_failed" in source
    assert "daemon_reload_failed" in source
    assert "legacy_disable_failed" in source
    assert "standalone_enable_failed" in source


def test_fresh_checkout_can_materialize_the_fixed_wheelhouse() -> None:
    source = _source()
    assert 'if [[ "$#" -eq 1 && "$1" == prepare-wheelhouse ]]' in source
    assert "prepare_wheelhouse" in source
    assert "wheelhouse_prepare_must_be_unprivileged" in source
    assert 'validate_wheelhouse "$WHEELHOUSE"' in source
    assert "--require-hashes --only-binary=:all: --no-cache-dir" in source
    assert '--dest "$prepare_files" -r "$REQUIREMENTS"' in source
    assert 'validate_wheelhouse "$prepare_files"' in source
    assert 'mv -- "$prepare_files" "$WHEELHOUSE"' in source
    assert "wheelhouse_prepare_parent_fsync_failed" in source


def test_standalone_installer_builds_only_from_hash_locked_inputs() -> None:
    source = _source()
    template_digest = re.search(r"^TEMPLATE_SHA256=([0-9a-f]{64})$", source, re.M)
    lock_digest = re.search(r"^REQUIREMENTS_SHA256=([0-9a-f]{64})$", source, re.M)
    assert template_digest
    assert lock_digest
    import hashlib

    assert template_digest.group(1) == hashlib.sha256(UNIT.read_bytes()).hexdigest()
    assert lock_digest.group(1) == hashlib.sha256(LOCK.read_bytes()).hexdigest()
    assert '--require-hashes -r "$REQUIREMENTS_COPY"' in source
    assert '--no-index --no-deps --force-reinstall "$WHEEL_COPY"' in source
    assert "WHEEL_COPY=$TMP/agent_runtime_ops-0.1.0-py3-none-any.whl" in source
    assert "WHEEL_COPY=$TMP/source.whl" not in source
    assert '/usr/bin/python3 -m venv --copies "$STAGE/.venv"' in source
    assert "copied_wheel_sha256_mismatch" in source
    assert "unit_template_sha256_mismatch" in source
    assert "requirements_lock_sha256_mismatch" in source
    assert "flock -n 9 || die install_lock_busy" in source
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in source


def test_standalone_installer_pins_release_and_process_identity() -> None:
    source = _source()
    for expected in (
        "FINAL=$RELEASE_ROOT/$SOURCE_COMMIT",
        '"@@BROKER_RELEASE_DIR@@": release',
        '"@@SOURCE_COMMIT@@": commit',
        '"@@BROKER_TREE_SHA256@@": f"sha256:{tree}"',
        'b"agent_runtime_ops.root_actions.service"',
        "AGENT_RUNTIME_ROOT_ACTION_RELEASE={release}",
        "AGENT_RUNTIME_ROOT_ACTION_SOURCE_COMMIT={commit}",
        "AGENT_RUNTIME_ROOT_ACTION_TREE_SHA256=sha256:{tree}",
    ):
        assert expected in source
    assert "unsupported release inode" in source
    assert "release inode owner mismatch" in source
    assert "release file link count mismatch" in source
    assert "release symlink escapes tree" in source
    assert "staged_release_invalid" in source
    assert "existing_release_invalid" in source


def test_standalone_cutover_rolls_back_before_reporting_success() -> None:
    source = _source()
    stop_legacy = source.index('systemctl disable --now "$LEGACY_UNIT"')
    enable_new = source.index(
        'systemctl enable "$UNIT_NAME" || die standalone_enable_failed'
    )
    restart_new = source.index(
        'systemctl restart "$UNIT_NAME" || die standalone_restart_failed'
    )
    attest = source.index("standalone broker argv mismatch")
    receipt = source.index("write_receipt succeeded cutover_attested")
    committed = source.index("cutover_committed=1", receipt)
    assert stop_legacy < enable_new < restart_new < attest < receipt < committed
    cleanup = source[source.index("cleanup() {") : source.index("tree_digest() {")]
    assert 'systemctl stop "$UNIT_NAME"' in cleanup
    assert 'systemctl disable "$UNIT_NAME"' in cleanup
    assert 'if [[ "$standalone_was_enabled" -eq 1 ]]; then' in cleanup
    assert 'systemctl enable "$UNIT_NAME"' in cleanup
    assert 'if [[ "$standalone_was_active" -eq 1 ]]; then' in cleanup
    assert 'systemctl start "$UNIT_NAME"' in cleanup
    assert 'systemctl start "$LEGACY_UNIT"' in cleanup
    assert 'install -o root -g root -m 0644 "$PREVIOUS_UNIT" "$UNIT_PATH"' in cleanup


def test_standalone_receipt_is_durable_and_svcops_readable() -> None:
    source = _source()
    for expected in (
        'install -d -o root -g svcops -m 0750 "$RECEIPT_ROOT"',
        "os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL",
        "os.fsync(fd)",
        'os.fchown(fd, 0, grp.getgrnam("svcops").gr_gid)',
        "os.replace(tmp, target)",
        "os.fsync(directory)",
        '"legacy_broker_active": legacy_active',
        '"standalone_broker_active": standalone_active',
        '"terminal": terminal',
        "write_receipt succeeded cutover_attested",
    ):
        assert expected in source


def test_standalone_failure_receipt_follows_rollback_and_is_sanitized() -> None:
    source = _source()
    cleanup = source[source.index("cleanup() {") : source.index("tree_digest() {")]
    assert "rollback_attempted=1" in cleanup
    assert "rollback_verified=1" in cleanup
    assert 'write_receipt failed "$failure_reason" || true' in cleanup
    assert '"reason": reason' in source
    assert '"rollback_attempted": rollback_attempted' in source
    assert '"rollback_verified": rollback_verified' in source
    assert "stderr" not in source


def test_standalone_installer_never_seeds_from_mutable_current_release() -> None:
    source = _source()
    assert "/opt/agent-runtime-ops/current" not in source
    assert "cp -a" not in source
    assert "--system-site-packages" not in source
    assert (
        "grep -Eq '^ExecStart=/opt/agent-runtime-root-action-broker/releases/" in source
    )


def test_embedded_python_blocks_compile(tmp_path: Path) -> None:
    source = _source()
    blocks = re.findall(r"(?ms)<<'PY'\n(.*?)^PY$", source)
    assert len(blocks) == 5
    for index, block in enumerate(blocks):
        path = tmp_path / f"embedded-{index}.py"
        path.write_text(block, encoding="utf-8")
        result = subprocess.run(
            [__import__("sys").executable, "-m", "py_compile", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash unavailable")
def test_standalone_installer_is_valid_bash() -> None:
    result = subprocess.run(
        ["bash", "-n", str(INSTALLER)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
