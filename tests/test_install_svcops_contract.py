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
    finalizer = _function("attest_active_cli_and_prune")
    package = _function("install_package")
    assert "/usr/bin/timeout --kill-after=1" in runner
    assert "runuser -u \"$OPS_USER\" -- env -i" in runner
    assert "PATH=/usr/local/bin:/usr/bin:/bin" in runner
    assert '"$release_dir/.venv/bin/opsctl"' in candidate
    assert '"$release_dir/agent-clis/gemini-cli/node_modules/.bin/gemini"' in candidate
    assert 'run_cli_as_ops "$BIN_LINK" --state-root "$STATE_ROOT" update status' in active
    assert finalizer.index('attest_active_cli_as_ops "$release_dir" "$commit"') < finalizer.index(
        "prune_old_release_code"
    )
    assert "previous release preserved" in finalizer
    assert package.index('activate_release "$release_dir"') < package.index(
        'attest_active_cli_and_prune "$release_dir" "$commit"'
    )
    assert "prune_old_release_code" not in package
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


def test_post_activation_failure_never_reaches_prune(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { printf 'die:%s\\n' \"$*\" >>\"$TRACE\"; exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 1; }\n"
        + "prune_old_release_code() { printf 'prune\\n' >>\"$TRACE\"; }\n"
        + _function("attest_active_cli_and_prune")
        + f"\nattest_active_cli_and_prune /release {TARGET}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 23
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "die:post-activation svcops CLI attestation failed; previous release preserved"
    ]


def test_post_activation_success_allows_prune(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    body = (
        f"TRACE={str(trace)!r}\n"
        + "die() { exit 23; }\n"
        + "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
        + "attest_active_cli_as_ops() { return 0; }\n"
        + "prune_old_release_code() { printf 'prune\\n' >>\"$TRACE\"; }\n"
        + _function("attest_active_cli_and_prune")
        + f"\nattest_active_cli_and_prune /release {TARGET}\n"
    )
    completed = _run_bash(tmp_path, body)
    assert completed.returncode == 0, completed.stderr
    assert trace.read_text(encoding="utf-8").splitlines() == [
        "info:ops_cli_post_activation=svcops_verified",
        "prune",
    ]
