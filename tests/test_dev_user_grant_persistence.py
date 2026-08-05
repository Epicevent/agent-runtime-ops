from pathlib import Path
import os
import subprocess


INSTALL = Path("install.sh").read_text(encoding="utf-8")


def _function(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _run_bash(tmp_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "contract.sh"
    script.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    return subprocess.run(
        ["bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )


def test_dev_users_are_loaded_from_durable_root_owned_state() -> None:
    assert 'DEV_USERS_FILE="${AGENT_RUNTIME_DEV_USERS_FILE:-/etc/agent-runtime-ops/developer-users}"' in INSTALL
    assert "elif [[ -r \"$DEV_USERS_FILE\" ]]" in INSTALL
    assert "DEV_USERS=\"$(tr '\\n' ' ' <\"$DEV_USERS_FILE\")\"" in INSTALL


def test_dev_users_are_persisted_before_sudoers_and_effective_grants_are_attested() -> None:
    package = _function("install_package")
    assert package.index("persist_dev_users") < package.index("install_ops_sudoers")
    assert package.index("install_ops_sudoers") < package.index("attest_dev_user_sudoers")

    persistence = _function("persist_dev_users")
    assert "invalid developer account" in persistence
    assert 'mv -f "$tmp" "$DEV_USERS_FILE"' in persistence

    attestation = _function("attest_dev_user_sudoers")
    assert attestation.count("runuser -u") == 3
    assert "dev-upstream status dev-attest --authorization-check" in attestation
    assert "dev-upstream apply dev-attest --container attest --authorization-check" in attestation
    assert "dev-upstream rollback dev-attest --authorization-check" in attestation


def test_persisted_dev_users_survive_without_environment_override(tmp_path: Path) -> None:
    state = tmp_path / "developer-users"
    result = _run_bash(
        tmp_path,
        f"""
DEV_USERS='openclawdev atelier'
DEV_USERS_FILE={state!s}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
install() {{ :; }}
chown() {{ :; }}
{_function('persist_dev_users')}
persist_dev_users
unset AGENT_RUNTIME_DEV_USERS
DEV_USERS="$(tr '\\n' ' ' <"$DEV_USERS_FILE")"
[[ "$DEV_USERS" == 'openclawdev atelier ' ]]
""",
    )
    assert result.returncode == 0, result.stderr
    assert state.read_text(encoding="utf-8") == "openclawdev\natelier\n"


def test_attestation_rejects_one_missing_effective_grant_and_accepts_all(tmp_path: Path) -> None:
    body = f"""
DEV_USERS='atelier'
BIN_LINK=/usr/local/bin/opsctl
die() {{ printf '%s\\n' "$*" >&2; exit 9; }}
runuser() {{ [[ "${{DENY_APPLY:-no}}" != yes || "$*" != *' dev-upstream apply '* ]]; }}
{_function('attest_dev_user_sudoers')}
attest_dev_user_sudoers
"""
    accepted = _run_bash(tmp_path, body)
    assert accepted.returncode == 0, accepted.stderr
    rejected = subprocess.run(
        ["bash", str(tmp_path / "contract.sh")],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "DENY_APPLY": "yes", "PATH": os.environ.get("PATH", "")},
    )
    assert rejected.returncode == 9
    assert "developer grant is not effective: atelier dev-upstream apply" in rejected.stderr
