from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Any

import pytest

try:
    import pwd
except ImportError:  # pragma: no cover - exercised by Windows collection
    pwd = None  # type: ignore[assignment]


INSTALL = Path("install.sh").read_text(encoding="utf-8")
ACTIVATION_HELPER = Path("scripts/activation_transaction.py").resolve()
ACTIVATION_COMMIT = "b" * 40
LEGACY_RESTRICTIVE_UMASK_REF = "443c5fdaac231a1c62d4a927ca93e19d055e400a"
SYSTEMD_TUPLE_SHOW = (
    "show --property=LoadState --property=ActiveState --property=SubState "
    "--property=MainPID --property=Job broker.service"
)


def _function(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _function_block(name: str, next_name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index(f"\n{next_name}() {{", start)
    return INSTALL[start:end] + "\n"


def test_validate_install_root_named_block_is_complete_and_syntax_valid(
    tmp_path: Path,
) -> None:
    body = _function_block("validate_install_root", "with_install_lock")
    assert body.startswith("validate_install_root() {")
    assert body.rstrip().endswith("}")
    assert body.count("<<'PY'") == 1
    assert body.count("\nPY\n") == 1

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required for extracted shell syntax validation")
    script = tmp_path / "validate-install-root.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n" + body,
        encoding="utf-8",
        newline="\n",
    )
    completed = subprocess.run(
        [bash, "-n", str(script)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr


def test_exact_legacy_identity_named_block_is_complete_and_syntax_valid(
    tmp_path: Path,
) -> None:
    body = _function_block(
        "exact_preexisting_unrunnable_cli_baseline_identity",
        "attest_exact_preexisting_unrunnable_cli_baseline",
    )
    assert body.startswith("exact_preexisting_unrunnable_cli_baseline_identity() {")
    assert body.rstrip().endswith("}")
    assert body.count("<<'PY'") == 1
    assert body.count("\nPY\n") == 1

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required for extracted shell syntax validation")
    script = tmp_path / "exact-legacy-identity.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n" + body,
        encoding="utf-8",
        newline="\n",
    )
    completed = subprocess.run(
        [bash, "-n", str(script)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr


def _reader() -> Any:
    if pwd is None or os.name != "posix" or os.geteuid() != 0:
        pytest.skip("root POSIX ownership semantics are required")
    name = os.environ.get("SUDO_USER", "")
    if not name or name == "root":
        if os.environ.get("CI") == "true" and os.name == "posix" and os.geteuid() == 0:
            pytest.fail("Linux CI must provide a distinct SUDO_USER for ownership tests")
        pytest.skip("a distinct SUDO_USER reader is required")
    reader = pwd.getpwnam(name)
    assert reader.pw_uid != 0
    return reader


@contextmanager
def _root_temp(reader: Any):
    root = Path(tempfile.mkdtemp(prefix="ops-venv-contract.", dir="/tmp"))
    try:
        os.chown(root, 0, reader.pw_gid)
        root.chmod(0o750)
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _chown_tree(path: Path, gid: int) -> None:
    for candidate in [path, *path.rglob("*")]:
        os.chown(candidate, 0, gid, follow_symlinks=False)


def _as_reader(reader: Any, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/usr/sbin/runuser",
            "-u",
            reader.pw_name,
            "--",
            "/usr/bin/env",
            "-i",
            f"HOME={reader.pw_dir}",
            f"USER={reader.pw_name}",
            f"LOGNAME={reader.pw_name}",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            *argv,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _run_normalizer(tree: Path, *, path: str | None = None) -> subprocess.CompletedProcess[str]:
    script = tree.parent / "normalize.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        + _function("normalize_generated_runtime_tree_permissions")
        + "\nnormalize_generated_runtime_tree_permissions \"$1\"\n",
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(0o700)
    return subprocess.run(
        ["/usr/bin/bash", str(script), str(tree)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": path or os.environ.get("PATH", "")},
        timeout=5,
    )


def _run_contract_script(
    root: Path, body: str
) -> subprocess.CompletedProcess[str]:
    script = root / "contract.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n" + body,
        encoding="utf-8",
        newline="\n",
    )
    script.chmod(0o700)
    return subprocess.run(
        ["/usr/bin/bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": "/usr/local/bin:/usr/bin:/bin"},
        timeout=10,
    )


def test_restrictive_umask_tree_becomes_group_executable_and_world_denied() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        old_umask = os.umask(0o077)
        try:
            tree = root / ".venv"
            binary = tree / "bin" / "opsctl"
            data = tree / "lib" / "receipt.json"
            binary.parent.mkdir(parents=True)
            data.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\nprintf 'svcops-cli-ok\\n'\n", encoding="utf-8")
            binary.chmod(0o700)
            data.write_text("{}\n", encoding="utf-8")
        finally:
            os.umask(old_umask)
        _chown_tree(tree, reader.pw_gid)

        denied = _as_reader(reader, [str(binary)])
        assert denied.returncode != 0

        completed = _run_normalizer(tree)
        assert completed.returncode == 0, completed.stderr
        for directory in (tree, tree / "bin", tree / "lib"):
            meta = directory.lstat()
            assert meta.st_uid == 0
            assert meta.st_gid == reader.pw_gid
            assert stat.S_IMODE(meta.st_mode) == 0o750
        assert stat.S_IMODE(binary.lstat().st_mode) == 0o750
        assert stat.S_IMODE(data.lstat().st_mode) == 0o640
        assert not any(
            stat.S_IMODE(candidate.lstat().st_mode) & 0o007
            for candidate in (tree, tree / "bin", tree / "lib", binary, data)
        )
        allowed = _as_reader(reader, [str(binary)])
        assert allowed.returncode == 0, allowed.stderr
        assert allowed.stdout == "svcops-cli-ok\n"


def test_normalizer_does_not_follow_external_symlink() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = root / ".venv"
        tree.mkdir(mode=0o700)
        external = root / "system-python"
        external.write_text("external\n", encoding="utf-8")
        external.chmod(0o711)
        os.chown(external, 0, 0)
        link = tree / "python"
        link.symlink_to(external)
        _chown_tree(tree, reader.pw_gid)
        before = external.lstat()

        completed = _run_normalizer(tree)
        assert completed.returncode == 0, completed.stderr
        after = external.lstat()
        assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        assert link.is_symlink()


def test_normalizer_rejects_special_nodes_and_chmod_failure() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = root / ".venv"
        tree.mkdir(mode=0o700)
        fifo = tree / "unexpected.fifo"
        os.mkfifo(fifo, mode=0o600)
        _chown_tree(tree, reader.pw_gid)
        special = _run_normalizer(tree)
        assert special.returncode != 0

        fifo.unlink()
        (tree / "bin").mkdir(mode=0o700)
        fake_bin = root / "fake-bin"
        fake_bin.mkdir(mode=0o755)
        fake_chmod = fake_bin / "chmod"
        fake_chmod.write_text("#!/bin/sh\nexit 19\n", encoding="utf-8")
        fake_chmod.chmod(0o755)
        # find and the shell remain the real fixed executables; only the
        # chmod subprocess that find dispatches is fault-injected.
        failed = _run_normalizer(
            tree, path=f"{fake_bin}:/usr/local/bin:/usr/bin:/bin"
        )
        assert failed.returncode != 0


def _activation_fixture(reader: Any, root: Path, *, previous: bool = False) -> dict[str, Any]:
    install_root = root / "install"
    releases = install_root / "releases"
    bin_dir = root / "bin"
    for directory in (install_root, releases, bin_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, 0, reader.pw_gid)
        directory.chmod(0o750)
    candidate = releases / f"{ACTIVATION_COMMIT}.20260730000000.1234"
    candidate.mkdir()
    os.chown(candidate, 0, reader.pw_gid)
    candidate.chmod(0o750)
    candidate_dir = install_root / ".activation-candidate.prepare"
    candidate_dir.mkdir(mode=0o700)
    os.chown(candidate_dir, 0, 0)
    payloads = {
        "opsctl": b"#!/bin/sh\nexec candidate-opsctl\n",
        "mcp": b"#!/bin/sh\nexec candidate-mcp\n",
        "gemini": b"#!/bin/sh\n# agent-runtime-ops managed gemini wrapper\n",
        "broker-unit": b"[Service]\nEnvironment=AGENT_RUNTIME_OPS_RELEASE=candidate\n",
        "manifest-target": b"current/.agent-runtime-ops-manifest\n",
        "current-target": f"releases/{candidate.name}\n".encode(),
    }
    for name, data in payloads.items():
        path = candidate_dir / name
        path.write_bytes(data)
        os.chown(path, 0, 0)
        path.chmod(0o600)
    paths = {
        "opsctl": bin_dir / "opsctl",
        "mcp": bin_dir / "agent-runtime-ops-mcp",
        "gemini": bin_dir / "gemini",
        "manifest": install_root / ".agent-runtime-ops-manifest",
        "current": install_root / "current",
    }
    broker_unit = root / "agent-runtime-root-action-broker.service"
    previous_release: Path | None = None
    broker_state = "absent"
    if previous:
        previous_release = releases / f"{'a' * 40}.20260729000000.1234"
        previous_release.mkdir()
        os.chown(previous_release, 0, reader.pw_gid)
        previous_release.chmod(0o750)
        for name in ("opsctl", "mcp", "gemini"):
            path = paths[name]
            path.write_bytes(f"previous-{name}\n".encode())
            os.chown(path, 0, reader.pw_gid)
            path.chmod(0o755)
        os.symlink("current/.agent-runtime-ops-manifest", paths["manifest"])
        os.lchown(paths["manifest"], 0, reader.pw_gid)
        os.symlink(f"releases/{previous_release.name}", paths["current"])
        os.lchown(paths["current"], 0, reader.pw_gid)
        broker_unit.write_text("previous-broker-unit\n", encoding="utf-8")
        os.chown(broker_unit, 0, 0)
        broker_unit.chmod(0o644)
        broker_state = "inactive"
    return {
        "install_root": install_root,
        "releases": releases,
        "candidate": candidate,
        "candidate_dir": candidate_dir,
        "previous": previous_release,
        "paths": paths,
        "broker_unit": broker_unit,
        "broker_state": broker_state,
        "ops_gid": reader.pw_gid,
        "tx": install_root / ".activation-transaction.pending",
    }


def _legacy_gemini_wrapper(current: Path, ops_user: str, gemini_home: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "# agent-runtime-ops managed gemini wrapper\n"
        f'OPS_USER="{ops_user}"\n'
        f'GEMINI_ENV="${{AGENT_RUNTIME_GEMINI_ENV:-{gemini_home}/.env}}"\n'
        'if [[ -r "$GEMINI_ENV" ]]; then\n'
        "  set -a\n"
        "  # shellcheck disable=SC1090\n"
        '  . "$GEMINI_ENV"\n'
        "  set +a\n"
        "fi\n"
        'if [[ "$(id -un 2>/dev/null || true)" == "$OPS_USER" ]]; then\n'
        '  export GEMINI_CLI_TRUST_WORKSPACE="${GEMINI_CLI_TRUST_WORKSPACE:-true}"\n'
        "  skip_agent_runtime_mcp_default=0\n"
        '  for arg in "$@"; do\n'
        '    case "$arg" in\n'
        "      --)\n"
        "        break\n"
        "        ;;\n"
        "      mcp|extensions|extension|skills|skill|hooks|hook|gemma)\n"
        "        skip_agent_runtime_mcp_default=1\n"
        "        ;;\n"
        "    esac\n"
        "  done\n"
        "  has_allowed_mcp=0\n"
        '  for arg in "$@"; do\n'
        '    case "$arg" in\n'
        "      --allowed-mcp-server-names|--allowed-mcp-server-names=*)\n"
        "        has_allowed_mcp=1\n"
        "        ;;\n"
        "    esac\n"
        "  done\n"
        '  if [[ "$skip_agent_runtime_mcp_default" -eq 0 '
        '&& "$has_allowed_mcp" -eq 0 ]]; then\n'
        '    set -- --allowed-mcp-server-names agent-runtime-ops "$@"\n'
        "  fi\n"
        "fi\n"
        f'exec "{current}/agent-clis/gemini-cli/node_modules/.bin/gemini" "$@"\n'
    )


def _fixture_source_projection(release: Path) -> tuple[str, int, int, int]:
    rows: list[str] = []
    source_files = 0
    source_dirs = 0
    source_bytes = 0
    generated_roots = {
        ".venv",
        "agent-clis/gemini-cli/node_modules",
        "build",
        "opsctl/agent_runtime_ops.egg-info",
    }

    def visit(directory: Path, relative: str) -> None:
        nonlocal source_files, source_dirs, source_bytes
        for entry in sorted(os.scandir(directory), key=lambda value: value.name):
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            if not relative and entry.name == ".agent-runtime-ops-manifest":
                continue
            if child_relative in generated_roots or entry.name == "__pycache__":
                continue
            path = Path(entry.path)
            meta = os.lstat(path)
            if stat.S_ISDIR(meta.st_mode) and not stat.S_ISLNK(meta.st_mode):
                assert stat.S_IMODE(meta.st_mode) == 0o755
                rows.append("\0".join(("D", child_relative, "0755")))
                source_dirs += 1
                visit(path, child_relative)
                continue
            assert stat.S_ISREG(meta.st_mode) and not stat.S_ISLNK(meta.st_mode)
            expected_mode = 0o755 if child_relative == "install.sh" else 0o644
            assert stat.S_IMODE(meta.st_mode) == expected_mode
            payload = path.read_bytes()
            rows.append(
                "\0".join(
                    (
                        "F",
                        child_relative,
                        f"{expected_mode:04o}",
                        hashlib.sha256(payload).hexdigest(),
                    )
                )
            )
            source_files += 1
            source_bytes += len(payload)

    visit(release, "")
    rows.sort()
    digest = hashlib.sha256("\0".join(rows).encode("utf-8")).hexdigest()
    return digest, source_files, source_dirs, source_bytes


def _legacy_unrunnable_fixture(reader: Any, root: Path) -> dict[str, Any]:
    install_root = root / "legacy-install"
    releases = install_root / "releases"
    state_root = root / "state"
    bin_dir = root / "legacy-bin"
    for directory, mode in (
        (install_root, 0o755),
        (releases, 0o755),
        (state_root, 0o750),
        (bin_dir, 0o755),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        os.chown(directory, 0, reader.pw_gid)
        directory.chmod(mode)

    release = releases / f"{LEGACY_RESTRICTIVE_UMASK_REF}.20260730095851.891379"
    release.mkdir()
    os.chown(release, 0, reader.pw_gid)
    release.chmod(0o755)
    source_payloads = {
        "install.sh": b"#!/usr/bin/env bash\nset -euo pipefail\n",
        "README.md": b"synthetic legacy source projection fixture\n",
        "opsctl/agent_runtime_ops/cli.py": b"def main():\n    return 0\n",
        "agent-clis/gemini-cli/package.json": (
            b'{"dependencies":{"@google/gemini-cli":"0.45.2"}}\n'
        ),
        "agent-clis/gemini-cli/package-lock.json": (
            b'{"lockfileVersion":3,"packages":{"node_modules/@google/'
            b'gemini-cli":{"integrity":"sha512-fixture","version":"0.45.2"}}}\n'
        ),
    }
    for relative, payload in source_payloads.items():
        target = release / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    for path in [release, *release.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o755 if path == release / "install.sh" else 0o644)
    _chown_tree(release, reader.pw_gid)
    current = install_root / "current"
    manifest_link = install_root / ".agent-runtime-ops-manifest"
    os.symlink(f"releases/{release.name}", current)
    os.symlink("current/.agent-runtime-ops-manifest", manifest_link)
    os.lchown(current, 0, reader.pw_gid)
    os.lchown(manifest_link, 0, reader.pw_gid)

    wrappers = {
        "opsctl": bin_dir / "opsctl",
        "mcp": bin_dir / "agent-runtime-ops-mcp",
        "gemini": bin_dir / "gemini",
    }
    wrappers["opsctl"].write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec "{current}/.venv/bin/opsctl" "$@"\n',
        encoding="utf-8",
    )
    wrappers["mcp"].write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec "{current}/.venv/bin/agent-runtime-ops-mcp" "$@"\n',
        encoding="utf-8",
    )
    wrappers["gemini"].write_text(
        _legacy_gemini_wrapper(current, reader.pw_name, reader.pw_dir),
        encoding="utf-8",
    )
    for wrapper in wrappers.values():
        os.chown(wrapper, 0, reader.pw_gid)
        wrapper.chmod(0o755)

    venv = release / ".venv"
    venv_bin = venv / "bin"
    venv_bin.mkdir(parents=True)
    inner_opsctl = venv_bin / "opsctl"
    inner_mcp = venv_bin / "agent-runtime-ops-mcp"
    entrypoint = (
        f"#!{venv}/bin/python3\n"
        "# -*- coding: utf-8 -*-\n"
        "import re\n"
        "import sys\n"
        "if __name__ == '__main__':\n"
        "    from {module} import main\n"
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        "    sys.exit(main())\n"
    )
    inner_opsctl.write_text(
        entrypoint.format(module="agent_runtime_ops.cli"), encoding="utf-8"
    )
    inner_mcp.write_text(
        entrypoint.format(module="agent_runtime_ops.mcp_server"), encoding="utf-8"
    )
    node_modules = release / "agent-clis" / "gemini-cli" / "node_modules"
    gemini_package_dir = node_modules / "@google" / "gemini-cli"
    gemini_bundle = gemini_package_dir / "bundle" / "gemini.js"
    gemini_bundle.parent.mkdir(parents=True)
    gemini_bundle.write_text(
        "#!/usr/bin/env node\nconsole.log('fixture gemini');\n", encoding="utf-8"
    )
    gemini_package = gemini_package_dir / "package.json"
    gemini_package.write_text(
        json.dumps(
            {
                "name": "@google/gemini-cli",
                "version": "0.45.2",
                "bin": {"gemini": "bundle/gemini.js"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    gemini_bin_dir = node_modules / ".bin"
    gemini_bin_dir.mkdir(parents=True)
    inner_gemini = gemini_bin_dir / "gemini"
    inner_gemini.symlink_to("../@google/gemini-cli/bundle/gemini.js")
    for path in (venv, venv_bin):
        os.chown(path, 0, reader.pw_gid)
        path.chmod(0o700)
    for path in (inner_opsctl, inner_mcp):
        os.chown(path, 0, reader.pw_gid)
        path.chmod(0o755)
    _chown_tree(node_modules, reader.pw_gid)
    for path in [node_modules, *node_modules.rglob("*")]:
        if path.is_symlink():
            os.lchown(path, 0, reader.pw_gid)
        elif path.is_dir():
            path.chmod(0o700)
        elif path == gemini_bundle:
            path.chmod(0o700)
        else:
            path.chmod(0o600)

    ops_group = "fixture-ops"
    release_manifest = release / ".agent-runtime-ops-manifest"
    release_manifest.write_text(
        "\n".join(
            (
                f"source_commit={LEGACY_RESTRICTIVE_UMASK_REF}",
                "source_summary=Merge pull request #71 from Epicevent/"
                "codex/kwrag-legacy-backup-collision-recovery",
                "installed_at=2026-07-30T09:58:51+09:00",
                f"installed_dir={release}",
                f"install_root={install_root}",
                f"ops_user={reader.pw_name}",
                f"ops_group={ops_group}",
                f"state_root={state_root}",
                f"opsctl={wrappers['opsctl']}",
                f"mcp={wrappers['mcp']}",
                "source_path=/root/agent-runtime-ops",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    os.chown(release_manifest, 0, reader.pw_gid)
    release_manifest.chmod(0o644)

    policy = state_root / "ops-update.yaml"
    policy.write_text(
        "meta:\n"
        "  schema_version: 1\n"
        "updates:\n"
        "  agent-runtime-ops:\n"
        "    repo_url: https://github.com/Epicevent/agent-runtime-ops.git\n"
        f"    approved_ref: {ACTIVATION_COMMIT}\n",
        encoding="utf-8",
    )
    os.chown(policy, 0, reader.pw_gid)
    policy.chmod(0o640)
    source_projection, source_files, source_dirs, source_bytes = (
        _fixture_source_projection(release)
    )
    return {
        "install_root": install_root,
        "releases": releases,
        "state_root": state_root,
        "release": release,
        "current": current,
        "manifest_link": manifest_link,
        "release_manifest": release_manifest,
        "policy": policy,
        "wrappers": wrappers,
        "venv": venv,
        "venv_bin": venv_bin,
        "inner_opsctl": inner_opsctl,
        "inner_mcp": inner_mcp,
        "inner_gemini": inner_gemini,
        "gemini_package": gemini_package,
        "gemini_bundle": gemini_bundle,
        "node_modules": node_modules,
        "ops_group": ops_group,
        "source_projection": source_projection,
        "source_files": source_files,
        "source_dirs": source_dirs,
        "source_bytes": source_bytes,
    }


def _legacy_fixture_snapshot(tree: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    paths = (
        tree["install_root"],
        tree["state_root"],
        *tree["wrappers"].values(),
    )
    return {str(path): _path_fingerprint(path) for path in paths}


def _validate_install_paths(tree: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    paths = tree["paths"]
    return _run_contract_script(
        tree["install_root"].parent,
        f"INSTALL_ROOT={str(tree['install_root'])!r}\n"
        f"RELEASES_DIR={str(tree['releases'])!r}\n"
        f"CURRENT_LINK={str(paths['current'])!r}\n"
        f"ACTIVATION_TRANSACTION_DIR={str(tree['tx'])!r}\n"
        f"ACTIVATION_CANDIDATE_DIR={str(tree['candidate_dir'])!r}\n"
        f"BIN_LINK={str(paths['opsctl'])!r}\n"
        f"MCP_BIN_LINK={str(paths['mcp'])!r}\n"
        f"GEMINI_BIN_LINK={str(paths['gemini'])!r}\n"
        f"MANIFEST={str(paths['manifest'])!r}\n"
        f"ROOT_ACTION_BROKER_SERVICE_FILE={str(tree['broker_unit'])!r}\n"
        "die() { exit 23; }\n"
        + _function("require_canonical_absolute_path_string")
        + _function("validate_activation_path_strings")
        + _function_block("validate_install_root", "with_install_lock")
        + "\nvalidate_install_root\n",
    )


def test_shell_activation_path_gate_accepts_canonical_protected_layout() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        completed = _validate_install_paths(tree)
        assert completed.returncode == 0, completed.stderr
        assert not os.path.lexists(tree["tx"])


@pytest.mark.parametrize("invalid", ("symlink-dotdot", "sticky-immediate-parent"))
def test_shell_activation_path_gate_rejects_ambiguous_or_raceable_path(
    invalid: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        if invalid == "sticky-immediate-parent":
            tree["paths"]["mcp"] = Path("/tmp") / f"{root.name}.direct-shell-mcp"
        else:
            actual_parent = root / "attacker-parent" / "target"
            actual_parent.mkdir(parents=True, mode=0o750)
            os.chown(actual_parent.parent, 0, reader.pw_gid)
            os.chown(actual_parent, 0, reader.pw_gid)
            actual_parent.parent.chmod(0o750)
            actual_parent.chmod(0o750)
            linked_parent = root / "attacker-link"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            tree["paths"]["mcp"] = (
                linked_parent / ".." / "bin" / "agent-runtime-ops-mcp"
            )
        completed = _validate_install_paths(tree)
        assert completed.returncode == 23
        assert not os.path.lexists(tree["tx"])


def _tx_argv(tree: dict[str, Any], command: str, *extra: str) -> list[str]:
    paths = tree["paths"]
    return [
        sys.executable,
        str(ACTIVATION_HELPER),
        command,
        "--transaction-dir", str(tree["tx"]),
        "--ops-gid", str(tree["ops_gid"]),
        "--opsctl-link", str(paths["opsctl"]),
        "--mcp-link", str(paths["mcp"]),
        "--gemini-link", str(paths["gemini"]),
        "--manifest-link", str(paths["manifest"]),
        "--current-link", str(paths["current"]),
        "--broker-unit", str(tree["broker_unit"]),
        *extra,
    ]


def _run_tx(tree: dict[str, Any], command: str, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _tx_argv(tree, command, *extra),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _fault_injected_tx_argv(
    tree: dict[str, Any], child: str, command: str, *extra: str
) -> list[str]:
    transaction = _tx_argv(tree, command, *extra)
    return [transaction[0], "-c", child, *transaction[1:]]


def test_fault_injected_argv_preserves_helper_and_command_positions() -> None:
    tree = {
        "tx": Path("/install/.activation-transaction.pending"),
        "ops_gid": 1234,
        "paths": {
            "opsctl": Path("/bin/opsctl"),
            "mcp": Path("/bin/mcp"),
            "gemini": Path("/bin/gemini"),
            "manifest": Path("/install/.agent-runtime-ops-manifest"),
            "current": Path("/install/current"),
        },
        "broker_unit": Path("/etc/systemd/system/broker.service"),
    }
    argv = _fault_injected_tx_argv(tree, "child-code", "recover")
    assert argv[:5] == [
        sys.executable,
        "-c",
        "child-code",
        str(ACTIVATION_HELPER),
        "recover",
    ]


def _begin(tree: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    previous = tree["previous"]
    return _run_tx(
        tree,
        "begin",
        "--install-root", str(tree["install_root"]),
        "--releases-dir", str(tree["releases"]),
        "--candidate-dir", str(tree["candidate_dir"]),
        "--candidate-release", str(tree["candidate"]),
        "--candidate-commit", ACTIVATION_COMMIT,
        "--previous-release", str(previous) if previous is not None else "",
        "--broker-service-name", tree["broker_unit"].name,
        "--broker-state", tree["broker_state"],
    )


def _path_fingerprint(path: Path) -> tuple[Any, ...]:
    if not os.path.lexists(path):
        return ("absent",)
    meta = os.lstat(path)
    common = (
        meta.st_dev,
        meta.st_ino,
        stat.S_IFMT(meta.st_mode),
        stat.S_IMODE(meta.st_mode),
        meta.st_uid,
        meta.st_gid,
        meta.st_nlink,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    )
    if stat.S_ISREG(meta.st_mode):
        return ("regular", *common, hashlib.sha256(path.read_bytes()).hexdigest())
    if stat.S_ISLNK(meta.st_mode):
        return ("symlink", *common, os.readlink(path))
    if stat.S_ISDIR(meta.st_mode):
        children = tuple(
            (entry.name, _path_fingerprint(Path(entry.path)))
            for entry in sorted(os.scandir(path), key=lambda value: value.name)
        )
        return ("directory", *common, children)
    return ("special", *common)


def _activation_state_snapshot(tree: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    live = [*tree["paths"].values(), tree["broker_unit"]]
    journal = [
        tree["candidate_dir"],
        tree["tx"],
        Path(f"{tree['tx']}.new"),
        Path(f"{tree['tx']}.complete"),
        Path(f"{tree['tx']}.recovered.complete"),
        Path(f"{tree['tx']}.recovered.acknowledged"),
        Path(f"{tree['tx']}.recovered.retired"),
    ]
    temps = [Path(f"{path}.agent-runtime-activation-next") for path in live]
    return {
        str(path): _path_fingerprint(path)
        for path in (*live, *journal, *temps)
    }


def _legacy_capture_body(reader: Any, tree: dict[str, Any]) -> str:
    wrappers = tree["wrappers"]
    return (
        f"PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n"
        f"INSTALL_ROOT={str(tree['install_root'])!r}\n"
        f"RELEASES_DIR={str(tree['releases'])!r}\n"
        f"CURRENT_LINK={str(tree['current'])!r}\n"
        f"BIN_LINK={str(wrappers['opsctl'])!r}\n"
        f"MCP_BIN_LINK={str(wrappers['mcp'])!r}\n"
        f"GEMINI_BIN_LINK={str(wrappers['gemini'])!r}\n"
        f"MANIFEST={str(tree['manifest_link'])!r}\n"
        f"STATE_ROOT={str(tree['state_root'])!r}\n"
        f"OPS_USER={reader.pw_name!r}\n"
        f"OPS_GROUP={tree['ops_group']!r}\n"
        f"OPS_HOME={reader.pw_dir!r}\n"
        f"GEMINI_HOME={reader.pw_dir!r}\n"
        "OPS_CLI_ATTESTATION_COMMAND_TIMEOUT_SECONDS=2\n"
        "REPO_URL='https://github.com/Epicevent/agent-runtime-ops.git'\n"
        f"LEGACY_RESTRICTIVE_UMASK_BASELINE_REF={LEGACY_RESTRICTIVE_UMASK_REF!r}\n"
        f"LEGACY_RESTRICTIVE_UMASK_SOURCE_PROJECTION_SHA256={tree['source_projection']!r}\n"
        f"LEGACY_RESTRICTIVE_UMASK_SOURCE_FILE_COUNT={tree['source_files']}\n"
        f"LEGACY_RESTRICTIVE_UMASK_SOURCE_DIR_COUNT={tree['source_dirs']}\n"
        f"LEGACY_RESTRICTIVE_UMASK_SOURCE_BYTE_COUNT={tree['source_bytes']}\n"
        "RESTORED_CLI_RESULT=''\n"
        "die() { printf 'error:%s\\n' \"$*\" >&2; exit 23; }\n"
        + _function("manifest_value")
        + _function("run_cli_as_ops")
        + _function("path_is_not_executable_as_ops")
        + _function("validate_update_status_output")
        + _function("attest_restored_cli_as_ops")
        + _function("legacy_restrictive_umask_baseline_is_shaped")
        + _function_block(
            "exact_preexisting_unrunnable_cli_baseline_identity",
            "attest_exact_preexisting_unrunnable_cli_baseline",
        )
        + _function("attest_exact_preexisting_unrunnable_cli_baseline")
        + _function("attest_restored_cli_or_exact_preexisting_unrunnable")
        + _function("capture_previous_active_release")
        + f"\ncapture_previous_active_release {ACTIVATION_COMMIT}\n"
    )


def test_exact_legacy_0700_baseline_is_admitted_without_mutation() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        assert stat.S_IMODE(tree["venv"].stat().st_mode) == 0o700
        assert stat.S_IMODE(tree["venv_bin"].stat().st_mode) == 0o700
        assert stat.S_IMODE(tree["inner_opsctl"].stat().st_mode) == 0o755
        assert stat.S_IMODE(tree["inner_mcp"].stat().st_mode) == 0o755
        assert stat.S_IMODE(tree["gemini_package"].stat().st_mode) == 0o600
        assert stat.S_IMODE(tree["gemini_bundle"].stat().st_mode) == 0o700
        denied = _as_reader(reader, [str(tree["inner_opsctl"])])
        assert denied.returncode == 126
        before = _legacy_fixture_snapshot(tree)
        completed = _run_contract_script(root, _legacy_capture_body(reader, tree))
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout == f"{tree['release']}\n"
        assert (
            "previous_active_cli_state="
            "restored_exact_but_preexisting_unrunnable\n"
            in completed.stderr
        )
        assert _legacy_fixture_snapshot(tree) == before


def test_legacy_shaped_altered_wrapper_never_executes_before_rejection() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        trace_dir = root / "reader-trace"
        trace_dir.mkdir()
        os.chown(trace_dir, reader.pw_uid, reader.pw_gid)
        trace_dir.chmod(0o700)
        sentinel = trace_dir / "altered-wrapper-executed"
        tree["wrappers"]["opsctl"].write_text(
            "#!/usr/bin/env bash\n"
            f"printf 'executed\\n' > {str(sentinel)!r}\n"
            "exit 126\n",
            encoding="utf-8",
        )
        os.chown(tree["wrappers"]["opsctl"], 0, reader.pw_gid)
        tree["wrappers"]["opsctl"].chmod(0o755)
        before = _legacy_fixture_snapshot(tree)
        completed = _run_contract_script(root, _legacy_capture_body(reader, tree))
        assert completed.returncode != 0
        assert not sentinel.exists()
        assert _legacy_fixture_snapshot(tree) == before


def test_exact_legacy_0700_recovery_finalizes_with_honest_degraded_state() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        wrappers = tree["wrappers"]
        trace = root / "legacy-recovery-trace"
        body = (
            f"PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'\n"
            f"TRACE={str(trace)!r}\n"
            f"INSTALL_ROOT={str(tree['install_root'])!r}\n"
            f"RELEASES_DIR={str(tree['releases'])!r}\n"
            f"CURRENT_LINK={str(tree['current'])!r}\n"
            f"BIN_LINK={str(wrappers['opsctl'])!r}\n"
            f"MCP_BIN_LINK={str(wrappers['mcp'])!r}\n"
            f"GEMINI_BIN_LINK={str(wrappers['gemini'])!r}\n"
            f"MANIFEST={str(tree['manifest_link'])!r}\n"
            f"STATE_ROOT={str(tree['state_root'])!r}\n"
            f"OPS_USER={reader.pw_name!r}\n"
            f"OPS_GROUP={tree['ops_group']!r}\n"
            f"OPS_HOME={reader.pw_dir!r}\n"
            f"GEMINI_HOME={reader.pw_dir!r}\n"
            "OPS_CLI_ATTESTATION_COMMAND_TIMEOUT_SECONDS=2\n"
            "REPO_URL='https://github.com/Epicevent/agent-runtime-ops.git'\n"
            f"LEGACY_RESTRICTIVE_UMASK_BASELINE_REF={LEGACY_RESTRICTIVE_UMASK_REF!r}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_PROJECTION_SHA256={tree['source_projection']!r}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_FILE_COUNT={tree['source_files']}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_DIR_COUNT={tree['source_dirs']}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_BYTE_COUNT={tree['source_bytes']}\n"
            "RESTORED_CLI_RESULT=''\n"
            "quiesce_root_action_broker_before_recovery() { printf 'quiesce\\n' >>\"$TRACE\"; }\n"
            "run_activation_transaction() { printf 'tx:%s\\n' \"$2\" >>\"$TRACE\"; }\n"
            "restore_broker_service_from_transaction() { printf 'broker\\n' >>\"$TRACE\"; }\n"
            "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
            + _function("manifest_value")
            + _function("run_cli_as_ops")
            + _function("path_is_not_executable_as_ops")
            + _function("validate_update_status_output")
            + _function("attest_restored_cli_as_ops")
            + _function("legacy_restrictive_umask_baseline_is_shaped")
            + _function_block(
                "exact_preexisting_unrunnable_cli_baseline_identity",
                "attest_exact_preexisting_unrunnable_cli_baseline",
            )
            + _function("attest_exact_preexisting_unrunnable_cli_baseline")
            + _function("attest_restored_cli_or_exact_preexisting_unrunnable")
            + _function("recover_and_attest_activation_baseline")
            + f"\nrecover_and_attest_activation_baseline /helper {ACTIVATION_COMMIT} {str(tree['release'])!r}\n"
        )
        before = _legacy_fixture_snapshot(tree)
        completed = _run_contract_script(root, body)
        assert completed.returncode == 0, completed.stderr
        assert trace.read_text(encoding="utf-8").splitlines() == [
            "quiesce",
            "tx:recover",
            "broker",
            "info:ops_cli_restoration=restored_exact_but_preexisting_unrunnable",
            "tx:finalize",
        ]
        assert _legacy_fixture_snapshot(tree) == before


def test_exact_legacy_0700_baseline_reaches_real_candidate_svcops_attestation() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        candidate = root / "candidate"
        candidate_opsctl = candidate / ".venv" / "bin" / "opsctl"
        candidate_gemini = (
            candidate
            / "agent-clis"
            / "gemini-cli"
            / "node_modules"
            / ".bin"
            / "gemini"
        )
        candidate_opsctl.parent.mkdir(parents=True)
        candidate_gemini.parent.mkdir(parents=True)
        trace_dir = root / "candidate-reader-trace"
        trace_dir.mkdir()
        os.chown(trace_dir, reader.pw_uid, reader.pw_gid)
        trace_dir.chmod(0o700)
        opsctl_trace = trace_dir / "opsctl"
        gemini_trace = trace_dir / "gemini"
        candidate_opsctl.write_text(
            "#!/bin/sh\n"
            f"printf 'uid=%s\\nargv=%s\\n' \"$(id -u)\" \"$*\" > {str(opsctl_trace)!r}\n"
            "cat <<'EOF'\n"
            "update_status=ready\n"
            f"installed_ref={LEGACY_RESTRICTIVE_UMASK_REF}\n"
            "repo_url=https://github.com/Epicevent/agent-runtime-ops.git\n"
            f"approved_ref={ACTIVATION_COMMIT}\n"
            "approved_matches_installed=no\n"
            "EOF\n",
            encoding="utf-8",
        )
        candidate_gemini.write_text(
            "#!/bin/sh\n"
            f"printf 'uid=%s\\nargv=%s\\n' \"$(id -u)\" \"$*\" > {str(gemini_trace)!r}\n"
            "printf 'candidate-gemini-ok\\n'\n",
            encoding="utf-8",
        )
        for path in [candidate, *candidate.rglob("*")]:
            os.chown(path, 0, reader.pw_gid, follow_symlinks=False)
            path.chmod(0o750 if path.is_dir() or os.access(path, os.X_OK) else 0o640)
        candidate_opsctl.chmod(0o750)
        candidate_gemini.chmod(0o750)

        body = (
            _legacy_capture_body(reader, tree)
            + _function("normalize_generated_runtime_tree_permissions")
            + _function("attest_candidate_cli_as_ops")
            + _function("prepare_release_for_activation")
            + "info() { printf '%s\\n' \"$*\"; }\n"
            + f"\nprepare_release_for_activation {str(candidate)!r} {ACTIVATION_COMMIT}\n"
        )
        completed = _run_contract_script(root, body)
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.splitlines() == [
            str(tree["release"]),
            "ops_cli_pre_activation=svcops_verified",
        ]
        assert opsctl_trace.read_text(encoding="utf-8").splitlines() == [
            f"uid={reader.pw_uid}",
            f"argv=--state-root {tree['state_root']} update status",
        ]
        assert gemini_trace.read_text(encoding="utf-8").splitlines() == [
            f"uid={reader.pw_uid}",
            "argv=--version",
        ]


@pytest.mark.parametrize(
    "invalid",
    (
        "venv-mode",
        "venv-bin-symlink",
        "inner-hardlink",
        "wrapper-hardlink",
        "wrapper-owner",
        "policy-mismatch",
        "manifest-mismatch",
        "successor-gemini-body",
        "missing-inner-mcp",
        "replaced-inner-mcp",
        "appended-inner-mcp",
        "noncanonical-inner-opsctl-mode",
        "unsafe-inner-mcp-mode",
        "missing-gemini-link",
        "wrong-gemini-link-target",
        "unsafe-gemini-package-mode",
        "missing-gemini-bundle",
        "unsafe-gemini-bundle-mode",
        "source-projection-changed",
        "source-projection-extra",
    ),
)
def test_legacy_baseline_exception_rejects_unsafe_identity_without_writes(
    invalid: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        if invalid == "venv-mode":
            tree["venv"].chmod(0o750)
        elif invalid == "venv-bin-symlink":
            real_bin = tree["venv"] / "real-bin"
            tree["venv_bin"].rename(real_bin)
            tree["venv_bin"].symlink_to(real_bin, target_is_directory=True)
        elif invalid == "inner-hardlink":
            os.link(tree["inner_opsctl"], tree["venv_bin"] / "opsctl-copy")
        elif invalid == "wrapper-hardlink":
            os.link(tree["wrappers"]["opsctl"], root / "opsctl-copy")
        elif invalid == "wrapper-owner":
            os.chown(tree["wrappers"]["opsctl"], reader.pw_uid, reader.pw_gid)
        elif invalid == "policy-mismatch":
            tree["policy"].write_text(
                tree["policy"].read_text(encoding="utf-8").replace(
                    ACTIVATION_COMMIT, "c" * 40
                ),
                encoding="utf-8",
            )
            os.chown(tree["policy"], 0, reader.pw_gid)
            tree["policy"].chmod(0o640)
        elif invalid == "manifest-mismatch":
            tree["release_manifest"].write_text(
                tree["release_manifest"].read_text(encoding="utf-8").replace(
                    LEGACY_RESTRICTIVE_UMASK_REF, "a" * 40, 1
                ),
                encoding="utf-8",
            )
            os.chown(tree["release_manifest"], 0, reader.pw_gid)
            tree["release_manifest"].chmod(0o644)
        elif invalid == "successor-gemini-body":
            legacy = tree["wrappers"]["gemini"].read_text(encoding="utf-8")
            successor = legacy.replace(
                "      --)\n        break\n        ;;\n",
                "      --) break ;;\n",
            ).replace(
                "      mcp|extensions|extension|skills|skill|hooks|hook|gemma)\n"
                "        skip_agent_runtime_mcp_default=1\n"
                "        ;;\n",
                "      mcp|extensions|extension|skills|skill|hooks|hook|gemma) "
                "skip_agent_runtime_mcp_default=1 ;;\n",
            )
            tree["wrappers"]["gemini"].write_text(successor, encoding="utf-8")
            os.chown(tree["wrappers"]["gemini"], 0, reader.pw_gid)
            tree["wrappers"]["gemini"].chmod(0o755)
        elif invalid == "missing-inner-mcp":
            tree["inner_mcp"].unlink()
        elif invalid == "replaced-inner-mcp":
            tree["inner_mcp"].write_text(
                "#!/bin/sh\nprintf 'not-the-mcp-entrypoint\\n'\n", encoding="utf-8"
            )
            os.chown(tree["inner_mcp"], 0, reader.pw_gid)
            tree["inner_mcp"].chmod(0o755)
        elif invalid == "appended-inner-mcp":
            with tree["inner_mcp"].open("a", encoding="utf-8") as stream:
                stream.write("open('/tmp/unexpected-side-effect', 'w').close()\n")
        elif invalid == "noncanonical-inner-opsctl-mode":
            tree["inner_opsctl"].chmod(0o700)
        elif invalid == "unsafe-inner-mcp-mode":
            tree["inner_mcp"].chmod(0o775)
        elif invalid == "missing-gemini-link":
            tree["inner_gemini"].unlink()
        elif invalid == "wrong-gemini-link-target":
            tree["inner_gemini"].unlink()
            tree["inner_gemini"].symlink_to("../attacker/gemini.js")
            os.lchown(tree["inner_gemini"], 0, reader.pw_gid)
        elif invalid == "unsafe-gemini-package-mode":
            tree["gemini_package"].chmod(0o660)
        elif invalid == "missing-gemini-bundle":
            tree["gemini_bundle"].unlink()
        elif invalid == "unsafe-gemini-bundle-mode":
            tree["gemini_bundle"].chmod(0o775)
        elif invalid == "source-projection-changed":
            source = tree["release"] / "README.md"
            source.write_bytes(source.read_bytes() + b"\nchanged\n")
            os.chown(source, 0, reader.pw_gid)
            source.chmod(0o644)
        else:
            source = tree["release"] / "unexpected-source.txt"
            source.write_text("not part of 443\n", encoding="utf-8")
            os.chown(source, 0, reader.pw_gid)
            source.chmod(0o644)

        before = _legacy_fixture_snapshot(tree)
        completed = _run_contract_script(root, _legacy_capture_body(reader, tree))
        assert completed.returncode != 0
        assert _legacy_fixture_snapshot(tree) == before


@pytest.mark.parametrize("drift_key", ("release_manifest", "inner_mcp", "gemini_bundle"))
def test_legacy_baseline_identity_drift_during_nonexecuting_probe_is_rejected(
    drift_key: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _legacy_unrunnable_fixture(reader, root)
        wrappers = tree["wrappers"]
        body = (
            f"INSTALL_ROOT={str(tree['install_root'])!r}\n"
            f"RELEASES_DIR={str(tree['releases'])!r}\n"
            f"CURRENT_LINK={str(tree['current'])!r}\n"
            f"BIN_LINK={str(wrappers['opsctl'])!r}\n"
            f"MCP_BIN_LINK={str(wrappers['mcp'])!r}\n"
            f"GEMINI_BIN_LINK={str(wrappers['gemini'])!r}\n"
            f"MANIFEST={str(tree['manifest_link'])!r}\n"
            f"STATE_ROOT={str(tree['state_root'])!r}\n"
            f"OPS_USER={reader.pw_name!r}\n"
            f"OPS_GROUP={tree['ops_group']!r}\n"
            f"OPS_HOME={reader.pw_dir!r}\n"
            f"GEMINI_HOME={reader.pw_dir!r}\n"
            "REPO_URL='https://github.com/Epicevent/agent-runtime-ops.git'\n"
            f"LEGACY_RESTRICTIVE_UMASK_BASELINE_REF={LEGACY_RESTRICTIVE_UMASK_REF!r}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_PROJECTION_SHA256={tree['source_projection']!r}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_FILE_COUNT={tree['source_files']}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_DIR_COUNT={tree['source_dirs']}\n"
            f"LEGACY_RESTRICTIVE_UMASK_SOURCE_BYTE_COUNT={tree['source_bytes']}\n"
            f"DRIFT_PATH={str(tree[drift_key])!r}\n"
            "path_is_not_executable_as_ops() { "
            "local original_mode; original_mode=\"$(/usr/bin/stat -c %a -- \"$DRIFT_PATH\")\"; "
            "/usr/bin/chmod 0600 \"$DRIFT_PATH\"; "
            "/usr/bin/chmod \"$original_mode\" \"$DRIFT_PATH\"; return 0; }\n"
            + _function_block(
                "exact_preexisting_unrunnable_cli_baseline_identity",
                "attest_exact_preexisting_unrunnable_cli_baseline",
            )
            + _function("attest_exact_preexisting_unrunnable_cli_baseline")
            + f"\nattest_exact_preexisting_unrunnable_cli_baseline {str(tree['release'])!r} {ACTIVATION_COMMIT}\n"
        )
        completed = _run_contract_script(root, body)
        assert completed.returncode != 0


def _symlink_instance(path: Path) -> tuple[Any, ...]:
    meta = path.lstat()
    assert stat.S_ISLNK(meta.st_mode)
    return (
        meta.st_dev,
        meta.st_ino,
        os.readlink(path),
        meta.st_uid,
        meta.st_gid,
        stat.S_IMODE(meta.st_mode),
        meta.st_nlink,
    )


def test_activation_begin_rejects_negative_gid_without_writes() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        tree["ops_gid"] = -1
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


def test_activation_begin_preserves_preexisting_reserved_temp() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        reserved = Path(f"{tree['paths']['opsctl']}.agent-runtime-activation-next")
        reserved.write_bytes(b"unrelated-root-file")
        os.chown(reserved, 0, 0)
        reserved.chmod(0o600)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize("name", ("opsctl", "mcp", "gemini", "manifest", "current"))
def test_activation_first_install_dangling_entry_is_preserved_without_writes(name: str) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        path = tree["paths"][name]
        os.symlink("missing-target", path)
        os.lchown(path, 0, reader.pw_gid)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize("name", ("opsctl", "mcp", "gemini"))
def test_activation_previous_wrapper_hardlink_is_rejected_without_writes(name: str) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        extra = root / f"hardlink-{name}"
        os.link(tree["paths"][name], extra)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize(
    ("name", "kind"),
    (("opsctl", "directory"), ("manifest", "regular"), ("current", "fifo")),
)
def test_activation_wrong_managed_type_is_rejected_without_writes(name: str, kind: str) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        path = tree["paths"][name]
        path.unlink()
        if kind == "directory":
            path.mkdir()
        elif kind == "regular":
            path.write_text("wrong-type\n", encoding="utf-8")
        else:
            os.mkfifo(path)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize("wrong_axis", ("uid", "gid"))
def test_activation_wrong_previous_owner_is_rejected_without_writes(
    wrong_axis: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        uid = reader.pw_uid if wrong_axis == "uid" else 0
        gid = 0 if wrong_axis == "gid" else reader.pw_gid
        os.chown(tree["paths"]["opsctl"], uid, gid)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize("invalid", ("hardlink", "fifo", "directory", "uid", "gid"))
def test_activation_unsafe_broker_identity_is_rejected_without_writes(
    invalid: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        unit = tree["broker_unit"]
        if invalid == "hardlink":
            os.link(unit, root / "broker-hardlink")
        elif invalid == "fifo":
            unit.unlink()
            os.mkfifo(unit)
        elif invalid == "directory":
            unit.unlink()
            unit.mkdir()
        elif invalid == "uid":
            os.chown(unit, reader.pw_uid, 0)
        else:
            os.chown(unit, 0, reader.pw_gid)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


def test_activation_manifest_cross_field_gid_mismatch_fails_closed() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        manifest_path = tree["tx"] / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["entries"]["opsctl"]["candidate"]["gid"] = tree["ops_gid"] + 1
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        manifest_path.chmod(0o600)
        completed = _run_tx(tree, "show", "--field", "candidate_commit")
        assert completed.returncode != 0
        assert tree["paths"]["current"].resolve() == tree["previous"]


def test_activation_absolute_current_target_is_rejected_before_journal() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        current = tree["paths"]["current"]
        current.unlink()
        os.symlink(str(tree["previous"]), current)
        os.lchown(current, 0, reader.pw_gid)
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


@pytest.mark.parametrize(
    "overlap",
    (
        "alias",
        "staging-alias",
        "transaction",
        "manifest-outside",
        "writable-parent",
        "sticky-immediate-parent",
        "symlink-parent",
        "symlink-dotdot",
    ),
)
def test_activation_endpoint_overlap_is_rejected_without_writes(overlap: str) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        if overlap == "alias":
            tree["paths"]["mcp"] = tree["paths"]["opsctl"]
        elif overlap == "staging-alias":
            tree["paths"]["mcp"] = Path(
                f"{tree['paths']['opsctl']}.agent-runtime-activation-next"
            )
        elif overlap == "transaction":
            tree["paths"]["mcp"] = tree["tx"] / "managed-entry"
        elif overlap == "manifest-outside":
            tree["paths"]["manifest"] = root / "bin" / "manifest"
        elif overlap == "writable-parent":
            parent = root / "writable"
            parent.mkdir(mode=0o777)
            os.chown(parent, 0, 0)
            parent.chmod(0o777)
            tree["paths"]["mcp"] = parent / "agent-runtime-ops-mcp"
        elif overlap == "sticky-immediate-parent":
            tree["paths"]["mcp"] = Path("/tmp") / f"{root.name}.direct-mcp"
        elif overlap == "symlink-parent":
            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o750)
            os.chown(real_parent, 0, reader.pw_gid)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            tree["paths"]["mcp"] = linked_parent / "agent-runtime-ops-mcp"
        else:
            actual_parent = root / "attacker-parent" / "target"
            actual_parent.mkdir(parents=True, mode=0o750)
            os.chown(actual_parent.parent, 0, reader.pw_gid)
            os.chown(actual_parent, 0, reader.pw_gid)
            actual_parent.parent.chmod(0o750)
            actual_parent.chmod(0o750)
            linked_parent = root / "attacker-link"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            tree["paths"]["mcp"] = (
                linked_parent / ".." / "bin" / "agent-runtime-ops-mcp"
            )
        before = _activation_state_snapshot(tree)
        completed = _begin(tree)
        assert completed.returncode != 0
        assert _activation_state_snapshot(tree) == before


def test_activation_endpoint_parent_chain_accepts_protected_child_under_sticky_tmp() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        assert stat.S_IMODE(root.lstat().st_mode) & 0o022 == 0
        assert stat.S_IMODE(Path("/tmp").lstat().st_mode) & stat.S_ISVTX
        completed = _begin(tree)
        assert completed.returncode == 0, completed.stderr


def test_activation_recovery_is_terminal_and_cannot_republish() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        assert _run_tx(tree, "publish-broker").returncode == 0
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "publish").returncode != 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert tree["paths"]["current"].resolve() == tree["previous"]
        assert tree["broker_unit"].read_text(encoding="utf-8") == "previous-broker-unit\n"


def test_activation_first_install_valid_candidate_commits_without_residue() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root)
        assert _begin(tree).returncode == 0
        cleanup = subprocess.run(
            [
                sys.executable,
                str(ACTIVATION_HELPER),
                "cleanup-staging",
                "--install-root", str(tree["install_root"]),
                "--transaction-dir", str(tree["tx"]),
                "--candidate-dir", str(tree["candidate_dir"]),
                "--path", str(tree["candidate_dir"]),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert cleanup.returncode == 0, cleanup.stderr
        assert _run_tx(tree, "publish").returncode == 0
        assert _run_tx(tree, "publish-broker").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "candidate").returncode == 0
        assert tree["paths"]["current"].resolve() == tree["candidate"]
        for residue in (
            tree["tx"],
            Path(f"{tree['tx']}.new"),
            Path(f"{tree['tx']}.complete"),
            Path(f"{tree['tx']}.recovered.complete"),
            Path(f"{tree['tx']}.recovered.acknowledged"),
            Path(f"{tree['tx']}.recovered.retired"),
            tree["candidate_dir"],
        ):
            assert not os.path.lexists(residue)
        for path in (*tree["paths"].values(), tree["broker_unit"]):
            assert not os.path.lexists(Path(f"{path}.agent-runtime-activation-next"))


@pytest.mark.parametrize("kill_after", range(1, 5))
def test_activation_sigkill_each_divergent_publication_boundary_recovers_fresh_process(
    kill_after: int,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        managed = [str(tree["paths"][name]) for name in ("opsctl", "mcp", "gemini", "manifest", "current")]
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"managed=set({managed!r}); target={kill_after}; count=0; original=mod.os.replace\n"
            "def replace(src,dst):\n"
            " global count\n"
            " original(src,dst)\n"
            " if str(dst) in managed:\n"
            "  count += 1\n"
            "  if count == target: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.replace=replace\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(tree, child, "publish"),
            check=False, capture_output=True, text=True, timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert tree["paths"]["current"].resolve() == tree["previous"]


def test_activation_publish_preserves_identity_equal_manifest_inode() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        before_identity = _path_fingerprint(tree["paths"]["manifest"])
        before_instance = _symlink_instance(tree["paths"]["manifest"])
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        assert _path_fingerprint(tree["paths"]["manifest"]) == before_identity
        assert _symlink_instance(tree["paths"]["manifest"]) == before_instance
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0


@pytest.mark.parametrize("kill_after", range(1, 6))
def test_activation_sigkill_during_baseline_restore_is_replay_safe(kill_after: int) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        manifest_baseline = _path_fingerprint(tree["paths"]["manifest"])
        manifest_baseline_instance = _symlink_instance(tree["paths"]["manifest"])
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        assert _run_tx(tree, "publish-broker").returncode == 0
        managed = [
            str(tree["paths"][name])
            for name in ("opsctl", "mcp", "gemini", "manifest", "current")
        ] + [str(tree["broker_unit"])]
        # The manifest symlink has the same exact identity in both variants, so
        # recovery replaces the other four managed entries plus the broker unit.
        assert _path_fingerprint(tree["paths"]["manifest"]) == manifest_baseline
        published_manifest = _symlink_instance(tree["paths"]["manifest"])
        assert published_manifest == manifest_baseline_instance
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"managed=set({managed!r}); target={kill_after}; count=0; original=mod.os.replace\n"
            "def replace(src,dst):\n"
            " global count\n"
            " original(src,dst)\n"
            " if str(dst) in managed:\n"
            "  count += 1\n"
            "  if count == target: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.replace=replace\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(tree, child, "recover"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert _symlink_instance(tree["paths"]["manifest"]) == published_manifest
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert _symlink_instance(tree["paths"]["manifest"]) == published_manifest
        assert tree["paths"]["current"].resolve() == tree["previous"]
        assert tree["broker_unit"].read_text(encoding="utf-8") == "previous-broker-unit\n"


def test_activation_sigkill_after_broker_publication_recovers_unit() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"target={str(tree['broker_unit'])!r}; original=mod.os.replace\n"
            "def replace(src,dst):\n"
            " original(src,dst)\n"
            " if str(dst)==target: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.replace=replace\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(tree, child, "publish-broker"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert tree["broker_unit"].read_text(encoding="utf-8") == "previous-broker-unit\n"


@pytest.mark.parametrize("command", ("publish", "recover"))
def test_activation_sigkill_between_symlink_create_and_lchown_replays(
    command: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        manifest_instance = _symlink_instance(tree["paths"]["manifest"])
        assert _begin(tree).returncode == 0
        if command == "recover":
            assert _run_tx(tree, "publish").returncode == 0
        symlink_name = "current"
        symlink_temp = Path(
            f"{tree['paths'][symlink_name]}.agent-runtime-activation-next"
        )
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"target={str(symlink_temp)!r}\n"
            "original=mod.os.lchown\n"
            "def lchown(path,uid,gid):\n"
            " if str(path)==target: os.kill(os.getpid(), signal.SIGKILL)\n"
            " original(path,uid,gid)\n"
            "mod.os.lchown=lchown\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(tree, child, command),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert symlink_temp.is_symlink()
        assert symlink_temp.lstat().st_uid == 0
        assert symlink_temp.lstat().st_gid == 0
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert _symlink_instance(tree["paths"]["manifest"]) == manifest_instance
        assert tree["paths"]["current"].resolve() == tree["previous"]


def test_activation_partial_safe_temp_is_replayed_not_wedged() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        temp = Path(f"{tree['paths']['opsctl']}.agent-runtime-activation-next")
        partial = b"previous-"
        temp.write_bytes(partial)
        os.chown(temp, 0, 0)
        temp.chmod(0o600)
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0
        assert not temp.exists()
        assert tree["paths"]["opsctl"].read_bytes() == b"previous-opsctl\n"


def test_activation_kill_at_recovered_marker_is_terminal_and_replayable() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "publish").returncode == 0
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            "original=mod._write_file\n"
            "def write_file(path,data,**kwargs):\n"
            " original(path,data,**kwargs)\n"
            " if path.name=='recovered': os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod._write_file=write_file\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(tree, child, "recover"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert _run_tx(tree, "publish").returncode != 0
        assert _run_tx(tree, "recover").returncode == 0
        assert _run_tx(tree, "finalize", "--expect", "baseline").returncode == 0


def test_activation_finalize_rename_kill_leaves_restartable_complete_tombstone() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        tree = _activation_fixture(reader, root, previous=True)
        assert _begin(tree).returncode == 0
        assert _run_tx(tree, "recover").returncode == 0
        complete = Path(f"{tree['tx']}.recovered.complete")
        acknowledged = Path(f"{tree['tx']}.recovered.acknowledged")
        retired = Path(f"{tree['tx']}.recovered.retired")
        baseline = _activation_state_snapshot(tree)
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"pending={str(tree['tx'])!r}; complete={str(complete)!r}; original=mod.os.rename\n"
            "def rename(src,dst):\n"
            " original(src,dst)\n"
            " if str(src)==pending and str(dst)==complete: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.rename=rename\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed = subprocess.run(
            _fault_injected_tx_argv(
                tree, child, "finalize", "--expect", "baseline"
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed.returncode == -signal.SIGKILL
        assert not os.path.lexists(tree["tx"])
        assert complete.is_dir()
        wrong_commit = _run_tx(
            tree,
            "ack-recovered",
            "--expected-commit",
            "c" * 40,
        )
        assert wrong_commit.returncode != 0
        assert complete.is_dir()
        child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"complete={str(complete)!r}; acknowledged={str(acknowledged)!r}; original=mod.os.rename\n"
            "def rename(src,dst):\n"
            " original(src,dst)\n"
            " if str(src)==complete and str(dst)==acknowledged: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.rename=rename\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed_ack = subprocess.run(
            _fault_injected_tx_argv(
                tree,
                child,
                "ack-recovered",
                "--expected-commit",
                ACTIVATION_COMMIT,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed_ack.returncode == -signal.SIGKILL
        assert not os.path.lexists(complete)
        assert acknowledged.is_dir()
        retire_child = (
            "import importlib.util, os, signal, sys\n"
            f"spec=importlib.util.spec_from_file_location('tx', {str(ACTIVATION_HELPER)!r})\n"
            "mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
            f"acknowledged={str(acknowledged)!r}; retired={str(retired)!r}; original=mod.os.rename\n"
            "def rename(src,dst):\n"
            " original(src,dst)\n"
            " if str(src)==acknowledged and str(dst)==retired: os.kill(os.getpid(), signal.SIGKILL)\n"
            "mod.os.rename=rename\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(mod.main())\n"
        )
        killed_retire = subprocess.run(
            _fault_injected_tx_argv(
                tree,
                retire_child,
                "ack-recovered",
                "--expected-commit",
                ACTIVATION_COMMIT,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert killed_retire.returncode == -signal.SIGKILL
        assert not os.path.lexists(acknowledged)
        assert retired.is_dir()
        acknowledged_result = _run_tx(
            tree,
            "ack-recovered",
            "--expected-commit",
            ACTIVATION_COMMIT,
        )
        assert acknowledged_result.returncode == 0, acknowledged_result.stderr
        assert acknowledged_result.stdout == "recovered_completion_cleaned=yes\n"
        assert not any(os.path.lexists(path) for path in (complete, acknowledged, retired))
        after = _activation_state_snapshot(tree)
        for path in (*tree["paths"].values(), tree["broker_unit"]):
            assert after[str(path)] == baseline[str(path)]


def test_trusted_helper_ignores_malicious_cwd_and_pythonpath() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        shadow = root / "shadow"
        shadow.mkdir()
        sentinel = root / "imported"
        for name in ("hashlib.py", "argparse.py", "sitecustomize.py"):
            (shadow / name).write_text(
                f"open({str(sentinel)!r}, 'a', encoding='utf-8').write({name!r} + '\\n')\n",
                encoding="utf-8",
            )
        data = ACTIVATION_HELPER.read_bytes()
        blob = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
        completed = _run_contract_script(
            root,
            f"ACTIVATION_HELPER_BLOB={blob!r}\n"
            "ACTIVATION_HELPER_TIMEOUT_SECONDS=10\n"
            f"cd {str(shadow)!r}\n"
            f"export PYTHONPATH={str(shadow)!r}\n"
            + _function("run_trusted_activation_helper")
            + f"\nrun_trusted_activation_helper {str(ACTIVATION_HELPER)!r} --help >/dev/null\n",
        )
        assert completed.returncode == 0, completed.stderr
        assert not sentinel.exists()


def test_exact_git_tree_materialization_matches_commit_not_worktree() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
        (repo / "install.sh").write_text("committed-install\n", encoding="utf-8")
        helper = repo / "scripts" / "activation_transaction.py"
        helper.parent.mkdir()
        helper.write_text("committed-helper\n", encoding="utf-8")
        payload = repo / "payload"
        payload.mkdir()
        (payload / "data.txt").write_text("committed-data\n", encoding="utf-8")
        os.symlink("data.txt", payload / "data-link")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        (repo / "install.sh").write_text("dirty-install\n", encoding="utf-8")
        (payload / "data.txt").write_text("dirty-data\n", encoding="utf-8")
        (repo / "untracked-secret").write_text("must-not-copy\n", encoding="utf-8")
        destination = root / "materialized"
        completed = _run_contract_script(
            root,
            "FULL_SHA_RE='^[0-9a-f]{40}$'\n"
            f"OPS_GROUP={reader.pw_gid!r}\n"
            + _function("require_full_sha")
            + _function("materialize_exact_source_tree")
            + f"\nmaterialize_exact_source_tree {str(repo)!r} {commit!r} {str(destination)!r}\n",
        )
        assert completed.returncode == 0, completed.stderr
        assert (destination / "install.sh").read_text(encoding="utf-8") == "committed-install\n"
        assert (destination / "scripts" / "activation_transaction.py").read_text(encoding="utf-8") == "committed-helper\n"
        assert (destination / "payload" / "data.txt").read_text(encoding="utf-8") == "committed-data\n"
        assert (destination / "payload" / "data-link").is_symlink()
        assert os.readlink(destination / "payload" / "data-link") == "data.txt"
        assert not (destination / "untracked-secret").exists()
        actual_files = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        assert actual_files == {
            "install.sh",
            "scripts/activation_transaction.py",
            "payload/data.txt",
            "payload/data-link",
        }


@pytest.mark.parametrize(
    ("state", "previous", "load_state", "live_state"),
    (
        ("active", "/previous", "loaded", "active"),
        ("inactive", "/previous", "loaded", "auto_restart"),
        ("absent", "", "not-found", "inactive"),
        ("absent", "", "not-found", "queued"),
    ),
)
def test_broker_service_state_is_restored_before_transaction_finalize(
    state: str,
    previous: str,
    load_state: str,
    live_state: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        trace = root / "trace"
        live = root / "live-state"
        live.write_text(f"{live_state}\n", encoding="utf-8")
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >>\"$TRACE\"\n"
            "case \"$1\" in\n"
            "  daemon-reload) exit 0 ;;\n"
            "  stop) printf 'inactive\\n' >\"$LIVE\"; exit 0 ;;\n"
            "  show)\n"
            "    current=$(cat \"$LIVE\")\n"
            "    printf 'LoadState=%s\\n' \"$LOAD_STATE\"\n"
            "    [[ \"$current\" == active ]] && printf 'ActiveState=active\\nSubState=running\\nMainPID=123\\n' || { [[ \"$current\" == auto_restart ]] && printf 'ActiveState=activating\\nSubState=auto-restart\\nMainPID=0\\n' || printf 'ActiveState=inactive\\nSubState=dead\\nMainPID=0\\n'; }\n"
            "    [[ \"$current\" == queued ]] && printf 'Job=77\\n' || printf 'Job=\\n'\n"
            "    ;;\n"
            "  *) exit 19 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        systemctl.chmod(0o755)
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            f"LIVE={str(live)!r}\n"
            f"LOAD_STATE={load_state!r}\n"
            "export TRACE LIVE LOAD_STATE\n"
            f"PATH={str(fake_bin)!r}:/usr/local/bin:/usr/bin:/bin\n"
            "ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=5\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=5\n"
            f"BROKER_STATE={state!r}\n"
            "run_activation_transaction() { if [[ \"$*\" == *broker_state* ]]; then printf '%s\\n' \"$BROKER_STATE\"; else printf 'broker.service\\n'; fi; }\n"
            "restart_root_action_broker_for_release() { printf 'restart:%s:%s\\n' \"$1\" \"$2\" >>\"$TRACE\"; }\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_inactive_attested")
            + _function("root_action_broker_absent_attested")
            + _function("root_action_broker_quiesced_attested")
            + _function("quiesce_root_action_broker_for_transaction")
            + _function("restore_broker_service_from_transaction")
            + f"\nrestore_broker_service_from_transaction /helper {previous!r}\n",
        )
        assert completed.returncode == 0, completed.stderr
        tuple_trace = [SYSTEMD_TUPLE_SHOW]
        if state == "active":
            expected = ["daemon-reload", "restart:broker.service:/previous"]
        elif state == "inactive":
            expected = ["daemon-reload", "stop broker.service", *tuple_trace]
        elif live_state == "inactive":
            expected = ["daemon-reload", *tuple_trace, *tuple_trace]
        else:
            expected = [
                "daemon-reload",
                *tuple_trace,
                *tuple_trace,
                "stop broker.service",
                *tuple_trace,
                *tuple_trace,
            ]
        assert trace.read_text(encoding="utf-8").splitlines() == expected


@pytest.mark.parametrize("journal_state", ("inactive", "absent"))
@pytest.mark.parametrize("live_state", ("inactive", "auto_restart", "queued"))
def test_candidate_inactive_attestation_rejects_restart_or_job_drift(
    journal_state: str,
    live_state: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        trace = root / "trace"
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >>\"$TRACE\"\n"
            "[[ \"$1\" == show ]] || exit 19\n"
            "printf 'LoadState=loaded\\n'\n"
            "[[ \"$LIVE_STATE\" == auto_restart ]] && printf 'ActiveState=activating\\nSubState=auto-restart\\n' || printf 'ActiveState=inactive\\nSubState=dead\\n'\n"
            "printf 'MainPID=0\\n'\n"
            "[[ \"$LIVE_STATE\" == queued ]] && printf 'Job=77\\n' || printf 'Job=\\n'\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            f"LIVE_STATE={live_state!r}\n"
            "export TRACE LIVE_STATE\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            f"BROKER_STATE={journal_state!r}\n"
            "run_activation_transaction() { if [[ \"$*\" == *broker_state* ]]; then printf '%s\\n' \"$BROKER_STATE\"; else printf 'broker.service\\n'; fi; }\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_inactive_attested")
            + _function("attest_candidate_root_action_broker_state")
            + f"\nattest_candidate_root_action_broker_state /candidate /helper {journal_state!r}\n",
        )
        assert completed.returncode == (0 if live_state == "inactive" else 1)
        assert trace.read_text(encoding="utf-8").splitlines() == [SYSTEMD_TUPLE_SHOW]


@pytest.mark.parametrize(
    "live_state", ("active", "auto_restart", "queued", "inactive")
)
def test_loaded_broker_is_quiesced_before_managed_publication(
    live_state: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        trace = root / "trace"
        state = root / "broker-state"
        state.write_text(f"{live_state}\n", encoding="utf-8")
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >>\"$TRACE\"\n"
            "case \"$1\" in\n"
            "  stop) printf 'inactive\\n' >\"$STATE\"; exit 0 ;;\n"
            "  show)\n"
            "    current=$(cat \"$STATE\")\n"
            "    printf 'LoadState=loaded\\n'\n"
            "    [[ \"$current\" == active ]] && printf 'ActiveState=active\\nSubState=running\\nMainPID=123\\n' || { [[ \"$current\" == auto_restart ]] && printf 'ActiveState=activating\\nSubState=auto-restart\\nMainPID=0\\n' || printf 'ActiveState=inactive\\nSubState=dead\\nMainPID=0\\n'; }\n"
            "    [[ \"$current\" == queued ]] && printf 'Job=77\\n' || printf 'Job=\\n'\n"
            "    exit 0 ;;\n"
            "  *) exit 19 ;;\n"
            "esac\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            f"STATE={str(state)!r}\n"
            "export TRACE STATE\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            f"ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=1\n"
            f"ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            "run_activation_transaction() {\n"
            "  [[ \"$4\" == broker_state ]] && printf 'active\\n' || printf 'broker.service\\n'\n"
            "}\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_quiesced_attested")
            + _function("quiesce_root_action_broker_for_transaction")
            + _function("quiesce_root_action_broker_for_publication")
            + "\nquiesce_root_action_broker_for_publication /helper\n",
        )
        assert completed.returncode == 0, completed.stderr
        initial_tuple = [SYSTEMD_TUPLE_SHOW]
        expected = initial_tuple
        if live_state != "inactive":
            expected = [
                *initial_tuple,
                *initial_tuple,
                "stop broker.service",
                *initial_tuple,
            ]
        assert trace.read_text(encoding="utf-8").splitlines() == expected


def test_absent_broker_quiesce_accepts_only_exact_not_found_without_stop() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        trace = root / "trace"
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >>\"$TRACE\"\n"
            "[[ \"$1\" == show ]] || exit 19\n"
            "printf 'LoadState=not-found\\nActiveState=inactive\\nSubState=dead\\nMainPID=0\\nJob=\\n'\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            "export TRACE\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            "ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=1\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            "run_activation_transaction() {\n"
            "  [[ \"$4\" == broker_state ]] && printf 'absent\\n' || printf 'broker.service\\n'\n"
            "}\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_quiesced_attested")
            + _function("quiesce_root_action_broker_for_transaction")
            + "\nquiesce_root_action_broker_for_transaction /helper\n",
        )
        assert completed.returncode == 0, completed.stderr
        assert trace.read_text(encoding="utf-8").splitlines() == [SYSTEMD_TUPLE_SHOW]


def test_terminal_attestation_uses_one_coherent_systemd_snapshot() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        counter = root / "counter"
        counter.write_text("0\n", encoding="utf-8")
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "count=$(cat \"$COUNTER\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" >\"$COUNTER\"\n"
            "case \"$*\" in\n"
            "  'show --property=LoadState --property=ActiveState --property=SubState --property=MainPID --property=Job broker.service')\n"
            "    printf 'LoadState=loaded\\nActiveState=activating\\nSubState=auto-restart\\nMainPID=0\\nJob=77\\n' ;;\n"
            "  'show --property=LoadState --value broker.service') printf 'loaded\\n' ;;\n"
            "  'show --property=ActiveState --value broker.service') printf 'inactive\\n' ;;\n"
            "  'show --property=SubState --value broker.service') printf 'dead\\n' ;;\n"
            "  'show --property=MainPID --value broker.service') printf '0\\n' ;;\n"
            "  'show --property=Job --value broker.service') printf '\\n' ;;\n"
            "  *) exit 19 ;;\n"
            "esac\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"COUNTER={str(counter)!r}\n"
            "export COUNTER\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + "\nroot_action_broker_terminal_tuple_attested broker.service loaded\n",
        )
        assert completed.returncode == 1
        assert counter.read_text(encoding="utf-8") == "1\n"


@pytest.mark.parametrize(
    ("payload", "systemctl_rc", "expected_output"),
    (
        (
            "Job=\nMainPID=0\nSubState=dead\nActiveState=inactive\nLoadState=loaded\n",
            0,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJobPresent=no\n",
        ),
        (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=77\n",
            0,
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJobPresent=yes\n",
        ),
        ("LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n", 0, None),
        (
            "LoadState=loaded\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n",
            0,
            None,
        ),
        (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\nUnknown=value\n",
            0,
            None,
        ),
        (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=12345678901\nJob=\n",
            0,
            None,
        ),
        (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n",
            19,
            None,
        ),
    ),
)
def test_systemd_tuple_reader_is_strict_and_canonical(
    payload: str,
    systemctl_rc: int,
    expected_output: str | None,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        payload_file = root / "payload"
        payload_file.write_text(payload, encoding="utf-8")
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "cat \"$PAYLOAD_FILE\"\n"
            "exit \"$SYSTEMCTL_RC\"\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"PAYLOAD_FILE={str(payload_file)!r}\n"
            f"SYSTEMCTL_RC={systemctl_rc}\n"
            "export PAYLOAD_FILE SYSTEMCTL_RC\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            + _function("read_root_action_broker_systemd_tuple")
            + "\nread_root_action_broker_systemd_tuple broker.service\n",
        )
        if expected_output is None:
            assert completed.returncode == 1
        else:
            assert completed.returncode == 0, completed.stderr
            assert completed.stdout == expected_output


@pytest.mark.parametrize("systemctl_present", (False, True))
def test_unavailable_broker_quiesce_requires_systemctl_absent(
    systemctl_present: bool,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        if systemctl_present:
            systemctl = fake_bin / "systemctl"
            systemctl.write_text("#!/usr/bin/env bash\nexit 19\n", encoding="utf-8")
            os.chown(systemctl, 0, reader.pw_gid)
            systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"PATH={str(fake_bin)!r}\n"
            "run_activation_transaction() {\n"
            "  [[ \"$4\" == broker_state ]] && printf 'unavailable\\n' || printf 'broker.service\\n'\n"
            "}\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_quiesced_attested")
            + _function("quiesce_root_action_broker_for_transaction")
            + "\nquiesce_root_action_broker_for_transaction /helper\n",
        )
        assert completed.returncode == (1 if systemctl_present else 0)


@pytest.mark.parametrize(
    "restoration_state,expected_rc",
    (
        ("svcops_verified", 0),
        ("restored_exact_but_preexisting_unrunnable", 0),
        ("rejected", 1),
    ),
)
def test_recovery_finalizes_only_after_broker_and_cli_attestation(
    restoration_state: str,
    expected_rc: int,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        trace = root / "trace"
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            "quiesce_root_action_broker_before_recovery() { printf 'quiesce\\n' >>\"$TRACE\"; }\n"
            "run_activation_transaction() { printf 'tx:%s\\n' \"$2\" >>\"$TRACE\"; }\n"
            "restore_broker_service_from_transaction() { printf 'broker\\n' >>\"$TRACE\"; }\n"
            f"RESTORATION_STATE={restoration_state!r}\n"
            "RESTORED_CLI_RESULT=''\n"
            "attest_restored_cli_or_exact_preexisting_unrunnable() {\n"
            "  printf 'cli:%s\\n' \"$RESTORATION_STATE\" >>\"$TRACE\"\n"
            "  [[ \"$RESTORATION_STATE\" != rejected ]] || return 1\n"
            "  RESTORED_CLI_RESULT=\"$RESTORATION_STATE\"\n"
            "}\n"
            "info() { printf 'info:%s\\n' \"$*\" >>\"$TRACE\"; }\n"
            + _function("recover_and_attest_activation_baseline")
            + f"\nrecover_and_attest_activation_baseline /helper {ACTIVATION_COMMIT} /previous\n",
        )
        assert completed.returncode == expected_rc, completed.stderr
        expected_trace = [
            "quiesce",
            "tx:recover",
            "broker",
            f"cli:{restoration_state}",
        ]
        if expected_rc == 0:
            expected_trace.extend(
                [
                    f"info:ops_cli_restoration={restoration_state}",
                    "tx:finalize",
                ]
            )
        assert trace.read_text(encoding="utf-8").splitlines() == expected_trace


@pytest.mark.parametrize("journal_state", ("active", "inactive", "absent"))
@pytest.mark.parametrize("load_state", ("loaded", "not-found"))
@pytest.mark.parametrize(
    "live_state", ("active", "auto_restart", "queued", "inactive")
)
def test_recovery_sigkill_after_filesystem_restore_leaves_broker_quiesced(
    journal_state: str,
    load_state: str,
    live_state: str,
) -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        fake_bin = root / "fake-bin"
        fake_bin.mkdir(mode=0o750)
        os.chown(fake_bin, 0, reader.pw_gid)
        trace = root / "trace"
        state = root / "broker-state"
        state.write_text(f"{live_state}\n", encoding="utf-8")
        tx_marker = root / "transaction-preserved"
        tx_marker.write_text("pending\n", encoding="utf-8")
        systemctl = fake_bin / "systemctl"
        systemctl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf 'systemctl:%s\\n' \"$*\" >>\"$TRACE\"\n"
            "case \"$1\" in\n"
            "  stop) printf 'inactive\\n' >\"$STATE\"; exit 0 ;;\n"
            "  show)\n"
            "    current=$(cat \"$STATE\")\n"
            "    printf 'LoadState=%s\\n' \"$LOAD_STATE\"\n"
            "    [[ \"$current\" == active ]] && printf 'ActiveState=active\\nSubState=running\\nMainPID=123\\n' || { [[ \"$current\" == auto_restart ]] && printf 'ActiveState=activating\\nSubState=auto-restart\\nMainPID=0\\n' || printf 'ActiveState=inactive\\nSubState=dead\\nMainPID=0\\n'; }\n"
            "    [[ \"$current\" == queued ]] && printf 'Job=77\\n' || printf 'Job=\\n'\n"
            "    exit 0 ;;\n"
            "  *) exit 19 ;;\n"
            "esac\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chown(systemctl, 0, reader.pw_gid)
        systemctl.chmod(0o750)
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            f"STATE={str(state)!r}\n"
            f"LOAD_STATE={load_state!r}\n"
            f"TX_MARKER={str(tx_marker)!r}\n"
            "export TRACE STATE LOAD_STATE TX_MARKER\n"
            f"PATH={str(fake_bin)!r}:/usr/bin:/bin\n"
            "ROOT_ACTION_MUTATION_COMMAND_TIMEOUT_SECONDS=1\n"
            "ROOT_ACTION_POST_RESTART_COMMAND_TIMEOUT_SECONDS=1\n"
            "run_activation_transaction() {\n"
            "  if [[ \"$2\" == show ]]; then\n"
            f"    [[ \"$4\" == broker_state ]] && printf '{journal_state}\\n' || printf 'broker.service\\n'\n"
            "  elif [[ \"$2\" == recover ]]; then\n"
            "    printf 'filesystem-recover\\n' >>\"$TRACE\"\n"
            "    kill -KILL $$\n"
            "  elif [[ \"$2\" == finalize ]]; then\n"
            "    rm -f \"$TX_MARKER\"\n"
            "  fi\n"
            "}\n"
            "restore_broker_service_from_transaction() { printf 'unexpected-restore\\n' >>\"$TRACE\"; }\n"
            "attest_restored_cli_as_ops() { printf 'unexpected-cli\\n' >>\"$TRACE\"; }\n"
            + _function("read_root_action_broker_systemd_tuple")
            + _function("root_action_broker_terminal_tuple_attested")
            + _function("root_action_broker_quiesced_attested")
            + _function("quiesce_root_action_broker_for_transaction")
            + _function("quiesce_root_action_broker_before_recovery")
            + _function("recover_and_attest_activation_baseline")
            + f"\nrecover_and_attest_activation_baseline /helper {ACTIVATION_COMMIT} /previous\n",
        )
        assert completed.returncode == -signal.SIGKILL
        assert state.read_text(encoding="utf-8") == "inactive\n"
        assert tx_marker.read_text(encoding="utf-8") == "pending\n"
        initial_tuple = [f"systemctl:{SYSTEMD_TUPLE_SHOW}"]
        expected = [*initial_tuple, "filesystem-recover"]
        if live_state != "inactive":
            expected = [
                *initial_tuple,
                *initial_tuple,
                "systemctl:stop broker.service",
                *initial_tuple,
                "filesystem-recover",
            ]
        assert trace.read_text(encoding="utf-8").splitlines() == expected


def test_broker_state_drift_before_begin_prevents_publication() -> None:
    reader = _reader()
    with _root_temp(reader) as root:
        install_root = root / "install"
        releases = install_root / "releases"
        release = releases / f"{ACTIVATION_COMMIT}.20260730000000.1234"
        unit_source = release / "systemd" / "agent-runtime-root-action-broker.service"
        unit_source.parent.mkdir(parents=True)
        unit_source.write_text(
            "[Service]\nExecStart=@@CURRENT_LINK@@/.venv/bin/opsctl\n"
            "Environment=AGENT_RUNTIME_OPS_RELEASE=@@RELEASE_DIR@@\n",
            encoding="utf-8",
        )
        trace = root / "trace"
        completed = _run_contract_script(
            root,
            f"TRACE={str(trace)!r}\n"
            f"INSTALL_ROOT={str(install_root)!r}\n"
            f"RELEASES_DIR={str(releases)!r}\n"
            f"ACTIVATION_CANDIDATE_DIR={str(install_root / '.activation-candidate.prepare')!r}\n"
            f"CURRENT_LINK={str(install_root / 'current')!r}\n"
            f"ROOT_ACTION_BROKER_SERVICE_FILE={str(root / 'broker.service')!r}\n"
            f"OPS_USER={reader.pw_name!r}\n"
            f"GEMINI_HOME={reader.pw_dir!r}\n"
            "run_trusted_activation_helper() { printf 'fsync\\n' >>\"$TRACE\"; }\n"
            "capture_root_action_broker_state() { printf 'capture\\n' >>\"$TRACE\"; printf 'active\\n'; }\n"
            "cleanup_abandoned_activation_staging() { printf 'cleanup\\n' >>\"$TRACE\"; return 0; }\n"
            "run_activation_transaction() { printf 'begin:%s\\n' \"$2\" >>\"$TRACE\"; }\n"
            + _function("activate_release")
            + f"\nactivate_release {str(release)!r} {ACTIVATION_COMMIT} /previous /helper inactive\n",
        )
        assert completed.returncode != 0
        assert trace.read_text(encoding="utf-8").splitlines() == [
            "fsync",
            "capture",
            "cleanup",
        ]
