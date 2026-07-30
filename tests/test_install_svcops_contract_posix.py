from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import shutil
import stat
import subprocess
import tempfile
from typing import Any

import pytest

try:
    import pwd
except ImportError:  # pragma: no cover - exercised by Windows collection
    pwd = None  # type: ignore[assignment]


INSTALL = Path("install.sh").read_text(encoding="utf-8")


def _function(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _reader() -> Any:
    if pwd is None or os.name != "posix" or os.geteuid() != 0:
        pytest.skip("root POSIX ownership semantics are required")
    name = os.environ.get("SUDO_USER", "")
    if not name or name == "root":
        pytest.skip("a distinct SUDO_USER reader is required")
    return pwd.getpwnam(name)


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
