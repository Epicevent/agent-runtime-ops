from __future__ import annotations

import json
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PACKAGE = REPO_ROOT / "opsctl" / "agent_runtime_ops"
SOURCE_COMMIT = "a" * 40
UNIT_PATH = (
    REPO_ROOT / "systemd" / "agent-runtime-root-action-broker-standalone.service"
)
DOC_PATH = REPO_ROOT / "docs" / "ROOT_ACTION_CONTROL_PLANE_CUTOVER.md"


def _load_release_module():
    name = "_standalone_root_action_release_contract"
    source = SOURCE_PACKAGE / "root_actions" / "release.py"
    specification = importlib.util.spec_from_file_location(name, source)
    if specification is None or specification.loader is None:
        raise RuntimeError("standalone release module could not be loaded")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


release = _load_release_module()


def _chmod_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    os.chmod(root, 0o755)


def _build_release(base: Path) -> tuple[Path, Path, int, int]:
    release_dir = base / SOURCE_COMMIT
    package_root = (
        release_dir
        / ".runtime"
        / "lib"
        / "python3.11"
        / "site-packages"
        / "agent_runtime_ops"
    )
    root_actions = package_root / "root_actions"
    domain = package_root / "domain"
    root_actions.mkdir(parents=True)
    domain.mkdir()
    shutil.copy2(SOURCE_PACKAGE / "__init__.py", package_root / "__init__.py")
    for name in ("__init__.py", "artifact_probe.py"):
        shutil.copy2(SOURCE_PACKAGE / "domain" / name, domain / name)
    for name in release._ROOT_ACTION_FILES:
        shutil.copy2(SOURCE_PACKAGE / "root_actions" / name, root_actions / name)
    third_party = package_root.parent / "webauthn"
    third_party.mkdir()
    (third_party / "__init__.py").write_text("VERSION = 'bound'\n", encoding="utf-8")
    bin_dir = release_dir / ".runtime" / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("python", "python3", "python3.11"):
        (bin_dir / name).write_bytes(b"standalone-copied-python\n")
    _chmod_tree(release_dir)
    for name in ("python", "python3", "python3.11"):
        os.chmod(bin_dir / name, 0o755)
    identity = release_dir.stat()
    return release_dir, package_root, identity.st_uid, identity.st_gid


def _write_descriptor(
    base: Path,
    descriptor: release.ReleaseDescriptor,
) -> Path:
    path = base / "descriptor.json"
    path.write_bytes(descriptor.canonical_bytes())
    os.chmod(path, 0o644)
    return path


def _copy_launcher(base: Path) -> Path:
    path = base / "agent-runtime-root-action-release.py"
    shutil.copy2(Path(release.__file__), path)
    os.chmod(path, 0o644)
    return path


class StandaloneReleaseContractTests(unittest.TestCase):
    def test_descriptor_parser_requires_canonical_exact_fields(self) -> None:
        descriptor = release.ReleaseDescriptor(
            source_commit=SOURCE_COMMIT,
            release_basename=SOURCE_COMMIT,
            tree_digest="sha256:" + "1" * 64,
            entry_count=42,
            total_file_bytes=1000,
            python_relpath=".runtime/bin/python",
            package_root_relpath=(
                ".runtime/lib/python3.11/site-packages/agent_runtime_ops"
            ),
        )
        self.assertEqual(
            release.parse_descriptor(descriptor.canonical_bytes()),
            descriptor,
        )
        values = descriptor.value()
        values["unexpected"] = True
        with self.assertRaises(release.StandaloneReleaseError):
            release.parse_descriptor(release._canonical_json(values))
        with self.assertRaises(release.StandaloneReleaseError):
            release.parse_descriptor(b" " + descriptor.canonical_bytes())

    @unittest.skipUnless(os.name == "posix", "release identity is POSIX-only")
    def test_descriptor_binds_complete_tree_and_minimal_first_party_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_dir, package_root, uid, gid = _build_release(Path(temporary))
            descriptor = release.describe_release(
                release_dir,
                SOURCE_COMMIT,
                required_uid=uid,
                required_gid=gid,
            )
            self.assertEqual(descriptor.source_commit, SOURCE_COMMIT)
            self.assertRegex(descriptor.tree_digest, r"^sha256:[0-9a-f]{64}$")
            self.assertGreater(descriptor.entry_count, 20)
            self.assertGreater(descriptor.total_file_bytes, 1_000)
            self.assertEqual(
                set(path.name for path in (package_root / "root_actions").iterdir()),
                set(release._ROOT_ACTION_FILES),
            )
            self.assertFalse((release_dir / ".runtime" / "bin" / "opsctl").exists())

            before = descriptor.tree_digest
            dependency = package_root.parent / "webauthn" / "__init__.py"
            dependency.write_text("VERSION = 'drifted'\n", encoding="utf-8")
            os.chmod(dependency, 0o644)
            after = release.describe_release(
                release_dir,
                SOURCE_COMMIT,
                required_uid=uid,
                required_gid=gid,
            ).tree_digest
            self.assertNotEqual(before, after)

    @unittest.skipUnless(os.name == "posix", "release identity is POSIX-only")
    def test_descriptor_rejects_opsctl_and_extra_first_party_code(self) -> None:
        for relative in (
            Path(".runtime/bin/opsctl"),
            Path(
                ".runtime/lib/python3.11/site-packages/agent_runtime_ops/cli.py"
            ),
            Path(
                ".runtime/lib/python3.11/site-packages/agent_runtime_ops/commands"
            ),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                release_dir, _, uid, gid = _build_release(Path(temporary))
                target = release_dir / relative
                if target.suffix:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("retired\n", encoding="utf-8")
                    os.chmod(target, 0o644)
                else:
                    target.mkdir(parents=True)
                    os.chmod(target, 0o755)
                with self.assertRaises(release.StandaloneReleaseError):
                    release.describe_release(
                        release_dir,
                        SOURCE_COMMIT,
                        required_uid=uid,
                        required_gid=gid,
                    )

    @unittest.skipIf(os.name == "nt", "POSIX link identity is required")
    def test_descriptor_rejects_symlink_and_hardlink_entries(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                release_dir, package_root, uid, gid = _build_release(Path(temporary))
                source = package_root.parent / "webauthn" / "__init__.py"
                target = package_root.parent / "webauthn" / "alias.py"
                if kind == "symlink":
                    target.symlink_to("__init__.py")
                else:
                    os.link(source, target)
                with self.assertRaises(release.StandaloneReleaseError):
                    release.describe_release(
                        release_dir,
                        SOURCE_COMMIT,
                        required_uid=uid,
                        required_gid=gid,
                    )

    @unittest.skipUnless(os.name == "posix", "site startup proof is POSIX-only")
    def test_descriptor_rejects_every_python_site_startup_escape(self) -> None:
        relatives = (
            Path(".runtime/pyvenv.cfg"),
            Path(".runtime/lib/python3.11/site-packages/escape.pth"),
            Path(".runtime/lib/python3.11/site-packages/escape.egg-link"),
            Path(".runtime/lib/python3.11/site-packages/sitecustomize.py"),
            Path(".runtime/lib/python3.11/site-packages/usercustomize.py"),
        )
        for relative in relatives:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                release_dir, _, uid, gid = _build_release(Path(temporary))
                target = release_dir / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    "import sys; sys.path.insert(0, '/mutable/current')\n",
                    encoding="utf-8",
                )
                os.chmod(target, 0o644)
                with self.assertRaisesRegex(
                    release.StandaloneReleaseError,
                    "forbidden startup hook",
                ):
                    release.describe_release(
                        release_dir,
                        SOURCE_COMMIT,
                        required_uid=uid,
                        required_gid=gid,
                    )

    @unittest.skipUnless(os.name == "posix", "release identity is POSIX-only")
    def test_descriptor_rejects_mode_owner_parent_and_special_node_drift(self) -> None:
        cases = ("mode", "owner", "parent", "fifo", "missing")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                release_dir, package_root, uid, gid = _build_release(base)
                target = package_root.parent / "webauthn" / "__init__.py"
                expected_uid = uid
                if case == "mode":
                    os.chmod(target, 0o664)
                elif case == "owner":
                    expected_uid = uid + 1
                elif case == "parent":
                    os.chmod(base, 0o777)
                elif case == "fifo":
                    target.unlink()
                    os.mkfifo(target, 0o644)
                else:
                    (package_root / "root_actions" / "service.py").unlink()
                before = release_dir.lstat()
                with self.assertRaises(release.StandaloneReleaseError):
                    release.describe_release(
                        release_dir,
                        SOURCE_COMMIT,
                        required_uid=expected_uid,
                        required_gid=gid,
                    )
                after = release_dir.lstat()
                self.assertEqual(
                    (before.st_dev, before.st_ino, before.st_mtime_ns),
                    (after.st_dev, after.st_ino, after.st_mtime_ns),
                )

    @unittest.skipUnless(os.name == "posix", "release identity is POSIX-only")
    def test_runtime_validation_binds_launcher_descriptor_commit_and_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            release_dir, _, uid, gid = _build_release(base)
            descriptor = release.describe_release(
                release_dir,
                SOURCE_COMMIT,
                required_uid=uid,
                required_gid=gid,
            )
            descriptor_path = _write_descriptor(base, descriptor)
            launcher_path = _copy_launcher(base)
            validated = release.validate_runtime_release(
                release_dir=release_dir,
                descriptor_path=descriptor_path,
                expected_source_commit=SOURCE_COMMIT,
                expected_descriptor_sha256=release._sha256(
                    descriptor_path.read_bytes()
                ),
                launcher_path=launcher_path,
                expected_launcher_sha256=release._sha256(launcher_path.read_bytes()),
                required_uid=uid,
                required_gid=gid,
            )
            self.assertEqual(validated, descriptor)

            different_launcher = base / "different-launcher.py"
            different_launcher.write_bytes(launcher_path.read_bytes() + b"\n")
            os.chmod(different_launcher, 0o644)
            with self.assertRaisesRegex(
                release.StandaloneReleaseError,
                "stable launcher and packaged launcher bytes differ",
            ):
                release.validate_runtime_release(
                    release_dir=release_dir,
                    descriptor_path=descriptor_path,
                    expected_source_commit=SOURCE_COMMIT,
                    expected_descriptor_sha256=release._sha256(
                        descriptor_path.read_bytes()
                    ),
                    launcher_path=different_launcher,
                    expected_launcher_sha256=release._sha256(
                        different_launcher.read_bytes()
                    ),
                    required_uid=uid,
                    required_gid=gid,
                )

            for field, value in (
                ("expected_source_commit", "b" * 40),
                ("expected_descriptor_sha256", "sha256:" + "0" * 64),
                ("expected_launcher_sha256", "sha256:" + "1" * 64),
            ):
                arguments = {
                    "release_dir": release_dir,
                    "descriptor_path": descriptor_path,
                    "expected_source_commit": SOURCE_COMMIT,
                    "expected_descriptor_sha256": release._sha256(
                        descriptor_path.read_bytes()
                    ),
                    "launcher_path": launcher_path,
                    "expected_launcher_sha256": release._sha256(
                        launcher_path.read_bytes()
                    ),
                    "required_uid": uid,
                    "required_gid": gid,
                }
                arguments[field] = value
                with self.subTest(field=field), self.assertRaises(
                    release.StandaloneReleaseError
                ):
                    release.validate_runtime_release(**arguments)

            dependency = (
                release_dir
                / ".runtime/lib/python3.11/site-packages/webauthn/__init__.py"
            )
            dependency.write_text("VERSION = 'post-validation-drift'\n", encoding="utf-8")
            os.chmod(dependency, 0o644)
            with self.assertRaises(release.StandaloneReleaseError):
                release.validate_runtime_release(
                    release_dir=release_dir,
                    descriptor_path=descriptor_path,
                    expected_source_commit=SOURCE_COMMIT,
                    expected_descriptor_sha256=release._sha256(
                        descriptor_path.read_bytes()
                    ),
                    launcher_path=launcher_path,
                    expected_launcher_sha256=release._sha256(
                        launcher_path.read_bytes()
                    ),
                    required_uid=uid,
                    required_gid=gid,
                )

    @unittest.skipUnless(os.name == "posix", "release identity is POSIX-only")
    def test_exec_uses_only_pinned_release_python_and_service_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_dir, _, uid, gid = _build_release(Path(temporary))
            descriptor = release.describe_release(
                release_dir,
                SOURCE_COMMIT,
                required_uid=uid,
                required_gid=gid,
            )
            calls: list[tuple[str, list[str], dict[str, str]]] = []

            def capture(path: str, argv: list[str], environment: dict[str, str]) -> None:
                calls.append((path, argv, environment))
                raise OSError("sentinel")

            with mock.patch.dict(
                os.environ,
                {"LD_PRELOAD": "attacker.so", "PYTHONPATH": "/attacker"},
            ), self.assertRaisesRegex(OSError, "sentinel"):
                release.exec_broker(descriptor, release_dir, execve=capture)
            self.assertEqual(len(calls), 1)
            path, argv, environment = calls[0]
            self.assertEqual(path, str(release_dir / ".runtime/bin/python"))
            self.assertEqual(
                argv,
                [
                    path,
                    "-I",
                    "-B",
                    "-S",
                    "-c",
                    release._BROKER_ENTRY_CODE,
                    str(
                        release_dir
                        / ".runtime/lib/python3.11/site-packages"
                    ),
                ],
            )
            self.assertEqual(environment["AGENT_RUNTIME_ROOT_ACTION_RELEASE"], str(release_dir))
            self.assertEqual(environment["AGENT_RUNTIME_ROOT_ACTION_SOURCE_COMMIT"], SOURCE_COMMIT)
            self.assertEqual(
                environment["AGENT_RUNTIME_ROOT_ACTION_TREE_SHA256"],
                descriptor.tree_digest,
            )
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertNotIn("PYTHONPATH", environment)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership is required")
    def test_file_owner_validator_rejects_the_entry_it_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.txt"
            path.write_text("bound\n", encoding="utf-8")
            os.chmod(path, 0o644)
            identity = path.stat()
            with self.assertRaisesRegex(
                release.StandaloneReleaseError,
                "file identity is unsafe",
            ):
                release._read_regular(
                    path,
                    required_uid=identity.st_uid + 1,
                    required_gid=identity.st_gid,
                )

    def test_policy_and_inventory_boundary_are_unchanged(self) -> None:
        execution = (
            SOURCE_PACKAGE / "root_actions" / "execution.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'ExecutionPolicy(\n            "artifact.probe_kwrag_product",\n'
            "            1,\n            OperationAvailability.ENABLED,",
            execution,
        )
        self.assertIn(
            'ExecutionPolicy(\n            "kwrag.network_ensure",\n'
            "            1,\n"
            "            OperationAvailability.DISABLED_BY_PRODUCT_BOUNDARY,",
            execution,
        )
        self.assertIn(
            "DEFAULT_OPERATION_HANDLERS = OperationHandlerRegistry(\n"
            "    (KwragProductArtifactProbeHandler(),)\n)",
            execution,
        )
        self.assertIn(
            "historical_inventory_v1.json",
            release._ROOT_ACTION_FILES,
        )

    def test_unit_is_pinned_and_has_no_opsctl_or_current_dependency(self) -> None:
        unit = UNIT_PATH.read_text(encoding="utf-8")
        exec_start = next(
            line for line in unit.splitlines() if line.startswith("ExecStart=")
        )
        self.assertNotIn("opsctl", exec_start)
        self.assertNotIn("CURRENT", unit)
        self.assertIn("@@BROKER_RELEASE_DIR@@", exec_start)
        self.assertIn("@@BROKER_DESCRIPTOR@@", exec_start)
        self.assertIn("@@SOURCE_COMMIT@@", exec_start)
        self.assertIn("@@DESCRIPTOR_SHA256@@", exec_start)
        self.assertIn("@@LAUNCHER_SHA256@@", exec_start)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        self.assertIn(
            "ReadWritePaths=/var/lib/agent-runtime-ops/root-actions /run/agent-runtime-ops",
            unit,
        )

    def test_no_unsafe_console_import_and_documentation_states_bounded_cutover(self) -> None:
        project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertNotIn(
            "agent-runtime-root-action-release",
            project["project"]["scripts"],
        )
        unit = UNIT_PATH.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/python3 -I -B -S @@BROKER_LAUNCHER@@ run", unit)
        document = DOC_PATH.read_text(encoding="utf-8")
        for required in (
            "must not contain `agent_runtime_ops.cli`",
            "does **not** expose a bootstrap command",
            "response-loss idempotency",
            "user-ratified secret transport",
            "MCP `root_action_submit`",
            "No browserless machine mutation authority",
            "`kwrag.network_ensure`",
        ):
            self.assertIn(required, document)
        self.assertNotIn("bootstrap-create", release._runtime_parser().format_help())


if __name__ == "__main__":
    unittest.main()
