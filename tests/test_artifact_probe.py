from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from types import ModuleType
import unittest
from unittest.mock import patch

if os.name == "nt":
    for module_name in ("pwd", "grp"):
        sys.modules.setdefault(module_name, ModuleType(module_name))

from agent_runtime_ops.cli import build_parser
from agent_runtime_ops.commands.artifact import cmd_artifact_probe
import agent_runtime_ops.domain.artifact_probe as artifact_probe_module
from agent_runtime_ops.domain.artifact_probe import (
    _default_docker_runner,
    ArtifactProbeError,
    CommandResult,
    MAX_DOCKER_OUTPUT_BYTES,
    MAX_FILE_BYTES,
    probe_kwrag_product_artifact,
    serialize_probe_payload,
    validate_revision,
)


REVISION = "1" * 40
FINAL_NAME = f"kwrag-product-{REVISION}"
STAGING_NAME = f".staging-kwrag-product-{REVISION}-20260727T010203Z"
CANDIDATE = "kwrag-product:candidate-11111111"


class Node:
    def __init__(
        self,
        kind: str,
        *,
        data: bytes = b"",
        children: dict[str, "Node"] | None = None,
        nlink: int = 1,
        stat_size: int | None = None,
        mutate_after_open: bool = False,
    ) -> None:
        self.kind = kind
        self.data = data
        self.children = children or {}
        self.nlink = nlink
        self.stat_size = len(data) if stat_size is None else stat_size
        self.mutate_after_open = mutate_after_open
        self.fstat_count = 0
        self.ino = id(self) & 0x7FFFFFFF

    def stat_value(self, *, opened: bool = False):
        if self.kind == "directory":
            mode = stat.S_IFDIR | 0o750
        elif self.kind == "symlink":
            mode = stat.S_IFLNK | 0o777
        elif self.kind == "fifo":
            mode = stat.S_IFIFO | 0o440
        else:
            mode = stat.S_IFREG | 0o440
        if opened:
            self.fstat_count += 1
        changed = self.mutate_after_open and self.fstat_count >= 2
        return SimpleNamespace(
            st_dev=7,
            st_ino=self.ino,
            st_mode=mode,
            st_uid=0,
            st_gid=0,
            st_nlink=self.nlink,
            st_size=self.stat_size,
            st_mtime_ns=2 if changed else 1,
            st_ctime_ns=2 if changed else 1,
        )


class FakeSyscalls:
    def __init__(self, root: Node) -> None:
        self.root = root
        self.fds: dict[int, tuple[Node, int]] = {}
        self.next_fd = 10
        self.open_calls: list[tuple[str, int, int | None]] = []

    def _allocate(self, node: Node) -> int:
        fd = self.next_fd
        self.next_fd += 1
        self.fds[fd] = (node, 0)
        return fd

    def open(self, path: str | Path, flags: int, *, dir_fd: int | None = None) -> int:
        name = str(path)
        self.open_calls.append((name, flags, dir_fd))
        if dir_fd is None:
            node = self.root
        else:
            parent = self.fds[dir_fd][0]
            node = parent.children[name]
        if node.kind == "symlink":
            raise OSError("nofollow")
        return self._allocate(node)

    def close(self, fd: int) -> None:
        self.fds.pop(fd)

    def fstat(self, fd: int):
        return self.fds[fd][0].stat_value(opened=True)

    def stat(self, path: str, *, dir_fd: int, follow_symlinks: bool):
        assert follow_symlinks is False
        return self.fds[dir_fd][0].children[path].stat_value()

    def listdir(self, fd: int) -> list[str]:
        return list(self.fds[fd][0].children)

    def read(self, fd: int, size: int) -> bytes:
        node, position = self.fds[fd]
        chunk = node.data[position : position + size]
        self.fds[fd] = (node, position + len(chunk))
        return chunk


class FakeDocker:
    def __init__(self, *, images: object | None = None, ancestors: bytes = b"") -> None:
        self.images = images if images is not None else [valid_image()]
        self.ancestors = ancestors
        self.calls: list[list[str]] = []
        self.inspect_stdout: bytes | None = None

    def __call__(
        self, argv: list[str], *, timeout: int, output_limit: int
    ) -> CommandResult:
        self.calls.append(argv)
        assert timeout == 8
        assert output_limit == MAX_DOCKER_OUTPUT_BYTES
        if argv[:3] == ["docker", "image", "inspect"]:
            body = (
                self.inspect_stdout
                if self.inspect_stdout is not None
                else json.dumps(self.images).encode()
            )
            return CommandResult(0, body, b"")
        if argv[:3] == ["docker", "ps", "-aq"]:
            return CommandResult(0, self.ancestors, b"")
        raise AssertionError(f"unexpected command: {argv}")


def metadata_bytes(*, descriptor: bool = False, extra_keys: int = 0) -> bytes:
    payload: dict[str, object] = {
        "buildx.build.provenance": {
            "buildConfig": {},
            "buildType": "fixture",
            "builder": {},
            "invocation": {},
            "materials": [],
            "metadata": {},
        },
        "containerimage.config.digest": "sha256:" + "a" * 64,
        "containerimage.digest": "sha256:" + "a" * 64,
        "image.name": "docker.io/library/" + CANDIDATE,
    }
    if descriptor:
        payload["containerimage.descriptor"] = {
            "digest": "sha256:" + "a" * 64,
            "mediaType": "fixture",
        }
    for index in range(extra_keys):
        payload[f"fixture-key-{index:05d}-" + "x" * 20] = index
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def context_receipt_bytes() -> bytes:
    return json.dumps(
        {
            "schema": "kwrag-build-context/v1",
            "source_archive_sha256": "sha256:" + "b" * 64,
            "source_subdirectory": "service",
            "transform": "fixture",
            "member_count": 38,
            "context_tar_sha256": "sha256:" + "c" * 64,
            "context_tar_bytes": 204800,
            "ignoredSecretLikeField": "must-not-appear",
        },
        separators=(",", ":"),
    ).encode()


def image_receipt_bytes() -> bytes:
    return json.dumps(
        {
            "schema": "kwrag-image-build-receipt/recovery-v1",
            "version": 5,
            "source_revision": REVISION,
            "build_input_digest": "sha256:" + "d" * 64,
            "candidate_tag": CANDIDATE,
            "image_id": "sha256:" + "a" * 64,
            "candidate_executed": False,
            "secretLikeField": "must-not-appear",
        },
        separators=(",", ":"),
    ).encode()


def valid_root(*, descriptor: bool = False) -> Node:
    final = Node(
        "directory",
        children={
            "build-metadata.json": Node(
                "file", data=metadata_bytes(descriptor=descriptor)
            ),
            "service-context-receipt.json": Node("file", data=context_receipt_bytes()),
            "image-build-receipt.json": Node("file", data=image_receipt_bytes()),
            "unrelated.log": Node("file", data=b"not-read"),
        },
    )
    staging = Node(
        "directory",
        children={
            "build-metadata.json": Node("file", data=metadata_bytes(descriptor=False))
        },
    )
    return Node(
        "directory",
        children={
            FINAL_NAME: final,
            STAGING_NAME: staging,
            "other-revision": Node("directory"),
        },
    )


def valid_image() -> dict[str, object]:
    return {
        "Id": "sha256:" + "a" * 64,
        "Os": "linux",
        "Architecture": "arm64",
        "RepoTags": [CANDIDATE, "private:must-not-appear"],
        "RepoDigests": ["private@sha256:" + "d" * 64],
        "Created": "2026-07-27T00:00:00Z",
        "Size": 123456,
        "RootFS": {"Layers": ["sha256:" + "e" * 64]},
        "Config": {
            "Labels": {
                "org.opencontainers.image.revision": REVISION,
                "io.kwrag.build-input.digest": "sha256:" + "f" * 64,
                "private.secret": "must-not-appear",
            }
        },
    }


def run_probe(root: Node, docker: FakeDocker | None = None):
    return probe_kwrag_product_artifact(
        REVISION,
        build_root=Path("/fixture/image-builds"),
        syscalls=FakeSyscalls(root),
        docker_runner=docker or FakeDocker(),
        observed_at="2026-07-27T00:00:00+00:00",
    )


class ArtifactProbeTests(unittest.TestCase):
    def test_valid_final_and_staging_descriptor_absent_and_unrelated_entries(
        self,
    ) -> None:
        docker = FakeDocker()
        payload = run_probe(valid_root(), docker)

        self.assertEqual(payload["writes"], 0)
        self.assertEqual(payload["directoryObservation"]["matchingCount"], 2)
        self.assertEqual(payload["directoryObservation"]["unrelatedEntryCount"], 1)
        final = next(
            item
            for item in payload["directoryObservation"]["directories"]
            if item["kind"] == "final"
        )
        self.assertEqual(final["unrelatedEntryCount"], 1)
        metadata = next(
            item for item in final["artifacts"] if item["name"] == "build-metadata.json"
        )
        self.assertEqual(
            metadata["selectedJson"]["descriptor"],
            {"present": False, "type": "missing"},
        )
        serialized = serialize_probe_payload(payload)
        self.assertNotIn("must-not-appear", serialized)
        self.assertNotIn("private:must-not-appear", serialized)
        self.assertEqual(payload["dockerObservation"]["ancestorContainerCount"], 0)
        self.assertEqual(len(docker.calls), 2)
        self.assertEqual(docker.calls[0], ["docker", "image", "inspect", CANDIDATE])
        self.assertEqual(
            docker.calls[1],
            [
                "docker",
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"ancestor={CANDIDATE}",
                "--format",
                "{{.ID}}",
            ],
        )

    def test_root_child_and_file_opens_use_directory_nofollow_and_cloexec_flags(
        self,
    ) -> None:
        syscalls = FakeSyscalls(valid_root())
        with (
            patch.object(
                artifact_probe_module.os, "O_DIRECTORY", 0x010000, create=True
            ),
            patch.object(artifact_probe_module.os, "O_NOFOLLOW", 0x020000, create=True),
            patch.object(artifact_probe_module.os, "O_CLOEXEC", 0x040000, create=True),
        ):
            probe_kwrag_product_artifact(
                REVISION,
                build_root=Path("/fixture/image-builds"),
                syscalls=syscalls,
                docker_runner=FakeDocker(),
            )
        root_call, child_call, file_call = syscalls.open_calls[:3]
        self.assertEqual(root_call[1] & 0x070000, 0x070000)
        self.assertEqual(child_call[1] & 0x070000, 0x070000)
        self.assertEqual(file_call[1] & 0x060000, 0x060000)

    def test_descriptor_presence_is_observed_without_becoming_a_verdict(self) -> None:
        payload = run_probe(valid_root(descriptor=True))
        final = next(
            item
            for item in payload["directoryObservation"]["directories"]
            if item["kind"] == "final"
        )
        metadata = next(
            item for item in final["artifacts"] if item["name"] == "build-metadata.json"
        )
        self.assertEqual(metadata["selectedJson"]["descriptor"]["present"], True)
        self.assertEqual(
            metadata["selectedJson"]["descriptor"]["keys"], ["digest", "mediaType"]
        )
        self.assertNotIn("qualification", serialize_probe_payload(payload))

    def test_invalid_scope_and_revision_are_rejected_by_cli_parser(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["artifact", "probe", "other", "--revision", REVISION])
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["artifact", "probe", "kwrag-product", "--revision", "A" * 40]
            )
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "artifact",
                    "probe",
                    "kwrag-product",
                    "--revision",
                    REVISION,
                    "--path",
                    "/tmp",
                ]
            )
        with self.assertRaises(ArtifactProbeError):
            validate_revision("1" * 39)

    def test_symlink_matching_directory_is_rejected(self) -> None:
        root = Node("directory", children={FINAL_NAME: Node("symlink")})
        with self.assertRaisesRegex(ArtifactProbeError, "matching_directory_symlink"):
            run_probe(root)

    def test_hardlink_nonregular_and_oversize_artifacts_are_rejected(self) -> None:
        cases = (
            (Node("file", data=b"{}", nlink=2), "artifact_hardlink"),
            (Node("fifo"), "artifact_not_regular"),
            (Node("file", stat_size=MAX_FILE_BYTES + 1), "artifact_size_limit"),
        )
        for artifact, code in cases:
            with self.subTest(code=code):
                root = Node(
                    "directory",
                    children={
                        FINAL_NAME: Node(
                            "directory", children={"build-metadata.json": artifact}
                        )
                    },
                )
                with self.assertRaisesRegex(ArtifactProbeError, code):
                    run_probe(root)

    def test_invalid_and_duplicate_key_json_are_rejected(self) -> None:
        cases = (
            (b"{", "json_parse_failed"),
            (b'{"schema":"one","schema":"two"}', "json_duplicate_key"),
        )
        for data, code in cases:
            with self.subTest(code=code):
                root = Node(
                    "directory",
                    children={
                        FINAL_NAME: Node(
                            "directory",
                            children={
                                "image-build-receipt.json": Node("file", data=data)
                            },
                        )
                    },
                )
                with self.assertRaisesRegex(ArtifactProbeError, code):
                    run_probe(root)

    def test_matching_directory_cardinality_is_bounded(self) -> None:
        children = {
            f".staging-kwrag-product-{REVISION}-20260727T{index:06d}Z": Node(
                "directory"
            )
            for index in range(17)
        }
        with self.assertRaisesRegex(ArtifactProbeError, "matching_directory_limit"):
            run_probe(Node("directory", children=children))

    def test_file_pre_post_fstat_mutation_is_rejected(self) -> None:
        artifact = Node("file", data=metadata_bytes(), mutate_after_open=True)
        root = Node(
            "directory",
            children={
                FINAL_NAME: Node(
                    "directory", children={"build-metadata.json": artifact}
                )
            },
        )
        with self.assertRaisesRegex(ArtifactProbeError, "artifact_toctou"):
            run_probe(root)

    def test_total_artifact_bytes_are_bounded(self) -> None:
        padding = "x" * (2 * 1024 * 1024 - 256)
        data = json.dumps(
            {"schema": "fixture", "padding": padding}, separators=(",", ":")
        ).encode()
        children = {
            f".staging-kwrag-product-{REVISION}-20260727T{index:06d}Z": Node(
                "directory",
                children={"image-build-receipt.json": Node("file", data=data)},
            )
            for index in range(5)
        }
        with self.assertRaisesRegex(ArtifactProbeError, "artifact_size_limit"):
            run_probe(Node("directory", children=children))

    def test_stdout_is_bounded(self) -> None:
        artifact = Node("file", data=metadata_bytes(extra_keys=9000))
        root = Node(
            "directory",
            children={
                FINAL_NAME: Node(
                    "directory", children={"build-metadata.json": artifact}
                )
            },
        )
        with self.assertRaisesRegex(ArtifactProbeError, "stdout_size_limit"):
            run_probe(root)

    def test_docker_timeout_oversize_and_multiple_match_are_rejected(self) -> None:
        class TimeoutDocker(FakeDocker):
            def __call__(self, argv, *, timeout, output_limit):
                raise ArtifactProbeError("docker_timeout")

        with self.assertRaisesRegex(ArtifactProbeError, "docker_timeout"):
            run_probe(valid_root(), TimeoutDocker())

        oversized = FakeDocker()
        oversized.inspect_stdout = b"x" * (MAX_DOCKER_OUTPUT_BYTES + 1)
        with self.assertRaisesRegex(ArtifactProbeError, "docker_output_limit"):
            run_probe(valid_root(), oversized)

        multiple = FakeDocker(images=[valid_image(), valid_image()])
        with self.assertRaisesRegex(
            ArtifactProbeError, "docker_inspect_multiple_matches"
        ):
            run_probe(valid_root(), multiple)

        duplicate_ancestor = FakeDocker(
            ancestors=("a" * 64 + "\n" + "a" * 64 + "\n").encode()
        )
        with self.assertRaisesRegex(
            ArtifactProbeError, "docker_ancestor_output_invalid"
        ):
            run_probe(valid_root(), duplicate_ancestor)

    def test_production_subprocess_runner_enforces_timeout_and_stream_cap(self) -> None:
        with self.assertRaisesRegex(ArtifactProbeError, "docker_output_limit"):
            _default_docker_runner(
                [
                    sys.executable,
                    "-c",
                    "import sys;sys.stdout.buffer.write(b'x'*4096);sys.stdout.flush()",
                ],
                timeout=5,
                output_limit=1024,
            )
        with self.assertRaisesRegex(ArtifactProbeError, "docker_timeout"):
            _default_docker_runner(
                [sys.executable, "-c", "import time;time.sleep(2)"],
                timeout=0.05,
                output_limit=1024,
            )

    def test_cli_dispatch_emits_json_and_requires_root(self) -> None:
        args = argparse.Namespace(scope="kwrag-product", revision=REVISION)
        with patch("agent_runtime_ops.commands.artifact.is_root", return_value=False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cmd_artifact_probe(args), 2)
            self.assertEqual(
                json.loads(output.getvalue())["error"]["code"], "root_required"
            )

        expected = {"schema": "fixture", "writes": 0}
        with (
            patch("agent_runtime_ops.commands.artifact.is_root", return_value=True),
            patch(
                "agent_runtime_ops.commands.artifact.probe_kwrag_product_artifact",
                return_value=expected,
            ) as probe,
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cmd_artifact_probe(args), 0)
            probe.assert_called_once_with(REVISION)
            self.assertEqual(json.loads(output.getvalue()), expected)

    def test_install_packaging_and_sudoers_are_exact_and_no_broad_surface_is_added(
        self,
    ) -> None:
        install = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn(
            'artifact probe kwrag-product --revision *\\n\' "$OPS_USER" "$BIN_LINK"',
            install,
        )
        self.assertNotIn(" artifact *", install)
        self.assertTrue(Path("opsctl/agent_runtime_ops/commands/artifact.py").is_file())
        self.assertTrue(
            Path("opsctl/agent_runtime_ops/domain/artifact_probe.py").is_file()
        )

        source = Path("opsctl/agent_runtime_ops/domain/artifact_probe.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("tempfile", source)
        self.assertNotIn("write_text", source)
        self.assertNotIn("os.write", source)
        self.assertNotIn("network", source.lower())
        self.assertNotIn("gpu", source.lower())
        self.assertNotIn("pid", source.lower())
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
