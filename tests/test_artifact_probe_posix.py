from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from agent_runtime_ops.domain.artifact_probe import (
    ArtifactProbeError,
    CommandResult,
    OsSyscalls,
    probe_kwrag_product_artifact,
)


REVISION = "2" * 40
CANDIDATE = "kwrag-product:candidate-22222222"


def docker_runner(argv: list[str], *, timeout: int, output_limit: int) -> CommandResult:
    if argv[:3] == ["docker", "image", "inspect"]:
        return CommandResult(
            0,
            json.dumps(
                [
                    {
                        "Id": "sha256:" + "a" * 64,
                        "Os": "linux",
                        "Architecture": "arm64",
                        "RepoTags": [CANDIDATE],
                        "RepoDigests": [],
                        "Created": "2026-07-27T00:00:00Z",
                        "Size": 1,
                        "RootFS": {"Layers": ["sha256:" + "b" * 64]},
                        "Config": {
                            "Labels": {"org.opencontainers.image.revision": REVISION}
                        },
                    }
                ]
            ).encode(),
            b"",
        )
    return CommandResult(0, b"", b"")


@unittest.skipUnless(
    os.name == "posix", "real dir_fd/O_NOFOLLOW coverage requires POSIX"
)
class PosixArtifactProbeTests(unittest.TestCase):
    def _root(self, base: Path) -> tuple[Path, Path]:
        root = base / "image-builds"
        final = root / f"kwrag-product-{REVISION}"
        final.mkdir(parents=True)
        (final / "build-metadata.json").write_text(
            json.dumps(
                {
                    "containerimage.digest": "sha256:" + "a" * 64,
                    "containerimage.config.digest": "sha256:" + "a" * 64,
                    "image.name": "docker.io/library/" + CANDIDATE,
                }
            ),
            encoding="utf-8",
        )
        return root, final

    def test_real_fd_relative_valid_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._root(Path(tmp))
            payload = probe_kwrag_product_artifact(
                REVISION,
                build_root=root,
                docker_runner=docker_runner,
                observed_at="2026-07-27T00:00:00+00:00",
            )
            self.assertEqual(payload["writes"], 0)
            self.assertEqual(payload["directoryObservation"]["matchingCount"], 1)

    def test_real_fd_relative_symlink_hardlink_and_fifo_catches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "image-builds"
            root.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (root / f"kwrag-product-{REVISION}").symlink_to(
                outside, target_is_directory=True
            )
            with self.assertRaisesRegex(
                ArtifactProbeError, "matching_directory_symlink"
            ):
                probe_kwrag_product_artifact(
                    REVISION, build_root=root, docker_runner=docker_runner
                )

        with tempfile.TemporaryDirectory() as tmp:
            root, final = self._root(Path(tmp))
            source = final / "source.json"
            source.write_text("{}", encoding="utf-8")
            metadata = final / "build-metadata.json"
            metadata.unlink()
            os.link(source, metadata)
            with self.assertRaisesRegex(ArtifactProbeError, "artifact_hardlink"):
                probe_kwrag_product_artifact(
                    REVISION, build_root=root, docker_runner=docker_runner
                )

        with tempfile.TemporaryDirectory() as tmp:
            root, final = self._root(Path(tmp))
            metadata = final / "build-metadata.json"
            metadata.unlink()
            os.mkfifo(metadata)
            with self.assertRaisesRegex(ArtifactProbeError, "artifact_not_regular"):
                probe_kwrag_product_artifact(
                    REVISION, build_root=root, docker_runner=docker_runner
                )

    def test_regular_file_swapped_to_fifo_before_open_does_not_block(self) -> None:
        class SwapToFifoSyscalls(OsSyscalls):
            swapped = False

            def stat(
                self, path: str, *, dir_fd: int, follow_symlinks: bool
            ) -> os.stat_result:
                value = super().stat(
                    path, dir_fd=dir_fd, follow_symlinks=follow_symlinks
                )
                if not self.swapped and path == "build-metadata.json":
                    os.unlink(path, dir_fd=dir_fd)
                    os.mkfifo(path, mode=0o600, dir_fd=dir_fd)
                    self.swapped = True
                return value

        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._root(Path(tmp))
            started = time.monotonic()
            with self.assertRaisesRegex(
                ArtifactProbeError, "artifact_(toctou|not_regular)"
            ):
                probe_kwrag_product_artifact(
                    REVISION,
                    build_root=root,
                    syscalls=SwapToFifoSyscalls(),
                    docker_runner=docker_runner,
                )
            self.assertLess(time.monotonic() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
