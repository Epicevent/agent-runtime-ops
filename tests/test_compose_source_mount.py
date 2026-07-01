"""A dev source mount satisfies the contract when it maps the host build output into the
container AT the recipe's ``source_output_target`` OR at a PARENT that contains it.

Mounting only ``/app/dist/control-ui`` gives a live frontend but a baked server; mounting the
whole ``/app/dist`` (a parent of ``control-ui``) gives full-stack live dev — server
(``dist/index.js``) and UI both from source. Both must pass without changing the
``source_output_target`` label baked into wrapper images.
"""
from __future__ import annotations

from agent_runtime_ops.compose_contract import _mount_covers_target


def test_exact_target_is_covered():
    assert _mount_covers_target("/app/dist/control-ui", "/app/dist/control-ui")


def test_parent_mount_covers_child_target():
    # full-stack live: mount the whole dist, target label still points at control-ui
    assert _mount_covers_target("/app/dist", "/app/dist/control-ui")
    assert _mount_covers_target("/app/dist/", "/app/dist/control-ui")  # trailing slash tolerated


def test_child_mount_does_not_cover_parent_target():
    # mounting only control-ui cannot satisfy a target that needs all of /app/dist
    assert not _mount_covers_target("/app/dist/control-ui", "/app/dist")


def test_sibling_and_prefix_lookalikes_rejected():
    assert not _mount_covers_target("/app/dist", "/app/distribution")  # not a path boundary
    assert not _mount_covers_target("/app/other", "/app/dist/control-ui")


def test_empty_mount_never_covers():
    assert not _mount_covers_target("", "/app/dist/control-ui")
