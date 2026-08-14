import ctypes
import os
from pathlib import Path
import platform

from .bind_mounts import _reject_existing_symlink_components
from .mounts import findmnt_one, mountinfo_under


_AT_FDCWD = -100
_OPEN_TREE_FLAGS = (0x80000, 0x88001)
_OPEN_TREE_FROM_FD_FLAGS = 0x89001
_MOVE_MOUNT_FLAGS = (4, 0x204)
_SYS_OPEN_TREE, _SYS_MOVE_MOUNT, _SYS_MOUNT_SETATTR = 428, 429, 442
_MACHINES = frozenset({"aarch64", "x86_64"})


class _MountAttr(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in ("attr_set", "attr_clr", "propagation", "userns_fd")
    ]


def _syscall(number: int, *args: object) -> int:
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.argtypes = [ctypes.c_long]
    syscall.restype = ctypes.c_long
    result = syscall(ctypes.c_long(number), *args)
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def _open_tree(path: Path, *, clone: bool) -> int:
    return _syscall(
        _SYS_OPEN_TREE,
        ctypes.c_long(_AT_FDCWD),
        ctypes.c_char_p(os.fsencode(path)),
        ctypes.c_ulong(_OPEN_TREE_FLAGS[clone]),
    )


def _clone_tree_from_fd(fd: int) -> int:
    return _syscall(
        _SYS_OPEN_TREE,
        ctypes.c_long(fd),
        ctypes.c_char_p(b""),
        ctypes.c_ulong(_OPEN_TREE_FROM_FD_FLAGS),
    )


def _move_mount(fd: int, target: Path, *, beneath: bool) -> None:
    _syscall(
        _SYS_MOVE_MOUNT,
        ctypes.c_long(fd),
        ctypes.c_char_p(b""),
        ctypes.c_long(_AT_FDCWD),
        ctypes.c_char_p(os.fsencode(target)),
        ctypes.c_ulong(_MOVE_MOUNT_FLAGS[beneath]),
    )


def _make_private_tree(fd: int) -> None:
    attributes = _MountAttr(0, 0, 0x40000, 0)
    _syscall(
        _SYS_MOUNT_SETATTR,
        ctypes.c_long(fd),
        ctypes.c_char_p(b""),
        ctypes.c_ulong(0x9000),
        ctypes.byref(attributes),
        ctypes.c_size_t(ctypes.sizeof(attributes)),
    )


def detach_top(target: Path) -> None:
    umount2 = ctypes.CDLL(None, use_errno=True).umount2
    umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    umount2.restype = ctypes.c_int
    if umount2(ctypes.c_char_p(os.fsencode(target)), ctypes.c_int(2)) == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _require_safe_paths(candidate: Path, target: Path, anchor: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in _MACHINES:
        raise RuntimeError("unsupported_platform")
    paths = candidate, target, anchor
    if (
        len(set(paths)) != 3
        or any(not path.is_absolute() for path in paths)
        or candidate.parent != anchor.parent
        or candidate.parent == Path(candidate.anchor)
        or any(
            left in right.parents or right in left.parents
            for left, right in ((candidate, target), (anchor, target))
        )
    ):
        raise RuntimeError("unsafe_path_relation")
    for path, label in ((candidate, "candidate"), (target, "target")):
        _reject_existing_symlink_components(path, label)
        rc, error, rows = findmnt_one(path)
        if rc or len(rows) != 1 or rows[0].get("target") != path.as_posix():
            raise RuntimeError(error or f"{label}_not_exact_mount")
    _reject_existing_symlink_components(anchor, "rollback_anchor")
    rc, error, rows = findmnt_one(anchor)
    if not anchor.is_dir() or rc != 1 or rows:
        raise RuntimeError(error or "rollback_anchor_not_vacant")


def root_mount_layers(target: Path, pid: int = 1) -> int:
    rc, _, rows = mountinfo_under(pid, target.as_posix())
    if rc:
        raise RuntimeError("mountinfo_unavailable")
    layers = {
        int(row["mount_id"]): int(row["parent_id"])
        for row in rows
        if row["target"] == target.as_posix()
    }
    ids = set(layers)
    tops = ids - ({parent for parent in layers.values()} & ids)
    if len(tops) != 1:
        raise RuntimeError("mount_layer_graph_invalid")
    seen, current = set(), tops.pop()
    while current in ids:
        if current in seen:
            raise RuntimeError("mount_layer_graph_invalid")
        seen.add(current)
        current = layers[current]
    if seen != ids:
        raise RuntimeError("mount_layer_graph_invalid")
    return len(layers)


def prepare_transaction(candidate: Path, target: Path, anchor: Path) -> tuple[int, int]:
    _require_safe_paths(candidate, target, anchor)
    anchor_fd = candidate_fd = -1
    anchor_attached = False
    try:
        anchor_fd = _open_tree(target, clone=True)
        _make_private_tree(anchor_fd)
        _move_mount(anchor_fd, anchor, beneath=False)
        anchor_attached = True
        candidate_fd = _open_tree(candidate, clone=True)
        _make_private_tree(candidate_fd)
        detach_top(candidate)
        rc, _, rows = findmnt_one(candidate)
        if rc != 1 or rows:
            raise OSError(16, "candidate_source_not_vacant")
        return anchor_fd, candidate_fd
    except OSError as exc:
        undo = None
        if anchor_attached:
            try:
                detach_top(anchor)
            except OSError as cleanup_error:
                undo = cleanup_error
        for fd in (anchor_fd, candidate_fd):
            if fd >= 0:
                os.close(fd)
        if undo is not None:
            raise RuntimeError(f"prepare_undo_failed:{exc.errno}:{undo.errno}") from undo
        raise RuntimeError(f"prepare_failed:{exc.errno}") from exc
