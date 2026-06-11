from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import sys

from ..apache import parse_apache_route, set_apache_host
from ..domain.apache_route_checks import apache_route_checks as _apache_route_checks
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..host.files import fsync_parent as _fsync_parent
from ..routing import (
    RuntimeBinding,
    dump_runtime_bindings,
    get_runtime_binding,
    load_runtime_bindings,
    replace_runtime_binding,
    runtime_bindings_path,
    validate_public_host as validate_binding_public_host,
)


def cmd_binding_list(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        bindings = load_runtime_bindings(state_root)
    except Exception as exc:
        print("binding_list_status=fail")
        print(f"reason={exc}")
        return 1
    for binding in bindings:
        print(
            f"instance_id={binding.instance_id} "
            f"linux_account={binding.linux_account} "
            f"public_host={binding.public_host} "
            f"family={binding.family} "
            f"runtime_class={binding.runtime_class} "
            f"gateway_port={binding.gateway_port} "
            f"bridge_port={binding.bridge_port} "
            f"enabled={'yes' if binding.enabled else 'no'}"
        )
    print(f"binding_list_status=ok count={len(bindings)}")
    return 0


def cmd_binding_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        target = getattr(args, "target", None)
        bindings = [get_runtime_binding(str(target), state_root)] if target else load_runtime_bindings(state_root)
    except Exception as exc:
        print("binding_status=fail")
        print(f"reason={exc}")
        return 1
    failed = 0
    for binding in bindings:
        try:
            apache_route = parse_apache_route(binding.linux_account)
            print(
                f"instance_id={binding.instance_id} "
                f"linux_account={binding.linux_account} "
                f"public_host={binding.public_host} "
                f"family={binding.family} "
                f"runtime_class={binding.runtime_class} "
                f"gateway_port={binding.gateway_port} "
                f"bridge_port={binding.bridge_port} "
                f"enabled={'yes' if binding.enabled else 'no'} "
                f"actual_public_host={apache_route.public_host} "
                f"actual_gateway_port={apache_route.gateway_port}"
            )
            for ok, name, detail in _apache_route_checks(binding, apache_route):
                if target:
                    _check_line(ok, name, detail)
                if not ok:
                    failed += 1
        except Exception as exc:
            failed += 1
            print(f"linux_account={binding.linux_account} binding_status=fail reason={exc}")
    print(f"binding_status={'ok' if failed == 0 else 'fail'} count={len(bindings)} failed={failed}")
    return 0 if failed == 0 else 1


def _write_runtime_bindings_file(state_root: Path, bindings: list[RuntimeBinding]) -> Path:
    path = runtime_bindings_path(state_root)
    if path.exists() and path.is_symlink():
        raise ValueError(f"runtime bindings must not be symlink: {path}")
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(dump_runtime_bindings(bindings))
            handle.flush()
            os.fsync(handle.fileno())
        if hasattr(os, "chown"):
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
        _fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return path


def cmd_binding_normalize(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        path = runtime_bindings_path(state_root)
        if not path.exists():
            raise FileNotFoundError(f"runtime bindings not found: {path}")
        bindings = load_runtime_bindings(state_root)
        text = dump_runtime_bindings(bindings)
        if getattr(args, "write", False):
            if not _is_root():
                print("error: run as root/admin: sudo /usr/local/bin/opsctl binding normalize --write", file=sys.stderr)
                return 2
            if path.exists() and path.is_symlink():
                raise ValueError(f"runtime bindings must not be symlink: {path}")
            if path.exists():
                backup_path = path.with_name(f"{path.name}.{datetime.now(timezone.utc).astimezone().strftime('%Y%m%d%H%M%S')}.bak")
                shutil.copy2(path, backup_path)
                print(f"backup_file={backup_path}")
            _write_runtime_bindings_file(state_root, bindings)
            print(f"runtime_bindings={path}")
        else:
            print(text, end="")
    except Exception as exc:
        print("binding_normalize_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"binding_normalize_status=ok count={len(bindings)} write={'yes' if getattr(args, 'write', False) else 'no'}")
    return 0


def cmd_binding_set_public_host(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl binding set-public-host TARGET HOST", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    target = str(args.target)
    host = validate_binding_public_host(str(args.host))
    old_text = ""
    path = runtime_bindings_path(state_root)
    try:
        old_text = path.read_text(encoding="utf-8")
        bindings = load_runtime_bindings(state_root)
        binding = get_runtime_binding(target, state_root)
        replacement = RuntimeBinding(
            instance_id=binding.instance_id,
            linux_account=binding.linux_account,
            public_host=host,
            family=binding.family,
            runtime_class=binding.runtime_class,
            gateway_port=binding.gateway_port,
            bridge_port=binding.bridge_port,
            enabled=binding.enabled,
        )
        bindings = replace_runtime_binding(bindings, binding.instance_id, replacement)
        suffix = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d%H%M%S")
        change = set_apache_host(binding.linux_account, host, backup_suffix=suffix)
        try:
            _write_runtime_bindings_file(state_root, bindings)
        except Exception:
            if old_text:
                path.write_text(old_text, encoding="utf-8")
            set_apache_host(binding.linux_account, binding.public_host, backup_suffix=f"{suffix}.rollback")
            raise
        after = parse_apache_route(binding.linux_account)
        for ok, name, detail in _apache_route_checks(replacement, after):
            if not ok:
                raise ValueError(f"{name}: {detail}")
    except Exception as exc:
        print(f"target={target}")
        print("binding_set_public_host_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"instance_id={binding.instance_id}")
    print(f"linux_account={binding.linux_account}")
    print(f"old_public_host={binding.public_host}")
    print(f"public_host={host}")
    print(f"gateway_port={after.gateway_port}")
    print(f"runtime_bindings={path}")
    print(f"apache_file={change.path}")
    print(f"apache_backup_file={change.backup_path}")
    print("binding_set_public_host_status=ok")
    return 0
