from __future__ import annotations

import argparse
from datetime import datetime, timezone
import sys

from ..apache import parse_apache_route, set_apache_host, validate_public_host
from ..domain.apache_route_checks import apache_route_checks as _apache_route_checks
from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..routing import RuntimeBinding, get_runtime_binding, load_runtime_bindings


def cmd_apache_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        bindings = load_runtime_bindings(state_root)
        if getattr(args, "target", None):
            bindings = [get_runtime_binding(str(args.target), state_root)]
    except Exception as exc:
        print("apache_status=fail")
        print(f"reason={exc}")
        return 1
    failed = 0
    count = 0
    for binding in bindings:
        count += 1
        try:
            apache_route = parse_apache_route(binding.linux_account)
            print(
                f"linux_account={binding.linux_account} "
                f"expected_public_host={binding.public_host} "
                f"public_host={apache_route.public_host} "
                f"gateway_port={apache_route.gateway_port} "
                f"binding_gateway_port={binding.gateway_port} "
                f"bridge_port={binding.bridge_port} "
                f"enabled={'yes' if binding.enabled else 'no'} "
                f"apache_file={apache_route.path}"
            )
            for ok, name, detail in _apache_route_checks(binding, apache_route):
                if getattr(args, "target", None):
                    _check_line(ok, name, detail)
                if not ok:
                    failed += 1
        except Exception as exc:
            failed += 1
            print(f"linux_account={binding.linux_account} apache_status=fail reason={exc}")
    print(f"apache_status={'ok' if failed == 0 else 'fail'} count={count} failed={failed}")
    return 0 if failed == 0 else 1


def cmd_apache_set_host(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apache set-host LINUX_ACCOUNT HOST", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    linux_account = str(args.linux_account)
    try:
        host = validate_public_host(str(args.host))
        binding = get_runtime_binding(linux_account, state_root)
        if binding.linux_account != linux_account:
            raise ValueError("apache set-host repair target must be a linux_account, not public_host or instance_id")
        before = parse_apache_route(linux_account)
        suffix = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d%H%M%S")
        change = set_apache_host(linux_account, host, backup_suffix=suffix)
        after = parse_apache_route(linux_account)
        repair_binding = RuntimeBinding(
            instance_id=binding.instance_id,
            linux_account=binding.linux_account,
            public_host=host,
            family=binding.family,
            runtime_class=binding.runtime_class,
            gateway_port=binding.gateway_port,
            bridge_port=binding.bridge_port,
            enabled=binding.enabled,
        )
        for ok, name, detail in _apache_route_checks(repair_binding, after):
            if not ok:
                raise ValueError(f"{name}: {detail}")
    except Exception as exc:
        print(f"linux_account={linux_account}")
        print("apache_set_host_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"linux_account={linux_account}")
    print(f"old_public_host={change.old_host}")
    print(f"public_host={change.new_host}")
    print(f"gateway_port={after.gateway_port}")
    print(f"binding_gateway_port={binding.gateway_port}")
    print(f"apache_file={change.path}")
    print(f"backup_file={change.backup_path}")
    print("warning=apache_set_host_only_updates_apache_use_binding_set_public_host_for_normal_changes")
    print("apache_set_host_status=ok")
    return 0
