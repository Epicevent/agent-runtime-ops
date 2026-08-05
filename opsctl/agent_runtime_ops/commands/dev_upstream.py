from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import urllib.request

from ..apache import parse_apache_route, set_apache_proxy_port
from ..domain.common import is_root
from ..profiles import load_profile
from ..state import load_runtime_target


def _state_path(state_root: Path, target: str) -> Path:
    return state_root / "dev-upstreams" / f"{target}.json"


def _rootless_port(owner: str, container: str) -> int:
    uid = int(subprocess.run(["id", "-u", owner], text=True, capture_output=True, check=True).stdout.strip())
    proc = subprocess.run(
        ["runuser", "-u", owner, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", "docker", "inspect", container,
         "--format", "{{json .NetworkSettings.Ports}} {{.State.Running}} {{.State.Health.Status}}"],
        text=True, capture_output=True, check=True,
    )
    raw, running, health = proc.stdout.strip().rsplit(" ", 2)
    ports = json.loads(raw)
    bindings = ports.get("3000/tcp") or []
    if running != "true" or health not in {"healthy", ""} or len(bindings) != 1:
        raise ValueError("rootless container is not a healthy single-port Hermes workspace")
    binding = bindings[0]
    if binding.get("HostIp") != "127.0.0.1":
        raise ValueError("rootless workspace must bind only host loopback")
    return int(binding["HostPort"])


def _validate_target(target: str, state_root: Path) -> None:
    desired = load_runtime_target(target, state_root)
    profile = load_profile(desired.runtime_profile)
    if not target.startswith("dev-") or desired.family != "hermes" or desired.runtime_class != "dev" or profile.metadata.get("mode") != "source":
        raise ValueError("dev upstream requires a Hermes dev source-mode target")


def cmd_dev_upstream(args: argparse.Namespace) -> int:
    target, action = str(args.target), str(args.dev_upstream_command)
    root = Path(args.state_root or "/srv/openclaw-ops")
    path = _state_path(root, target)
    try:
        _validate_target(target, root)
        if action == "status":
            state = json.loads(path.read_text()) if path.exists() else None
            route = parse_apache_route(target)
            print(f"target={target}\ndev_upstream_status={'active' if state else 'inactive'}\napache_port={route.gateway_port}")
            if state:
                for key in ("owner", "container", "rootless_port", "rollback_port"):
                    print(f"{key}={state[key]}")
                print(f"route_matches_rootless={'yes' if route.gateway_port == state['rootless_port'] else 'no'}")
            return 0
        if not is_root():
            raise ValueError("run as root/admin through the managed opsctl grant")
        if action == "apply":
            if path.exists():
                raise ValueError("dev upstream is already active; rollback first")
            owner = os.environ.get("SUDO_USER") or ""
            if not owner or owner in {"root", "svcops"}:
                raise ValueError("apply requires a developer sudo identity")
            port = _rootless_port(owner, str(args.container))
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
                if response.status != 200 or b"Hermes Workspace" not in response.read(262144):
                    raise ValueError("rootless upstream workspace probe failed")
            route = parse_apache_route(target)
            change = set_apache_proxy_port(target, port, backup_suffix="dev-upstream")
            path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            payload = {"target": target, "owner": owner, "container": str(args.container), "rootless_port": port, "rollback_port": route.gateway_port}
            path.write_text(json.dumps(payload, sort_keys=True) + "\n")
            os.chmod(path, 0o640)
            print(f"target={target}\ncontainer={args.container}\nrootless_port={port}\nrollback_port={change.old_port}\ndev_upstream_apply_status=ok")
            return 0
        state = json.loads(path.read_text())
        route = parse_apache_route(target)
        if route.gateway_port != int(state["rootless_port"]):
            raise ValueError("apache route drifted; refusing automatic rollback")
        set_apache_proxy_port(target, int(state["rollback_port"]), backup_suffix="dev-upstream-rollback")
        path.unlink()
        print(f"target={target}\nrestored_port={state['rollback_port']}\ndev_upstream_rollback_status=ok")
        return 0
    except Exception as exc:
        print(f"target={target}\ndev_upstream_{action}_status=fail\nreason={exc}")
        return 1
