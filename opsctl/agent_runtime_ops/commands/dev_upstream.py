from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import urllib.request

from ..apache import parse_apache_route, set_apache_proxy_port
from ..domain.common import is_root, sudo_user
from ..profiles import load_profile
from ..routing import load_runtime_bindings, replace_runtime_binding
from ..state import load_runtime_target
from .binding import _write_runtime_bindings_file


def _state_path(root: Path, target: str) -> Path:
    return root / "dev-upstreams" / f"{target}.json"


def _write_state(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _inspect_rootless(owner: str, container: str) -> tuple[int, str]:
    if container != f"{owner}-hermes-src":
        raise ValueError("rootless container identity must be OWNER-hermes-src")
    uid = int(subprocess.run(["id", "-u", owner], text=True, capture_output=True, check=True).stdout.strip())
    proc = subprocess.run(
        ["runuser", "-u", owner, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{uid}", "docker", "inspect", container],
        text=True, capture_output=True, check=True,
    )
    info = json.loads(proc.stdout)[0]
    state, labels = info.get("State") or {}, (info.get("Config") or {}).get("Labels") or {}
    expected_source = f"/home/{owner}/src/jitech/hermes-workspace"
    expected_nas = f"/home/{owner}/runtime/{owner}-hermes-nas"
    mounts = info.get("Mounts") or []
    required = {
        (expected_source, "/opt/hermes-workspace", False),
        (expected_nas, "/workspace/nas_docs", False),
    }
    actual = {(m.get("Source"), m.get("Destination"), bool(m.get("RW"))) for m in mounts if m.get("Type") == "bind"}
    if not required <= actual:
        raise ValueError("rootless source or NAS read-only bind identity mismatch")
    expected_labels = {
        "com.jitech.local.owner": owner,
        "com.jitech.local.mode": "source",
        "com.jitech.local.source-repository": "hermes-workspace",
        "com.jitech.local.target": f"{owner.upper()}-HERMES-SRC",
        "com.epicevent.agent-runtime.family": "hermes",
        "com.epicevent.agent-runtime.runtime-contract.dev": "hermes-runtime-source-http-3000",
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise ValueError("rootless container labels do not match the Hermes source contract")
    revision = str(labels.get("com.jitech.local.source-revision") or "")
    head = subprocess.run(["git", "-C", expected_source, "rev-parse", "HEAD"], text=True, capture_output=True, check=True).stdout.strip()
    if revision != head:
        raise ValueError("rootless source revision does not match mounted checkout HEAD")
    bindings = ((info.get("NetworkSettings") or {}).get("Ports") or {}).get("3000/tcp") or []
    if state.get("Running") is not True or (state.get("Health") or {}).get("Status") != "healthy" or len(bindings) != 1:
        raise ValueError("rootless container is not a healthy single-port Hermes workspace")
    if bindings[0].get("HostIp") != "127.0.0.1":
        raise ValueError("rootless workspace must bind only host loopback")
    return int(bindings[0]["HostPort"]), revision


def _target(target: str, root: Path):
    desired = load_runtime_target(target, root)
    profile = load_profile(desired.runtime_profile)
    if not target.startswith("dev-") or desired.family != "hermes" or desired.runtime_class != "dev" or profile.metadata.get("mode") != "source":
        raise ValueError("dev upstream requires a Hermes dev source-mode target")
    return desired


def cmd_dev_upstream(args: argparse.Namespace) -> int:
    target, action, root = str(args.target), str(args.dev_upstream_command), Path(args.state_root or "/srv/openclaw-ops")
    path = _state_path(root, target)
    try:
        if bool(getattr(args, "authorization_check", False)):
            owner = sudo_user()
            if not is_root() or not owner or owner in {"root", "svcops"}:
                raise ValueError("authorization check requires a developer managed grant")
            print(f"target={target}\ndev_upstream_{action}_authorization=ok")
            return 0
        desired = _target(target, root)
        route = parse_apache_route(desired.route.linux_account)
        state = json.loads(path.read_text()) if path.exists() else None
        if action == "status":
            active = desired.route.upstream_kind == "developer-rootless"
            agreement = bool(active and state and route.gateway_port == desired.route.gateway_port == state["rootless_port"])
            print(f"target={target}\ndev_upstream_status={'active' if active else 'inactive'}\nbinding_upstream_kind={desired.route.upstream_kind}\nbinding_gateway_port={desired.route.gateway_port}\napache_port={route.gateway_port}\nmanaged_truth_agreement={'yes' if agreement else 'no'}")
            return 0 if (not active and not state and route.gateway_port == desired.route.gateway_port) or agreement else 1
        if not is_root():
            raise ValueError("run as root/admin through the managed opsctl grant")
        if action == "apply":
            owner = sudo_user()
            if not owner or owner in {"root", "svcops"} or state or desired.route.upstream_kind != "managed-rootful":
                raise ValueError("apply requires a developer identity and an inactive managed-rootful target")
            port, revision = _inspect_rootless(owner, str(args.container))
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
                if response.status != 200 or b"Hermes Workspace" not in response.read(262144):
                    raise ValueError("rootless workspace probe failed")
            payload = {"status": "prepared", "target": target, "instance_id": desired.route.instance_id, "owner": owner, "container": str(args.container), "source_revision": revision, "rootless_port": port, "rollback_binding": desired.route.to_json()}
            _write_state(path, payload)  # durable rollback intent precedes mutation
            replacement = replace(desired.route, gateway_port=port, upstream_kind="developer-rootless", upstream_owner=owner, upstream_container=str(args.container))
            bindings = load_runtime_bindings(root)
            try:
                _write_runtime_bindings_file(root, replace_runtime_binding(bindings, desired.route.instance_id, replacement))
                set_apache_proxy_port(target, port, backup_suffix="dev-upstream")
                payload["status"] = "active"
                _write_state(path, payload)
            except Exception:
                _write_runtime_bindings_file(root, bindings)
                if parse_apache_route(target).gateway_port != route.gateway_port:
                    set_apache_proxy_port(target, route.gateway_port, backup_suffix="dev-upstream-abort")
                raise
            print(f"target={target}\ninstance_id={replacement.instance_id}\nrootless_port={port}\nsource_revision={revision}\ndev_upstream_apply_status=ok")
            return 0
        if not state or state.get("status") != "active" or desired.route.upstream_kind != "developer-rootless":
            raise ValueError("active managed rootless state is required for rollback")
        old = desired.route.__class__(**state["rollback_binding"])
        bindings = load_runtime_bindings(root)
        _write_runtime_bindings_file(root, replace_runtime_binding(bindings, desired.route.instance_id, old))
        try:
            set_apache_proxy_port(target, old.gateway_port, backup_suffix="dev-upstream-rollback")
        except Exception:
            _write_runtime_bindings_file(root, bindings)
            raise
        path.unlink()
        print(f"target={target}\nrestored_port={old.gateway_port}\ndev_upstream_rollback_status=ok")
        return 0
    except Exception as exc:
        print(f"target={target}\ndev_upstream_{action}_status=fail\nreason={exc}")
        return 1
