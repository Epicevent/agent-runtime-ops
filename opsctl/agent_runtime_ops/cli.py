from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import getpass
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.error
import urllib.request
from pathlib import Path

from .apache import parse_apache_route, set_apache_host, validate_public_host
from .canonical_recipes import (
    canonical_label_values,
    canonical_recipe_for_product,
    canonical_recipe_for_image_spec,
    canonical_recipe_identity,
    list_canonical_recipe_names,
    load_canonical_recipe,
    projection_checks as canonical_projection_checks,
    validate_canonical_recipe,
)
from .compose_contract import validate_compose_contract
from .image_components import image_component_name as _image_component_name
from .image_components import image_repo as _image_repo
from .paths import DEFAULT_STATE_ROOT, REPO_ROOT
from .nas import (
    agent_nas_dir,
    check_nas_policy,
    customer_credential_path,
    history_dir,
    mountpoint_for_share,
    parse_smb_share,
    request_dir,
    request_path,
    root_credential_path,
)
from .profiles import list_profile_names, load_profile
from .redaction import redact
from .renderer import render_compose
from .routing import (
    RuntimeBinding,
    dump_runtime_bindings,
    get_runtime_binding,
    load_runtime_bindings,
    replace_runtime_binding,
    runtime_bindings_path,
    validate_linux_account,
    validate_public_host as validate_binding_public_host,
)
from .runtime_secrets import (
    PROVIDER_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_provider_secret_values,
)
from .state import RuntimeTarget, digest_from_image_ref, image_spec_from_manifest, load_runtime_target, runtime_manifest_path
from .yamlio import dump_yaml, load_yaml

DEFAULT_REPO_URL = "https://github.com/Epicevent/agent-runtime-ops.git"
UPDATE_POLICY_NAME = "ops-update.yaml"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"
DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"
IMAGE_RECIPE_LABEL_PREFIX = "com.epicevent.agent-runtime."
IMAGE_RECIPE_SCHEMA = "v1"
IMAGE_ROLLOUT_IMAGE_NAME = "direct-image"


def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.state_root)


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def _approved_update_from_policy(state_root: Path) -> tuple[str, str]:
    policy_path = state_root / UPDATE_POLICY_NAME
    data = load_yaml(policy_path)
    item = (data.get("updates") or {}).get("agent-runtime-ops")
    if not isinstance(item, dict):
        raise ValueError(f"missing updates.agent-runtime-ops in {policy_path}")
    repo_url = item.get("repo_url", DEFAULT_REPO_URL)
    ref = item.get("approved_ref")
    return str(repo_url), str(ref or "")


def _validate_update_target(repo_url: str, ref: str) -> None:
    if repo_url != DEFAULT_REPO_URL:
        raise ValueError(f"unapproved update repository: {repo_url}")
    if not FULL_SHA_RE.match(ref):
        raise ValueError("self-update requires an approved full 40-character commit sha")


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _installed_source_commit() -> str:
    manifest_path = REPO_ROOT / ".agent-runtime-ops-manifest"
    try:
        for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
            key, _, value = raw_line.partition("=")
            if key == "source_commit":
                return value.strip()
    except OSError:
        return ""
    return ""


def _write_update_policy(state_root: Path, ref: str) -> Path:
    _validate_update_target(DEFAULT_REPO_URL, ref)
    if not state_root.is_dir():
        raise FileNotFoundError(state_root)

    policy_path = state_root / UPDATE_POLICY_NAME
    data = {
        "meta": {
            "schema_version": 1,
            "updated_at": _now_iso(),
            "scope": "private_server_state",
        },
        "updates": {
            "agent-runtime-ops": {
                "repo_url": DEFAULT_REPO_URL,
                "approved_ref": ref,
                "approved_at": _now_iso(),
                "approved_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
            }
        },
    }

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_root, delete=False) as fh:
        tmp_path = Path(fh.name)
        fh.write(dump_yaml(data))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        if hasattr(os, "chown"):
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, policy_path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return policy_path


def cmd_profile_list(args: argparse.Namespace) -> int:
    for name in list_profile_names():
        profile = load_profile(name)
        print(f"{profile.name} {profile.digest}")
    return 0


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
    tmp_path.write_text(dump_runtime_bindings(bindings), encoding="utf-8")
    if hasattr(os, "chown"):
        os.chown(tmp_path, 0, state_root.stat().st_gid)
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, path)
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


def _apache_route_checks(binding: RuntimeBinding, apache_route) -> list[tuple[bool, str, str | None]]:
    checks = [
        (
            apache_route.public_host == binding.public_host,
            "apache_public_host_matches_binding",
            f"apache={apache_route.public_host} binding={binding.public_host}",
        ),
        (
            apache_route.gateway_port == binding.gateway_port,
            "apache_gateway_port_matches_binding",
            f"apache={apache_route.gateway_port} binding={binding.gateway_port}",
        )
    ]
    if apache_route.websocket_port is not None:
        checks.append(
            (
                apache_route.websocket_port == binding.gateway_port,
                "apache_websocket_port_matches_binding",
                f"apache={apache_route.websocket_port} binding={binding.gateway_port}",
            )
        )
    return checks


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


def cmd_self_update(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl self-update", file=sys.stderr)
        return 2
    if shutil.which("git") is None:
        print("error: missing command: git", file=sys.stderr)
        return 2
    if shutil.which("bash") is None:
        print("error: missing command: bash", file=sys.stderr)
        return 2

    try:
        repo_url, ref = _approved_update_from_policy(_state_root(args))
        policy_source = str(_state_root(args) / UPDATE_POLICY_NAME)
        _validate_update_target(repo_url, ref)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"hint: approve a full commit in {_state_root(args) / UPDATE_POLICY_NAME}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="agent-runtime-ops-update.") as tmp:
        repo = Path(tmp) / "agent-runtime-ops"
        print(f"update_repo={repo_url}")
        print(f"approved_ref={ref}")
        print(f"policy_source={policy_source}")
        try:
            subprocess.run(["git", "clone", "--no-checkout", repo_url, str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "fetch", "--depth", "1", "origin", ref], check=True)
            subprocess.run(["git", "-C", str(repo), "checkout", "--detach", ref], check=True)
            resolved = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            if resolved != ref:
                print(f"error: checkout mismatch: expected {ref}, got {resolved}", file=sys.stderr)
                return 1
            env = os.environ.copy()
            env["AGENT_RUNTIME_OPS_REF"] = ref
            subprocess.run(["bash", str(repo / "install.sh"), "install"], check=True, env=env)
        except subprocess.CalledProcessError as exc:
            return exc.returncode or 1
    return 0


def cmd_update_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl update approve FULL_SHA", file=sys.stderr)
        return 2
    try:
        policy_path = _write_update_policy(_state_root(args), args.ref)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"approved_ref={args.ref}")
    print(f"policy_file={policy_path}")
    return 0


def cmd_update_status(args: argparse.Namespace) -> int:
    installed_ref = _installed_source_commit()
    try:
        repo_url, ref = _approved_update_from_policy(_state_root(args))
        _validate_update_target(repo_url, ref)
    except Exception as exc:
        print("update_status=not_ready")
        if installed_ref:
            print(f"installed_ref={installed_ref}")
        print(f"reason={exc}")
        return 1
    matches = bool(installed_ref) and installed_ref == ref
    print(f"update_status={'current' if matches else 'ready'}")
    if installed_ref:
        print(f"installed_ref={installed_ref}")
    print(f"repo_url={repo_url}")
    print(f"approved_ref={ref}")
    print(f"approved_matches_installed={'yes' if matches else 'no'}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        binding = get_runtime_binding(args.slot, state_root)
        apache_route = parse_apache_route(binding.linux_account)
    except Exception as exc:
        print(f"status=unknown")
        print(f"reason={exc}")
        return 1
    print(f"instance_id={binding.instance_id}")
    print(f"linux_account={binding.linux_account}")
    print(f"public_host={binding.public_host}")
    print(f"actual_public_host={apache_route.public_host}")
    print(f"family={binding.family}")
    print(f"runtime_class={binding.runtime_class}")
    print(f"gateway_port={binding.gateway_port}")
    print(f"apache_gateway_port={apache_route.gateway_port}")
    print(f"bridge_port={binding.bridge_port}")
    print(f"enabled={'yes' if binding.enabled else 'no'}")
    for ok, name, detail in _apache_route_checks(binding, apache_route):
        _check_line(ok, name, detail)
        if not ok:
            print("status=fail")
            return 1
    if not _is_root():
        print("truth_source=live_image")
        print("truth_status=requires_live_root")
        print(f"next_action=sudo /usr/local/bin/opsctl runtime truth {binding.linux_account}")
        return 0
    try:
        truth, checks = _live_runtime_truth(binding.linux_account, state_root)
    except Exception as exc:
        print("truth_source=live_image")
        print("truth_status=fail")
        print(f"reason={exc}")
        return 1
    for key, value in truth.items():
        if key not in {
            "instance_id",
            "linux_account",
            "public_host",
            "actual_public_host",
            "family",
            "runtime_class",
            "gateway_port",
            "apache_gateway_port",
            "bridge_port",
            "enabled",
        }:
            print(f"{key}={value}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"status={'ok' if failed == 0 and truth.get('truth_status') == 'ok' else 'fail'}")
    return 0 if failed == 0 and truth.get("truth_status") == "ok" else 1


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        desired, profile = _desired_from_runtime_manifest(args.slot, _state_root(args))
    except Exception as exc:
        plan = {
            "target": args.slot,
            "status": "not_ready",
            "reason": str(exc),
            "mutates": False,
        }
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 1
    rendered = render_compose(profile, desired)
    plan = {
        "target": desired.slot,
        "linux_account": desired.route.linux_account,
        "family": desired.family,
        "runtime_class": desired.runtime_class,
        "image_name": desired.image_name,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "runtime_contract": _profile_runtime_contract(profile),
        "customer_surface": _profile_customer_surface(profile),
        "wrapper_image": desired.image_spec.get("wrapper_image"),
        "product_image": desired.image_spec.get("product_image"),
        "recipe": _image_spec_recipe_payload(desired.image_spec),
        "compose_sha256": rendered.sha256,
        "mutates": False,
    }
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def _check_line(ok: bool, name: str, detail: str | None = None) -> None:
    status = "PASS" if ok else "FAIL"
    if detail:
        print(f"{status} {name} {detail}")
    else:
        print(f"{status} {name}")


def _apache_public_host(slot: str) -> str:
    try:
        return parse_apache_route(slot).public_host
    except Exception:
        return ""


def _has_digest_ref(value: object) -> bool:
    return isinstance(value, str) and "@sha256:" in value


def _digest_from_image_ref(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


def _validate_safe_name(name: str) -> None:
    if not SAFE_NAME_RE.match(name):
        raise ValueError("name must contain only letters, numbers, '.', '_', or '-'")


def _validate_image_digest_ref(image_ref: str) -> str:
    if not IMAGE_REF_RE.match(image_ref):
        raise ValueError("image reference must be pinned by digest: REGISTRY/IMAGE@sha256:<64 hex>")
    digest = _digest_from_image_ref(image_ref)
    if not digest or not DIGEST_RE.match(digest):
        raise ValueError("image reference digest must be sha256:<64 hex>")
    return digest


def _optional_safe_text(value: object, name: str) -> str:
    text = str(value or "").strip()
    if text and not SAFE_TEXT_RE.match(text):
        raise ValueError(f"{name} must not contain control characters")
    return text


def _allowed_image_ref(family: object, role: str, image_ref: object) -> bool:
    if not isinstance(family, str) or not isinstance(image_ref, str):
        return False
    allowed = {
        ("openclaw", "wrapper"): (
            "ghcr.io/epicevent/agent-runtime-openclaw@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("openclaw", "product"): (
            "ghcr.io/epicevent/openclaw-jitech@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("hermes", "wrapper"): (
            "ghcr.io/epicevent/agent-runtime-hermes@sha256:",
            "ghcr.io/epicevent/hermes-jitech@sha256:",
            "ghcr.io/epicevent/hermes-workspace@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
        ("hermes", "product"): (
            "ghcr.io/epicevent/hermes-jitech@sha256:",
            "ghcr.io/epicevent/hermes-workspace@sha256:",
            "ghcr.io/epicevent/openclaw-nas-agent@sha256:",
        ),
    }
    return image_ref.startswith(allowed.get((family, role), ()))


def _metadata_list(value: object) -> list[str]:
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if isinstance(item, dict) and len(item) == 1 and next(iter(item.values())) is None:
                items.append(str(next(iter(item.keys()))))
            elif str(item):
                items.append(str(item))
        return items
    if isinstance(value, str) and value:
        return [value]
    return []


def _csv(values: list[str]) -> str:
    return ",".join(values)


def _profile_runtime_contract(profile) -> str:
    return str(profile.metadata.get("runtime_contract") or "")


def _profile_customer_surface(profile) -> str:
    return str(profile.metadata.get("customer_surface") or "")


def _image_spec_recipe_payload(image_spec: dict) -> dict[str, object]:
    product_image = image_spec.get("product_image")
    wrapper_image = image_spec.get("wrapper_image")
    image_recipe = _image_spec_recipe(image_spec)
    canonical_recipe = canonical_recipe_for_image_spec(image_spec)
    payload: dict[str, object] = {
        "mode": image_spec.get("mode") or "unknown",
        "product_component": image_recipe.get("product_component") or _image_component_name(product_image),
        "wrapper_component": image_recipe.get("wrapper_component") or _image_component_name(wrapper_image),
        "product_repo": _image_repo(product_image),
        "wrapper_repo": _image_repo(wrapper_image),
    }
    payload.update(canonical_recipe_identity(canonical_recipe))
    components = image_spec.get("components")
    if isinstance(components, dict):
        payload["components"] = {str(key): str(value) for key, value in components.items()}
    if image_recipe:
        payload["image_recipe"] = image_recipe
    return payload


def _image_spec_recipe_tokens(image_spec: dict) -> dict[str, str]:
    recipe = _image_spec_recipe_payload(image_spec)
    return {
        "recipe_mode": str(recipe.get("mode") or "unknown"),
        "product_component": str(recipe.get("product_component") or "unknown"),
        "wrapper_component": str(recipe.get("wrapper_component") or "unknown"),
        "canonical_recipe_name": str(recipe.get("canonical_recipe_name") or "unknown"),
        "canonical_recipe_digest": str(recipe.get("canonical_recipe_digest") or "unknown"),
    }


def _derived_image_components(product_image: str, wrapper_image: str) -> dict[str, str]:
    return {
        "product_image": product_image,
        "wrapper_image": wrapper_image,
        "product_component": _image_component_name(product_image),
        "wrapper_component": _image_component_name(wrapper_image),
    }


def _image_recipe_labels_from_wrapper(wrapper_image: str) -> dict[str, str]:
    docker = shutil.which("docker")
    if not docker:
        raise ValueError("docker is required to inspect wrapper image recipe labels")
    inspect = _run_text([docker, "image", "inspect", wrapper_image, "--format", "{{json .Config.Labels}}"], timeout=60)
    if inspect.returncode != 0:
        pull = _run_text([docker, "pull", wrapper_image], timeout=600)
        if pull.returncode != 0:
            raise ValueError(f"failed to pull wrapper image for recipe labels: {pull.stderr.strip() or pull.stdout.strip()}")
        inspect = _run_text([docker, "image", "inspect", wrapper_image, "--format", "{{json .Config.Labels}}"], timeout=60)
    if inspect.returncode != 0:
        raise ValueError(f"failed to inspect wrapper image recipe labels: {inspect.stderr.strip() or inspect.stdout.strip()}")
    try:
        labels = json.loads(inspect.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"wrapper image labels are not valid JSON: {exc}") from exc
    if not isinstance(labels, dict):
        raise ValueError("wrapper image labels are missing")
    return {str(key): str(value) for key, value in labels.items()}


def _recipe_label(labels: dict[str, str], name: str) -> str:
    return str(labels.get(IMAGE_RECIPE_LABEL_PREFIX + name) or "")


def _image_recipe_from_wrapper_image(wrapper_image: str, *, family: str, product_image: str) -> dict[str, object]:
    labels = _image_recipe_labels_from_wrapper(wrapper_image)
    schema = _recipe_label(labels, "recipe.schema")
    if schema != IMAGE_RECIPE_SCHEMA:
        raise ValueError(
            "wrapper image is missing agent-runtime recipe labels; rebuild wrapper with current publish workflow"
        )
    label_family = _recipe_label(labels, "family")
    label_product_image = _recipe_label(labels, "product-image")
    if label_family != family:
        raise ValueError(f"wrapper image recipe family mismatch: label={label_family or 'missing'} requested={family}")
    if label_product_image != product_image:
        raise ValueError("wrapper image recipe product-image does not match --product-image")
    customer_profile = _recipe_label(labels, "runtime-profile.customer")
    dev_profile = _recipe_label(labels, "runtime-profile.dev")
    customer_contract = _recipe_label(labels, "runtime-contract.customer")
    dev_contract = _recipe_label(labels, "runtime-contract.dev")
    product_component = _recipe_label(labels, "product-component")
    wrapper_component = _recipe_label(labels, "wrapper-component")
    command_mode = _recipe_label(labels, "command-mode")
    http_port = _recipe_label(labels, "http-port")
    source_output_target = _recipe_label(labels, "source-output-target")
    nas_container_root = _recipe_label(labels, "nas.container-root")
    nas_host_root_template = _recipe_label(labels, "nas.host-root-template")
    nas_read_only = _recipe_label(labels, "nas.read-only")
    nas_propagation = _recipe_label(labels, "nas.propagation")
    nas_child_mount_mode = _recipe_label(labels, "nas.child-mount-mode")
    canonical_name = _recipe_label(labels, "recipe.name")
    canonical_digest = _recipe_label(labels, "recipe.digest")
    if not canonical_name:
        raise ValueError("wrapper image recipe is missing canonical recipe name")
    if not canonical_digest:
        raise ValueError("wrapper image recipe is missing canonical recipe digest")
    required = {
        "recipe.name": canonical_name,
        "recipe.digest": canonical_digest,
        "product-component": product_component,
        "wrapper-component": wrapper_component,
        "runtime-profile.customer": customer_profile,
        "runtime-profile.dev": dev_profile,
        "runtime-contract.customer": customer_contract,
        "runtime-contract.dev": dev_contract,
        "command-mode": command_mode,
        "http-port": http_port,
        "source-output-target": source_output_target,
        "nas.container-root": nas_container_root,
        "nas.host-root-template": nas_host_root_template,
        "nas.read-only": nas_read_only,
        "nas.propagation": nas_propagation,
        "nas.child-mount-mode": nas_child_mount_mode,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError("wrapper image recipe labels are incomplete: " + ",".join(missing))
    derived_product_component = _image_component_name(product_image)
    derived_wrapper_component = _image_component_name(wrapper_image)
    if product_component != derived_product_component:
        raise ValueError(
            f"wrapper image recipe product-component mismatch: label={product_component} derived={derived_product_component}"
        )
    if wrapper_component != derived_wrapper_component:
        raise ValueError(
            f"wrapper image recipe wrapper-component mismatch: label={wrapper_component} derived={derived_wrapper_component}"
        )
    canonical_recipe = load_canonical_recipe(canonical_name)
    canonical_failures = [name for ok, name, _ in validate_canonical_recipe(canonical_recipe) if not ok]
    if canonical_failures:
        raise ValueError("canonical runtime recipe validation failed: " + ",".join(canonical_failures))
    expected_labels = canonical_label_values(canonical_recipe)
    label_checks = {
        "product-component": product_component,
        "wrapper-component": wrapper_component,
        "runtime-profile.customer": customer_profile,
        "runtime-profile.dev": dev_profile,
        "runtime-contract.customer": customer_contract,
        "runtime-contract.dev": dev_contract,
        "command-mode": command_mode,
        "working-dir": _recipe_label(labels, "working-dir"),
        "http-port": http_port,
        "source-output-target": source_output_target,
        "nas.container-root": nas_container_root,
        "nas.host-root-template": nas_host_root_template,
        "nas.read-only": nas_read_only,
        "nas.propagation": nas_propagation,
        "nas.child-mount-mode": nas_child_mount_mode,
    }
    for label_name, actual in label_checks.items():
        expected = expected_labels[label_name]
        if actual != expected:
            raise ValueError(
                f"wrapper image canonical recipe mismatch: {label_name} label={actual or 'missing'} canonical={expected or 'missing'}"
            )
    if canonical_name and canonical_name != canonical_recipe.name:
        raise ValueError(f"wrapper image canonical recipe name mismatch: label={canonical_name} canonical={canonical_recipe.name}")
    if canonical_digest and canonical_digest != canonical_recipe.digest:
        raise ValueError(
            f"wrapper image canonical recipe digest mismatch: label={canonical_digest} canonical={canonical_recipe.digest}"
        )
    recipe = {
        "schema": schema,
        "source": "wrapper_image_labels",
        "canonical_recipe_name": canonical_recipe.name,
        "canonical_recipe_digest": canonical_recipe.digest,
        "family": label_family,
        "product_image": label_product_image,
        "product_component": product_component,
        "wrapper_component": wrapper_component,
        "runtime_profiles": {
            "customer": customer_profile,
            "dev": dev_profile,
        },
        "runtime_contracts": {
            "customer": customer_contract,
            "dev": dev_contract,
        },
        "command_mode": command_mode,
        "working_dir": _recipe_label(labels, "working-dir"),
        "http_port": http_port,
        "source_output_target": source_output_target,
        "container_nas_root": nas_container_root,
        "host_nas_root_template": nas_host_root_template,
        "nas_read_only": nas_read_only,
        "nas_mount_propagation": nas_propagation,
        "nas_child_mount_mode": nas_child_mount_mode,
        "ops_repo_commit": _recipe_label(labels, "ops-repo-commit"),
    }
    for runtime_class, profile_name in recipe["runtime_profiles"].items():
        profile = load_profile(str(profile_name))
        if profile.metadata.get("family") != family:
            raise ValueError(f"recipe {runtime_class} profile family mismatch: {profile_name}")
        if profile.metadata.get("slot_class") != runtime_class:
            raise ValueError(f"recipe {runtime_class} profile runtime_class mismatch: {profile_name}")
        expected_contract = recipe["runtime_contracts"][runtime_class]
        if profile.metadata.get("runtime_contract") != expected_contract:
            raise ValueError(f"recipe {runtime_class} profile contract mismatch: {profile_name}")
        profile_component = str(profile.metadata.get("product_component") or "")
        if profile_component and profile_component != product_component:
            raise ValueError(f"recipe {runtime_class} profile product_component mismatch: {profile_name}")
    return recipe


def _image_recipe_from_wrapper_image_auto(wrapper_image: str, *, product_image: str) -> dict[str, object]:
    labels = _image_recipe_labels_from_wrapper(wrapper_image)
    family = _recipe_label(labels, "family")
    if family not in {"openclaw", "hermes"}:
        raise ValueError(f"wrapper image recipe family mismatch: label={family or 'missing'}")
    return _image_recipe_from_wrapper_image(wrapper_image, family=family, product_image=product_image)


def _image_spec_from_direct_images(wrapper_image: str, product_image: str) -> dict[str, object]:
    wrapper_digest = _validate_image_digest_ref(wrapper_image)
    product_digest = _validate_image_digest_ref(product_image)
    image_recipe = _image_recipe_from_wrapper_image_auto(wrapper_image, product_image=product_image)
    family = str(image_recipe.get("family") or "")
    if family not in {"openclaw", "hermes"}:
        raise ValueError("wrapper image recipe did not declare a supported family")
    if not _allowed_image_ref(family, "wrapper", wrapper_image):
        raise ValueError(f"wrapper image repository is not allowed for {family}")
    if not _allowed_image_ref(family, "product", product_image):
        raise ValueError(f"product image repository is not allowed for {family}")
    components = _derived_image_components(product_image, wrapper_image)
    components.update(
        {
            "product_component": str(image_recipe.get("product_component") or components["product_component"]),
            "wrapper_component": str(image_recipe.get("wrapper_component") or components["wrapper_component"]),
            "canonical_recipe_name": str(image_recipe.get("canonical_recipe_name") or ""),
            "canonical_recipe_digest": str(image_recipe.get("canonical_recipe_digest") or ""),
            "runtime_profile_customer": str(
                (image_recipe.get("runtime_profiles") or {}).get("customer")
                if isinstance(image_recipe.get("runtime_profiles"), dict)
                else ""
            ),
            "runtime_profile_dev": str(
                (image_recipe.get("runtime_profiles") or {}).get("dev")
                if isinstance(image_recipe.get("runtime_profiles"), dict)
                else ""
            ),
        }
    )
    return {
        "family": family,
        "image_name": IMAGE_ROLLOUT_IMAGE_NAME,
        "product_image": product_image,
        "wrapper_image": wrapper_image,
        "digest": wrapper_digest,
        "product_digest": product_digest,
        "components": components,
        "mode": "wrapped_product_image",
        "image_recipe": image_recipe,
    }


def _image_spec_recipe(image_spec: dict) -> dict[str, object]:
    recipe = image_spec.get("image_recipe")
    return recipe if isinstance(recipe, dict) else {}


def _image_spec_runtime_profile_name(image_spec: dict, runtime_class: str, fallback: str | None = None) -> str:
    recipe = _image_spec_recipe(image_spec)
    profiles = recipe.get("runtime_profiles")
    if isinstance(profiles, dict) and profiles.get(runtime_class):
        return str(profiles[runtime_class])
    if image_spec.get("mode") == "wrapped_product_image":
        raise ValueError("wrapped image is missing image recipe runtime profile; rebuild a labeled wrapper image")
    return str(fallback or "")


def _image_spec_profile_contract_checks(image_spec: dict, profile) -> list[tuple[bool, str, str | None]]:
    runtime_contract = _profile_runtime_contract(profile)
    customer_surface = _profile_customer_surface(profile)
    expected_components = _metadata_list(profile.metadata.get("expected_image_components"))
    compatible_product_prefixes = _metadata_list(profile.metadata.get("compatible_product_image_prefixes"))
    product_image = str(image_spec.get("product_image") or "")
    runtime_class = str(profile.metadata.get("slot_class") or "")
    image_recipe = _image_spec_recipe(image_spec)
    canonical_recipe = canonical_recipe_for_image_spec(image_spec)
    checks: list[tuple[bool, str, str | None]] = [
        (bool(runtime_contract), "runtime_contract_declared", f"contract={runtime_contract or 'missing'}"),
        (
            bool(customer_surface),
            "runtime_contract_customer_surface_declared",
            f"surface={customer_surface or 'missing'}",
        ),
    ]
    if canonical_recipe is not None:
        runtime_class = str(profile.metadata.get("slot_class") or "")
        canonical_profiles = canonical_recipe.data.get("runtime_profiles")
        canonical_profile_name = (
            canonical_profiles.get(runtime_class)
            if isinstance(canonical_profiles, dict)
            else ""
        )
        checks.extend(
            [
                (True, "canonical_recipe_identified", f"name={canonical_recipe.name} digest={canonical_recipe.digest}"),
                (
                    canonical_profile_name == profile.name,
                    "canonical_projection_matches_runtime_profile",
                    f"recipe={canonical_profile_name or 'missing'} profile={profile.name}",
                ),
                (
                    _image_repo(product_image) == canonical_recipe.data.get("product_image_repo"),
                    "canonical_product_repo_matches_image_spec",
                    f"image_spec={_image_repo(product_image) or 'missing'} canonical={canonical_recipe.data.get('product_image_repo') or 'missing'}",
                ),
                (
                    image_spec.get("mode") != "wrapped_product_image"
                    or _image_repo(image_spec.get("wrapper_image")) == canonical_recipe.data.get("wrapper_repo"),
                    "canonical_wrapper_repo_matches_image_spec",
                    f"image_spec={_image_repo(image_spec.get('wrapper_image')) or 'missing'} canonical={canonical_recipe.data.get('wrapper_repo') or 'missing'}",
                ),
                (
                    not image_recipe or image_recipe.get("canonical_recipe_digest") in (None, "", canonical_recipe.digest),
                    "canonical_recipe_digest_matches_image_spec",
                    f"image_spec={image_recipe.get('canonical_recipe_digest') if image_recipe else 'derived'} canonical={canonical_recipe.digest}",
                ),
            ]
        )
        checks.extend(canonical_projection_checks(canonical_recipe, runtime_class))
    elif image_spec.get("mode") == "wrapped_product_image":
        checks.append((False, "canonical_recipe_identified", f"product_image={product_image or 'missing'}"))
    else:
        checks.append((True, "canonical_recipe_not_required_for_unwrapped_image", f"product_image={product_image or 'missing'}"))
    if image_recipe:
        runtime_profiles = image_recipe.get("runtime_profiles")
        expected_profile = runtime_profiles.get(runtime_class) if isinstance(runtime_profiles, dict) else ""
        checks.append(
            (
                expected_profile == profile.name,
                "image_recipe_profile_matches_runtime_profile",
                f"recipe={expected_profile or 'missing'} profile={profile.name}",
            )
        )
        runtime_contracts = image_recipe.get("runtime_contracts")
        expected_contract = runtime_contracts.get(runtime_class) if isinstance(runtime_contracts, dict) else ""
        checks.append(
            (
                expected_contract == runtime_contract,
                "image_recipe_contract_matches_profile",
                f"recipe={expected_contract or 'missing'} profile={runtime_contract or 'missing'}",
            )
        )
        checks.append(
            (
                image_recipe.get("product_image") == product_image,
                "image_recipe_product_image_matches_spec",
                f"recipe={image_recipe.get('product_image') or 'missing'} image_spec={product_image or 'missing'}",
            )
        )
        profile_component = str(profile.metadata.get("product_component") or "")
        if profile_component:
            checks.append(
                (
                    image_recipe.get("product_component") == profile_component,
                    "image_recipe_product_component_matches_profile",
                    f"recipe={image_recipe.get('product_component') or 'missing'} profile={profile_component}",
                )
            )
    if expected_components:
        checks.append(
            (
                True,
                "runtime_contract_expected_components",
                "components=" + _csv(expected_components),
            )
        )
    if compatible_product_prefixes:
        ok = any(product_image.startswith(prefix) for prefix in compatible_product_prefixes)
        checks.append(
            (
                ok,
                "product_image_matches_runtime_contract",
                (
                    f"contract={runtime_contract or 'unknown'} "
                    f"product_component={_image_component_name(product_image)} "
                    f"expected_prefixes={_csv(compatible_product_prefixes)}"
                ),
            )
        )
    return checks


def _image_spec_profile_contract_failures(image_spec: dict, profile) -> list[str]:
    return [name for ok, name, _ in _image_spec_profile_contract_checks(image_spec, profile) if not ok]


def _container_name(slot: str, profile) -> str:
    service = profile.metadata.get("service") or "openclaw-gateway"
    return f"openclaw-{slot}-{service}-1"


def _run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _run_text_cwd(command: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _http_backend_smoke(slot: str, path: str, state_root: Path) -> tuple[bool, str]:
    try:
        binding = get_runtime_binding(slot, state_root)
        apache_route = parse_apache_route(binding.linux_account)
    except Exception as exc:
        return False, f"binding_truth_missing reason={exc}"
    port = binding.gateway_port
    smoke_path = path if path.startswith("/") else f"/{path}"
    url = f"http://127.0.0.1:{port}{smoke_path}"
    request = urllib.request.Request(url, headers={"Host": binding.public_host})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = int(response.getcode())
            return 200 <= status < 500, f"url={url} host={binding.public_host} status={status}"
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        return 200 <= status < 500, f"url={url} host={binding.public_host} status={status}"
    except Exception as exc:
        return False, f"url={url} host={binding.public_host} reason={exc}"


def _parse_findmnt_pairs(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        item: dict[str, str] = {}
        for part in shlex.split(line):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            item[key.lower()] = _decode_findmnt_value(value)
        if item:
            rows.append(item)
    return rows


def _decode_findmnt_value(value: str) -> str:
    def replace_hex(match: re.Match[str]) -> str:
        raw = match.group(0).encode("latin1").decode("unicode_escape").encode("latin1")
        return raw.decode("utf-8", errors="replace")

    return re.sub(r"(?:\\x[0-9A-Fa-f]{2})+", replace_hex, value)


def _decode_mountinfo_field(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(0)[1:], 8))

    return re.sub(r"\\[0-7]{3}", replace, value)


def _mountinfo_propagation(optional_fields: list[str]) -> str:
    has_shared = any(field.startswith("shared:") for field in optional_fields)
    has_master = any(field.startswith("master:") for field in optional_fields)
    if has_shared:
        return "shared"
    if has_master:
        return "slave"
    if "unbindable" in optional_fields:
        return "unbindable"
    return "private"


def _mountinfo_under(container_pid: int, path: str) -> tuple[int, str, list[dict[str, str]]]:
    mountinfo_path = Path("/proc") / str(container_pid) / "mountinfo"
    root = path.rstrip("/") or "/"
    try:
        lines = mountinfo_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return 1, str(exc), []

    rows: list[dict[str, str]] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 3 or separator < 6:
            continue
        target = _decode_mountinfo_field(fields[4])
        if target != root and not target.startswith(root + "/"):
            continue
        mount_options = fields[5]
        optional = fields[6:separator]
        fstype = fields[separator + 1]
        source = _decode_mountinfo_field(fields[separator + 2])
        super_options = fields[separator + 3]
        options = ",".join(part for part in (mount_options, super_options) if part)
        rows.append(
            {
                "target": target,
                "source": source,
                "fstype": fstype,
                "options": options,
                "propagation": _mountinfo_propagation(optional),
            }
        )
    return 0, "", rows


def _findmnt_tree(path: str, container_pid: int | None = None) -> tuple[int, str, list[dict[str, str]]]:
    if container_pid is not None:
        return _mountinfo_under(container_pid, path)
    command = ["findmnt", "-R", "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION", path]
    proc = _run_text(command)
    return proc.returncode, (proc.stderr or proc.stdout).strip(), _parse_findmnt_pairs(proc.stdout)


def _findmnt_under(path: str, container_pid: int | None = None) -> tuple[int, str, list[dict[str, str]]]:
    if container_pid is not None:
        return _mountinfo_under(container_pid, path)
    command = ["findmnt", "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION"]
    proc = _run_text(command)
    rows = [
        row
        for row in _parse_findmnt_pairs(proc.stdout)
        if row.get("target") == path or row.get("target", "").startswith(path.rstrip("/") + "/")
    ]
    return proc.returncode, (proc.stderr or proc.stdout).strip(), rows


def _is_readonly_mount(row: dict[str, str]) -> bool:
    options = row.get("options", "")
    return "ro" in {part.strip() for part in options.split(",") if part.strip()}


def _propagation_satisfies(actual: str | None, required: str | None) -> bool:
    if not required:
        return True
    value = (actual or "").lower()
    if required in {"rslave", "slave"}:
        return value in {"slave", "rslave", "shared", "rshared"}
    if required in {"rshared", "shared"}:
        return value in {"shared", "rshared"}
    return value == required


def _find_gateway_container(binding: RuntimeBinding, profile) -> tuple[str | None, str | None]:
    service_label = "gateway"
    by_label = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.instance-id={binding.instance_id}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if by_label.returncode == 0:
        ids = [line.strip() for line in by_label.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "instance_label"
        if len(ids) > 1:
            return None, f"multiple_instance_label_matches:{len(ids)}"
    legacy = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={binding.linux_account}",
            "--filter",
            f"label=agent-runtime.profile={profile.name}",
            "--filter",
            f"label=agent-runtime.service={service_label}",
            "--format",
            "{{.ID}}",
        ]
    )
    if legacy.returncode == 0:
        ids = [line.strip() for line in legacy.stdout.splitlines() if line.strip()]
        if len(ids) == 1:
            return ids[0], "legacy_linux_account_label"
        if len(ids) > 1:
            return None, f"multiple_legacy_label_matches:{len(ids)}"
    return _container_name(binding.linux_account, profile), "fallback_name"


def _find_gateway_container_by_binding(binding: RuntimeBinding) -> tuple[str | None, str | None]:
    by_label = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.instance-id={binding.instance_id}",
            "--filter",
            "label=agent-runtime.service=gateway",
            "--format",
            "{{.ID}}",
        ]
    )
    if by_label.returncode != 0:
        return None, (by_label.stderr or by_label.stdout).strip() or "docker_ps_failed"
    ids = [line.strip() for line in by_label.stdout.splitlines() if line.strip()]
    if len(ids) == 1:
        return ids[0], "instance_label"
    if len(ids) > 1:
        return None, f"multiple_instance_label_matches:{len(ids)}"
    legacy = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={binding.linux_account}",
            "--filter",
            "label=agent-runtime.service=gateway",
            "--format",
            "{{.ID}}",
        ]
    )
    if legacy.returncode != 0:
        return None, (legacy.stderr or legacy.stdout).strip() or "docker_ps_failed"
    ids = [line.strip() for line in legacy.stdout.splitlines() if line.strip()]
    if len(ids) == 1:
        return ids[0], "legacy_linux_account_label"
    if len(ids) > 1:
        return None, f"multiple_legacy_label_matches:{len(ids)}"
    return None, "not_found"


def _labels_from_container_info(info: dict) -> dict[str, str]:
    config = info.get("Config") if isinstance(info, dict) else {}
    labels = config.get("Labels") if isinstance(config, dict) else {}
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items()}


def _live_image_truth_from_info(binding: RuntimeBinding, info: dict, apache_route) -> dict[str, str]:
    labels = _labels_from_container_info(info)
    config = info.get("Config") if isinstance(info, dict) else {}
    image = str((config or {}).get("Image") or "")
    runtime_class = binding.runtime_class
    schema = _recipe_label(labels, "recipe.schema")
    family = _recipe_label(labels, "family")
    product_image = _recipe_label(labels, "product-image")
    runtime_profile = _recipe_label(labels, f"runtime-profile.{runtime_class}")
    runtime_contract = _recipe_label(labels, f"runtime-contract.{runtime_class}")
    canonical_recipe_name = _recipe_label(labels, "recipe.name")
    canonical_recipe_digest = _recipe_label(labels, "recipe.digest")
    truth_status = "ok"
    if schema != IMAGE_RECIPE_SCHEMA:
        truth_status = "legacy_or_unlabeled"
    elif not canonical_recipe_name or not canonical_recipe_digest:
        truth_status = "incomplete_recipe_labels"
    return {
        "instance_id": binding.instance_id,
        "linux_account": binding.linux_account,
        "truth_source": "live_image",
        "truth_status": truth_status,
        "public_host": binding.public_host,
        "actual_public_host": apache_route.public_host,
        "gateway_port": str(binding.gateway_port),
        "apache_gateway_port": str(apache_route.gateway_port),
        "bridge_port": str(binding.bridge_port),
        "enabled": "yes" if binding.enabled else "no",
        "family": binding.family,
        "runtime_class": runtime_class,
        "wrapper_image": image,
        "image_family": family,
        "product_image": product_image,
        "product_component": _recipe_label(labels, "product-component"),
        "wrapper_component": _recipe_label(labels, "wrapper-component"),
        "runtime_profile": runtime_profile,
        "runtime_contract": runtime_contract,
        "canonical_recipe_name": canonical_recipe_name,
        "canonical_recipe_digest": canonical_recipe_digest,
        "source_output_target": _recipe_label(labels, "source-output-target"),
        "container_nas_root": _recipe_label(labels, "nas.container-root"),
        "host_nas_root_template": _recipe_label(labels, "nas.host-root-template"),
        "nas_read_only": _recipe_label(labels, "nas.read-only"),
        "nas_mount_propagation": _recipe_label(labels, "nas.propagation"),
        "nas_child_mount_mode": _recipe_label(labels, "nas.child-mount-mode"),
        "ops_repo_commit": _recipe_label(labels, "ops-repo-commit"),
    }


def _live_runtime_truth(slot: str, state_root: Path) -> tuple[dict[str, str], list[tuple[bool, str, str | None]]]:
    checks: list[tuple[bool, str, str | None]] = []
    binding = get_runtime_binding(slot, state_root)
    apache_route = parse_apache_route(binding.linux_account)
    checks.extend(_apache_route_checks(binding, apache_route))
    container, lookup = _find_gateway_container_by_binding(binding)
    checks.append((bool(container), "truth_container_lookup", lookup))
    if not container:
        return (
            {
                "instance_id": binding.instance_id,
                "linux_account": binding.linux_account,
                "truth_source": "live_image",
                "truth_status": "not_running",
                "public_host": binding.public_host,
                "actual_public_host": apache_route.public_host,
                "gateway_port": str(binding.gateway_port),
                "apache_gateway_port": str(apache_route.gateway_port),
                "bridge_port": str(binding.bridge_port),
                "enabled": "yes" if binding.enabled else "no",
                "family": binding.family,
                "runtime_class": binding.runtime_class,
            },
            checks,
        )
    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "truth_container_inspect_ok", container))
    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout).strip()
        return (
            {
                "linux_account": binding.linux_account,
                "truth_source": "live_image",
                "truth_status": "inspect_failed",
                "reason": detail[:200],
            },
            checks,
        )
    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "truth_container_inspect_parse_ok", str(exc)))
        return ({"linux_account": binding.linux_account, "truth_source": "live_image", "truth_status": "parse_failed", "reason": str(exc)}, checks)
    truth = _live_image_truth_from_info(binding, info, apache_route)
    labels = _labels_from_container_info(info)
    checks.extend(
        [
            (truth["truth_status"] == "ok", "truth_image_labeled", truth["truth_status"]),
            (truth.get("image_family") == binding.family, "truth_family_matches_binding", f"image={truth.get('image_family') or 'missing'} binding={binding.family}"),
            (bool(truth.get("runtime_profile")), "truth_runtime_profile_present", truth.get("runtime_profile") or "missing"),
            (
                labels.get("agent-runtime.instance-id") in {None, binding.instance_id},
                "truth_container_instance_label_matches",
                f"label={labels.get('agent-runtime.instance-id') or 'missing'} binding={binding.instance_id}",
            ),
            (
                labels.get("agent-runtime.linux-account") in {None, binding.linux_account}
                and labels.get("agent-runtime.slot") in {None, binding.linux_account},
                "truth_container_linux_account_label_matches",
                f"label={labels.get('agent-runtime.linux-account') or labels.get('agent-runtime.slot') or 'missing'} binding={binding.linux_account}",
            ),
        ]
    )
    return truth, checks


def _print_key_values(data: dict[str, object]) -> None:
    for key, value in data.items():
        print(f"{key}={value}")


def cmd_runtime_truth(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime truth ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        all_slots = bool(getattr(args, "all", False))
        slot_arg = getattr(args, "slot", None)
        if all_slots and slot_arg:
            raise ValueError("provide either TARGET or --all, not both")
        if not all_slots and not slot_arg:
            raise ValueError("provide TARGET or --all")
        if all_slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        else:
            slots = [str(slot_arg)]
        all_ok = True
        for slot in slots:
            truth, checks = _live_runtime_truth(slot, state_root)
            if len(slots) > 1:
                summary = " ".join(f"{key}={value}" for key, value in truth.items())
                print(summary)
            else:
                _print_key_values(truth)
                for ok, name, detail in checks:
                    _check_line(ok, name, detail)
            if truth.get("truth_status") != "ok":
                all_ok = False
            if any(not ok for ok, _, _ in checks):
                all_ok = False
    except Exception as exc:
        print("runtime_truth_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"runtime_truth_status={'ok' if all_ok else 'fail'} count={len(slots)}")
    return 0 if all_ok else 1


def _run_live_slot_checks(desired, profile, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not _is_root():
        return [(False, "live_check_requires_root", "run as root/admin or a restricted root helper")]

    binding = get_runtime_binding(desired.slot, state_root)
    container, container_lookup = _find_gateway_container(binding, profile)
    checks.append((bool(container), "live_container_lookup", container_lookup))
    if not container:
        return checks
    target_home = f"/home/{desired.slot}"
    host_nas_root = f"{target_home}/nas_docs"
    container_nas_root = str(profile.metadata.get("container_nas_root") or "")
    required_read_only_nas = profile.metadata.get("required_read_only_nas") is True
    required_propagation = str(profile.metadata.get("required_mount_propagation") or "")

    docker = shutil.which("docker")
    checks.append((bool(docker), "live_docker_cli_available", docker))
    if not docker:
        return checks
    nsenter = shutil.which("nsenter")
    checks.append((bool(nsenter), "live_nsenter_available", nsenter))
    if not nsenter:
        return checks

    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "live_container_exists", container))
    if inspect.returncode != 0:
        detail = (inspect.stderr or inspect.stdout).strip()
        checks.append((False, "live_container_inspect_ok", detail[:200] if detail else None))
        return checks

    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "live_container_inspect_parse_ok", str(exc)))
        return checks
    try:
        truth, truth_checks = _live_runtime_truth(desired.slot, state_root)
        checks.extend(truth_checks)
        checks.append(
            (
                truth.get("truth_status") == "ok",
                "live_image_truth_labeled",
                f"status={truth.get('truth_status')}",
            )
        )
        checks.append(
            (
                truth.get("runtime_profile") in {"", profile.name} if truth.get("truth_status") != "ok" else truth.get("runtime_profile") == profile.name,
                "live_image_truth_profile_matches",
                f"image={truth.get('runtime_profile') or 'missing'} profile={profile.name}",
            )
        )
        checks.append(
            (
                truth.get("canonical_recipe_name") not in {None, "", "unknown"} if truth.get("truth_status") == "ok" else True,
                "live_image_truth_canonical_present",
                f"name={truth.get('canonical_recipe_name') or 'missing'}",
            )
        )
    except Exception as exc:
        checks.append((False, "live_image_truth_read_ok", str(exc)))
    state = info.get("State") or {}
    config = info.get("Config") or {}
    image_data = info.get("Image") or ""
    repo_digests = info.get("RepoDigests") or []
    running = str(state.get("Running")).lower()
    pid = int(state.get("Pid") or 0)
    health_data = state.get("Health") or {}
    health = str(health_data.get("Status") or "none")
    image = str(config.get("Image") or "")
    user = str(config.get("User") or "")
    runtime_user_mode = str(profile.metadata.get("runtime_user_mode") or "compose")
    checks.append((running == "true", "live_container_running", f"running={running}"))
    checks.append((pid > 0, "live_container_pid_present", f"pid={pid}"))
    checks.append((health in {"healthy", "none", ""}, "live_container_health_ok", f"health={health}"))
    checks.append((bool(image), "live_container_image_present", image or None))
    desired_image = str(desired.image_spec.get("wrapper_image") or "")
    desired_digest = str(desired.image_spec.get("digest") or "")
    image_matches = bool(desired_image) and (
        image == desired_image
        or desired_image in repo_digests
        or (desired_digest and (desired_digest in image or desired_digest in image_data or any(desired_digest in item for item in repo_digests)))
    )
    checks.append((image_matches, "live_container_image_matches_spec", f"image={image}"))
    if runtime_user_mode == "image-managed":
        checks.append((user in {"", "0", "0:0", "root"}, "live_container_user_image_managed", f"user={user or 'empty'}"))
    else:
        checks.append((bool(user) and user not in {"0", "0:0", "root"}, "live_container_user_non_root", f"user={user or 'empty'}"))
    if pid <= 0:
        return checks

    smoke_path = str(profile.metadata.get("http_smoke_path") or "")
    if smoke_path:
        smoke_ok, smoke_detail = _http_backend_smoke(desired.slot, smoke_path, state_root)
        checks.append((smoke_ok, "live_backend_http_smoke_ok", smoke_detail))

    host_rc, host_error, host_mounts = _findmnt_under(host_nas_root)
    checks.append((host_rc == 0, "live_host_nas_root_findmnt_ok", host_error if host_rc != 0 else host_nas_root))
    host_cifs = [row for row in host_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(host_nas_root + "/")]
    checks.append((True, "live_host_child_cifs_count", f"count={len(host_cifs)}"))
    for row in host_cifs:
        source = row.get("source") or ""
        if source.startswith("//") and desired.runtime_class == "customer":
            try:
                decision = check_nas_policy(desired.slot, source, state_root)
                checks.append((decision.allowed, "live_host_child_cifs_allowed_by_policy", f"source={source} reason={decision.reason}"))
            except Exception as exc:
                checks.append((False, "live_host_child_cifs_policy_check_ok", f"source={source} reason={exc}"))
        elif source.startswith("//"):
            checks.append((True, "live_host_child_cifs_policy_not_required_for_dev", f"source={source}"))
    if required_read_only_nas and host_cifs:
        host_ro = all(_is_readonly_mount(row) for row in host_cifs)
        checks.append((bool(host_cifs) and host_ro, "live_host_child_cifs_readonly", f"count={len(host_cifs)}"))

    if not container_nas_root:
        checks.append((False, "live_container_nas_root_configured", None))
        return checks

    container_rc, container_error, container_mounts = _findmnt_tree(container_nas_root, container_pid=pid)
    checks.append(
        (
            container_rc == 0,
            "live_container_nas_root_findmnt_ok",
            container_error if container_rc != 0 else container_nas_root,
        )
    )
    root_rows = [row for row in container_mounts if row.get("target") == container_nas_root]
    checks.append((bool(root_rows), "live_container_nas_root_mounted", container_nas_root))
    if required_read_only_nas:
        checks.append(
            (
                bool(root_rows) and _is_readonly_mount(root_rows[0]),
                "live_container_nas_root_readonly",
                root_rows[0].get("options") if root_rows else None,
            )
        )
    if root_rows and required_propagation:
        checks.append(
            (
                _propagation_satisfies(root_rows[0].get("propagation"), required_propagation),
                "live_container_nas_root_propagation",
                f"required={required_propagation} actual={root_rows[0].get('propagation')}",
            )
        )

    container_cifs = [
        row for row in container_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(container_nas_root + "/")
    ]
    checks.append((True, "live_container_child_cifs_count", f"count={len(container_cifs)}"))
    if required_read_only_nas and container_cifs:
        container_ro = all(_is_readonly_mount(row) for row in container_cifs)
        checks.append((bool(container_cifs) and container_ro, "live_container_child_cifs_readonly", f"count={len(container_cifs)}"))

    host_sources = {row.get("source") for row in host_cifs if row.get("source")}
    container_sources = {row.get("source") for row in container_cifs if row.get("source")}
    if host_sources:
        checks.append(
            (
                host_sources.issubset(container_sources),
                "live_container_sees_host_cifs_sources",
                f"host={len(host_sources)} container={len(container_sources)}",
            )
        )
    else:
        checks.append((True, "live_no_host_child_cifs_mounted", None))
    return checks


def _run_static_slot_checks(desired, profile, rendered=None) -> list[tuple[bool, str, str | None]]:
    target_family = desired.family
    runtime_class = desired.runtime_class
    profile_family = profile.metadata.get("family")
    profile_runtime_class = profile.metadata.get("slot_class")
    profile_mode = profile.metadata.get("mode")
    image_family = desired.image_spec.get("family")
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    image_digest = desired.image_spec.get("digest")
    wrapper_digest = _digest_from_image_ref(wrapper_image)
    allow_source_mount = profile.metadata.get("allow_source_mount")

    checks: list[tuple[bool, str, str | None]] = [
        (target_family == profile_family, "target_family_matches_profile", f"target={target_family} profile={profile_family}"),
        (
            runtime_class == profile_runtime_class,
            "target_runtime_class_matches_profile",
            f"target={runtime_class} profile={profile_runtime_class}",
        ),
        (
            image_family == target_family == profile_family,
            "image_family_matches_target",
            f"image={image_family} target={target_family}",
        ),
        (bool(wrapper_image), "wrapper_image_present", str(wrapper_image) if wrapper_image else None),
        (bool(product_image), "product_image_present", str(product_image) if product_image else None),
        (_has_digest_ref(wrapper_image), "wrapper_image_pinned_by_digest", str(wrapper_image) if wrapper_image else None),
        (_has_digest_ref(product_image), "product_image_pinned_by_digest", str(product_image) if product_image else None),
        (
            isinstance(image_digest, str) and image_digest.startswith("sha256:"),
            "wrapper_image_digest_present",
            str(image_digest) if image_digest else None,
        ),
        (
            bool(wrapper_digest) and wrapper_digest == image_digest,
            "wrapper_image_digest_matches_spec",
            f"wrapper={wrapper_digest} image_spec={image_digest}",
        ),
        (
            _allowed_image_ref(target_family, "wrapper", wrapper_image),
            "wrapper_image_repository_allowed",
            str(wrapper_image) if wrapper_image else None,
        ),
        (
            _allowed_image_ref(target_family, "product", product_image),
            "product_image_repository_allowed",
            str(product_image) if product_image else None,
        ),
    ]
    checks.extend(_image_spec_profile_contract_checks(desired.image_spec, profile))

    if runtime_class == "customer":
        checks.extend(
            [
                (
                    bool(getattr(desired, "route", None)) and desired.route.runtime_class == "customer",
                    "binding_runtime_class_customer",
                    f"binding={getattr(desired.route, 'runtime_class', 'missing') if getattr(desired, 'route', None) else 'missing'}",
                ),
                (profile_mode == "image", "customer_profile_mode_image", f"mode={profile_mode}"),
                (allow_source_mount is False, "customer_source_mount_disabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    elif runtime_class == "dev":
        checks.extend(
            [
                (
                    bool(getattr(desired, "route", None)) and desired.route.runtime_class == "dev",
                    "binding_runtime_class_dev",
                    f"binding={getattr(desired.route, 'runtime_class', 'missing') if getattr(desired, 'route', None) else 'missing'}",
                ),
                (profile_mode == "source", "dev_profile_mode_source", f"mode={profile_mode}"),
                (allow_source_mount is True, "dev_source_mount_enabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    else:
        checks.append((False, "known_runtime_class", f"runtime_class={runtime_class}"))

    if rendered is not None:
        checks.extend(
            (item.ok, item.name, item.detail)
            for item in validate_compose_contract(profile, desired, rendered.text)
        )

    return checks


def cmd_check(args: argparse.Namespace) -> int:
    try:
        state_root = _state_root(args)
        if args.live:
            desired, profile = _desired_from_live_image_truth(args.slot, state_root)
        else:
            desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
        rendered = render_compose(profile, desired)
    except Exception as exc:
        print(f"target={args.slot}")
        print("check_status=not_ready")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"image_name={desired.image_name}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"runtime_contract={_profile_runtime_contract(profile)}")
    print(f"customer_surface={_profile_customer_surface(profile)}")
    for key, value in canonical_recipe_identity(canonical_recipe_for_image_spec(desired.image_spec)).items():
        print(f"{key}={value}")
    print(f"compose_sha256={rendered.sha256}")
    print("check_mode=non_mutating")
    print(f"live_runtime_check={'enabled' if args.live else 'not_run'}")

    failed = 0
    for ok, name, detail in _run_static_slot_checks(desired, profile, rendered):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1

    _check_line(bool(rendered.text.strip()), "compose_rendered")
    if not rendered.text.strip():
        failed += 1

    if args.live:
        for ok, name, detail in _run_live_slot_checks(desired, profile, _state_root(args)):
            _check_line(ok, name, detail)
            if not ok:
                failed += 1
    else:
        print("INFO live_runtime_check_not_run use='opsctl check --live TARGET'")

    if failed:
        print(f"check_status=fail failed={failed}")
        return 1
    if args.live:
        print("check_status=pass scope=contract_and_live")
    else:
        print("check_status=pass scope=contract_only")
    return 0


def _slot_runtime_dir(slot: str) -> Path:
    validate_linux_account(slot)
    target_home = Path("/home") / slot
    runtime_dir = target_home / "openclaw"
    for path in (target_home, runtime_dir):
        if path.is_symlink():
            raise ValueError(f"managed path must not be symlink: {path}")
        if not path.is_dir():
            raise FileNotFoundError(path)
    return runtime_dir


def _agent_compose_path(runtime_dir: Path) -> Path:
    return runtime_dir / "docker-compose.agent-runtime.yml"


def _agent_manifest_path(runtime_dir: Path) -> Path:
    return runtime_dir / ".agent-runtime-manifest"


def _agent_backup_root(runtime_dir: Path) -> Path:
    return runtime_dir / ".agent-runtime-backups"


def _safe_managed_file(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed file must not be symlink: {path}")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError(f"managed parent is not a safe directory: {parent}")


def _compose_project_name(slot: str) -> str:
    return f"openclaw-{slot}"


def _docker_compose_command(slot: str, compose_path: Path, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "-p",
        _compose_project_name(slot),
        "-f",
        str(compose_path),
        *args,
    ]


def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    _safe_managed_file(path)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp_path.write_text(text, encoding="utf-8")
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)


def _required_compose_variables(rendered_text: str) -> set[str]:
    return set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", rendered_text))


def _env_file_keys(path: Path) -> set[str]:
    _safe_managed_file(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    keys: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            keys.add(key)
    return keys


def _state_runtime_dir(state_root: Path, slot: str, *, create: bool = False) -> Path:
    runtime_root = state_root / "runtime"
    slot_dir = runtime_root / slot
    for path in (state_root, runtime_root, slot_dir):
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed state path must not be symlink: {path}")
    if create:
        runtime_root.mkdir(mode=0o755, exist_ok=True)
        slot_dir.mkdir(mode=0o755, exist_ok=True)
    return slot_dir


def _state_manifest_path(state_root: Path, slot: str, *, create_parent: bool = False) -> Path:
    return _state_runtime_dir(state_root, slot, create=create_parent) / "manifest.yaml"


def _manifest_payload(
    *,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> dict:
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    payload = {
        "schema_version": 1,
        "target": desired.slot,
        "linux_account": desired.route.linux_account if getattr(desired, "route", None) else desired.slot,
        "applied_at": applied_at,
        "ops_commit": _installed_source_commit(),
        "image_name": desired.image_name,
        "family": desired.family,
        "runtime_class": desired.runtime_class,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "runtime_contract": _profile_runtime_contract(profile),
        "customer_surface": _profile_customer_surface(profile),
        "public_host": _apache_public_host(desired.slot),
        "gateway_port": desired.route.gateway_port if getattr(desired, "route", None) else "",
        "bridge_port": desired.route.bridge_port if getattr(desired, "route", None) else "",
        "wrapper_image": wrapper_image,
        "wrapper_image_digest": _digest_from_image_ref(wrapper_image),
        "product_image": product_image,
        "product_image_digest": _digest_from_image_ref(product_image),
        "recipe": _image_spec_recipe_payload(desired.image_spec),
        "compose_sha256": rendered.sha256,
        "compose_path": str(compose_path),
    }
    if previous_manifest is not None:
        payload["previous_manifest"] = str(previous_manifest)
    return payload


def _desired_from_runtime_manifest(slot: str, state_root: Path):
    target = load_runtime_target(slot, state_root)
    profile = load_profile(target.runtime_profile)
    if profile.metadata.get("family") != target.family:
        raise ValueError(f"runtime manifest profile family mismatch: profile={profile.metadata.get('family')} manifest={target.family}")
    if profile.metadata.get("slot_class") != target.runtime_class:
        raise ValueError(
            f"runtime manifest profile runtime_class mismatch: profile={profile.metadata.get('slot_class')} manifest={target.runtime_class}"
        )
    return target, profile


def _write_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    applied_at: str,
) -> None:
    lines = [
        f"target={desired.slot}",
        f"linux_account={desired.route.linux_account if getattr(desired, 'route', None) else desired.slot}",
        f"image_name={desired.image_name}",
        f"family={desired.family}",
        f"runtime_class={desired.runtime_class}",
        f"runtime_profile={profile.name}",
        f"runtime_profile_digest={profile.digest}",
        f"runtime_contract={_profile_runtime_contract(profile)}",
        f"customer_surface={_profile_customer_surface(profile)}",
        f"public_host={_apache_public_host(desired.slot)}",
        f"gateway_port={desired.route.gateway_port if getattr(desired, 'route', None) else ''}",
        f"bridge_port={desired.route.bridge_port if getattr(desired, 'route', None) else ''}",
        f"ops_repo_commit={_installed_source_commit()}",
        f"wrapper_image={desired.image_spec.get('wrapper_image')}",
        f"product_image={desired.image_spec.get('product_image')}",
        f"recipe_mode={_image_spec_recipe_tokens(desired.image_spec)['recipe_mode']}",
        f"product_component={_image_spec_recipe_tokens(desired.image_spec)['product_component']}",
        f"wrapper_image_digest={desired.image_spec.get('digest')}",
        f"compose_sha256={rendered.sha256}",
        f"compose_file={path.parent / 'docker-compose.agent-runtime.yml'}",
        f"applied_at={applied_at}",
    ]
    _atomic_write(path, "\n".join(lines) + "\n", 0o644)


def _write_state_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> None:
    _atomic_write(
        path,
        dump_yaml(
            _manifest_payload(
                desired=desired,
                profile=profile,
                rendered=rendered,
                compose_path=compose_path,
                applied_at=applied_at,
                previous_manifest=previous_manifest,
            )
        ),
        0o644,
    )


def _write_slot_manifests(
    *,
    state_root: Path,
    runtime_dir: Path,
    desired,
    profile,
    rendered,
    compose_path: Path,
    applied_at: str,
    previous_manifest: Path | None,
) -> tuple[Path, Path]:
    legacy_path = _agent_manifest_path(runtime_dir)
    state_path = _state_manifest_path(state_root, desired.slot, create_parent=True)
    _write_slot_manifest(
        legacy_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        applied_at=applied_at,
    )
    _write_state_slot_manifest(
        state_path,
        desired=desired,
        profile=profile,
        rendered=rendered,
        compose_path=compose_path,
        applied_at=applied_at,
        previous_manifest=previous_manifest,
    )
    return legacy_path, state_path


def _backup_agent_runtime_state(slot: str, runtime_dir: Path, state_root: Path) -> Path:
    backup_root = _agent_backup_root(runtime_dir)
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o755, exist_ok=True)
    backup_dir = backup_root / datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    suffix = 1
    original_backup_dir = backup_dir
    while backup_dir.exists():
        suffix += 1
        backup_dir = Path(f"{original_backup_dir}.{suffix}")
    backup_dir.mkdir(mode=0o755)

    compose_path = _agent_compose_path(runtime_dir)
    manifest_path = _agent_manifest_path(runtime_dir)
    state_manifest_path = _state_manifest_path(state_root, slot)
    metadata = {
        "created_at": _now_iso(),
        "had_compose": compose_path.is_file() and not compose_path.is_symlink(),
        "had_manifest": manifest_path.is_file() and not manifest_path.is_symlink(),
        "had_state_manifest": state_manifest_path.is_file() and not state_manifest_path.is_symlink(),
        "state_manifest_path": str(state_manifest_path),
    }
    if metadata["had_compose"]:
        shutil.copy2(compose_path, backup_dir / "docker-compose.agent-runtime.yml")
    if metadata["had_manifest"]:
        shutil.copy2(manifest_path, backup_dir / ".agent-runtime-manifest")
    if metadata["had_state_manifest"]:
        shutil.copy2(state_manifest_path, backup_dir / "manifest.yaml")
    (backup_dir / "backup.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return backup_dir


def _latest_backup(runtime_dir: Path) -> Path | None:
    backup_root = _agent_backup_root(runtime_dir)
    if not backup_root.is_dir():
        return None
    backups = sorted([item for item in backup_root.iterdir() if item.is_dir()])
    return backups[-1] if backups else None


def _restore_backup(slot: str, runtime_dir: Path, backup_dir: Path, state_root: Path) -> tuple[bool, str]:
    metadata = load_yaml(backup_dir / "backup.json")
    compose_path = _agent_compose_path(runtime_dir)
    manifest_path = _agent_manifest_path(runtime_dir)
    state_manifest_path = _state_manifest_path(state_root, slot, create_parent=True)
    had_compose = bool(metadata.get("had_compose"))
    had_manifest = bool(metadata.get("had_manifest"))
    had_state_manifest = bool(metadata.get("had_state_manifest"))

    if had_compose:
        shutil.copy2(backup_dir / "docker-compose.agent-runtime.yml", compose_path)
    else:
        compose_path.unlink(missing_ok=True)
    if had_manifest:
        shutil.copy2(backup_dir / ".agent-runtime-manifest", manifest_path)
    else:
        manifest_path.unlink(missing_ok=True)
    if had_state_manifest:
        shutil.copy2(backup_dir / "manifest.yaml", state_manifest_path)
    else:
        state_manifest_path.unlink(missing_ok=True)

    if not had_compose:
        return False, "no_previous_agent_runtime_compose"

    config = _run_text_cwd(_docker_compose_command(slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        return False, (config.stderr or config.stdout).strip() or "rollback_compose_config_failed"
    up = _run_text_cwd(
        _docker_compose_command(slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=180,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "rollback_compose_up_failed"
    return True, "rollback_applied"


def _read_legacy_slot_manifest(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.is_file():
        return data
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = raw_line.partition("=")
        if sep:
            data[key.strip()] = value.strip()
    return data


def _backup_manifest_data(backup_dir: Path) -> dict:
    yaml_manifest = backup_dir / "manifest.yaml"
    if yaml_manifest.is_file():
        data = load_yaml(yaml_manifest)
        if isinstance(data, dict):
            return data
    return _read_legacy_slot_manifest(backup_dir / ".agent-runtime-manifest")


def _desired_from_manifest(slot: str, manifest: dict, state_root: Path):
    target = str(manifest.get("target") or manifest.get("slot") or slot)
    family = str(manifest.get("family") or "")
    runtime_class = str(manifest.get("runtime_class") or manifest.get("slot_class") or "")
    image_spec = {
        "family": family,
        "image_name": str(manifest.get("image_name") or manifest.get("release") or IMAGE_ROLLOUT_IMAGE_NAME),
        "wrapper_image": manifest.get("wrapper_image"),
        "product_image": manifest.get("product_image"),
        "digest": manifest.get("wrapper_image_digest") or manifest.get("release_digest"),
        "product_digest": manifest.get("product_image_digest"),
        "mode": "wrapped_product_image",
    }
    return RuntimeTarget(
        target=target,
        family=family,
        runtime_class=runtime_class,
        image_name=str(image_spec["image_name"]),
        image_spec=image_spec,
        runtime_profile=str(manifest.get("runtime_profile") or ""),
        route=get_runtime_binding(target, state_root),
    )


def _load_backup_runtime_contract(slot: str, backup_dir: Path, state_root: Path):
    manifest = _backup_manifest_data(backup_dir)
    desired = _desired_from_manifest(slot, manifest, state_root)
    if not desired.runtime_profile:
        raise ValueError("backup manifest is missing runtime_profile")
    return desired, load_profile(desired.runtime_profile)


def _print_process_result(prefix: str, proc: subprocess.CompletedProcess[str], limit: int = 2000) -> None:
    detail = (proc.stderr or proc.stdout).strip()
    if detail:
        print(f"{prefix}={detail[:limit]}")


def _write_failed_container_diagnostics(slot: str, profile, backup_dir: Path) -> Path | None:
    try:
        container, lookup = _find_gateway_container(slot, profile)
        diag_dir = backup_dir / "failed-container"
        diag_dir.mkdir(mode=0o700, exist_ok=True)
        (diag_dir / "lookup.txt").write_text(f"container={container or ''}\nlookup={lookup or ''}\n", encoding="utf-8")
        if not container:
            return diag_dir
        commands = {
            "inspect.json": ["docker", "inspect", container],
            "logs.txt": ["docker", "logs", "--tail", "300", container],
            "ports.txt": ["docker", "port", container],
            "top.txt": ["docker", "top", container],
        }
        for name, command in commands.items():
            proc = _run_text(command, timeout=30)
            body = {
                "argv": command,
                "returncode": proc.returncode,
                "stdout": redact(proc.stdout or ""),
                "stderr": redact(proc.stderr or ""),
            }
            (diag_dir / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return diag_dir
    except Exception as exc:
        try:
            diag_dir = backup_dir / "failed-container"
            diag_dir.mkdir(mode=0o700, exist_ok=True)
            (diag_dir / "error.txt").write_text(str(exc) + "\n", encoding="utf-8")
            return diag_dir
        except Exception:
            return None


def _is_under_path(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_diagnostics_dir(slot: str, value: str | None = None) -> Path:
    backup_root = _agent_backup_root(_slot_runtime_dir(slot)).resolve(strict=False)
    if value:
        requested = Path(value)
        if not requested.is_absolute():
            raise ValueError("diagnostics path must be absolute")
        path = requested.resolve(strict=False)
        if path.name != "failed-container":
            path = path / "failed-container"
    else:
        if not backup_root.is_dir():
            raise ValueError(f"backup root not found: {backup_root}")
        backups = sorted(item for item in backup_root.iterdir() if item.is_dir())
        if not backups:
            raise ValueError(f"no backups found for target: {slot}")
        path = backups[-1].resolve(strict=False) / "failed-container"
    path = path.resolve(strict=False)
    if not _is_under_path(path, backup_root):
        raise ValueError("diagnostics path must stay under the target backup root")
    if path.is_symlink():
        raise ValueError(f"diagnostics path must not be symlink: {path}")
    if not path.is_dir():
        raise ValueError(f"diagnostics dir not found: {path}")
    return path


def _load_diagnostics_payload(path: Path) -> dict:
    data = load_yaml(path)
    return data if isinstance(data, dict) else {}


def _format_command_list(value) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    if value in {None, ""}:
        return "empty"
    return str(value)


def _redacted_tail(text: str, *, lines: int, chars: int = 12000) -> str:
    redacted = redact(text or "")
    parts = redacted.splitlines()
    if lines > 0:
        redacted = "\n".join(parts[-lines:])
    return redacted[-chars:]


def _print_block(name: str, text: str) -> None:
    print(f"{name}_begin")
    if text:
        print(text)
    print(f"{name}_end")


def _print_inspect_summary(diag_dir: Path) -> None:
    path = diag_dir / "inspect.json"
    if not path.is_file():
        print("inspect_status=missing")
        return
    payload = _load_diagnostics_payload(path)
    print(f"inspect_returncode={payload.get('returncode')}")
    if payload.get("returncode") != 0:
        stderr = _redacted_tail(str(payload.get("stderr") or payload.get("stdout") or ""), lines=20)
        _print_block("inspect_error", stderr)
        return
    try:
        rows = json.loads(str(payload.get("stdout") or "[]"))
        info = rows[0] if isinstance(rows, list) and rows else {}
    except Exception as exc:
        print(f"inspect_parse_status=fail reason={exc}")
        return
    state = info.get("State") if isinstance(info, dict) else {}
    config = info.get("Config") if isinstance(info, dict) else {}
    health = state.get("Health") if isinstance(state, dict) else {}
    print("inspect_status=ok")
    print(f"container_id={str(info.get('Id') or '')[:12]}")
    print(f"container_name={info.get('Name') or ''}")
    print(f"container_image={config.get('Image') or ''}")
    print(f"container_running={state.get('Running')}")
    print(f"container_pid={state.get('Pid')}")
    print(f"container_exit_code={state.get('ExitCode')}")
    print(f"container_health={(health or {}).get('Status') if isinstance(health, dict) else 'none'}")
    print(f"container_entrypoint={_format_command_list(config.get('Entrypoint'))}")
    print(f"container_cmd={_format_command_list(config.get('Cmd'))}")
    print(f"container_working_dir={config.get('WorkingDir') or ''}")


def cmd_diagnostics_show(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics show TARGET", file=sys.stderr)
        return 2
    try:
        slot = str(args.slot)
        validate_linux_account(slot)
        diag_dir = _resolve_diagnostics_dir(slot, getattr(args, "dir", None))
        tail_lines = max(1, min(int(getattr(args, "tail", 120)), 300))
    except Exception as exc:
        print("diagnostics_status=fail")
        print(f"reason={exc}")
        return 1

    print("diagnostics_status=ok")
    print(f"target={slot}")
    print(f"diagnostics_dir={diag_dir}")
    print("secret_value_printed=no")
    lookup_path = diag_dir / "lookup.txt"
    if lookup_path.is_file():
        print(redact(lookup_path.read_text(encoding="utf-8", errors="replace").strip()))
    _print_inspect_summary(diag_dir)
    for stem in ("ports", "top", "logs"):
        path = diag_dir / f"{stem}.txt"
        if not path.is_file():
            print(f"{stem}_status=missing")
            continue
        payload = _load_diagnostics_payload(path)
        print(f"{stem}_returncode={payload.get('returncode')}")
        text = "\n".join(part for part in (str(payload.get("stdout") or ""), str(payload.get("stderr") or "")) if part)
        _print_block(f"{stem}_tail", _redacted_tail(text, lines=tail_lines))
    return 0


def _run_live_slot_checks_with_wait(desired, profile, state_root: Path, timeout_seconds: int = 90) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    wait_names = {
        "live_container_running",
        "live_container_pid_present",
        "live_container_health_ok",
        "live_backend_http_smoke_ok",
    }
    while True:
        checks = _run_live_slot_checks(desired, profile, state_root)
        last_checks = checks
        failed_names = {name for ok, name, _ in checks if not ok}
        if not failed_names:
            return checks
        if not (failed_names & wait_names):
            return checks
        if time.monotonic() >= deadline:
            return checks
        time.sleep(5)


def _profile_startup_timeout_seconds(profile) -> int:
    raw_value = profile.metadata.get("startup_timeout_seconds", 90)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return 90
    return max(30, min(value, 600))


def _apply_desired_slot(
    *,
    desired,
    profile,
    state_root: Path,
    allow_first_apply: bool,
    action_name: str = "apply",
) -> int:
    try:
        rendered = render_compose(profile, desired)
        static_failures = [
            name for ok, name, _ in _run_static_slot_checks(desired, profile, rendered) if not ok
        ]
        if static_failures:
            raise ValueError(f"static contract check failed: {','.join(static_failures)}")
        runtime_dir = _slot_runtime_dir(desired.slot)
        compose_path = _agent_compose_path(runtime_dir)
        manifest_path = _agent_manifest_path(runtime_dir)
        state_manifest_path = _state_manifest_path(state_root, desired.slot)
        env_path = runtime_dir / ".env"
        required = _required_compose_variables(rendered.text)
        present = _env_file_keys(env_path)
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"missing required .env keys: {','.join(missing)}")
        if not manifest_path.exists() and not state_manifest_path.exists() and not allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        previous_manifest = state_manifest_path if state_manifest_path.exists() else manifest_path if manifest_path.exists() else None
        backup_dir = _backup_agent_runtime_state(desired.slot, runtime_dir, state_root)
        _atomic_write(compose_path, rendered.text, 0o644)
    except Exception as exc:
        print(f"target={getattr(desired, 'slot', '')}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, action_name, getattr(desired, "slot", ""), getattr(desired, "slot", ""), "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_dir={runtime_dir}")
    print(f"compose_file={compose_path}")
    print(f"manifest={manifest_path}")
    print(f"state_manifest={state_manifest_path}")
    print(f"backup_dir={backup_dir}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")

    config = _run_text_cwd(_docker_compose_command(desired.slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        _print_process_result("compose_config_error", config)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_config_failed")
        return config.returncode or 1

    up = _run_text_cwd(
        _docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", "--remove-orphans"),
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        _print_process_result("compose_up_error", up)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", "compose_up_failed")
        return up.returncode or 1

    failed = 0
    for ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    if failed:
        diagnostics_dir = _write_failed_container_diagnostics(desired.slot, profile, backup_dir)
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print(f"apply_status=fail live_failed={failed}")
        if diagnostics_dir:
            print(f"failure_diagnostics_dir={diagnostics_dir}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"live_failed={failed}")
        return 1

    applied_at = _now_iso()
    try:
        _write_slot_manifests(
            state_root=state_root,
            runtime_dir=runtime_dir,
            desired=desired,
            profile=profile,
            rendered=rendered,
            compose_path=compose_path,
            applied_at=applied_at,
            previous_manifest=previous_manifest,
        )
        _append_action_log(state_root, action_name, desired.slot, desired.image_name, "ok", rendered.sha256)
    except Exception as exc:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        print(f"reason=manifest_write_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        try:
            _append_action_log(state_root, action_name, desired.slot, desired.slot, "fail", f"manifest_write_failed:{exc}")
        except Exception:
            pass
        return 1
    print("apply_status=ok")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _desired_from_runtime_manifest(args.slot, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "apply", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    return _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(args.allow_first_apply),
        action_name="apply",
    )


def cmd_rollback(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollback TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        runtime_dir = _slot_runtime_dir(args.slot)
        backup_dir = _latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = _restore_backup(args.slot, runtime_dir, backup_dir, state_root)
    except Exception as exc:
        print(f"target={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollback", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"target={args.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_reason={reason}")
    if not ok:
        print("rollback_status=fail")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", reason)
        return 1

    try:
        desired, profile = _load_backup_runtime_contract(args.slot, backup_dir, state_root)
    except Exception as exc:
        print("rollback_status=fail")
        print(f"reason={exc}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", str(exc))
        return 1

    failed = 0
    for check_ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        state_root,
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(check_ok, name, detail)
        if not check_ok:
            failed += 1
    if failed:
        print(f"rollback_status=fail live_failed={failed}")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", f"live_failed={failed}")
        return 1

    print("rollback_status=ok")
    _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "ok", reason)
    return 0


def _slot_home(slot: str) -> Path:
    return Path(_passwd_record(slot).pw_dir)


def _assert_secret_path_safe(slot: str, path: Path, *, create_parent: bool = False) -> None:
    if not path.is_absolute():
        raise ValueError(f"secret file path must be absolute: {path}")
    home = _slot_home(slot).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved != home and not str(resolved).startswith(str(home) + os.sep):
        raise ValueError(f"secret file path outside slot home: {path}")
    _ensure_not_symlink_chain(path.parent, home)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_not_symlink_chain(path, home)
    if path.exists() and not path.is_file():
        raise ValueError(f"secret file path is not a regular file: {path}")
    if path.is_symlink():
        raise ValueError(f"secret file must not be a symlink: {path}")


def _read_root_secret_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.is_symlink():
        raise ValueError(f"env file must not be a symlink: {path}")
    stat_result = path.stat()
    if not stat.S_ISREG(stat_result.st_mode):
        raise ValueError(f"env file must be regular: {path}")
    if stat_result.st_uid != 0 or stat_result.st_gid != 0:
        raise ValueError(f"env file must be root:root: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"env file must be mode 0600 or stricter: {path}")
    if stat_result.st_nlink != 1:
        raise ValueError(f"env file must not be hardlinked: {path}")
    return parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))


def _secret_values_from_args(args: argparse.Namespace) -> dict[str, str]:
    if args.env_file and (args.key or args.value_stdin):
        raise ValueError("use either --env-file or --key/--value-stdin, not both")
    if args.env_file:
        return validate_provider_secret_values(_read_root_secret_env_file(Path(args.env_file)))
    if not args.key or not args.value_stdin:
        raise ValueError("use --env-file FILE or --key KEY --value-stdin")
    key = str(args.key)
    if key not in PROVIDER_SECRET_KEYS:
        raise ValueError(f"unsupported runtime secret key: {key}")
    value = sys.stdin.read().rstrip("\r\n")
    return validate_provider_secret_values({key: value})


def _safe_write_secret_env(path: Path, text: str, uid: int, gid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise ValueError(f"secret file is not regular: {path}")
        if stat_result.st_nlink != 1:
            raise ValueError(f"secret file must not be hardlinked: {path}")
        os.ftruncate(fd, 0)
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chown(path, uid, gid)
    os.chmod(path, 0o600)


def _secret_owner_ids(slot: str, owner_mode: str) -> tuple[int, int]:
    if owner_mode == "runtime":
        runtime_uid, _, data_gid = _runtime_ids(slot)
        return runtime_uid, data_gid
    return 0, 0


def _upsert_runtime_secret_file(slot: str, profile, values: dict[str, str]) -> Path:
    secret_file = primary_profile_secret_file(profile, slot)
    _assert_secret_path_safe(slot, secret_file.path, create_parent=True)
    existing_text = secret_file.path.read_text(encoding="utf-8", errors="replace") if secret_file.path.exists() else ""
    uid, gid = _secret_owner_ids(slot, secret_file.owner_mode)
    if secret_file.owner_mode == "runtime":
        secret_file.path.parent.chmod(0o750)
        os.chown(secret_file.path.parent, uid, gid)
    _safe_write_secret_env(secret_file.path, render_upserted_secret_env(existing_text, values), uid, gid)
    return secret_file.path


def _restart_runtime_secret_slot(desired, profile, runtime_dir: Path) -> tuple[bool, str]:
    compose_path = _agent_compose_path(runtime_dir)
    service = str(profile.metadata.get("service") or "openclaw-gateway")
    if compose_path.is_file():
        command = _docker_compose_command(desired.slot, compose_path, "up", "-d", "--force-recreate", service)
        restart_mode = "agent-runtime-compose"
    else:
        legacy_compose = runtime_dir / "docker-compose.yml"
        if not legacy_compose.is_file():
            return False, f"compose_missing:{compose_path},{legacy_compose}"
        compose_files = [legacy_compose]
        source_compose = runtime_dir / "docker-compose.source.yml"
        if source_compose.is_file():
            compose_files.append(source_compose)
        if profile.metadata.get("family") != "hermes":
            for name in (
                "docker-compose.extra.yml",
                "docker-compose.host-user.yml",
                "docker-compose.shared-ollama.yml",
                "docker-compose.sandbox.yml",
            ):
                item = runtime_dir / name
                if item.is_file():
                    compose_files.append(item)
        command = ["docker", "compose", "-p", _compose_project_name(desired.slot)]
        for item in compose_files:
            command.extend(["-f", str(item)])
        command.extend(["up", "-d", "--force-recreate", service])
        restart_mode = "legacy-compose"
    up = _run_text_cwd(
        command,
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "runtime_secret_restart_failed"
    return True, restart_mode


def _run_runtime_secret_container_checks(desired, profile, keys: set[str]) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not _is_root():
        return [(False, "runtime_secret_check_requires_root", "run as root/admin")]
    docker = shutil.which("docker")
    checks.append((bool(docker), "runtime_secret_docker_cli_available", docker))
    if not docker:
        return checks
    container, lookup = _find_gateway_container(desired.slot, profile)
    checks.append((bool(container), "runtime_secret_container_lookup", lookup))
    if not container:
        return checks
    inspect = _run_text(["docker", "inspect", container])
    checks.append((inspect.returncode == 0, "runtime_secret_container_exists", container))
    if inspect.returncode != 0:
        return checks
    try:
        info = json.loads(inspect.stdout)[0]
    except Exception as exc:
        checks.append((False, "runtime_secret_container_inspect_parse_ok", str(exc)))
        return checks
    state = info.get("State") or {}
    running = str(state.get("Running")).lower()
    health_data = state.get("Health") or {}
    health = str(health_data.get("Status") or "none")
    checks.append((running == "true", "runtime_secret_container_running", f"running={running}"))
    checks.append((health in {"healthy", "none", ""}, "runtime_secret_container_health_ok", f"health={health}"))
    for key in sorted(keys):
        proc = _run_text(["docker", "exec", container, "sh", "-lc", f'test -n "${{{key}:-}}"'])
        checks.append((proc.returncode == 0, f"runtime_secret_{key.lower()}_present_in_container", "secret_value_printed=no"))
    return checks


def _run_runtime_secret_container_checks_with_wait(desired, profile, keys: set[str], timeout_seconds: int) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    while True:
        checks = _run_runtime_secret_container_checks(desired, profile, keys)
        last_checks = checks
        if not any(not ok for ok, _, _ in checks):
            return checks
        if time.monotonic() >= deadline:
            return last_checks
        time.sleep(5)


def _secret_status_rows(path: Path) -> tuple[str, dict[str, bool]]:
    if not path.exists():
        return "missing", {}
    if path.is_symlink():
        return "symlink_refused", {}
    if not path.is_file():
        return "not_regular", {}
    try:
        values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    except Exception:
        return "parse_failed", {}
    return "present", {key: bool(values.get(key)) for key in sorted(PROVIDER_SECRET_KEYS)}


def cmd_runtime_secret_set(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret set TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired = load_runtime_target(args.slot, state_root)
        profile = load_profile(desired.runtime_profile)
        values = _secret_values_from_args(args)
        secret_path = _upsert_runtime_secret_file(desired.slot, profile, values)
        runtime_dir = _slot_runtime_dir(desired.slot)
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "runtime_secret_set", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"secret_file={secret_path}")
    print("secret_value_printed=no")
    print("secret_keys_imported=" + ",".join(sorted(values)))

    if args.no_restart:
        print("restart=skipped")
        _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "restart=skipped keys=" + ",".join(sorted(values)))
        print("runtime_secret_status=stored")
        return 0

    restart_ok, restart_reason = _restart_runtime_secret_slot(desired, profile, runtime_dir)
    print(f"restart_status={'ok' if restart_ok else 'fail'}")
    print(f"restart_reason={restart_reason}")
    if not restart_ok:
        _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", restart_reason)
        print("runtime_secret_status=fail")
        return 1

    if args.check:
        failed = 0
        for check_ok, name, detail in _run_runtime_secret_container_checks_with_wait(
            desired,
            profile,
            set(values),
            timeout_seconds=_profile_startup_timeout_seconds(profile),
        ):
            _check_line(check_ok, name, detail)
            if not check_ok:
                failed += 1
        if failed:
            _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "fail", f"live_failed={failed}")
            print(f"runtime_secret_status=fail live_failed={failed}")
            return 1

    _append_action_log(state_root, "runtime_secret_set", desired.slot, desired.slot, "ok", "keys=" + ",".join(sorted(values)))
    print("runtime_secret_status=stored")
    return 0


def cmd_runtime_secret_status(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret status TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        secret_file = primary_profile_secret_file(profile, desired.slot)
        _assert_secret_path_safe(desired.slot, secret_file.path)
        file_state, key_state = _secret_status_rows(secret_file.path)
    except Exception as exc:
        print(f"target={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"secret_file={secret_file.path}")
    print(f"secret_file_state={file_state}")
    for key in sorted(PROVIDER_SECRET_KEYS):
        if key in key_state:
            print(f"{key.lower()}={'present' if key_state[key] else 'absent'}")
    print("secret_value_printed=no")
    print("runtime_secret_status=ok")
    return 0


def _json_path_present(path: Path, keys: list[str]) -> tuple[str, str]:
    if not path.exists():
        return "missing", "absent"
    if path.is_symlink():
        return "symlink_refused", "unknown"
    if not path.is_file():
        return "not_regular", "unknown"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return "parse_failed", "unknown"
    value = data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return "present", "absent"
        value = value[key]
    return "present", "present" if isinstance(value, str) and bool(value) else "absent"


def _env_key_present(path: Path, key: str) -> tuple[str, str]:
    if not path.exists():
        return "missing", "absent"
    if path.is_symlink():
        return "symlink_refused", "unknown"
    if not path.is_file():
        return "not_regular", "unknown"
    try:
        values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    except Exception:
        return "parse_failed", "unknown"
    return "present", "present" if values.get(key) else "absent"


def cmd_handoff_status(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl handoff status TARGET", file=sys.stderr)
        return 2
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        family = str(profile.metadata.get("family") or desired.family or "")
    except Exception as exc:
        print(f"target={args.slot}")
        print("handoff_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"runtime_profile={profile.name}")
    print(f"family={family}")
    print("handoff_value_printed=no")

    if family == "openclaw":
        config_path = _slot_home(desired.slot) / ".openclaw" / "openclaw.json"
        try:
            _assert_secret_path_safe(desired.slot, config_path)
            file_state, token_state = _json_path_present(config_path, ["gateway", "auth", "token"])
        except Exception as exc:
            file_state, token_state = "invalid", "unknown"
            print(f"reason={exc}")
        print("handoff_kind=openclaw_gateway_token")
        print(f"handoff_secret_file={config_path}")
        print("handoff_secret_json_path=gateway.auth.token")
        print("handoff_container_file=/home/node/.openclaw/openclaw.json")
        print(f"handoff_file_state={file_state}")
        print(f"handoff_token={token_state}")
        print("handoff_value_retrieval=legacy_exception")
        print(
            "handoff_value_command="
            + shlex.join(
                [
                    "sudo",
                    "/opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh",
                    "handoff-credential",
                    desired.slot,
                ]
            )
        )
        print(f"handoff_status={'ok' if file_state == 'present' and token_state == 'present' else 'fail'}")
        return 0 if file_state == "present" and token_state == "present" else 1

    if family == "hermes":
        secret_file = _state_root(args) / "handoff" / f"hermes-workspace-{desired.slot}.env"
        legacy_file = _state_root(args) / "reports" / f"hermes-workspace-{desired.slot}.password"
        file_state, password_state = _env_key_present(secret_file, "password")
        print("handoff_kind=hermes_workspace_password")
        print(f"handoff_secret_file={secret_file}")
        print("handoff_secret_key=password")
        print(f"handoff_legacy_secret_file={legacy_file}")
        print(f"handoff_file_state={file_state}")
        print(f"handoff_password={password_state}")
        print("handoff_value_retrieval=legacy_exception")
        print(
            "handoff_value_command="
            + shlex.join(
                [
                    "sudo",
                    "/opt/openclaw-nas-agent-baseline/scripts/svcops-control.sh",
                    "handoff-credential",
                    desired.slot,
                ]
            )
        )
        print(f"handoff_status={'ok' if file_state == 'present' and password_state == 'present' else 'fail'}")
        return 0 if file_state == "present" and password_state == "present" else 1

    print("handoff_status=fail")
    print("reason=unsupported_runtime_family")
    return 1


def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: enable lane rollout only after single-slot apply/rollback migration tests pass", file=sys.stderr)
    return 2


def _assert_state_parent_safe(path: Path) -> None:
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise ValueError(f"managed state parent must not be symlink: {parent}")
    parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")


def _backup_state_file(state_root: Path, path: Path) -> Path | None:
    if not path.exists():
        return None
    if path.is_symlink():
        raise ValueError(f"managed state file must not be symlink: {path}")
    backup_root = state_root / "backups" / "state"
    if backup_root.exists() and backup_root.is_symlink():
        raise ValueError(f"managed backup root must not be symlink: {backup_root}")
    backup_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%dT%H%M%S%z")
    backup_path = backup_root / f"{path.name}.{stamp}"
    suffix = 1
    while backup_path.exists():
        suffix += 1
        backup_path = backup_root / f"{path.name}.{stamp}.{suffix}"
    shutil.copy2(path, backup_path)
    return backup_path


def _write_state_yaml_file(state_root: Path, name: str, data: dict) -> Path | None:
    path = state_root / name
    _assert_state_parent_safe(path)
    backup_path = _backup_state_file(state_root, path)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp_path.write_text(dump_yaml(data), encoding="utf-8")
        if hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(tmp_path, 0, state_root.stat().st_gid)
        os.chmod(tmp_path, 0o640)
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    return backup_path


def _state_meta(source: str | None = None) -> dict[str, object]:
    meta: dict[str, object] = {
        "schema_version": 1,
        "updated_at": _now_iso(),
        "scope": "private_server_state",
    }
    if source:
        meta["source"] = source
    return meta


def _load_dev_recipe_state(state_root: Path) -> dict:
    data = load_yaml(state_root / DEV_RECIPE_STATE_NAME, default={})
    if not isinstance(data, dict):
        data = {}
    data.setdefault("meta", _state_meta("opsctl recipe"))
    data.setdefault("recipes", {})
    return data


def _write_dev_recipe_state(state_root: Path, data: dict) -> Path | None:
    data["meta"] = _state_meta("opsctl recipe")
    data.setdefault("recipes", {})
    return _write_state_yaml_file(state_root, DEV_RECIPE_STATE_NAME, data)


def _validate_recipe_name(name: str) -> None:
    _validate_safe_name(name)


def _build_arg_lines_for_canonical_recipe(name: str) -> list[str]:
    recipe = load_canonical_recipe(name)
    labels = canonical_label_values(recipe)
    return [
        f"CANONICAL_RECIPE_NAME={recipe.name}",
        f"CANONICAL_RECIPE_DIGEST={recipe.digest}",
        f"RUNTIME_FAMILY={labels['family']}",
        f"PRODUCT_COMPONENT={labels['product-component']}",
        f"WRAPPER_COMPONENT={labels['wrapper-component']}",
        f"RUNTIME_PROFILE_CUSTOMER={labels['runtime-profile.customer']}",
        f"RUNTIME_PROFILE_DEV={labels['runtime-profile.dev']}",
        f"RUNTIME_CONTRACT_CUSTOMER={labels['runtime-contract.customer']}",
        f"RUNTIME_CONTRACT_DEV={labels['runtime-contract.dev']}",
        f"RUNTIME_COMMAND_MODE={labels['command-mode']}",
        f"RUNTIME_WORKING_DIR={labels['working-dir']}",
        f"RUNTIME_HTTP_PORT={labels['http-port']}",
        f"RUNTIME_SOURCE_OUTPUT_TARGET={labels['source-output-target']}",
        f"RUNTIME_NAS_CONTAINER_ROOT={labels['nas.container-root']}",
        f"RUNTIME_NAS_HOST_ROOT_TEMPLATE={labels['nas.host-root-template']}",
        f"RUNTIME_NAS_READ_ONLY={labels['nas.read-only']}",
        f"RUNTIME_NAS_PROPAGATION={labels['nas.propagation']}",
        f"RUNTIME_NAS_CHILD_MOUNT_MODE={labels['nas.child-mount-mode']}",
    ]


def cmd_recipe_validate_canonical(args: argparse.Namespace) -> int:
    name = str(args.name)
    try:
        recipe = load_canonical_recipe(name)
        checks = validate_canonical_recipe(recipe)
    except Exception as exc:
        print(f"name={name}")
        print("canonical_recipe_status=fail")
        print(f"reason={exc}")
        return 1

    failed = sum(1 for ok, _check_name, _detail in checks if not ok)
    if getattr(args, "emit_build_args", False):
        if failed:
            print(f"canonical_recipe_status=fail failed={failed}", file=sys.stderr)
            return 1
        for line in _build_arg_lines_for_canonical_recipe(name):
            print(line)
        return 0

    print(f"name={recipe.name}")
    print(f"canonical_recipe_digest={recipe.digest}")
    print(f"family={recipe.data.get('family')}")
    print(f"product_component={recipe.data.get('product_component')}")
    for ok, check_name, detail in checks:
        _check_line(ok, check_name, detail)
    if failed:
        print(f"canonical_recipe_status=fail failed={failed}")
        return 1
    print("canonical_recipe_status=ok")
    return 0


def cmd_recipe_list_canonical(args: argparse.Namespace) -> int:
    for name in list_canonical_recipe_names():
        recipe = load_canonical_recipe(name)
        print(f"{recipe.name} {recipe.digest}")
    return 0


def _safe_existing_directory(value: object, name: str) -> Path:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if path.is_symlink():
        raise ValueError(f"{name} must not be a symlink")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{name} must be an existing directory")
    return resolved


def _reject_tree_symlinks(root: Path) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        for name in [*dirs, *files]:
            item = current_path / name
            if item.is_symlink():
                raise ValueError(f"source tree must not contain symlinks: {item}")


def _assert_child_of(child: Path, parent: Path) -> None:
    child_resolved = child.resolve(strict=False)
    parent_resolved = parent.resolve(strict=False)
    if child_resolved != parent_resolved and parent_resolved not in child_resolved.parents:
        raise ValueError(f"path escaped managed root: {child}")


def _ensure_dev_runtime_dir(slot: str) -> Path:
    uid, gid = _slot_uid_gid(slot)
    home = Path("/home") / slot
    if home.is_symlink():
        raise ValueError(f"managed home must not be symlink: {home}")
    if not home.is_dir():
        raise FileNotFoundError(home)
    runtime_dir = home / "openclaw"
    if runtime_dir.exists() and runtime_dir.is_symlink():
        raise ValueError(f"managed runtime dir must not be symlink: {runtime_dir}")
    runtime_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(runtime_dir, uid, gid)
    os.chmod(runtime_dir, 0o750)
    return runtime_dir


def _chmod_source_tree(root: Path, uid: int, gid: int) -> None:
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        os.chown(current_path, uid, gid)
        os.chmod(current_path, 0o750)
        for dirname in dirs:
            path = current_path / dirname
            os.chown(path, uid, gid)
            os.chmod(path, 0o750)
        for filename in files:
            path = current_path / filename
            mode = path.stat().st_mode
            file_mode = 0o750 if mode & stat.S_IXUSR else 0o640
            os.chown(path, uid, gid)
            os.chmod(path, file_mode)


def _sync_dev_source_output(slot: str, recipe_name: str, source: Path) -> Path:
    _reject_tree_symlinks(source)
    runtime_uid, _, data_gid = _runtime_ids(slot)
    home = Path("/home") / slot
    stage_root = home / DEV_RECIPE_STAGE_ROOT
    if stage_root.exists() and stage_root.is_symlink():
        raise ValueError(f"managed source stage root must not be symlink: {stage_root}")
    stage_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(stage_root, runtime_uid, data_gid)
    os.chmod(stage_root, 0o750)
    dest = stage_root / recipe_name
    tmp = stage_root / f".{recipe_name}.tmp.{os.getpid()}"
    backup = stage_root / f".{recipe_name}.previous.{os.getpid()}"
    for path in (dest, tmp, backup):
        _assert_child_of(path, stage_root)
    if tmp.exists():
        shutil.rmtree(tmp)
    if backup.exists():
        shutil.rmtree(backup)
    shutil.copytree(source, tmp, symlinks=False)
    _chmod_source_tree(tmp, runtime_uid, data_gid)
    if dest.exists():
        if dest.is_symlink():
            raise ValueError(f"managed source stage must not be symlink: {dest}")
        os.replace(dest, backup)
    os.replace(tmp, dest)
    if backup.exists():
        shutil.rmtree(backup)
    return dest


def _upsert_runtime_env_file(path: Path, updates: dict[str, str], uid: int, gid: int) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"runtime env file must not be symlink: {path}")
    data = _read_key_value_file(path) if path.exists() else {}
    data.update({key: value for key, value in updates.items() if value})
    _atomic_write_key_value(path, data, 0o640, uid, gid)


def _dev_recipe_runtime_env(desired, state_root: Path) -> dict[str, str]:
    family = str(desired.family or "")
    binding = get_runtime_binding(desired.slot, state_root)
    env = {
        "OPENCLAW_RUNTIME_FAMILY": family,
        "OPENCLAW_IMAGE": str(desired.image_spec.get("wrapper_image") or ""),
        "OPENCLAW_GATEWAY_PORT": str(binding.gateway_port),
        "OPENCLAW_BRIDGE_PORT": str(binding.bridge_port),
    }
    return env


def _redact_git_url(value: str) -> str:
    return re.sub(r"://[^/@]+@", "://<redacted>@", value)


def _source_provenance(source: Path) -> dict[str, object]:
    data: dict[str, object] = {
        "path": str(source),
        "status": "unknown",
        "git_head": "",
        "git_dirty": None,
        "git_toplevel": "",
        "git_remote_origin": "",
    }
    rev = _run_text(["git", "-C", str(source), "rev-parse", "--show-toplevel", "HEAD"], timeout=30)
    if rev.returncode != 0:
        data["status"] = "no_git"
        return data
    lines = [line.strip() for line in rev.stdout.splitlines() if line.strip()]
    if len(lines) >= 2:
        data["git_toplevel"] = lines[0]
        data["git_head"] = lines[1]
    status = _run_text(["git", "-C", str(source), "status", "--porcelain"], timeout=30)
    data["git_dirty"] = bool(status.stdout.strip()) if status.returncode == 0 else None
    remote = _run_text(["git", "-C", str(source), "remote", "get-url", "origin"], timeout=30)
    if remote.returncode == 0:
        data["git_remote_origin"] = _redact_git_url(remote.stdout.strip())
    data["status"] = "git"
    return data


def cmd_recipe_dev_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_runtime_target(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        recipes = _load_dev_recipe_state(state_root).get("recipes") or {}
        recipe = recipes.get(slot) if isinstance(recipes, dict) else None
    except Exception as exc:
        print(f"target={slot}")
        print("recipe_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={desired.slot}")
    print(f"family={desired.family}")
    print(f"runtime_class={desired.runtime_class}")
    print(f"image_name={desired.image_name}")
    print(f"runtime_profile={profile.name}")
    print(f"mode={profile.metadata.get('mode')}")
    if isinstance(recipe, dict):
        print("recipe_status=present")
        for key in ("recipe_name", "source_output", "sync_from", "build_command", "updated_at"):
            print(f"{key}={recipe.get(key, '')}")
        source_provenance = recipe.get("source_provenance")
        if isinstance(source_provenance, dict):
            for key in ("status", "git_head", "git_dirty", "git_toplevel", "git_remote_origin"):
                print(f"source_provenance_{key}={source_provenance.get(key, '')}")
    else:
        print("recipe_status=missing")
    return 0


def cmd_recipe_dev_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl recipe apply-dev TARGET ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_runtime_target(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        if desired.runtime_class != "dev" or profile.metadata.get("mode") != "source":
            raise ValueError("recipe apply-dev requires a dev target using source mode")
        recipe_name = str(args.recipe_name or slot)
        _validate_recipe_name(recipe_name)
        sync_from = str(args.sync_from or "").strip()
        source_output_arg = str(args.source_output or "").strip()
        if bool(sync_from) == bool(source_output_arg):
            raise ValueError("provide exactly one of --sync-from or --source-output")
        if sync_from:
            source = _safe_existing_directory(sync_from, "--sync-from")
            source_output = _sync_dev_source_output(slot, recipe_name, source)
            sync_from_value = str(source)
        else:
            source_output = _safe_existing_directory(source_output_arg, "--source-output")
            sync_from_value = ""
        provenance_source = source if sync_from else source_output
        runtime_dir = _ensure_dev_runtime_dir(slot)
        uid, gid = _slot_uid_gid(slot)
        env_updates = _dev_recipe_runtime_env(desired, state_root)
        env_updates["SOURCE_OUTPUT"] = str(source_output)
        _upsert_runtime_env_file(runtime_dir / ".env", env_updates, uid, gid)
        recipe_state = _load_dev_recipe_state(state_root)
        recipes = recipe_state.setdefault("recipes", {})
        if not isinstance(recipes, dict):
            raise ValueError("dev recipe state recipes must be a mapping")
        recipes[slot] = {
            "target": slot,
            "family": desired.family,
            "runtime_profile": profile.name,
            "recipe_name": recipe_name,
            "source_output": str(source_output),
            "sync_from": sync_from_value,
            "source_provenance": _source_provenance(provenance_source),
            "build_command": _optional_safe_text(args.build_command, "--build-command"),
            "updated_at": _now_iso(),
            "updated_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
        }
        backup_path = _write_dev_recipe_state(state_root, recipe_state)
        _append_action_log(state_root, "recipe_apply_dev", slot, recipe_name, "prepared", f"source_output={source_output}")
    except Exception as exc:
        print(f"target={slot}")
        print("recipe_apply_dev_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "recipe_apply_dev", slot, slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"target={slot}")
    print(f"runtime_profile={profile.name}")
    print("mode=source")
    print(f"recipe_name={recipe_name}")
    print(f"source_output={source_output}")
    if sync_from_value:
        print(f"sync_from={sync_from_value}")
    if backup_path:
        print(f"backup={backup_path}")
    print("recipe_apply_dev_status=prepared")
    if args.no_apply:
        print("apply=skipped")
        return 0
    print("apply=running")
    rc = cmd_apply(
        SimpleNamespace(
            state_root=str(state_root),
            slot=slot,
            allow_first_apply=bool(args.allow_first_apply),
        )
    )
    _append_action_log(state_root, "recipe_apply_dev", slot, recipe_name, "ok" if rc == 0 else "fail", f"apply_rc={rc}")
    return rc


def _runtime_manifest_rollup(state_root: Path, slots: list[str], family: str) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    seen_slots: set[str] = set()
    for slot in slots:
        path = _state_manifest_path(state_root, slot)
        if path.exists() and path.is_symlink():
            raise ValueError(f"managed runtime manifest must not be symlink: {path}")
        if not path.is_file():
            continue
        manifest = load_yaml(path, default={})
        if not isinstance(manifest, dict) or str(manifest.get("family") or "") != family:
            continue
        rows.append(manifest)
        seen_slots.add(slot)

    def item_target(item: dict[str, object]) -> str:
        return str(item.get("target") or item.get("slot") or "")

    def item_runtime_class(item: dict[str, object]) -> str:
        return str(item.get("runtime_class") or item.get("slot_class") or "")

    def item_image_name(item: dict[str, object]) -> str:
        return str(item.get("image_name") or item.get("release") or "")

    direct_targets = [item_target(item) for item in rows if item_image_name(item) == IMAGE_ROLLOUT_IMAGE_NAME]
    customer_targets = [item_target(item) for item in rows if item_runtime_class(item) == "customer"]
    dev_targets = [item_target(item) for item in rows if item_runtime_class(item) == "dev"]
    recipes: list[str] = []
    recipe_digests: list[str] = []
    wrapper_images: list[str] = []
    product_images: list[str] = []
    for item in rows:
        recipe = item.get("recipe")
        recipe_name = ""
        recipe_digest = ""
        if isinstance(recipe, dict):
            recipe_name = str(recipe.get("canonical_recipe_name") or "")
            recipe_digest = str(recipe.get("canonical_recipe_digest") or "")
        if recipe_name:
            recipes.append(recipe_name)
        if recipe_digest:
            recipe_digests.append(recipe_digest)
        if item.get("wrapper_image"):
            wrapper_images.append(str(item.get("wrapper_image")))
        if item.get("product_image"):
            product_images.append(str(item.get("product_image")))

    return {
        "count": len(rows),
        "targets": [item_target(item) for item in rows],
        "customer_targets": customer_targets,
        "dev_targets": dev_targets,
        "direct_targets": direct_targets,
        "missing_targets": [slot for slot in slots if slot not in seen_slots],
        "wrapper_images": sorted(set(wrapper_images)),
        "product_images": sorted(set(product_images)),
        "canonical_recipe_names": sorted(set(recipes)),
        "canonical_recipe_digests": sorted(set(recipe_digests)),
    }


def cmd_rollout_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        family = str(args.family)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        bindings = [binding for binding in load_runtime_bindings(state_root) if binding.enabled and binding.family == family]
        runtime_slots = [binding.linux_account for binding in bindings]
        runtime_rollup = _runtime_manifest_rollup(state_root, runtime_slots, family)
    except Exception as exc:
        print("rollout_status=fail")
        print(f"reason={exc}")
        return 1
    print("rollout_status=ok")
    print("status_source=runtime_manifests")
    print(f"family={family}")
    print(f"binding_targets={','.join(runtime_slots)}")
    print(f"runtime_manifest_count={runtime_rollup['count']}")
    print(f"runtime_manifest_targets={','.join(runtime_rollup['targets'])}")
    print(f"runtime_manifest_customer_targets={','.join(runtime_rollup['customer_targets'])}")
    print(f"runtime_manifest_dev_targets={','.join(runtime_rollup['dev_targets'])}")
    print(f"runtime_manifest_direct_image_targets={','.join(runtime_rollup['direct_targets'])}")
    print(f"runtime_manifest_missing_targets={','.join(runtime_rollup['missing_targets'])}")
    print(f"runtime_manifest_wrapper_images={','.join(runtime_rollup['wrapper_images'])}")
    print(f"runtime_manifest_product_images={','.join(runtime_rollup['product_images'])}")
    print(f"runtime_manifest_canonical_recipe_names={','.join(runtime_rollup['canonical_recipe_names'])}")
    print(f"runtime_manifest_canonical_recipe_digests={','.join(runtime_rollup['canonical_recipe_digests'])}")
    return 0


def _image_spec_canonical_record(image_spec: dict) -> dict[str, str]:
    return canonical_recipe_identity(canonical_recipe_for_image_spec(image_spec))


def _desired_from_direct_images(slot: str, image_spec: dict, state_root: Path):
    binding = get_runtime_binding(slot, state_root)
    runtime_class = binding.runtime_class
    image_recipe = _image_spec_recipe(image_spec)
    profiles = image_recipe.get("runtime_profiles") if isinstance(image_recipe, dict) else {}
    runtime_profile = profiles.get(runtime_class) if isinstance(profiles, dict) else ""
    if not runtime_profile:
        raise ValueError(f"wrapper image recipe has no runtime profile for runtime_class={runtime_class}")
    family = str(image_recipe.get("family") or image_spec.get("family") or "")
    profile = load_profile(str(runtime_profile))
    if profile.metadata.get("family") != family:
        raise ValueError(f"slot image family/profile mismatch: image={family} profile={profile.metadata.get('family')}")
    if profile.metadata.get("slot_class") != runtime_class:
        raise ValueError(
            f"binding image runtime_class/profile mismatch: binding={runtime_class} profile={profile.metadata.get('slot_class')}"
        )
    if family != binding.family:
        raise ValueError(f"binding image family mismatch: image={family} binding={binding.family}")
    desired = RuntimeTarget(
        target=binding.linux_account,
        family=family,
        runtime_class=runtime_class,
        image_name=IMAGE_ROLLOUT_IMAGE_NAME,
        image_spec=image_spec,
        runtime_profile=str(runtime_profile),
        route=binding,
    )
    return desired, profile


def _desired_from_live_image_truth(slot: str, state_root: Path):
    truth, checks = _live_runtime_truth(slot, state_root)
    failed = [name for ok, name, _ in checks if not ok]
    if failed or truth.get("truth_status") != "ok":
        raise ValueError(f"live image truth is not ok: status={truth.get('truth_status')} failed={','.join(failed)}")
    wrapper_image = str(truth.get("wrapper_image") or "")
    product_image = str(truth.get("product_image") or "")
    image_spec = _image_spec_from_direct_images(wrapper_image, product_image)
    return _desired_from_direct_images(slot, image_spec, state_root)


def _direct_image_spec_from_args(args: argparse.Namespace) -> dict[str, object]:
    return _image_spec_from_direct_images(str(args.wrapper_image), str(args.product_image))


def cmd_rollout_image_plan(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        image_spec = _direct_image_spec_from_args(args)
        slots = [str(item) for item in (getattr(args, "slots", None) or [])]
        if getattr(args, "slot", None):
            slots.append(str(args.slot))
        if not slots:
            slots = [binding.linux_account for binding in load_runtime_bindings(state_root) if binding.enabled]
        plans = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            rendered = render_compose(profile, desired)
            checks = [
                {"ok": ok, "name": name, "detail": detail}
                for ok, name, detail in _run_static_slot_checks(desired, profile, rendered)
            ]
            plans.append(
                {
                    "linux_account": desired.slot,
                    "runtime_class": desired.runtime_class,
                    "public_host": _apache_public_host(slot),
                    "gateway_port": desired.route.gateway_port if desired.route else "",
                    "bridge_port": desired.route.bridge_port if desired.route else "",
                    "runtime_profile": profile.name,
                    "runtime_contract": _profile_runtime_contract(profile),
                    "checks": checks,
                    "compatible": all(item["ok"] for item in checks),
                    "compose_sha256": rendered.sha256,
                }
            )
        payload = {
            "rollout_image_plan_status": "ok",
            "truth_source": "wrapper_image_labels",
            "family": image_spec.get("family"),
            "wrapper_image": image_spec.get("wrapper_image"),
            "product_image": image_spec.get("product_image"),
            "recipe": _image_spec_recipe_payload(image_spec),
            "targets": plans,
            "mutates": False,
        }
    except Exception as exc:
        print(json.dumps({"rollout_image_plan_status": "fail", "reason": str(exc), "mutates": False}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_rollout_image_apply_slot(args: argparse.Namespace, *, required_runtime_class: str, action_name: str) -> int:
    if not _is_root():
        print(f"error: run as root/admin: sudo /usr/local/bin/opsctl rollout {action_name} ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        image_spec = _direct_image_spec_from_args(args)
        desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
        if desired.runtime_class != required_runtime_class:
            raise ValueError(f"{action_name} requires runtime_class={required_runtime_class}: {slot}")
    except Exception as exc:
        print(f"rollout_{action_name.replace('-', '_')}_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, f"rollout_{action_name}", slot, IMAGE_ROLLOUT_IMAGE_NAME, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"rollout_{action_name.replace('-', '_')}_state=direct_image")
    print(f"target={slot}")
    print(f"family={desired.family}")
    print(f"runtime_profile={profile.name}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    for key, value in _image_spec_canonical_record(image_spec).items():
        print(f"{key}={value}")
    rc = _apply_desired_slot(
        desired=desired,
        profile=profile,
        state_root=state_root,
        allow_first_apply=bool(getattr(args, "allow_first_apply", False)),
        action_name=f"rollout_{action_name}",
    )
    if rc == 0:
        print(f"rollout_{action_name.replace('-', '_')}_status=ok")
    return rc


def cmd_rollout_image_dev_apply(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="dev", action_name="image-dev-apply")


def cmd_rollout_image_canary(args: argparse.Namespace) -> int:
    return _cmd_rollout_image_apply_slot(args, required_runtime_class="customer", action_name="image-canary")


def cmd_rollout_image_promote(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout image-promote ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    from_slot = str(args.from_slot)
    try:
        source_truth, source_checks = _live_runtime_truth(from_slot, state_root)
        failed = [name for ok, name, _ in source_checks if not ok]
        if failed or source_truth.get("truth_status") != "ok":
            raise ValueError(
                f"from-target live image truth is not ok: status={source_truth.get('truth_status')} failed={','.join(failed)}"
            )
        wrapper_image = str(source_truth.get("wrapper_image") or "")
        product_image = str(source_truth.get("product_image") or "")
        image_spec = _image_spec_from_direct_images(wrapper_image, product_image)
        slots = [item.strip() for item in str(args.slots).split(",") if item.strip()]
        if not slots:
            raise ValueError("--targets must name the promotion targets explicitly")
        applied: list[str] = []
        for slot in slots:
            desired, profile = _desired_from_direct_images(slot, image_spec, state_root)
            if desired.runtime_class != "customer":
                raise ValueError(f"promotion target is not a customer target: {slot}")
            rc = _apply_desired_slot(
                desired=desired,
                profile=profile,
                state_root=state_root,
                allow_first_apply=False,
                action_name="rollout_image_promote",
            )
            if rc != 0:
                print("rollout_image_promote_status=partial")
                print(f"failed_target={slot}")
                _append_action_log(state_root, "rollout_image_promote", slot, wrapper_image, "partial", "slot_apply_failed")
                return rc or 1
            applied.append(slot)
    except Exception as exc:
        print("rollout_image_promote_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_image_promote", from_slot, from_slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print("rollout_image_promote_status=ok")
    print(f"from_target={from_slot}")
    print(f"targets={','.join(applied)}")
    print(f"wrapper_image={image_spec.get('wrapper_image')}")
    print(f"product_image={image_spec.get('product_image')}")
    _append_action_log(state_root, "rollout_image_promote", from_slot, str(image_spec.get("wrapper_image") or ""), "ok", f"targets={len(applied)}")
    return 0


def _read_key_value_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        data[key] = value
    return data


def _atomic_write_key_value(path: Path, data: dict[str, str], mode: int, uid: int | None = None, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, value in data.items():
                handle.write(f"{key}={value}\n")
        os.chmod(tmp_path, mode)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            os.chown(tmp_path, uid, gid)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def _passwd_record(name: str):
    import pwd

    return pwd.getpwnam(name)


def _group_gid(name: str) -> int:
    import grp

    return grp.getgrnam(name).gr_gid


def _slot_uid_gid(slot: str) -> tuple[int, int]:
    record = _passwd_record(slot)
    return int(record.pw_uid), int(record.pw_gid)


def _runtime_ids(slot: str) -> tuple[int, int, int]:
    runtime = _passwd_record(f"{slot}_rt")
    data_gid = _group_gid(f"{slot}_data")
    return int(runtime.pw_uid), int(runtime.pw_gid), data_gid


def _ensure_not_symlink_chain(path: Path, stop_at: Path) -> None:
    current = path
    checked: list[Path] = []
    while True:
        checked.append(current)
        if current == stop_at:
            break
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(checked):
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"path component must not be symlink: {candidate}")


def _ensure_customer_agent_dirs(slot: str) -> None:
    uid, gid = _slot_uid_gid(slot)
    base = agent_nas_dir(slot)
    home = Path("/home") / slot
    _ensure_not_symlink_chain(base, home)
    for path, mode in [
        (base, 0o700),
        (request_dir(slot), 0o700),
        (base / "credentials", 0o700),
        (base / "history", 0o700),
        (history_dir(slot, "approved"), 0o700),
        (history_dir(slot, "rejected"), 0o700),
    ]:
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def _read_password_from_stdin() -> str:
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    if password.endswith("\r"):
        password = password[:-1]
    if not password:
        raise ValueError("password stdin is empty")
    return password


def _write_credential_file(path: Path, username: str, password: str, domain: str | None, uid: int, gid: int) -> None:
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    _ensure_not_symlink_chain(path.parent, path.parents[2] if len(path.parents) > 2 else path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, uid, gid)
    os.chmod(path.parent, 0o700)
    data = {"username": username, "password": password}
    if domain:
        data["domain"] = domain
    _atomic_write_key_value(path, data, 0o600, uid, gid)


def _credential_file_is_safe(path: Path, uid: int | None = None) -> None:
    if path.is_symlink():
        raise ValueError(f"credential file must not be symlink: {path}")
    stat_result = path.stat()
    if not path.is_file():
        raise ValueError(f"credential path is not a regular file: {path}")
    if stat_result.st_mode & 0o077:
        raise ValueError(f"credential file must be 0600: {path}")
    if uid is not None and stat_result.st_uid != uid:
        raise ValueError(f"credential file owner mismatch: {path}")


def _credential_file_is_safe_for_slot(slot: str, path: Path, uid: int | None = None) -> None:
    customer_root = agent_nas_dir(slot) / "credentials"
    root_credential_root = Path("/root") / "agent-runtime-ops" / "nas-credentials" / slot
    resolved = path.resolve(strict=False)
    if str(resolved).startswith(str(customer_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/home") / slot)
    elif str(resolved).startswith(str(root_credential_root.resolve(strict=False)) + os.sep):
        _ensure_not_symlink_chain(path.parent, Path("/root"))
    else:
        raise ValueError(f"credential path outside managed roots: {path}")
    _credential_file_is_safe(path, uid=uid)


def _credential_presence(path: Path) -> str:
    try:
        path.stat()
        return "yes"
    except FileNotFoundError:
        return "no"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"


def _official_credential_paths(slot: str, share) -> dict[str, Path]:
    return {
        "root": root_credential_path(slot, share),
        "customer": customer_credential_path(slot, share),
    }


def _combine_presence(*values: str) -> str:
    if "yes" in values:
        return "yes"
    if "unknown" in values:
        return "unknown"
    return "no"


def _official_credential_status(slot: str, share) -> dict[str, str]:
    paths = _official_credential_paths(slot, share)
    root_present = _credential_presence(paths["root"])
    customer_present = _credential_presence(paths["customer"])
    official_present = _combine_presence(root_present, customer_present)
    return {
        "root_credential_present": root_present,
        "customer_credential_present": customer_present,
        "official_credential_present": official_present,
        "remount_possible": "yes" if official_present == "yes" else official_present,
    }


def _print_official_credential_status(prefix: str, status: dict[str, str]) -> None:
    for key in [
        "root_credential_present",
        "customer_credential_present",
        "official_credential_present",
        "remount_possible",
    ]:
        print(f"{prefix}{key}={status[key]}")


def _fstab_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(" ", "\\040").replace("\t", "\\011").replace("\n", "")


def _managed_fstab_marker(slot: str, share: str) -> str:
    return f"# agent-runtime-ops nas slot={slot} source={share}"


def _write_managed_fstab_entry(slot: str, share: str, mountpoint: Path, credential_path: Path) -> None:
    slot_uid, _ = _slot_uid_gid(slot)
    _, _, data_gid = _runtime_ids(slot)
    escaped_target = _fstab_escape(str(mountpoint))
    escaped_source = _fstab_escape(share)
    options = ",".join(
        [
            f"credentials={_fstab_escape(str(credential_path))}",
            "ro",
            "nosuid",
            "nodev",
            "vers=3.1.1",
            "iocharset=utf8",
            "noserverino",
            f"uid={slot_uid}",
            "forceuid",
            f"gid={data_gid}",
            "forcegid",
            "file_mode=0440",
            "dir_mode=0550",
            "soft",
            "nofail",
            "_netdev",
        ]
    )
    marker = _managed_fstab_marker(slot, share)
    entry = f"{escaped_source} {escaped_target} cifs {options} 0 0"

    lock_path = Path("/run/agent-runtime-ops-fstab.lock")
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        import fcntl

        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        fstab = Path("/etc/fstab")
        lines = fstab.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        skip_next = False
        replaced = False
        for index, line in enumerate(lines):
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                skip_next = True
                if not replaced:
                    new_lines.extend([marker, entry])
                    replaced = True
                continue
            columns = line.split()
            if columns and not line.lstrip().startswith("#") and len(columns) >= 2 and columns[1] == escaped_target:
                raise ValueError(f"non-managed fstab entry already owns mountpoint: {mountpoint}")
            new_lines.append(line)
        if not replaced:
            if new_lines and new_lines[-1] != "":
                new_lines.append("")
            new_lines.extend([marker, entry])
        tmp = fstab.with_name("fstab.agent-runtime-ops.tmp")
        tmp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, fstab)


def _remove_managed_fstab_entry(
    slot: str,
    share: str,
    *,
    fstab_path: Path = Path("/etc/fstab"),
    lock_path: Path = Path("/run/agent-runtime-ops-fstab.lock"),
) -> bool:
    marker = _managed_fstab_marker(slot, share)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+") as lock_handle:
        try:
            import fcntl

            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass
        lines = fstab_path.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        removed = False
        skip_next = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line == marker:
                removed = True
                skip_next = True
                continue
            new_lines.append(line)
        if not removed:
            return False
        tmp = fstab_path.with_name(f"{fstab_path.name}.agent-runtime-ops.tmp")
        tmp.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, fstab_path)
        return True


def _append_action_log(state_root: Path, action: str, slot: str, target: str, status: str, detail: str = "") -> None:
    log_path = state_root / "actions.log"
    record = {
        "timestamp": _now_iso(),
        "action": action,
        "slot": slot,
        "target": target,
        "status": status,
        "detail": str(detail or "")[:500],
    }
    if action.startswith("nas_") or (isinstance(target, str) and target.startswith("//")):
        record["share"] = target
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _prepare_mount_entry(slot: str, share_source: str, credential_path: Path, state_root: Path) -> tuple[object, Path]:
    decision = check_nas_policy(slot, share_source, state_root)
    if not decision.allowed:
        raise ValueError(f"policy denied: {decision.reason}")
    _safe_mountpoint_path(decision.mountpoint)
    decision.mountpoint.mkdir(parents=True, exist_ok=True)
    _safe_mountpoint_path(decision.mountpoint)
    _credential_file_is_safe_for_slot(slot, credential_path)
    current_count = _mounted_child_cifs_count(decision.slot)
    existing_rc, _, existing_rows = _findmnt_one(decision.mountpoint)
    already_same_mount = (
        existing_rc == 0
        and bool(existing_rows)
        and existing_rows[0].get("source") == decision.share.source
    )
    if not already_same_mount and not _max_mounts_allows(decision.max_mounts, current_count):
        raise ValueError(f"max_mounts_exceeded: current={current_count} max={decision.max_mounts}")
    _write_managed_fstab_entry(decision.slot, decision.share.source, decision.mountpoint, credential_path)
    return decision, decision.mountpoint


def _mount_prepared_share(decision, state_root: Path) -> tuple[bool, str]:
    rc, _, rows = _findmnt_one(decision.mountpoint)
    if rc == 0 and rows:
        row = rows[0]
        ok = row.get("source") == decision.share.source and row.get("fstype") == "cifs" and _is_readonly_mount(row)
        return ok, "already_mounted" if ok else "mountpoint_has_unexpected_existing_mount"

    proc = _run_text(["mount", str(decision.mountpoint)], timeout=60)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()

    rc, error, rows = _findmnt_one(decision.mountpoint)
    ok = (
        rc == 0
        and bool(rows)
        and rows[0].get("source") == decision.share.source
        and rows[0].get("fstype") == "cifs"
        and _is_readonly_mount(rows[0])
    )
    return ok, "ok" if ok else (error or "mounted_state_did_not_match_expected_cifs_ro")


def _move_request(path: Path, slot: str, status: str) -> Path:
    target_dir = history_dir(slot, status)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{datetime.now().strftime('%Y%m%dT%H%M%S')}.{path.name}"
    os.replace(path, target)
    return target


def _safe_request_file(path: Path, slot: str) -> None:
    uid, _ = _slot_uid_gid(slot)
    if path.is_symlink():
        raise ValueError(f"request file must not be symlink: {path}")
    stat_result = path.stat()
    if stat_result.st_uid != uid:
        raise ValueError(f"request file owner mismatch: {path}")
    if stat_result.st_mode & 0o022:
        raise ValueError(f"request file must not be group/world writable: {path}")


def _approve_auto_once(state_root: Path) -> dict[str, int]:
    result = {"checked": 0, "approved": 0, "pending": 0, "rejected": 0, "failed": 0}
    for binding in load_runtime_bindings(state_root):
        if binding.runtime_class != "customer":
            continue
        slot = binding.linux_account
        pending_dir = request_dir(slot)
        if not pending_dir.is_dir():
            continue
        for path in sorted(pending_dir.glob("*.env")):
            result["checked"] += 1
            try:
                _safe_request_file(path, slot)
                data = _read_key_value_file(path)
                share_source = data.get("requested_share") or ""
                decision = check_nas_policy(slot, share_source, state_root)
                if not decision.allowed:
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, share_source, "rejected", decision.reason)
                    result["rejected"] += 1
                    continue
                credential_path = customer_credential_path(slot, decision.share)
                if not credential_path.exists():
                    print(f"pending target={slot} share={decision.share.source} reason=credential_missing")
                    result["pending"] += 1
                    continue
                slot_uid, _ = _slot_uid_gid(slot)
                _credential_file_is_safe_for_slot(slot, credential_path, uid=slot_uid)
                decision, _ = _prepare_mount_entry(slot, decision.share.source, credential_path, state_root)
                ok, reason = _mount_prepared_share(decision, state_root)
                if ok:
                    _move_request(path, slot, "approved")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "approved", reason)
                    result["approved"] += 1
                else:
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, decision.share.source, "rejected", reason)
                    result["rejected"] += 1
                    result["failed"] += 1
            except Exception as exc:
                try:
                    share_source = _read_key_value_file(path).get("requested_share", "")
                    _move_request(path, slot, "rejected")
                    _append_action_log(state_root, "nas_approve_auto", slot, share_source, "rejected", str(exc))
                except Exception:
                    pass
                print(f"rejected target={slot} file={path} reason={exc}")
                result["rejected"] += 1
                result["failed"] += 1
    return result


def cmd_nas_requests(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    total = 0
    for binding in load_runtime_bindings(state_root):
        if binding.runtime_class != "customer":
            continue
        slot = binding.linux_account
        pending_dir = request_dir(slot)
        if not pending_dir.is_dir():
            continue
        for path in sorted(pending_dir.glob("*.env")):
            if path.is_symlink():
                continue
            try:
                data = _read_key_value_file(path)
            except Exception as exc:
                print(f"request target={slot} file={path.name} status=unreadable reason={exc}")
                total += 1
                continue
            share = data.get("requested_share") or ""
            created_at = data.get("created_at") or ""
            print(f"request target={slot} share={share} created_at={created_at} file={path}")
            total += 1
    print(f"pending_request_count={total}")
    print("nas_requests_status=ok")
    print("mutates=false")
    return 0


def cmd_nas_approve_auto(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas approve-auto", file=sys.stderr)
        return 2

    def run_once() -> int:
        result = _approve_auto_once(_state_root(args))
        print(f"checked_request_count={result['checked']}")
        print(f"approved_request_count={result['approved']}")
        print(f"pending_request_count={result['pending']}")
        print(f"rejected_request_count={result['rejected']}")
        print(f"approve_auto_status={'ok' if result['failed'] == 0 else 'fail'}")
        return 0 if result["failed"] == 0 else 1

    if not args.watch:
        return run_once()

    interval = max(5, int(args.interval))
    while True:
        tick_started = _now_iso()
        result = _approve_auto_once(_state_root(args))
        print(
            "nas_request_watch_tick "
            f"checked={result['checked']} approved={result['approved']} "
            f"pending={result['pending']} rejected={result['rejected']} failed={result['failed']} "
            f"tick_at={tick_started}",
            flush=True,
        )
        import time

        time.sleep(interval)


def cmd_nas_policy_check(args: argparse.Namespace) -> int:
    try:
        decision = check_nas_policy(args.slot, args.share, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("policy_check_status=fail")
        print(f"reason={exc}")
        print("mutates=false")
        return 1
    print(f"target={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    print(f"matched_grant={decision.matched_grant or ''}")
    print(f"max_mounts={decision.max_mounts if decision.max_mounts is not None else ''}")
    print(f"policy_check_status={'pass' if decision.allowed else 'fail'}")
    print(f"reason={decision.reason}")
    print("mutates=false")
    return 0 if decision.allowed else 1


def _caller_customer_slot(state_root: Path) -> str:
    user = getpass.getuser()
    binding = get_runtime_binding(user, state_root)
    if binding.linux_account != user or binding.runtime_class != "customer":
        raise ValueError(f"this command must be run by a customer linux_account, got {user}")
    return user


def cmd_nas_request(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot(_state_root(args))
        decision = check_nas_policy(slot, args.share, _state_root(args))
        if not decision.allowed:
            raise ValueError(f"policy denied: {decision.reason}")
        _ensure_customer_agent_dirs(slot)
        path = request_path(slot, decision.share)
        uid, gid = _slot_uid_gid(slot)
        _atomic_write_key_value(
            path,
            {
                "slot": slot,
                "requested_share": decision.share.source,
                "mountpoint": str(decision.mountpoint),
                "created_at": _now_iso(),
            },
            0o600,
            uid,
            gid,
        )
    except Exception as exc:
        print("request_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={slot}")
    print(f"requested_share={decision.share.source}")
    print(f"request_file={path}")
    print(f"mountpoint={decision.mountpoint}")
    print("request_status=pending")
    print("next_action=run opsctl nas credential set //HOST/SHARE --username NAS_USER --password-stdin")
    return 0


def cmd_nas_credential_set(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot()
        decision = check_nas_policy(slot, args.share, _state_root(args))
        if not decision.allowed:
            raise ValueError(f"policy denied: {decision.reason}")
        password = _read_password_from_stdin()
        _ensure_customer_agent_dirs(slot)
        credential_path = customer_credential_path(slot, decision.share)
        uid, gid = _slot_uid_gid(slot)
        _write_credential_file(credential_path, args.username, password, args.domain, uid, gid)
    except Exception as exc:
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"target={slot}")
    print(f"share={decision.share.source}")
    print(f"credential_file={credential_path}")
    print("credential_status=stored")
    print("secret_value_printed=no")
    return 0


def _findmnt_one(path: Path) -> tuple[int, str, list[dict[str, str]]]:
    command = ["findmnt", "-M", str(path), "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION"]
    proc = _run_text(command)
    return proc.returncode, (proc.stderr or proc.stdout).strip(), _parse_findmnt_pairs(proc.stdout)


def _safe_mountpoint_path(mountpoint: Path) -> None:
    for candidate in [mountpoint.parent.parent, mountpoint.parent, mountpoint]:
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"mount path component must not be symlink: {candidate}")


def _mounted_child_cifs_count(slot: str) -> int:
    root = Path("/home") / slot / "nas_docs"
    rc, _, rows = _findmnt_under(str(root))
    if rc != 0:
        return 0
    return len([row for row in rows if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")])


def _max_mounts_allows(value: object, current_count: int) -> bool:
    if value in {None, "", "unlimited"}:
        return True
    try:
        return current_count < int(value)
    except (TypeError, ValueError):
        return False


def _print_mount_row(prefix: str, row: dict[str, str]) -> None:
    print(f"{prefix}_target={row.get('target', '')}")
    print(f"{prefix}_source={row.get('source', '')}")
    print(f"{prefix}_fstype={row.get('fstype', '')}")
    print(f"{prefix}_readonly={'yes' if _is_readonly_mount(row) else 'no'}")
    if row.get("propagation"):
        print(f"{prefix}_propagation={row.get('propagation')}")


def cmd_nas_credential_status(args: argparse.Namespace) -> int:
    try:
        load_runtime_target(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    status = _official_credential_status(args.slot, share)
    print(f"target={args.slot}")
    print(f"share={share.source}")
    print("credential_scope=official")
    print("mutates=false")
    _print_official_credential_status("", status)
    print("credential_status=ok")
    print("secret_value_printed=no")
    return 0


def cmd_nas_mounted(args: argparse.Namespace) -> int:
    try:
        desired = load_runtime_target(args.slot, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print("mounted_status=fail")
        print(f"reason={exc}")
        return 1
    root = Path("/home") / desired.slot / "nas_docs"
    rc, error, rows = _findmnt_under(str(root))
    print(f"target={desired.slot}")
    print(f"nas_root={root}")
    print("mutates=false")
    if rc != 0:
        print("mounted_status=fail")
        print(f"reason={error or 'findmnt_failed'}")
        return 1
    child_rows = [row for row in rows if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")]
    print(f"mounted_child_cifs_count={len(child_rows)}")
    for index, row in enumerate(child_rows, start=1):
        prefix = f"mount_{index}"
        _print_mount_row(prefix, row)
        try:
            share = parse_smb_share(row.get("source", ""))
            _print_official_credential_status(f"{prefix}_", _official_credential_status(desired.slot, share))
        except Exception:
            print(f"{prefix}_official_credential_present=unknown")
            print(f"{prefix}_remount_possible=unknown")
    print("mounted_status=ok")
    return 0


def cmd_nas_mount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas mount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        decision = check_nas_policy(args.slot, args.share, _state_root(args))
        if args.username or args.password_stdin:
            if not args.username or not args.password_stdin:
                raise ValueError("--username and --password-stdin must be used together")
            password = _read_password_from_stdin()
            credential_path = root_credential_path(args.slot, decision.share)
            _write_credential_file(credential_path, args.username, password, args.domain, 0, 0)
        else:
            credential_path = root_credential_path(args.slot, decision.share)
            if not credential_path.exists():
                credential_path = customer_credential_path(args.slot, decision.share)
            if not credential_path.exists():
                raise ValueError("credential_missing: pass --username USER --password-stdin or create a customer credential")
        decision, _ = _prepare_mount_entry(args.slot, args.share, credential_path, _state_root(args))
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("mount_status=fail")
        print(f"reason={exc}")
        return 1

    rc, _, rows = _findmnt_one(decision.mountpoint)
    if rc == 0 and rows:
        row = rows[0]
        _print_mount_row("existing_mount", row)
        ok = row.get("source") == decision.share.source and row.get("fstype") == "cifs" and _is_readonly_mount(row)
        print(f"mount_status={'already_mounted' if ok else 'fail'}")
        if not ok:
            print("reason=mountpoint_has_unexpected_existing_mount")
        _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "already_mounted" if ok else "fail")
        return 0 if ok else 1

    ok, reason = _mount_prepared_share(decision, _state_root(args))
    rc, error, rows = _findmnt_one(decision.mountpoint)
    print(f"target={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    if rows:
        _print_mount_row("mounted", rows[0])
    print(f"mount_status={'ok' if ok else 'fail'}")
    if not ok:
        print(f"reason={reason or error or 'mounted_state_did_not_match_expected_cifs_ro'}")
    _append_action_log(_state_root(args), "nas_mount", decision.slot, decision.share.source, "ok" if ok else "fail", reason)
    return 0 if ok else 1


def cmd_nas_unmount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas unmount TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        load_runtime_target(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(args.slot, share)
        _safe_mountpoint_path(mountpoint)
        credential_status = _official_credential_status(args.slot, share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("unmount_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, args.share, "fail", str(exc))
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    if rc != 0 or not rows:
        print(f"target={args.slot}")
        print(f"share={share.source}")
        print(f"mountpoint={mountpoint}")
        _print_official_credential_status("", credential_status)
        print("credential_removed=no")
        print("unmount_status=already_unmounted")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, share.source, "already_unmounted")
        return 0
    row = rows[0]
    _print_mount_row("existing_mount", row)
    if row.get("source") != share.source:
        print("unmount_status=fail")
        print("reason=mountpoint_source_does_not_match_requested_share")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, share.source, "fail", "mountpoint_source_does_not_match_requested_share")
        return 1

    command = ["umount"]
    if args.lazy:
        command.append("--lazy")
    command.append(str(mountpoint))
    proc = _run_text(command, timeout=60)
    if proc.returncode != 0:
        print("unmount_status=fail")
        print(f"reason={(proc.stderr or proc.stdout).strip()}")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, share.source, "fail", (proc.stderr or proc.stdout).strip())
        return proc.returncode or 1
    if args.delete_empty_dir:
        try:
            mountpoint.rmdir()
            print("empty_dir_removed=yes")
        except OSError:
            print("empty_dir_removed=no")
    _print_official_credential_status("", credential_status)
    print("credential_removed=no")
    print("unmount_status=ok")
    _append_action_log(_state_root(args), "nas_unmount", args.slot, share.source, "ok", "credential_removed=no")
    return 0


def _validate_official_credentials_for_delete(slot: str, share) -> None:
    paths = _official_credential_paths(slot, share)
    slot_uid, _ = _slot_uid_gid(slot)
    for name, path in paths.items():
        if _credential_presence(path) == "yes":
            _credential_file_is_safe_for_slot(slot, path, uid=0 if name == "root" else slot_uid)


def _delete_official_credentials(slot: str, share) -> dict[str, str]:
    paths = _official_credential_paths(slot, share)
    removed: dict[str, str] = {}
    for name, path in paths.items():
        if _credential_presence(path) == "yes":
            path.unlink()
            removed[f"{name}_credential_removed"] = "yes"
        else:
            removed[f"{name}_credential_removed"] = "no"
    return removed


def cmd_nas_remove(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas remove TARGET //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        load_runtime_target(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(args.slot, share)
        _safe_mountpoint_path(mountpoint)
        before_status = _official_credential_status(args.slot, share)
        # Validate credentials before mutating mount or fstab state.
        _validate_official_credentials_for_delete(args.slot, share)
    except Exception as exc:
        print(f"target={args.slot}")
        print(f"share={args.share}")
        print("remove_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_remove", args.slot, args.share, "fail", str(exc))
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    unmount_status = "already_unmounted"
    if rc == 0 and rows:
        row = rows[0]
        _print_mount_row("existing_mount", row)
        if row.get("source") != share.source:
            print("remove_status=fail")
            print("reason=mountpoint_source_does_not_match_requested_share")
            _append_action_log(_state_root(args), "nas_remove", args.slot, share.source, "fail", "mountpoint_source_does_not_match_requested_share")
            return 1
        command = ["umount"]
        if args.lazy:
            command.append("--lazy")
        command.append(str(mountpoint))
        proc = _run_text(command, timeout=60)
        if proc.returncode != 0:
            print("unmount_status=fail")
            print("remove_status=fail")
            print(f"reason={(proc.stderr or proc.stdout).strip()}")
            _append_action_log(_state_root(args), "nas_remove", args.slot, share.source, "fail", (proc.stderr or proc.stdout).strip())
            return proc.returncode or 1
        unmount_status = "ok"

    try:
        fstab_removed = _remove_managed_fstab_entry(args.slot, share.source)
        removed = _delete_official_credentials(args.slot, share)
    except Exception as exc:
        print("remove_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_remove", args.slot, share.source, "fail", str(exc))
        return 1
    if args.delete_empty_dir:
        try:
            mountpoint.rmdir()
            print("empty_dir_removed=yes")
        except OSError:
            print("empty_dir_removed=no")
    after_status = _official_credential_status(args.slot, share)
    print(f"target={args.slot}")
    print(f"share={share.source}")
    print(f"mountpoint={mountpoint}")
    print(f"unmount_status={unmount_status}")
    print(f"fstab_entry_removed={'yes' if fstab_removed else 'no'}")
    print(f"root_credential_removed={removed['root_credential_removed']}")
    print(f"customer_credential_removed={removed['customer_credential_removed']}")
    print("credential_scope=official")
    print("credential_present_before=" + before_status["official_credential_present"])
    _print_official_credential_status("", after_status)
    print("remove_status=ok")
    detail = (
        f"unmount_status={unmount_status} "
        f"fstab_entry_removed={'yes' if fstab_removed else 'no'} "
        f"root_credential_removed={removed['root_credential_removed']} "
        f"customer_credential_removed={removed['customer_credential_removed']}"
    )
    _append_action_log(_state_root(args), "nas_remove", args.slot, share.source, "ok", detail)
    return 0


def cmd_admin_serve(args: argparse.Namespace) -> int:
    from .admin_server import main as admin_main

    return admin_main(["--host", args.host, "--port", str(args.port)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT))
    sub = parser.add_subparsers(dest="command", required=True)

    self_update = sub.add_parser("self-update")
    self_update.set_defaults(func=cmd_self_update)

    update = sub.add_parser("update")
    update_sub = update.add_subparsers(dest="update_command", required=True)
    update_approve = update_sub.add_parser("approve")
    update_approve.add_argument("ref", help="approved full 40-character commit sha")
    update_approve.set_defaults(func=cmd_update_approve)
    update_status = update_sub.add_parser("status")
    update_status.set_defaults(func=cmd_update_status)

    profile = sub.add_parser("profile")
    profile_sub = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_sub.add_parser("list")
    profile_list.set_defaults(func=cmd_profile_list)

    binding = sub.add_parser("binding")
    binding_sub = binding.add_subparsers(dest="binding_command", required=True)
    binding_list = binding_sub.add_parser("list")
    binding_list.set_defaults(func=cmd_binding_list)
    binding_status = binding_sub.add_parser("status")
    binding_status.add_argument("target", nargs="?")
    binding_status.set_defaults(func=cmd_binding_status)
    binding_normalize = binding_sub.add_parser("normalize")
    binding_normalize.add_argument("--write", action="store_true")
    binding_normalize.set_defaults(func=cmd_binding_normalize)
    binding_set_host = binding_sub.add_parser("set-public-host")
    binding_set_host.add_argument("target")
    binding_set_host.add_argument("host")
    binding_set_host.set_defaults(func=cmd_binding_set_public_host)

    apache = sub.add_parser("apache")
    apache_sub = apache.add_subparsers(dest="apache_command", required=True)
    apache_status = apache_sub.add_parser("status")
    apache_status.add_argument("target", nargs="?")
    apache_status.set_defaults(func=cmd_apache_status)
    apache_set_host = apache_sub.add_parser("set-host")
    apache_set_host.add_argument("linux_account")
    apache_set_host.add_argument("host")
    apache_set_host.set_defaults(func=cmd_apache_set_host)

    runtime = sub.add_parser("runtime")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_truth = runtime_sub.add_parser("truth")
    runtime_truth.add_argument("slot", nargs="?", metavar="target")
    runtime_truth.add_argument("--all", action="store_true")
    runtime_truth.set_defaults(func=cmd_runtime_truth)

    for name, func in (("status", cmd_status), ("plan", cmd_plan), ("check", cmd_check)):
        item = sub.add_parser(name)
        item.add_argument("slot", metavar="target")
        if name == "check":
            item.add_argument("--live", action="store_true", help="also inspect Docker and NAS runtime state without writing")
        item.set_defaults(func=func)

    apply = sub.add_parser("apply")
    apply.add_argument("slot", metavar="target")
    apply.add_argument("--allow-first-apply", action="store_true")
    apply.set_defaults(func=cmd_apply)

    rollback = sub.add_parser("rollback")
    rollback.add_argument("slot", metavar="target")
    rollback.set_defaults(func=cmd_rollback)

    diagnostics = sub.add_parser("diagnostics")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command", required=True)
    diagnostics_show = diagnostics_sub.add_parser("show")
    diagnostics_show.add_argument("slot", metavar="target")
    diagnostics_show.add_argument("--dir", help="absolute backup dir or failed-container dir to show")
    diagnostics_show.add_argument("--tail", type=int, default=120)
    diagnostics_show.set_defaults(func=cmd_diagnostics_show)

    rollout = sub.add_parser("rollout", description="Inspect runtime manifests and apply digest-pinned wrapper/product images.")
    rollout_sub = rollout.add_subparsers(dest="rollout_command", required=True)
    rollout_status = rollout_sub.add_parser("status", help="summarize runtime manifests for a product family")
    rollout_status.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_status.set_defaults(func=cmd_rollout_status)
    rollout_image_plan = rollout_sub.add_parser("image-plan", help="validate digest-pinned images without release state")
    rollout_image_plan.add_argument("--wrapper-image", required=True)
    rollout_image_plan.add_argument("--product-image", required=True)
    rollout_image_plan.add_argument("--target", dest="slot")
    rollout_image_plan.add_argument("--targets", dest="slots", nargs="*")
    rollout_image_plan.set_defaults(func=cmd_rollout_image_plan)
    rollout_image_dev_apply = rollout_sub.add_parser("image-dev-apply", help="apply digest-pinned images to a dev target")
    rollout_image_dev_apply.add_argument("--target", dest="slot", required=True)
    rollout_image_dev_apply.add_argument("--wrapper-image", required=True)
    rollout_image_dev_apply.add_argument("--product-image", required=True)
    rollout_image_dev_apply.add_argument("--allow-first-apply", action="store_true")
    rollout_image_dev_apply.set_defaults(func=cmd_rollout_image_dev_apply)
    rollout_image_canary = rollout_sub.add_parser("image-canary", help="apply digest-pinned images to one customer canary target")
    rollout_image_canary.add_argument("--target", dest="slot", required=True)
    rollout_image_canary.add_argument("--wrapper-image", required=True)
    rollout_image_canary.add_argument("--product-image", required=True)
    rollout_image_canary.add_argument("--allow-first-apply", action="store_true")
    rollout_image_canary.set_defaults(func=cmd_rollout_image_canary)
    rollout_image_promote = rollout_sub.add_parser("image-promote", help="promote the exact live canary image to explicit targets")
    rollout_image_promote.add_argument("--from-target", dest="from_slot", required=True)
    rollout_image_promote.add_argument("--targets", dest="slots", required=True, help="comma-separated customer targets to apply")
    rollout_image_promote.set_defaults(func=cmd_rollout_image_promote)

    recipe = sub.add_parser("recipe")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_list_canonical = recipe_sub.add_parser("list-canonical")
    recipe_list_canonical.set_defaults(func=cmd_recipe_list_canonical)
    recipe_validate_canonical = recipe_sub.add_parser("validate-canonical")
    recipe_validate_canonical.add_argument("name")
    recipe_validate_canonical.add_argument("--emit-build-args", action="store_true")
    recipe_validate_canonical.set_defaults(func=cmd_recipe_validate_canonical)
    recipe_status = recipe_sub.add_parser("status")
    recipe_status.add_argument("slot", metavar="target")
    recipe_status.set_defaults(func=cmd_recipe_dev_status)
    recipe_apply_dev = recipe_sub.add_parser("apply-dev")
    recipe_apply_dev.add_argument("slot", metavar="target")
    recipe_apply_dev.add_argument("--recipe-name")
    source_group = recipe_apply_dev.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source-output")
    source_group.add_argument("--sync-from")
    recipe_apply_dev.add_argument("--build-command")
    recipe_apply_dev.add_argument("--allow-first-apply", action="store_true")
    recipe_apply_dev.add_argument("--no-apply", action="store_true")
    recipe_apply_dev.set_defaults(func=cmd_recipe_dev_apply)

    runtime_secret = sub.add_parser("runtime-secret")
    runtime_secret_sub = runtime_secret.add_subparsers(dest="runtime_secret_command", required=True)
    runtime_secret_set = runtime_secret_sub.add_parser("set")
    runtime_secret_set.add_argument("slot", metavar="target")
    runtime_secret_set.add_argument("--env-file")
    runtime_secret_set.add_argument("--key")
    runtime_secret_set.add_argument("--value-stdin", action="store_true")
    runtime_secret_set.add_argument("--no-restart", action="store_true")
    runtime_secret_set.add_argument("--check", action="store_true")
    runtime_secret_set.set_defaults(func=cmd_runtime_secret_set)
    runtime_secret_status = runtime_secret_sub.add_parser("status")
    runtime_secret_status.add_argument("slot", metavar="target")
    runtime_secret_status.set_defaults(func=cmd_runtime_secret_status)

    handoff = sub.add_parser("handoff")
    handoff_sub = handoff.add_subparsers(dest="handoff_command", required=True)
    handoff_status = handoff_sub.add_parser("status")
    handoff_status.add_argument("slot", metavar="target")
    handoff_status.set_defaults(func=cmd_handoff_status)

    nas = sub.add_parser("nas")
    nas_sub = nas.add_subparsers(dest="nas_command", required=True)
    nas_requests = nas_sub.add_parser("requests")
    nas_requests.set_defaults(func=cmd_nas_requests)
    nas_auto = nas_sub.add_parser("approve-auto")
    nas_auto.add_argument("--watch", action="store_true")
    nas_auto.add_argument("--interval", type=int, default=15)
    nas_auto.set_defaults(func=cmd_nas_approve_auto)
    nas_request = nas_sub.add_parser("request")
    nas_request.add_argument("share")
    nas_request.set_defaults(func=cmd_nas_request)
    nas_credential = nas_sub.add_parser("credential")
    nas_credential_sub = nas_credential.add_subparsers(dest="credential_command", required=True)
    nas_credential_set = nas_credential_sub.add_parser("set")
    nas_credential_set.add_argument("share")
    nas_credential_set.add_argument("--username", required=True)
    nas_credential_set.add_argument("--password-stdin", action="store_true", required=True)
    nas_credential_set.add_argument("--domain")
    nas_credential_set.set_defaults(func=cmd_nas_credential_set)
    nas_credential_status = nas_credential_sub.add_parser("status")
    nas_credential_status.add_argument("slot", metavar="target")
    nas_credential_status.add_argument("share")
    nas_credential_status.set_defaults(func=cmd_nas_credential_status)
    nas_mounted = nas_sub.add_parser("mounted")
    nas_mounted.add_argument("slot", metavar="target")
    nas_mounted.set_defaults(func=cmd_nas_mounted)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot", metavar="target")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)
    nas_mount = nas_sub.add_parser("mount")
    nas_mount.add_argument("slot", metavar="target")
    nas_mount.add_argument("share")
    nas_mount.add_argument("--username")
    nas_mount.add_argument("--password-stdin", action="store_true")
    nas_mount.add_argument("--domain")
    nas_mount.set_defaults(func=cmd_nas_mount)
    nas_unmount = nas_sub.add_parser("unmount")
    nas_unmount.add_argument("slot", metavar="target")
    nas_unmount.add_argument("share")
    nas_unmount.add_argument("--lazy", action="store_true")
    nas_unmount.add_argument("--delete-empty-dir", action="store_true")
    nas_unmount.set_defaults(func=cmd_nas_unmount)
    nas_remove = nas_sub.add_parser("remove")
    nas_remove.add_argument("slot", metavar="target")
    nas_remove.add_argument("share")
    nas_remove.add_argument("--lazy", action="store_true")
    nas_remove.add_argument("--delete-empty-dir", action="store_true")
    nas_remove.set_defaults(func=cmd_nas_remove)

    admin = sub.add_parser("admin")
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)
    serve = admin_sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=18088, type=int)
    serve.set_defaults(func=cmd_admin_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
