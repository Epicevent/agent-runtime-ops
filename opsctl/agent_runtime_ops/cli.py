from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .paths import DEFAULT_STATE_ROOT
from .profiles import list_profile_names, load_profile
from .renderer import render_compose
from .state import load_desired_slot
from .yamlio import dump_yaml, load_yaml

DEFAULT_REPO_URL = "https://github.com/Epicevent/agent-runtime-ops.git"
UPDATE_POLICY_NAME = "ops-update.yaml"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CUSTOMER_SLOT_RE = re.compile(r"^oc[0-9]+$")
DEV_SLOT_RE = re.compile(r"^dev-[a-z0-9-]+$")


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


def cmd_self_update(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo opsctl self-update", file=sys.stderr)
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
            subprocess.run(["bash", str(repo / "install.sh"), "install"], check=True)
        except subprocess.CalledProcessError as exc:
            return exc.returncode or 1
    return 0


def cmd_update_approve(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo opsctl update approve FULL_SHA", file=sys.stderr)
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
    try:
        repo_url, ref = _approved_update_from_policy(_state_root(args))
        _validate_update_target(repo_url, ref)
    except Exception as exc:
        print("update_status=not_ready")
        print(f"reason={exc}")
        return 1
    print("update_status=ready")
    print(f"repo_url={repo_url}")
    print(f"approved_ref={ref}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
    except Exception as exc:
        print(f"status=unknown")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"lane={desired.lane}")
    print(f"release={desired.release_name}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"family={profile.metadata.get('family')}")
    print(f"mode={profile.metadata.get('mode')}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
    except Exception as exc:
        plan = {
            "slot": args.slot,
            "status": "not_ready",
            "reason": str(exc),
            "mutates": False,
        }
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 1
    rendered = render_compose(profile, desired)
    plan = {
        "slot": desired.slot,
        "lane": desired.lane,
        "family": desired.lane_data.get("family"),
        "slot_class": desired.lane_data.get("slot_class"),
        "release": desired.release_name,
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "wrapper_image": desired.release_data.get("wrapper_image"),
        "product_image": desired.release_data.get("product_image"),
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


def _has_digest_ref(value: object) -> bool:
    return isinstance(value, str) and "@sha256:" in value


def _container_name(slot: str, profile) -> str:
    service = profile.metadata.get("service") or "openclaw-gateway"
    return f"openclaw-{slot}-{service}-1"


def _run_text(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout)


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
            item[key.lower()] = value
        if item:
            rows.append(item)
    return rows


def _findmnt_tree(path: str, container: str | None = None) -> tuple[int, str, list[dict[str, str]]]:
    command = ["findmnt", "-R", "-P", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", path]
    if container:
        command = ["docker", "exec", container, *command]
    proc = _run_text(command)
    return proc.returncode, (proc.stderr or proc.stdout).strip(), _parse_findmnt_pairs(proc.stdout)


def _is_readonly_mount(row: dict[str, str]) -> bool:
    options = row.get("options", "")
    return "ro" in {part.strip() for part in options.split(",") if part.strip()}


def _run_live_slot_checks(desired, profile) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    container = _container_name(desired.slot, profile)
    target_home = f"/home/{desired.slot}"
    host_nas_root = f"{target_home}/nas_docs"
    container_nas_root = str(profile.metadata.get("container_nas_root") or "")
    required_read_only_nas = profile.metadata.get("required_read_only_nas") is True

    docker = shutil.which("docker")
    checks.append((bool(docker), "live_docker_cli_available", docker))
    if not docker:
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
    state = info.get("State") or {}
    config = info.get("Config") or {}
    running = str(state.get("Running")).lower()
    health_data = state.get("Health") or {}
    health = str(health_data.get("Status") or "none")
    image = str(config.get("Image") or "")
    checks.append((running == "true", "live_container_running", f"running={running}"))
    checks.append((health in {"healthy", "starting", "none", ""}, "live_container_health_ok", f"health={health}"))
    checks.append((bool(image), "live_container_image_present", image or None))

    host_rc, host_error, host_mounts = _findmnt_tree(host_nas_root)
    checks.append((host_rc == 0, "live_host_nas_root_findmnt_ok", host_error if host_rc != 0 else host_nas_root))
    host_cifs = [row for row in host_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(host_nas_root + "/")]
    checks.append((bool(host_cifs), "live_host_child_cifs_present", f"count={len(host_cifs)}"))
    if required_read_only_nas:
        host_ro = all(_is_readonly_mount(row) for row in host_cifs)
        checks.append((bool(host_cifs) and host_ro, "live_host_child_cifs_readonly", f"count={len(host_cifs)}"))

    if not container_nas_root:
        checks.append((False, "live_container_nas_root_configured", None))
        return checks

    container_rc, container_error, container_mounts = _findmnt_tree(container_nas_root, container=container)
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

    container_cifs = [
        row for row in container_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(container_nas_root + "/")
    ]
    checks.append((bool(container_cifs), "live_container_child_cifs_present", f"count={len(container_cifs)}"))
    if required_read_only_nas:
        container_ro = all(_is_readonly_mount(row) for row in container_cifs)
        checks.append((bool(container_cifs) and container_ro, "live_container_child_cifs_readonly", f"count={len(container_cifs)}"))

    host_sources = {row.get("source") for row in host_cifs if row.get("source")}
    container_sources = {row.get("source") for row in container_cifs if row.get("source")}
    checks.append(
        (
            bool(host_sources) and host_sources.issubset(container_sources),
            "live_container_sees_host_cifs_sources",
            f"host={len(host_sources)} container={len(container_sources)}",
        )
    )
    return checks


def _run_static_slot_checks(desired, profile) -> list[tuple[bool, str, str | None]]:
    lane_family = desired.lane_data.get("family")
    lane_slot_class = desired.lane_data.get("slot_class")
    profile_family = profile.metadata.get("family")
    profile_slot_class = profile.metadata.get("slot_class")
    profile_mode = profile.metadata.get("mode")
    release_family = desired.release_data.get("family")
    wrapper_image = desired.release_data.get("wrapper_image")
    product_image = desired.release_data.get("product_image")
    release_digest = desired.release_data.get("digest")
    allow_source_mount = profile.metadata.get("allow_source_mount")

    checks: list[tuple[bool, str, str | None]] = [
        (lane_family == profile_family, "lane_family_matches_profile", f"lane={lane_family} profile={profile_family}"),
        (
            lane_slot_class == profile_slot_class,
            "lane_slot_class_matches_profile",
            f"lane={lane_slot_class} profile={profile_slot_class}",
        ),
        (
            release_family == lane_family == profile_family,
            "release_family_matches_lane",
            f"release={release_family} lane={lane_family}",
        ),
        (bool(wrapper_image), "wrapper_image_present", str(wrapper_image) if wrapper_image else None),
        (bool(product_image), "product_image_present", str(product_image) if product_image else None),
        (_has_digest_ref(wrapper_image), "wrapper_image_pinned_by_digest", str(wrapper_image) if wrapper_image else None),
        (
            isinstance(release_digest, str) and release_digest.startswith("sha256:"),
            "release_digest_present",
            str(release_digest) if release_digest else None,
        ),
    ]

    if lane_slot_class == "customer":
        checks.extend(
            [
                (bool(CUSTOMER_SLOT_RE.match(desired.slot)), "customer_slot_name_ok", desired.slot),
                (profile_mode == "image", "customer_profile_mode_image", f"mode={profile_mode}"),
                (allow_source_mount is False, "customer_source_mount_disabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    elif lane_slot_class == "dev":
        checks.extend(
            [
                (bool(DEV_SLOT_RE.match(desired.slot)), "dev_slot_name_ok", desired.slot),
                (profile_mode == "source", "dev_profile_mode_source", f"mode={profile_mode}"),
                (allow_source_mount is True, "dev_source_mount_enabled", f"allow_source_mount={allow_source_mount}"),
            ]
        )
    else:
        checks.append((False, "known_slot_class", f"slot_class={lane_slot_class}"))

    return checks


def cmd_check(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        rendered = render_compose(profile, desired)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("check_status=not_ready")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"lane={desired.lane}")
    print(f"release={desired.release_name}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")
    print("check_mode=non_mutating")
    print(f"live_runtime_check={'enabled' if args.live else 'not_run'}")

    failed = 0
    for ok, name, detail in _run_static_slot_checks(desired, profile):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1

    _check_line(bool(rendered.text.strip()), "compose_rendered")
    if not rendered.text.strip():
        failed += 1

    if args.live:
        for ok, name, detail in _run_live_slot_checks(desired, profile):
            _check_line(ok, name, detail)
            if not ok:
                failed += 1
    else:
        print("INFO live_runtime_check_not_run use='opsctl check --live SLOT'")

    if failed:
        print(f"check_status=fail failed={failed}")
        return 1
    if args.live:
        print("check_status=pass scope=contract_and_live")
    else:
        print("check_status=pass scope=contract_only")
    return 0


def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: implement apply/rollback/rollout only after renderer, rollback, and audit tests are in place", file=sys.stderr)
    return 2


def cmd_release_add(args: argparse.Namespace) -> int:
    print("error: release add is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_release_promote(args: argparse.Namespace) -> int:
    print("error: release promote is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_nas_requests(args: argparse.Namespace) -> int:
    print("nas_requests_status=skeleton")
    print("mutates=false")
    return 0


def cmd_nas_approve_auto(args: argparse.Namespace) -> int:
    print("error: nas approve-auto is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_nas_policy_check(args: argparse.Namespace) -> int:
    print(f"slot={args.slot}")
    print(f"share={args.share}")
    print("policy_check_status=skeleton")
    print("mutates=false")
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

    for name, func in (("status", cmd_status), ("plan", cmd_plan), ("check", cmd_check)):
        item = sub.add_parser(name)
        item.add_argument("slot")
        if name == "check":
            item.add_argument("--live", action="store_true", help="also inspect Docker and NAS runtime state without writing")
        item.set_defaults(func=func)

    for name in ("apply", "rollback"):
        item = sub.add_parser(name)
        item.add_argument("slot")
        item.set_defaults(func=cmd_blocked_mutation, command_name=name)

    rollout = sub.add_parser("rollout")
    rollout.add_argument("lane")
    rollout.set_defaults(func=cmd_blocked_mutation, command_name="rollout")

    release = sub.add_parser("release")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_add = release_sub.add_parser("add")
    release_add.add_argument("name")
    release_add.add_argument("image")
    release_add.set_defaults(func=cmd_release_add)
    release_promote = release_sub.add_parser("promote")
    release_promote.add_argument("name")
    release_promote.add_argument("lane")
    release_promote.set_defaults(func=cmd_release_promote)

    nas = sub.add_parser("nas")
    nas_sub = nas.add_subparsers(dest="nas_command", required=True)
    nas_requests = nas_sub.add_parser("requests")
    nas_requests.set_defaults(func=cmd_nas_requests)
    nas_auto = nas_sub.add_parser("approve-auto")
    nas_auto.set_defaults(func=cmd_nas_approve_auto)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)

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
