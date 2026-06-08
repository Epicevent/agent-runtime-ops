from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

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


def _digest_from_image_ref(value: object) -> str | None:
    if not isinstance(value, str) or "@sha256:" not in value:
        return None
    return "sha256:" + value.rsplit("@sha256:", 1)[1]


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


def _slot_gateway_port(slot: str) -> int | None:
    match = re.match(r"^oc([0-9]+)$", slot)
    if not match:
        return None
    return 28789 + (int(match.group(1)) - 1) * 100


def _http_backend_smoke(slot: str, path: str) -> tuple[bool, str]:
    port = _slot_gateway_port(slot)
    if port is None:
        return False, "slot_has_no_gateway_port"
    smoke_path = path if path.startswith("/") else f"/{path}"
    url = f"http://127.0.0.1:{port}{smoke_path}"
    request = urllib.request.Request(url, headers={"Host": f"{slot}.ji-tech.co.kr"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = int(response.getcode())
            return 200 <= status < 500, f"url={url} status={status}"
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        return 200 <= status < 500, f"url={url} status={status}"
    except Exception as exc:
        return False, f"url={url} reason={exc}"


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


def _find_gateway_container(slot: str, profile) -> tuple[str | None, str | None]:
    service_label = "gateway"
    by_label = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=agent-runtime.slot={slot}",
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
            return ids[0], "label"
        if len(ids) > 1:
            return None, f"multiple_label_matches:{len(ids)}"
    return _container_name(slot, profile), "fallback_name"


def _run_live_slot_checks(desired, profile, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not _is_root():
        return [(False, "live_check_requires_root", "run as root/admin or a restricted root helper")]

    container, container_lookup = _find_gateway_container(desired.slot, profile)
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
    desired_image = str(desired.release_data.get("wrapper_image") or "")
    desired_digest = str(desired.release_data.get("digest") or "")
    image_matches = bool(desired_image) and (
        image == desired_image
        or desired_image in repo_digests
        or (desired_digest and (desired_digest in image or desired_digest in image_data or any(desired_digest in item for item in repo_digests)))
    )
    checks.append((image_matches, "live_container_image_matches_release", f"image={image}"))
    if runtime_user_mode == "image-managed":
        checks.append((user in {"", "0", "0:0", "root"}, "live_container_user_image_managed", f"user={user or 'empty'}"))
    else:
        checks.append((bool(user) and user not in {"0", "0:0", "root"}, "live_container_user_non_root", f"user={user or 'empty'}"))
    if pid <= 0:
        return checks

    smoke_path = str(profile.metadata.get("http_smoke_path") or "")
    if smoke_path:
        smoke_ok, smoke_detail = _http_backend_smoke(desired.slot, smoke_path)
        checks.append((smoke_ok, "live_backend_http_smoke_ok", smoke_detail))

    host_rc, host_error, host_mounts = _findmnt_under(host_nas_root)
    checks.append((host_rc == 0, "live_host_nas_root_findmnt_ok", host_error if host_rc != 0 else host_nas_root))
    host_cifs = [row for row in host_mounts if row.get("fstype") == "cifs" and row.get("target", "").startswith(host_nas_root + "/")]
    checks.append((True, "live_host_child_cifs_count", f"count={len(host_cifs)}"))
    for row in host_cifs:
        source = row.get("source") or ""
        if source.startswith("//"):
            try:
                decision = check_nas_policy(desired.slot, source, state_root)
                checks.append((decision.allowed, "live_host_child_cifs_allowed_by_policy", f"source={source} reason={decision.reason}"))
            except Exception as exc:
                checks.append((False, "live_host_child_cifs_policy_check_ok", f"source={source} reason={exc}"))
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
    wrapper_digest = _digest_from_image_ref(wrapper_image)
    product_digest = _digest_from_image_ref(product_image)
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
        (_has_digest_ref(product_image), "product_image_pinned_by_digest", str(product_image) if product_image else None),
        (
            isinstance(release_digest, str) and release_digest.startswith("sha256:"),
            "release_digest_present",
            str(release_digest) if release_digest else None,
        ),
        (
            bool(wrapper_digest) and wrapper_digest == release_digest,
            "wrapper_image_digest_matches_release",
            f"wrapper={wrapper_digest} release={release_digest}",
        ),
        (
            _allowed_image_ref(lane_family, "wrapper", wrapper_image),
            "wrapper_image_repository_allowed",
            str(wrapper_image) if wrapper_image else None,
        ),
        (
            _allowed_image_ref(lane_family, "product", product_image),
            "product_image_repository_allowed",
            str(product_image) if product_image else None,
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
        for ok, name, detail in _run_live_slot_checks(desired, profile, _state_root(args)):
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


def _slot_runtime_dir(slot: str) -> Path:
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


def _write_slot_manifest(
    path: Path,
    *,
    desired,
    profile,
    rendered,
    applied_at: str,
) -> None:
    lines = [
        f"slot={desired.slot}",
        f"lane={desired.lane}",
        f"release={desired.release_name}",
        f"family={desired.lane_data.get('family')}",
        f"slot_class={desired.lane_data.get('slot_class')}",
        f"runtime_profile={profile.name}",
        f"runtime_profile_digest={profile.digest}",
        f"ops_repo_commit={_installed_source_commit()}",
        f"wrapper_image={desired.release_data.get('wrapper_image')}",
        f"product_image={desired.release_data.get('product_image')}",
        f"release_digest={desired.release_data.get('digest')}",
        f"compose_sha256={rendered.sha256}",
        f"compose_file={path.parent / 'docker-compose.agent-runtime.yml'}",
        f"applied_at={applied_at}",
    ]
    _atomic_write(path, "\n".join(lines) + "\n", 0o644)


def _backup_agent_runtime_state(runtime_dir: Path) -> Path:
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
    metadata = {
        "created_at": _now_iso(),
        "had_compose": compose_path.is_file() and not compose_path.is_symlink(),
        "had_manifest": manifest_path.is_file() and not manifest_path.is_symlink(),
    }
    if metadata["had_compose"]:
        shutil.copy2(compose_path, backup_dir / "docker-compose.agent-runtime.yml")
    if metadata["had_manifest"]:
        shutil.copy2(manifest_path, backup_dir / ".agent-runtime-manifest")
    (backup_dir / "backup.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return backup_dir


def _latest_backup(runtime_dir: Path) -> Path | None:
    backup_root = _agent_backup_root(runtime_dir)
    if not backup_root.is_dir():
        return None
    backups = sorted([item for item in backup_root.iterdir() if item.is_dir()])
    return backups[-1] if backups else None


def _restore_backup(slot: str, runtime_dir: Path, backup_dir: Path) -> tuple[bool, str]:
    metadata = load_yaml(backup_dir / "backup.json")
    compose_path = _agent_compose_path(runtime_dir)
    manifest_path = _agent_manifest_path(runtime_dir)
    had_compose = bool(metadata.get("had_compose"))
    had_manifest = bool(metadata.get("had_manifest"))

    if had_compose:
        shutil.copy2(backup_dir / "docker-compose.agent-runtime.yml", compose_path)
    else:
        compose_path.unlink(missing_ok=True)
    if had_manifest:
        shutil.copy2(backup_dir / ".agent-runtime-manifest", manifest_path)
    else:
        manifest_path.unlink(missing_ok=True)

    if not had_compose:
        return False, "no_previous_agent_runtime_compose"

    config = _run_text_cwd(_docker_compose_command(slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        return False, (config.stderr or config.stdout).strip() or "rollback_compose_config_failed"
    up = _run_text_cwd(
        _docker_compose_command(slot, compose_path, "up", "-d", "--remove-orphans"),
        runtime_dir,
        timeout=180,
    )
    if up.returncode != 0:
        return False, (up.stderr or up.stdout).strip() or "rollback_compose_up_failed"
    return True, "rollback_applied"


def _print_process_result(prefix: str, proc: subprocess.CompletedProcess[str], limit: int = 2000) -> None:
    detail = (proc.stderr or proc.stdout).strip()
    if detail:
        print(f"{prefix}={detail[:limit]}")


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


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply SLOT", file=sys.stderr)
        return 2
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        rendered = render_compose(profile, desired)
        runtime_dir = _slot_runtime_dir(desired.slot)
        compose_path = _agent_compose_path(runtime_dir)
        manifest_path = _agent_manifest_path(runtime_dir)
        env_path = runtime_dir / ".env"
        required = _required_compose_variables(rendered.text)
        present = _env_file_keys(env_path)
        missing = sorted(required - present)
        if missing:
            raise ValueError(f"missing required .env keys: {','.join(missing)}")
        if not manifest_path.exists() and not args.allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        backup_dir = _backup_agent_runtime_state(runtime_dir)
        _atomic_write(compose_path, rendered.text, 0o644)
        applied_at = _now_iso()
        _write_slot_manifest(
            manifest_path,
            desired=desired,
            profile=profile,
            rendered=rendered,
            applied_at=applied_at,
        )
    except Exception as exc:
        print(f"slot={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"slot={desired.slot}")
    print(f"runtime_dir={runtime_dir}")
    print(f"compose_file={compose_path}")
    print(f"manifest={manifest_path}")
    print(f"backup_dir={backup_dir}")
    print(f"runtime_profile={profile.name}")
    print(f"runtime_profile_digest={profile.digest}")
    print(f"compose_sha256={rendered.sha256}")

    config = _run_text_cwd(_docker_compose_command(desired.slot, compose_path, "config"), runtime_dir, timeout=60)
    if config.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir)
        print("apply_status=fail")
        _print_process_result("compose_config_error", config)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        return config.returncode or 1

    up = _run_text_cwd(
        _docker_compose_command(desired.slot, compose_path, "up", "-d", "--remove-orphans"),
        runtime_dir,
        timeout=240,
    )
    if up.returncode != 0:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir)
        print("apply_status=fail")
        _print_process_result("compose_up_error", up)
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        return up.returncode or 1

    failed = 0
    for ok, name, detail in _run_live_slot_checks_with_wait(
        desired,
        profile,
        _state_root(args),
        timeout_seconds=_profile_startup_timeout_seconds(profile),
    ):
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    if failed:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir)
        print(f"apply_status=fail live_failed={failed}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        return 1

    print("apply_status=ok")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollback SLOT", file=sys.stderr)
        return 2
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        runtime_dir = _slot_runtime_dir(desired.slot)
        backup_dir = _latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_status={'ok' if ok else 'fail'}")
    print(f"rollback_reason={reason}")
    return 0 if ok else 1


def cmd_blocked_mutation(args: argparse.Namespace) -> int:
    print(f"error: {args.command_name} is intentionally disabled in the initial skeleton", file=sys.stderr)
    print("hint: enable lane rollout only after single-slot apply/rollback migration tests pass", file=sys.stderr)
    return 2


def cmd_release_add(args: argparse.Namespace) -> int:
    print("error: release add is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


def cmd_release_promote(args: argparse.Namespace) -> int:
    print("error: release promote is intentionally disabled in the initial skeleton", file=sys.stderr)
    return 2


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
        if uid is not None and gid is not None:
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


def _append_action_log(state_root: Path, action: str, slot: str, share: str, status: str, detail: str = "") -> None:
    log_path = state_root / "actions.log"
    record = {
        "timestamp": _now_iso(),
        "action": action,
        "slot": slot,
        "share": share,
        "status": status,
        "detail": detail[:500],
    }
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
    slots = load_yaml(state_root / "slots.yaml").get("slots") or {}
    for slot in sorted(slots):
        try:
            desired = load_desired_slot(slot, state_root)
        except Exception:
            continue
        if desired.lane_data.get("slot_class") != "customer":
            continue
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
                    print(f"pending slot={slot} share={decision.share.source} reason=credential_missing")
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
                print(f"rejected slot={slot} file={path} reason={exc}")
                result["rejected"] += 1
                result["failed"] += 1
    return result


def cmd_nas_requests(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    slots_data = load_yaml(state_root / "slots.yaml").get("slots") or {}
    total = 0
    for slot in sorted(slots_data):
        try:
            desired = load_desired_slot(slot, state_root)
        except Exception:
            continue
        if desired.lane_data.get("slot_class") != "customer":
            continue
        pending_dir = request_dir(slot)
        if not pending_dir.is_dir():
            continue
        for path in sorted(pending_dir.glob("*.env")):
            if path.is_symlink():
                continue
            try:
                data = _read_key_value_file(path)
            except Exception as exc:
                print(f"request slot={slot} file={path.name} status=unreadable reason={exc}")
                total += 1
                continue
            share = data.get("requested_share") or ""
            created_at = data.get("created_at") or ""
            print(f"request slot={slot} share={share} created_at={created_at} file={path}")
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
        print(f"slot={args.slot}")
        print(f"share={args.share}")
        print("policy_check_status=fail")
        print(f"reason={exc}")
        print("mutates=false")
        return 1
    print(f"slot={decision.slot}")
    print(f"share={decision.share.source}")
    print(f"mountpoint={decision.mountpoint}")
    print(f"matched_grant={decision.matched_grant or ''}")
    print(f"max_mounts={decision.max_mounts if decision.max_mounts is not None else ''}")
    print(f"policy_check_status={'pass' if decision.allowed else 'fail'}")
    print(f"reason={decision.reason}")
    print("mutates=false")
    return 0 if decision.allowed else 1


def _caller_customer_slot() -> str:
    user = getpass.getuser()
    if not CUSTOMER_SLOT_RE.match(user):
        raise ValueError(f"this command must be run by an ocN customer slot account, got {user}")
    return user


def cmd_nas_request(args: argparse.Namespace) -> int:
    try:
        slot = _caller_customer_slot()
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
    print(f"slot={slot}")
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
    print(f"slot={slot}")
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


def cmd_nas_mounted(args: argparse.Namespace) -> int:
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
    except Exception as exc:
        print(f"slot={args.slot}")
        print("mounted_status=fail")
        print(f"reason={exc}")
        return 1
    root = Path("/home") / desired.slot / "nas_docs"
    rc, error, rows = _findmnt_under(str(root))
    print(f"slot={desired.slot}")
    print(f"nas_root={root}")
    print("mutates=false")
    if rc != 0:
        print("mounted_status=fail")
        print(f"reason={error or 'findmnt_failed'}")
        return 1
    child_rows = [row for row in rows if row.get("fstype") == "cifs" and row.get("target", "").startswith(str(root) + "/")]
    print(f"mounted_child_cifs_count={len(child_rows)}")
    for index, row in enumerate(child_rows, start=1):
        _print_mount_row(f"mount_{index}", row)
    print("mounted_status=ok")
    return 0


def cmd_nas_mount(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas mount SLOT //HOST/SHARE", file=sys.stderr)
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
        print(f"slot={args.slot}")
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
    print(f"slot={decision.slot}")
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas unmount SLOT //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        load_desired_slot(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(args.slot, share)
        _safe_mountpoint_path(mountpoint)
    except Exception as exc:
        print(f"slot={args.slot}")
        print(f"share={args.share}")
        print("unmount_status=fail")
        print(f"reason={exc}")
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    if rc != 0 or not rows:
        print(f"slot={args.slot}")
        print(f"share={share.source}")
        print(f"mountpoint={mountpoint}")
        print("unmount_status=already_unmounted")
        return 0
    row = rows[0]
    _print_mount_row("existing_mount", row)
    if row.get("source") != share.source:
        print("unmount_status=fail")
        print("reason=mountpoint_source_does_not_match_requested_share")
        return 1

    command = ["umount"]
    if args.lazy:
        command.append("--lazy")
    command.append(str(mountpoint))
    proc = _run_text(command, timeout=60)
    if proc.returncode != 0:
        print("unmount_status=fail")
        print(f"reason={(proc.stderr or proc.stdout).strip()}")
        return proc.returncode or 1
    if args.delete_empty_dir:
        try:
            mountpoint.rmdir()
            print("empty_dir_removed=yes")
        except OSError:
            print("empty_dir_removed=no")
    print("unmount_status=ok")
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

    apply = sub.add_parser("apply")
    apply.add_argument("slot")
    apply.add_argument("--allow-first-apply", action="store_true")
    apply.set_defaults(func=cmd_apply)

    rollback = sub.add_parser("rollback")
    rollback.add_argument("slot")
    rollback.set_defaults(func=cmd_rollback)

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
    nas_mounted = nas_sub.add_parser("mounted")
    nas_mounted.add_argument("slot")
    nas_mounted.set_defaults(func=cmd_nas_mounted)
    nas_policy = nas_sub.add_parser("policy-check")
    nas_policy.add_argument("slot")
    nas_policy.add_argument("share")
    nas_policy.set_defaults(func=cmd_nas_policy_check)
    nas_mount = nas_sub.add_parser("mount")
    nas_mount.add_argument("slot")
    nas_mount.add_argument("share")
    nas_mount.add_argument("--username")
    nas_mount.add_argument("--password-stdin", action="store_true")
    nas_mount.add_argument("--domain")
    nas_mount.set_defaults(func=cmd_nas_mount)
    nas_unmount = nas_sub.add_parser("unmount")
    nas_unmount.add_argument("slot")
    nas_unmount.add_argument("share")
    nas_unmount.add_argument("--lazy", action="store_true")
    nas_unmount.add_argument("--delete-empty-dir", action="store_true")
    nas_unmount.set_defaults(func=cmd_nas_unmount)

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
