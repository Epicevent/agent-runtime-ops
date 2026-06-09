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
from .runtime_secrets import (
    PROVIDER_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_provider_secret_values,
)
from .state import DesiredSlot, load_desired_slot
from .yamlio import dump_yaml, load_yaml

DEFAULT_REPO_URL = "https://github.com/Epicevent/agent-runtime-ops.git"
UPDATE_POLICY_NAME = "ops-update.yaml"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CUSTOMER_SLOT_RE = re.compile(r"^oc[0-9]+$")
DEV_SLOT_RE = re.compile(r"^dev-[a-z0-9-]+$")
RELEASE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
SAFE_TEXT_RE = re.compile(r"^[^\r\n\t]*$")
ROLLOUT_STATE_NAME = "rollout-state.yaml"
DEV_RECIPE_STATE_NAME = "dev-recipes.yaml"
DEV_RECIPE_STAGE_ROOT = "agent-runtime-source"
IMAGE_RECIPE_LABEL_PREFIX = "com.epicevent.agent-runtime."
IMAGE_RECIPE_SCHEMA = "v1"


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


def cmd_slot_list(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        slots_data = load_yaml(state_root / "slots.yaml").get("slots") or {}
    except Exception as exc:
        print("slot_list_status=fail")
        print(f"reason={exc}")
        return 1

    count = 0
    for slot in _slot_names_from_config(slots_data):
        count += 1
        try:
            desired = load_desired_slot(slot, state_root)
            profile = load_profile(desired.runtime_profile)
            family = profile.metadata.get("family") or desired.lane_data.get("family") or ""
            slot_class = desired.lane_data.get("slot_class") or ""
            mode = profile.metadata.get("mode") or ""
            recipe_tokens = _release_recipe_tokens(desired.release_data)
            print(
                f"slot={desired.slot} "
                f"lane={desired.lane} "
                f"family={family} "
                f"slot_class={slot_class} "
                f"runtime_profile={profile.name} "
                f"runtime_contract={_profile_runtime_contract(profile)} "
                f"customer_surface={_profile_customer_surface(profile)} "
                f"release={desired.release_name} "
                f"mode={mode} "
                f"recipe_mode={recipe_tokens['recipe_mode']} "
                f"product_component={recipe_tokens['product_component']}"
            )
        except Exception as exc:
            print(f"slot={slot} status=not_ready reason={exc}")
    print(f"slot_list_status=ok count={count}")
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
    print(f"runtime_contract={_profile_runtime_contract(profile)}")
    print(f"customer_surface={_profile_customer_surface(profile)}")
    print(f"family={profile.metadata.get('family')}")
    print(f"mode={profile.metadata.get('mode')}")
    recipe_tokens = _release_recipe_tokens(desired.release_data)
    for key, value in recipe_tokens.items():
        print(f"{key}={value}")
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
        "runtime_contract": _profile_runtime_contract(profile),
        "customer_surface": _profile_customer_surface(profile),
        "wrapper_image": desired.release_data.get("wrapper_image"),
        "product_image": desired.release_data.get("product_image"),
        "recipe": _release_recipe_payload(desired.release_data),
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


def _validate_release_name(name: str) -> None:
    if not RELEASE_NAME_RE.match(name):
        raise ValueError("release name must contain only letters, numbers, '.', '_', or '-'")


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


def _release_recipe_payload(release_data: dict) -> dict[str, object]:
    product_image = release_data.get("product_image")
    wrapper_image = release_data.get("wrapper_image")
    image_recipe = _release_image_recipe(release_data)
    payload: dict[str, object] = {
        "mode": release_data.get("compatibility_mode") or "unknown",
        "product_component": image_recipe.get("product_component") or _image_component_name(product_image),
        "wrapper_component": image_recipe.get("wrapper_component") or _image_component_name(wrapper_image),
        "product_repo": _image_repo(product_image),
        "wrapper_repo": _image_repo(wrapper_image),
    }
    components = release_data.get("components")
    if isinstance(components, dict):
        payload["components"] = {str(key): str(value) for key, value in components.items()}
    if image_recipe:
        payload["image_recipe"] = image_recipe
    return payload


def _release_recipe_tokens(release_data: dict) -> dict[str, str]:
    recipe = _release_recipe_payload(release_data)
    return {
        "recipe_mode": str(recipe.get("mode") or "unknown"),
        "product_component": str(recipe.get("product_component") or "unknown"),
        "wrapper_component": str(recipe.get("wrapper_component") or "unknown"),
    }


def _release_components_from_args(raw_components: object) -> dict[str, str]:
    components: dict[str, str] = {}
    if raw_components is None or raw_components == "":
        return components
    if not isinstance(raw_components, list):
        raise ValueError("--component must be repeatable NAME=VALUE entries")
    for raw_item in raw_components:
        item = str(raw_item or "")
        if "=" not in item:
            raise ValueError("--component must use NAME=VALUE")
        name, value = item.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not RELEASE_NAME_RE.match(name):
            raise ValueError(f"invalid component name: {name}")
        if not value or not SAFE_TEXT_RE.match(value):
            raise ValueError(f"invalid component value for {name}")
        components[name] = value
    return components


def _derived_release_components(product_image: str, wrapper_image: str) -> dict[str, str]:
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
    required = {
        "product-component": product_component,
        "wrapper-component": wrapper_component,
        "runtime-profile.customer": customer_profile,
        "runtime-profile.dev": dev_profile,
        "runtime-contract.customer": customer_contract,
        "runtime-contract.dev": dev_contract,
        "command-mode": command_mode,
        "http-port": http_port,
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
    recipe = {
        "schema": schema,
        "source": "wrapper_image_labels",
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
        "ops_repo_commit": _recipe_label(labels, "ops-repo-commit"),
    }
    for slot_class, profile_name in recipe["runtime_profiles"].items():
        profile = load_profile(str(profile_name))
        if profile.metadata.get("family") != family:
            raise ValueError(f"recipe {slot_class} profile family mismatch: {profile_name}")
        if profile.metadata.get("slot_class") != slot_class:
            raise ValueError(f"recipe {slot_class} profile slot_class mismatch: {profile_name}")
        expected_contract = recipe["runtime_contracts"][slot_class]
        if profile.metadata.get("runtime_contract") != expected_contract:
            raise ValueError(f"recipe {slot_class} profile contract mismatch: {profile_name}")
        profile_component = str(profile.metadata.get("product_component") or "")
        if profile_component and profile_component != product_component:
            raise ValueError(f"recipe {slot_class} profile product_component mismatch: {profile_name}")
    return recipe


def _release_image_recipe(release_data: dict) -> dict[str, object]:
    recipe = release_data.get("image_recipe")
    return recipe if isinstance(recipe, dict) else {}


def _release_runtime_profile_name(release_data: dict, slot_class: str, fallback: str | None = None) -> str:
    recipe = _release_image_recipe(release_data)
    profiles = recipe.get("runtime_profiles")
    if isinstance(profiles, dict) and profiles.get(slot_class):
        return str(profiles[slot_class])
    if release_data.get("compatibility_mode") == "wrapped_product_image":
        raise ValueError("wrapped release is missing image recipe runtime profile; reimport a labeled wrapper image")
    return str(fallback or "")


def _release_profile_contract_checks(release_data: dict, profile) -> list[tuple[bool, str, str | None]]:
    runtime_contract = _profile_runtime_contract(profile)
    customer_surface = _profile_customer_surface(profile)
    expected_components = _metadata_list(profile.metadata.get("expected_image_components"))
    compatible_product_prefixes = _metadata_list(profile.metadata.get("compatible_product_image_prefixes"))
    product_image = str(release_data.get("product_image") or "")
    slot_class = str(profile.metadata.get("slot_class") or "")
    image_recipe = _release_image_recipe(release_data)
    checks: list[tuple[bool, str, str | None]] = [
        (bool(runtime_contract), "runtime_contract_declared", f"contract={runtime_contract or 'missing'}"),
        (
            bool(customer_surface),
            "runtime_contract_customer_surface_declared",
            f"surface={customer_surface or 'missing'}",
        ),
    ]
    if image_recipe:
        runtime_profiles = image_recipe.get("runtime_profiles")
        expected_profile = runtime_profiles.get(slot_class) if isinstance(runtime_profiles, dict) else ""
        checks.append(
            (
                expected_profile == profile.name,
                "image_recipe_profile_matches_runtime_profile",
                f"recipe={expected_profile or 'missing'} profile={profile.name}",
            )
        )
        runtime_contracts = image_recipe.get("runtime_contracts")
        expected_contract = runtime_contracts.get(slot_class) if isinstance(runtime_contracts, dict) else ""
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
                "image_recipe_product_image_matches_release",
                f"recipe={image_recipe.get('product_image') or 'missing'} release={product_image or 'missing'}",
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


def _release_profile_contract_failures(release_data: dict, profile) -> list[str]:
    return [name for ok, name, _ in _release_profile_contract_checks(release_data, profile) if not ok]


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
    dev_ports = {
        "dev-oc": 30789,
        "dev-hermess": 30889,
    }
    if slot in dev_ports:
        return dev_ports[slot]
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
        if source.startswith("//") and desired.lane_data.get("slot_class") == "customer":
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
    checks.extend(_release_profile_contract_checks(desired.release_data, profile))

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

    if rendered is not None:
        checks.extend(
            (item.ok, item.name, item.detail)
            for item in validate_compose_contract(profile, desired, rendered.text)
        )

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
    print(f"runtime_contract={_profile_runtime_contract(profile)}")
    print(f"customer_surface={_profile_customer_surface(profile)}")
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
    if not CUSTOMER_SLOT_RE.match(slot) and not DEV_SLOT_RE.match(slot):
        raise ValueError(f"invalid slot name: {slot}")
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
    wrapper_image = desired.release_data.get("wrapper_image")
    product_image = desired.release_data.get("product_image")
    payload = {
        "schema_version": 1,
        "slot": desired.slot,
        "applied_at": applied_at,
        "ops_commit": _installed_source_commit(),
        "lane": desired.lane,
        "release": desired.release_name,
        "family": desired.lane_data.get("family"),
        "slot_class": desired.lane_data.get("slot_class"),
        "runtime_profile": profile.name,
        "runtime_profile_digest": profile.digest,
        "runtime_contract": _profile_runtime_contract(profile),
        "customer_surface": _profile_customer_surface(profile),
        "wrapper_image": wrapper_image,
        "wrapper_image_digest": _digest_from_image_ref(wrapper_image),
        "product_image": product_image,
        "product_image_digest": _digest_from_image_ref(product_image),
        "release_digest": desired.release_data.get("digest"),
        "recipe": _release_recipe_payload(desired.release_data),
        "compose_sha256": rendered.sha256,
        "compose_path": str(compose_path),
    }
    if previous_manifest is not None:
        payload["previous_manifest"] = str(previous_manifest)
    return payload


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
        f"runtime_contract={_profile_runtime_contract(profile)}",
        f"customer_surface={_profile_customer_surface(profile)}",
        f"ops_repo_commit={_installed_source_commit()}",
        f"wrapper_image={desired.release_data.get('wrapper_image')}",
        f"product_image={desired.release_data.get('product_image')}",
        f"recipe_mode={_release_recipe_tokens(desired.release_data)['recipe_mode']}",
        f"product_component={_release_recipe_tokens(desired.release_data)['product_component']}",
        f"release_digest={desired.release_data.get('digest')}",
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


def _desired_from_manifest(slot: str, manifest: dict):
    manifest_slot = str(manifest.get("slot") or slot)
    return SimpleNamespace(
        slot=manifest_slot,
        lane=str(manifest.get("lane") or ""),
        release_name=str(manifest.get("release") or ""),
        runtime_profile=str(manifest.get("runtime_profile") or ""),
        lane_data={
            "family": manifest.get("family"),
            "slot_class": manifest.get("slot_class"),
        },
        release_data={
            "wrapper_image": manifest.get("wrapper_image"),
            "product_image": manifest.get("product_image"),
            "digest": manifest.get("release_digest") or manifest.get("wrapper_image_digest"),
        },
    )


def _load_backup_runtime_contract(slot: str, backup_dir: Path):
    manifest = _backup_manifest_data(backup_dir)
    desired = _desired_from_manifest(slot, manifest)
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
            raise ValueError(f"no backups found for slot: {slot}")
        path = backups[-1].resolve(strict=False) / "failed-container"
    path = path.resolve(strict=False)
    if not _is_under_path(path, backup_root):
        raise ValueError("diagnostics path must stay under the slot backup root")
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl diagnostics show SLOT", file=sys.stderr)
        return 2
    try:
        slot = str(args.slot)
        if not (CUSTOMER_SLOT_RE.match(slot) or DEV_SLOT_RE.match(slot)):
            raise ValueError(f"invalid slot: {slot}")
        diag_dir = _resolve_diagnostics_dir(slot, getattr(args, "dir", None))
        tail_lines = max(1, min(int(getattr(args, "tail", 120)), 300))
    except Exception as exc:
        print("diagnostics_status=fail")
        print(f"reason={exc}")
        return 1

    print("diagnostics_status=ok")
    print(f"slot={slot}")
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


def cmd_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl apply SLOT", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired = load_desired_slot(args.slot, state_root)
        profile = load_profile(desired.runtime_profile)
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
        if not manifest_path.exists() and not state_manifest_path.exists() and not args.allow_first_apply:
            raise ValueError("first agent-runtime apply requires --allow-first-apply")
        previous_manifest = state_manifest_path if state_manifest_path.exists() else manifest_path if manifest_path.exists() else None
        backup_dir = _backup_agent_runtime_state(desired.slot, runtime_dir, state_root)
        _atomic_write(compose_path, rendered.text, 0o644)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "apply", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"slot={desired.slot}")
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
        _append_action_log(state_root, "apply", desired.slot, desired.slot, "fail", "compose_config_failed")
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
        _append_action_log(state_root, "apply", desired.slot, desired.slot, "fail", "compose_up_failed")
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
        _append_action_log(state_root, "apply", desired.slot, desired.slot, "fail", f"live_failed={failed}")
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
        _append_action_log(state_root, "apply", desired.slot, desired.release_name, "ok", rendered.sha256)
    except Exception as exc:
        ok, reason = _restore_backup(desired.slot, runtime_dir, backup_dir, state_root)
        print("apply_status=fail")
        print(f"reason=manifest_write_failed:{exc}")
        print(f"rollback_status={'ok' if ok else 'fail'}")
        print(f"rollback_reason={reason}")
        try:
            _append_action_log(state_root, "apply", desired.slot, desired.slot, "fail", f"manifest_write_failed:{exc}")
        except Exception:
            pass
        return 1
    print("apply_status=ok")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollback SLOT", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        runtime_dir = _slot_runtime_dir(args.slot)
        backup_dir = _latest_backup(runtime_dir)
        if backup_dir is None:
            raise FileNotFoundError("no agent-runtime backup")
        ok, reason = _restore_backup(args.slot, runtime_dir, backup_dir, state_root)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("rollback_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollback", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1
    print(f"slot={args.slot}")
    print(f"backup_dir={backup_dir}")
    print(f"rollback_reason={reason}")
    if not ok:
        print("rollback_status=fail")
        _append_action_log(state_root, "rollback", args.slot, str(backup_dir), "fail", reason)
        return 1

    try:
        desired, profile = _load_backup_runtime_contract(args.slot, backup_dir)
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret set SLOT", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired = load_desired_slot(args.slot, state_root)
        profile = load_profile(desired.runtime_profile)
        values = _secret_values_from_args(args)
        secret_path = _upsert_runtime_secret_file(desired.slot, profile, values)
        runtime_dir = _slot_runtime_dir(desired.slot)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "runtime_secret_set", args.slot, args.slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"slot={desired.slot}")
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl runtime-secret status SLOT", file=sys.stderr)
        return 2
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        secret_file = primary_profile_secret_file(profile, desired.slot)
        _assert_secret_path_safe(desired.slot, secret_file.path)
        file_state, key_state = _secret_status_rows(secret_file.path)
    except Exception as exc:
        print(f"slot={args.slot}")
        print("runtime_secret_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"slot={desired.slot}")
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl handoff status SLOT", file=sys.stderr)
        return 2
    try:
        desired = load_desired_slot(args.slot, _state_root(args))
        profile = load_profile(desired.runtime_profile)
        family = str(profile.metadata.get("family") or desired.lane_data.get("family") or "")
    except Exception as exc:
        print(f"slot={args.slot}")
        print("handoff_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"slot={desired.slot}")
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


def _load_slots_lanes_releases(state_root: Path) -> tuple[dict, dict, dict]:
    return (
        load_yaml(state_root / "slots.yaml"),
        load_yaml(state_root / "lanes.yaml"),
        load_yaml(state_root / "releases.yaml"),
    )


def _iter_slot_lanes(slots_data: dict) -> list[tuple[str, str]]:
    slots = slots_data.get("slots") or {}
    rows: list[tuple[str, str]] = []
    if isinstance(slots, dict):
        for slot, data in slots.items():
            lane = data.get("lane") if isinstance(data, dict) else None
            if lane:
                rows.append((str(slot), str(lane)))
    elif isinstance(slots, list):
        for item in slots:
            if isinstance(item, dict) and item.get("slot") and item.get("lane"):
                rows.append((str(item["slot"]), str(item["lane"])))
    return sorted(rows)


def _set_slot_lane(slots_data: dict, slot: str, lane: str) -> None:
    slots = slots_data.get("slots")
    if isinstance(slots, dict):
        entry = slots.setdefault(slot, {})
        if not isinstance(entry, dict):
            raise ValueError(f"slot entry is not a mapping: {slot}")
        entry["lane"] = lane
        return
    if isinstance(slots, list):
        for item in slots:
            if isinstance(item, dict) and item.get("slot") == slot:
                item["lane"] = lane
                return
        slots.append({"slot": slot, "lane": lane})
        return
    raise ValueError("slots.yaml must contain slots as a mapping or list")


def _slots_for_lane(slots_data: dict, lane: str) -> list[str]:
    return [slot for slot, slot_lane in _iter_slot_lanes(slots_data) if slot_lane == lane]


def _fleet_lane_for_family(lanes_data: dict, family: str) -> str:
    lanes = lanes_data.get("lanes") or {}
    if not isinstance(lanes, dict):
        raise ValueError("lanes.yaml must contain a lanes mapping")
    if family in lanes and isinstance(lanes[family], dict):
        data = lanes[family]
        if data.get("family") == family and data.get("slot_class") == "customer":
            return family
    candidates = [
        name
        for name, data in lanes.items()
        if isinstance(data, dict)
        and data.get("family") == family
        and data.get("slot_class") == "customer"
        and not str(name).endswith("-canary")
    ]
    if len(candidates) != 1:
        raise ValueError(f"expected exactly one customer fleet lane for {family}, found {len(candidates)}")
    return str(candidates[0])


def _canary_lane_for_family(family: str) -> str:
    return f"{family}-canary"


def _release_entry(releases_data: dict, release_name: str) -> dict:
    releases = releases_data.get("releases") or {}
    entry = releases.get(release_name)
    if not isinstance(entry, dict):
        raise KeyError(f"release not found: {release_name}")
    return entry


def _validate_release_for_family(releases_data: dict, release_name: str, family: str) -> dict:
    _validate_release_name(release_name)
    entry = _release_entry(releases_data, release_name)
    if entry.get("family") != family:
        raise ValueError(f"release family mismatch: release={entry.get('family')} requested={family}")
    wrapper_image = str(entry.get("wrapper_image") or "")
    product_image = str(entry.get("product_image") or "")
    wrapper_digest = _validate_image_digest_ref(wrapper_image)
    _validate_image_digest_ref(product_image)
    if entry.get("digest") != wrapper_digest:
        raise ValueError(f"release digest must match wrapper image digest: {release_name}")
    if not _allowed_image_ref(family, "wrapper", wrapper_image):
        raise ValueError(f"wrapper image repository is not allowed for {family}")
    if not _allowed_image_ref(family, "product", product_image):
        raise ValueError(f"product image repository is not allowed for {family}")
    return entry


def _load_rollout_state(state_root: Path) -> dict:
    data = load_yaml(state_root / ROLLOUT_STATE_NAME, default={})
    if not isinstance(data, dict):
        return {}
    data.setdefault("meta", _state_meta("opsctl rollout"))
    data.setdefault("families", {})
    return data


def _write_rollout_state(state_root: Path, data: dict) -> Path | None:
    data["meta"] = _state_meta("opsctl rollout")
    data.setdefault("families", {})
    return _write_state_yaml_file(state_root, ROLLOUT_STATE_NAME, data)


def _family_rollout_record(rollout_state: dict, family: str) -> dict:
    families = rollout_state.setdefault("families", {})
    if not isinstance(families, dict):
        raise ValueError("rollout state families must be a mapping")
    record = families.setdefault(family, {})
    if not isinstance(record, dict):
        raise ValueError(f"rollout state family record must be a mapping: {family}")
    return record


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
    _validate_release_name(name)


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


def _dev_recipe_runtime_env(desired) -> dict[str, str]:
    family = str(desired.lane_data.get("family") or "")
    gateway_port = _slot_gateway_port(desired.slot)
    env = {
        "OPENCLAW_RUNTIME_FAMILY": family,
        "OPENCLAW_IMAGE": str(desired.release_data.get("wrapper_image") or ""),
    }
    if gateway_port is not None:
        env["OPENCLAW_GATEWAY_PORT"] = str(gateway_port)
        env["OPENCLAW_BRIDGE_PORT"] = str(gateway_port + 1)
    return env


def cmd_recipe_dev_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_desired_slot(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        recipes = _load_dev_recipe_state(state_root).get("recipes") or {}
        recipe = recipes.get(slot) if isinstance(recipes, dict) else None
    except Exception as exc:
        print(f"slot={slot}")
        print("recipe_status=fail")
        print(f"reason={exc}")
        return 1
    print(f"slot={desired.slot}")
    print(f"lane={desired.lane}")
    print(f"runtime_profile={profile.name}")
    print(f"mode={profile.metadata.get('mode')}")
    if isinstance(recipe, dict):
        print("recipe_status=present")
        for key in ("recipe_name", "source_output", "sync_from", "build_command", "updated_at"):
            print(f"{key}={recipe.get(key, '')}")
    else:
        print("recipe_status=missing")
    return 0


def cmd_recipe_dev_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl recipe apply-dev SLOT ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    slot = str(args.slot)
    try:
        desired = load_desired_slot(slot, state_root)
        profile = load_profile(desired.runtime_profile)
        if desired.lane_data.get("slot_class") != "dev" or profile.metadata.get("mode") != "source":
            raise ValueError("recipe apply-dev requires a dev slot using source mode")
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
        runtime_dir = _ensure_dev_runtime_dir(slot)
        uid, gid = _slot_uid_gid(slot)
        env_updates = _dev_recipe_runtime_env(desired)
        env_updates["SOURCE_OUTPUT"] = str(source_output)
        _upsert_runtime_env_file(runtime_dir / ".env", env_updates, uid, gid)
        recipe_state = _load_dev_recipe_state(state_root)
        recipes = recipe_state.setdefault("recipes", {})
        if not isinstance(recipes, dict):
            raise ValueError("dev recipe state recipes must be a mapping")
        recipes[slot] = {
            "slot": slot,
            "family": desired.lane_data.get("family"),
            "runtime_profile": profile.name,
            "recipe_name": recipe_name,
            "source_output": str(source_output),
            "sync_from": sync_from_value,
            "build_command": _optional_safe_text(args.build_command, "--build-command"),
            "updated_at": _now_iso(),
            "updated_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
        }
        backup_path = _write_dev_recipe_state(state_root, recipe_state)
        _append_action_log(state_root, "recipe_apply_dev", slot, recipe_name, "prepared", f"source_output={source_output}")
    except Exception as exc:
        print(f"slot={slot}")
        print("recipe_apply_dev_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "recipe_apply_dev", slot, slot, "fail", str(exc))
        except Exception:
            pass
        return 1

    print(f"slot={slot}")
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


def cmd_release_import(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl release import ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        name = str(args.name)
        family = str(args.family)
        _validate_release_name(name)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        image_recipe: dict[str, object] = {}
        if args.compat_combined:
            if not args.image:
                raise ValueError("--compat-combined requires --image")
            if args.product_image or args.wrapper_image:
                raise ValueError("--compat-combined cannot be mixed with --product-image/--wrapper-image")
            product_image = str(args.image)
            wrapper_image = str(args.image)
            compatibility_mode = "combined_runtime_image"
        else:
            if args.image:
                raise ValueError("--image is only valid with --compat-combined")
            if not args.product_image or not args.wrapper_image:
                raise ValueError("split releases require --product-image and --wrapper-image")
            product_image = str(args.product_image)
            wrapper_image = str(args.wrapper_image)
            compatibility_mode = "wrapped_product_image"
        product_digest = _validate_image_digest_ref(product_image)
        wrapper_digest = _validate_image_digest_ref(wrapper_image)
        if not _allowed_image_ref(family, "product", product_image):
            raise ValueError(f"product image repository is not allowed for {family}")
        if not _allowed_image_ref(family, "wrapper", wrapper_image):
            raise ValueError(f"wrapper image repository is not allowed for {family}")
        if compatibility_mode == "wrapped_product_image":
            image_recipe = _image_recipe_from_wrapper_image(wrapper_image, family=family, product_image=product_image)
        components = _derived_release_components(product_image, wrapper_image)
        if image_recipe:
            components.update(
                {
                    "product_component": str(image_recipe.get("product_component") or components["product_component"]),
                    "wrapper_component": str(image_recipe.get("wrapper_component") or components["wrapper_component"]),
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
        components.update(_release_components_from_args(getattr(args, "component", None)))

        releases_data = load_yaml(state_root / "releases.yaml", default={})
        releases = releases_data.setdefault("releases", {})
        if not isinstance(releases, dict):
            raise ValueError("releases.yaml must contain a releases mapping")
        if name in releases and not args.replace:
            raise ValueError(f"release already exists: {name}; use --replace to overwrite")
        releases_data["meta"] = _state_meta("opsctl release import")
        releases[name] = {
            "family": family,
            "image_name": args.image_name or name,
            "product_image": product_image,
            "wrapper_image": wrapper_image,
            "digest": wrapper_digest,
            "product_digest": product_digest,
            "components": components,
            "imported_at": _now_iso(),
            "imported_by": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
            "compatibility_mode": compatibility_mode,
        }
        if image_recipe:
            releases[name]["image_recipe"] = image_recipe
        backup_path = _write_state_yaml_file(state_root, "releases.yaml", releases_data)
        _append_action_log(state_root, "release_import", "-", name, "ok", f"family={family} digest={wrapper_digest}")
    except Exception as exc:
        print("release_import_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "release_import", "-", str(getattr(args, "name", "")), "fail", str(exc))
        except Exception:
            pass
        return 1

    print("release_import_status=ok")
    print(f"release={name}")
    print(f"family={family}")
    print(f"wrapper_image={wrapper_image}")
    print(f"product_image={product_image}")
    print(f"recipe_mode={compatibility_mode}")
    print(f"product_component={components.get('product_component', '')}")
    if image_recipe:
        profiles = image_recipe.get("runtime_profiles") if isinstance(image_recipe, dict) else {}
        if isinstance(profiles, dict):
            print(f"runtime_profile_customer={profiles.get('customer', '')}")
            print(f"runtime_profile_dev={profiles.get('dev', '')}")
    print(f"release_digest={wrapper_digest}")
    if backup_path:
        print(f"backup={backup_path}")
    return 0


def cmd_release_add(args: argparse.Namespace) -> int:
    print("error: release add is deprecated; use release import", file=sys.stderr)
    return 2


def cmd_release_promote(args: argparse.Namespace) -> int:
    print("error: release promote is deprecated; use rollout promote", file=sys.stderr)
    return 2


def cmd_rollout_status(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        family = str(args.family)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
        fleet_lane = _fleet_lane_for_family(lanes_data, family)
        canary_lane = _canary_lane_for_family(family)
        lanes = lanes_data.get("lanes") or {}
        fleet = lanes.get(fleet_lane) or {}
        canary = lanes.get(canary_lane) or {}
        rollout_state = _load_rollout_state(state_root)
        record = _family_rollout_record(rollout_state, family).get("canary") or {}
        fleet_release = str(fleet.get("release") or "")
        _validate_release_for_family(releases_data, fleet_release, family)
        canary_release = str(canary.get("release") or "") if isinstance(canary, dict) else ""
        if canary_release:
            _validate_release_for_family(releases_data, canary_release, family)
    except Exception as exc:
        print("rollout_status=fail")
        print(f"reason={exc}")
        return 1
    print("rollout_status=ok")
    print(f"family={family}")
    print(f"fleet_lane={fleet_lane}")
    print(f"fleet_release={fleet_release}")
    print(f"fleet_slots={','.join(_slots_for_lane(slots_data, fleet_lane))}")
    if isinstance(canary, dict) and canary:
        print(f"canary_lane={canary_lane}")
        print(f"canary_release={canary_release}")
        print(f"canary_slots={','.join(_slots_for_lane(slots_data, canary_lane))}")
    else:
        print(f"canary_lane={canary_lane}")
        print("canary_release=")
        print("canary_slots=")
    if isinstance(record, dict) and record:
        print(f"recorded_canary_slot={record.get('slot', '')}")
        print(f"recorded_canary_release={record.get('release', '')}")
        print(f"recorded_canary_status={record.get('status', '')}")
        print(f"recorded_canary_checked_at={record.get('checked_at', '')}")
    return 0


def cmd_rollout_plan(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    try:
        family = str(args.family)
        release = str(args.release)
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
        release_data = _validate_release_for_family(releases_data, release, family)
        fleet_lane = _fleet_lane_for_family(lanes_data, family)
        canary_lane = _canary_lane_for_family(family)
        lanes = lanes_data.get("lanes") or {}
        fleet_release = str((lanes.get(fleet_lane) or {}).get("release") or "")
        fleet_profile_name = str((lanes.get(fleet_lane) or {}).get("runtime_profile") or "")
        target_profile_name = _release_runtime_profile_name(release_data, "customer", fleet_profile_name)
        fleet_profile = load_profile(target_profile_name)
        contract_checks = [
            {"ok": ok, "name": name, "detail": detail}
            for ok, name, detail in _release_profile_contract_checks(release_data, fleet_profile)
        ]
        plan = {
            "family": family,
            "release": release,
            "release_digest": release_data.get("digest"),
            "wrapper_image": release_data.get("wrapper_image"),
            "product_image": release_data.get("product_image"),
            "recipe": _release_recipe_payload(release_data),
            "runtime_profile": fleet_profile.name,
            "fleet_runtime_profile": fleet_profile_name,
            "runtime_contract": _profile_runtime_contract(fleet_profile),
            "customer_surface": _profile_customer_surface(fleet_profile),
            "contract_checks": contract_checks,
            "contract_compatible": all(item["ok"] for item in contract_checks),
            "fleet_lane": fleet_lane,
            "fleet_current_release": fleet_release,
            "fleet_slots": _slots_for_lane(slots_data, fleet_lane),
            "canary_lane": canary_lane,
            "canary_slots": _slots_for_lane(slots_data, canary_lane),
            "mutates": False,
            "steps": [
                "rollout canary --family FAMILY --release RELEASE --slot SLOT",
                "verify canary live checks",
                "rollout promote --family FAMILY --release RELEASE",
            ],
        }
    except Exception as exc:
        print(json.dumps({"rollout_plan_status": "fail", "reason": str(exc), "mutates": False}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def _restore_state_files(state_root: Path, *, slots_data: dict, lanes_data: dict) -> None:
    _write_state_yaml_file(state_root, "slots.yaml", slots_data)
    _write_state_yaml_file(state_root, "lanes.yaml", lanes_data)


def _desired_with_release_and_profile(desired: DesiredSlot, release: str, release_data: dict, runtime_profile: str) -> DesiredSlot:
    lane_data = dict(desired.lane_data)
    lane_data["release"] = release
    lane_data["runtime_profile"] = runtime_profile
    return DesiredSlot(
        slot=desired.slot,
        lane=desired.lane,
        lane_data=lane_data,
        release_name=release,
        release_data=release_data,
        runtime_profile=runtime_profile,
    )


def _dev_rollout_target(state_root: Path, family: str, release: str, slot: str) -> tuple[dict, dict, dict, DesiredSlot, object, object]:
    if family not in {"openclaw", "hermes"}:
        raise ValueError("family must be openclaw or hermes")
    if not DEV_SLOT_RE.match(slot):
        raise ValueError("dev rollout slot must be a dev slot like dev-NAME")
    slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
    release_data = _validate_release_for_family(releases_data, release, family)
    desired_before = load_desired_slot(slot, state_root)
    if desired_before.lane_data.get("family") != family or desired_before.lane_data.get("slot_class") != "dev":
        raise ValueError(f"slot is not a {family} dev slot: {slot}")
    lane_slots = _slots_for_lane(slots_data, desired_before.lane)
    if lane_slots != [slot]:
        raise ValueError(
            f"dev lane must be slot-scoped before mutation: lane={desired_before.lane} slots={','.join(lane_slots)}"
        )
    target_profile_name = _release_runtime_profile_name(release_data, "dev", desired_before.runtime_profile)
    target_profile = load_profile(target_profile_name)
    target_desired = _desired_with_release_and_profile(desired_before, release, release_data, target_profile.name)
    return slots_data, lanes_data, releases_data, target_desired, load_profile(desired_before.runtime_profile), target_profile


def cmd_rollout_dev_plan(args: argparse.Namespace) -> int:
    state_root = _state_root(args)
    family = str(args.family)
    release = str(args.release)
    slot = str(args.slot)
    try:
        slots_data, lanes_data, _releases_data, target_desired, profile_before, target_profile = _dev_rollout_target(
            state_root, family, release, slot
        )
        rendered = render_compose(target_profile, target_desired)
        contract_checks = [
            {"ok": ok, "name": name, "detail": detail}
            for ok, name, detail in _release_profile_contract_checks(target_desired.release_data, target_profile)
        ]
        static_checks = [
            {"ok": ok, "name": name, "detail": detail}
            for ok, name, detail in _run_static_slot_checks(target_desired, target_profile, rendered)
        ]
        plan = {
            "family": family,
            "slot": slot,
            "lane": target_desired.lane,
            "lane_slots": _slots_for_lane(slots_data, target_desired.lane),
            "release": release,
            "current_release": load_desired_slot(slot, state_root).release_name,
            "runtime_profile": target_profile.name,
            "current_runtime_profile": profile_before.name,
            "runtime_contract": _profile_runtime_contract(target_profile),
            "customer_surface": _profile_customer_surface(target_profile),
            "recipe": _release_recipe_payload(target_desired.release_data),
            "contract_checks": contract_checks,
            "static_checks": static_checks,
            "contract_compatible": all(item["ok"] for item in contract_checks + static_checks),
            "compose_sha256": rendered.sha256,
            "mutates": False,
            "steps": [
                "rollout dev-apply --family FAMILY --release RELEASE --slot DEV_SLOT",
                "verify dev live checks",
                "rollout canary --family FAMILY --release RELEASE --slot CUSTOMER_SLOT",
                "rollout promote --family FAMILY --release RELEASE",
            ],
        }
    except Exception as exc:
        print(json.dumps({"rollout_dev_plan_status": "fail", "reason": str(exc), "mutates": False}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def cmd_rollout_dev_apply(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout dev-apply ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    family = str(args.family)
    release = str(args.release)
    slot = str(args.slot)
    try:
        slots_data, lanes_data, _releases_data, target_desired, profile_before, target_profile = _dev_rollout_target(
            state_root, family, release, slot
        )
        original_lanes_data = copy.deepcopy(lanes_data)
        rendered = render_compose(target_profile, target_desired)
        static_failures = [
            name for ok, name, _ in _run_static_slot_checks(target_desired, target_profile, rendered) if not ok
        ]
        if static_failures:
            raise ValueError(f"static contract check failed: {','.join(static_failures)}")
        lanes = lanes_data.get("lanes") or {}
        lane_data = lanes.get(target_desired.lane)
        if not isinstance(lane_data, dict):
            raise ValueError(f"dev lane is invalid: {target_desired.lane}")
        previous_release = str(lane_data.get("release") or "")
        previous_runtime_profile = str(lane_data.get("runtime_profile") or "")
        lane_data["release"] = release
        lane_data["runtime_profile"] = target_profile.name
        _write_state_yaml_file(state_root, "lanes.yaml", lanes_data)
    except Exception as exc:
        print("rollout_dev_apply_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_dev_apply", slot, release, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("rollout_dev_apply_state=updated")
    print(f"family={family}")
    print(f"slot={slot}")
    print(f"lane={target_desired.lane}")
    print(f"previous_release={previous_release}")
    print(f"previous_runtime_profile={previous_runtime_profile}")
    print(f"release={release}")
    print(f"runtime_profile={target_profile.name}")
    apply_rc = cmd_apply(
        argparse.Namespace(
            slot=slot,
            state_root=str(state_root),
            allow_first_apply=bool(getattr(args, "allow_first_apply", False)),
        )
    )
    if apply_rc != 0:
        _write_state_yaml_file(state_root, "lanes.yaml", original_lanes_data)
        print("rollout_dev_apply_status=fail")
        print("reason=dev_apply_failed")
        _append_action_log(state_root, "rollout_dev_apply", slot, release, "fail", "dev_apply_failed")
        return apply_rc or 1

    rollout_state = _load_rollout_state(state_root)
    record = _family_rollout_record(rollout_state, family)
    dev_slots = record.setdefault("dev_slots", {})
    if not isinstance(dev_slots, dict):
        raise ValueError("rollout state dev_slots must be a mapping")
    dev_slots[slot] = {
        "slot": slot,
        "lane": target_desired.lane,
        "release": release,
        "previous_release": previous_release,
        "previous_runtime_profile": previous_runtime_profile,
        "runtime_profile": target_profile.name,
        "status": "ok",
        "checked_at": _now_iso(),
    }
    _write_rollout_state(state_root, rollout_state)
    print("rollout_dev_apply_status=ok")
    _append_action_log(state_root, "rollout_dev_apply", slot, release, "ok", f"profile={target_profile.name}")
    return 0


def cmd_rollout_canary(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout canary ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    family = str(args.family)
    release = str(args.release)
    slot = str(args.slot)
    try:
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        if not CUSTOMER_SLOT_RE.match(slot):
            raise ValueError("canary slot must be a customer slot like ocN")
        slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
        original_slots_data = copy.deepcopy(slots_data)
        original_lanes_data = copy.deepcopy(lanes_data)
        release_data = _validate_release_for_family(releases_data, release, family)
        desired_before = load_desired_slot(slot, state_root)
        profile_before = load_profile(desired_before.runtime_profile)
        if desired_before.lane_data.get("family") != family or desired_before.lane_data.get("slot_class") != "customer":
            raise ValueError(f"slot is not a {family} customer slot: {slot}")
        target_profile_name = _release_runtime_profile_name(release_data, "customer", profile_before.name)
        target_profile = load_profile(target_profile_name)
        contract_failures = _release_profile_contract_failures(release_data, target_profile)
        if contract_failures:
            raise ValueError(
                "release does not satisfy runtime contract "
                f"{_profile_runtime_contract(target_profile) or target_profile.name}:"
                + ",".join(contract_failures)
            )
        fleet_lane = _fleet_lane_for_family(lanes_data, family)
        canary_lane = _canary_lane_for_family(family)
        existing_rollout_state = _load_rollout_state(state_root)
        existing_canary = _family_rollout_record(existing_rollout_state, family).get("canary")
        if desired_before.lane == canary_lane and isinstance(existing_canary, dict):
            previous_lane = str(existing_canary.get("previous_lane") or fleet_lane)
            previous_release = str(existing_canary.get("previous_release") or desired_before.release_name)
        else:
            previous_lane = desired_before.lane if desired_before.lane != canary_lane else fleet_lane
            previous_release = str(desired_before.lane_data.get("release") or desired_before.release_name)
        lanes = lanes_data.setdefault("lanes", {})
        fleet_data = lanes.get(fleet_lane)
        if not isinstance(fleet_data, dict):
            raise ValueError(f"fleet lane is invalid: {fleet_lane}")
        lanes[canary_lane] = {
            "family": family,
            "slot_class": "customer",
            "release": release,
            "runtime_profile": target_profile.name,
        }
        _set_slot_lane(slots_data, slot, canary_lane)
        _write_state_yaml_file(state_root, "lanes.yaml", lanes_data)
        _write_state_yaml_file(state_root, "slots.yaml", slots_data)
    except Exception as exc:
        print("rollout_canary_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_canary", slot, release, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("rollout_canary_state=updated")
    print(f"family={family}")
    print(f"slot={slot}")
    print(f"canary_lane={canary_lane}")
    print(f"release={release}")
    print(f"runtime_profile={target_profile.name}")
    apply_rc = cmd_apply(
        argparse.Namespace(
            slot=slot,
            state_root=str(state_root),
            allow_first_apply=bool(getattr(args, "allow_first_apply", False)),
        )
    )
    if apply_rc != 0:
        _restore_state_files(state_root, slots_data=original_slots_data, lanes_data=original_lanes_data)
        print("rollout_canary_status=fail")
        print("reason=canary_apply_failed")
        _append_action_log(state_root, "rollout_canary", slot, release, "fail", "canary_apply_failed")
        return apply_rc or 1

    rollout_state = _load_rollout_state(state_root)
    record = _family_rollout_record(rollout_state, family)
    record["canary"] = {
        "slot": slot,
        "release": release,
        "lane": canary_lane,
        "previous_lane": previous_lane,
        "previous_release": previous_release,
        "previous_runtime_profile": profile_before.name,
        "runtime_profile": target_profile.name,
        "status": "ok",
        "checked_at": _now_iso(),
    }
    _write_rollout_state(state_root, rollout_state)
    print("rollout_canary_status=ok")
    _append_action_log(state_root, "rollout_canary", slot, release, "ok", f"lane={canary_lane}")
    return 0


def cmd_rollout_promote(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout promote ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    family = str(args.family)
    release = str(args.release)
    try:
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
        release_data = _validate_release_for_family(releases_data, release, family)
        rollout_state = _load_rollout_state(state_root)
        record = _family_rollout_record(rollout_state, family).get("canary")
        if not isinstance(record, dict) or record.get("status") != "ok" or record.get("release") != release:
            raise ValueError("matching successful canary record is required before promote")
        fleet_lane = _fleet_lane_for_family(lanes_data, family)
        canary_slot = str(record.get("slot") or "")
        if not CUSTOMER_SLOT_RE.match(canary_slot):
            raise ValueError("canary record is missing a valid customer slot")
        lanes = lanes_data.get("lanes") or {}
        fleet_data = lanes.get(fleet_lane)
        if not isinstance(fleet_data, dict):
            raise ValueError(f"fleet lane is invalid: {fleet_lane}")
        previous_release = str(fleet_data.get("release") or "")
        previous_profile = str(fleet_data.get("runtime_profile") or "")
        target_profile_name = _release_runtime_profile_name(release_data, "customer", previous_profile)
        target_profile = load_profile(target_profile_name)
        contract_failures = _release_profile_contract_failures(release_data, target_profile)
        if contract_failures:
            raise ValueError(
                "release does not satisfy runtime contract "
                f"{_profile_runtime_contract(target_profile) or target_profile.name}:"
                + ",".join(contract_failures)
            )
        fleet_data["release"] = release
        fleet_data["runtime_profile"] = target_profile.name
        _set_slot_lane(slots_data, canary_slot, fleet_lane)
        _write_state_yaml_file(state_root, "lanes.yaml", lanes_data)
        _write_state_yaml_file(state_root, "slots.yaml", slots_data)
        slots_to_apply = _slots_for_lane(slots_data, fleet_lane)
    except Exception as exc:
        print("rollout_promote_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_promote", "-", release, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("rollout_promote_state=updated")
    print(f"family={family}")
    print(f"fleet_lane={fleet_lane}")
    print(f"previous_release={previous_release}")
    print(f"previous_runtime_profile={previous_profile}")
    print(f"release={release}")
    print(f"runtime_profile={target_profile.name}")
    print(f"slots={','.join(slots_to_apply)}")
    for slot in slots_to_apply:
        rc = cmd_apply(argparse.Namespace(slot=slot, state_root=str(state_root), allow_first_apply=False))
        if rc != 0:
            rollout_state = _load_rollout_state(state_root)
            record = _family_rollout_record(rollout_state, family)
            record["promotion"] = {
                "release": release,
                "status": "partial",
                "failed_slot": slot,
                "updated_at": _now_iso(),
            }
            _write_rollout_state(state_root, rollout_state)
            print("rollout_promote_status=partial")
            print(f"failed_slot={slot}")
            _append_action_log(state_root, "rollout_promote", slot, release, "partial", "slot_apply_failed")
            return rc or 1

    rollout_state = _load_rollout_state(state_root)
    record = _family_rollout_record(rollout_state, family)
    canary = record.get("canary")
    if isinstance(canary, dict):
        canary["status"] = "promoted"
        canary["promoted_at"] = _now_iso()
    record["promotion"] = {
        "release": release,
        "runtime_profile": target_profile.name,
        "status": "ok",
        "slots": slots_to_apply,
        "updated_at": _now_iso(),
    }
    _write_rollout_state(state_root, rollout_state)
    print("rollout_promote_status=ok")
    _append_action_log(state_root, "rollout_promote", "-", release, "ok", f"slots={len(slots_to_apply)}")
    return 0


def cmd_rollout_rollback_canary(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl rollout rollback-canary ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    family = str(args.family)
    try:
        if family not in {"openclaw", "hermes"}:
            raise ValueError("family must be openclaw or hermes")
        slots_data, lanes_data, releases_data = _load_slots_lanes_releases(state_root)
        rollout_state = _load_rollout_state(state_root)
        record = _family_rollout_record(rollout_state, family).get("canary")
        inferred_without_record = False
        if isinstance(record, dict) and record.get("slot") and record.get("previous_lane"):
            slot = str(record["slot"])
            previous_lane = str(record["previous_lane"])
            previous_release = str(record.get("previous_release") or "")
            canary_release = str(record.get("release") or "")
        else:
            fleet_lane = _fleet_lane_for_family(lanes_data, family)
            canary_lane = _canary_lane_for_family(family)
            canary_slots = _slots_for_lane(slots_data, canary_lane)
            if len(canary_slots) != 1:
                raise ValueError(
                    f"no canary record to roll back and expected exactly one {canary_lane} slot, found {len(canary_slots)}"
                )
            lanes = lanes_data.get("lanes") or {}
            fleet_data = lanes.get(fleet_lane)
            canary_data = lanes.get(canary_lane)
            if not isinstance(fleet_data, dict):
                raise ValueError(f"fleet lane is invalid: {fleet_lane}")
            slot = canary_slots[0]
            previous_lane = fleet_lane
            previous_release = str(fleet_data.get("release") or "")
            canary_release = str(canary_data.get("release") or "") if isinstance(canary_data, dict) else ""
            inferred_without_record = True
        if previous_lane not in (lanes_data.get("lanes") or {}):
            raise ValueError(f"previous lane no longer exists: {previous_lane}")
        _validate_release_for_family(releases_data, previous_release, family)
        _set_slot_lane(slots_data, slot, previous_lane)
        _write_state_yaml_file(state_root, "slots.yaml", slots_data)
    except Exception as exc:
        print("rollout_rollback_canary_status=fail")
        print(f"reason={exc}")
        try:
            _append_action_log(state_root, "rollout_rollback_canary", "-", family, "fail", str(exc))
        except Exception:
            pass
        return 1

    print("rollout_rollback_canary_state=updated")
    print(f"family={family}")
    print(f"slot={slot}")
    print(f"lane={previous_lane}")
    print(f"release={previous_release}")
    if inferred_without_record:
        print("inferred_without_record=true")
    rc = cmd_apply(argparse.Namespace(slot=slot, state_root=str(state_root), allow_first_apply=False))
    if rc != 0:
        print("rollout_rollback_canary_status=fail")
        print("reason=rollback_apply_failed")
        _append_action_log(state_root, "rollout_rollback_canary", slot, previous_release, "fail", "rollback_apply_failed")
        return rc or 1
    rollout_state = _load_rollout_state(state_root)
    record = _family_rollout_record(rollout_state, family)
    canary = record.get("canary")
    if isinstance(canary, dict):
        canary["status"] = "rolled_back"
        canary["rolled_back_at"] = _now_iso()
    elif inferred_without_record:
        record["canary"] = {
            "slot": slot,
            "release": canary_release,
            "lane": _canary_lane_for_family(family),
            "previous_lane": previous_lane,
            "previous_release": previous_release,
            "status": "rolled_back_without_record",
            "rolled_back_at": _now_iso(),
            "recovered_from": "canary_state_without_rollout_record",
        }
    _write_rollout_state(state_root, rollout_state)
    print("rollout_rollback_canary_status=ok")
    _append_action_log(state_root, "rollout_rollback_canary", slot, previous_release, "ok")
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


def _slot_names_from_config(slots_data: object) -> list[str]:
    if isinstance(slots_data, dict):
        return sorted(str(slot) for slot in slots_data)
    if isinstance(slots_data, list):
        names = []
        for item in slots_data:
            if isinstance(item, dict) and item.get("slot"):
                names.append(str(item["slot"]))
            elif isinstance(item, str):
                names.append(item)
        return sorted(names)
    return []


def _approve_auto_once(state_root: Path) -> dict[str, int]:
    result = {"checked": 0, "approved": 0, "pending": 0, "rejected": 0, "failed": 0}
    slots = load_yaml(state_root / "slots.yaml").get("slots") or {}
    for slot in _slot_names_from_config(slots):
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
    for slot in _slot_names_from_config(slots_data):
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


def cmd_nas_credential_status(args: argparse.Namespace) -> int:
    try:
        load_desired_slot(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
    except Exception as exc:
        print(f"slot={args.slot}")
        print(f"share={args.share}")
        print("credential_status=fail")
        print(f"reason={exc}")
        return 1
    status = _official_credential_status(args.slot, share)
    print(f"slot={args.slot}")
    print(f"share={share.source}")
    print("credential_scope=official")
    print("mutates=false")
    _print_official_credential_status("", status)
    print("credential_status=ok")
    print("secret_value_printed=no")
    return 0


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
        credential_status = _official_credential_status(args.slot, share)
    except Exception as exc:
        print(f"slot={args.slot}")
        print(f"share={args.share}")
        print("unmount_status=fail")
        print(f"reason={exc}")
        _append_action_log(_state_root(args), "nas_unmount", args.slot, args.share, "fail", str(exc))
        return 1

    rc, _, rows = _findmnt_one(mountpoint)
    if rc != 0 or not rows:
        print(f"slot={args.slot}")
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
        print("error: run as root/admin: sudo /usr/local/bin/opsctl nas remove SLOT //HOST/SHARE", file=sys.stderr)
        return 2
    try:
        load_desired_slot(args.slot, _state_root(args))
        share = parse_smb_share(args.share)
        mountpoint = mountpoint_for_share(args.slot, share)
        _safe_mountpoint_path(mountpoint)
        before_status = _official_credential_status(args.slot, share)
        # Validate credentials before mutating mount or fstab state.
        _validate_official_credentials_for_delete(args.slot, share)
    except Exception as exc:
        print(f"slot={args.slot}")
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
    print(f"slot={args.slot}")
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

    slot = sub.add_parser("slot")
    slot_sub = slot.add_subparsers(dest="slot_command", required=True)
    slot_list = slot_sub.add_parser("list")
    slot_list.set_defaults(func=cmd_slot_list)

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

    diagnostics = sub.add_parser("diagnostics")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command", required=True)
    diagnostics_show = diagnostics_sub.add_parser("show")
    diagnostics_show.add_argument("slot")
    diagnostics_show.add_argument("--dir", help="absolute backup dir or failed-container dir to show")
    diagnostics_show.add_argument("--tail", type=int, default=120)
    diagnostics_show.set_defaults(func=cmd_diagnostics_show)

    rollout = sub.add_parser("rollout")
    rollout_sub = rollout.add_subparsers(dest="rollout_command", required=True)
    rollout_status = rollout_sub.add_parser("status")
    rollout_status.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_status.set_defaults(func=cmd_rollout_status)
    rollout_plan = rollout_sub.add_parser("plan")
    rollout_plan.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_plan.add_argument("--release", required=True)
    rollout_plan.set_defaults(func=cmd_rollout_plan)
    rollout_dev_plan = rollout_sub.add_parser("dev-plan")
    rollout_dev_plan.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_dev_plan.add_argument("--release", required=True)
    rollout_dev_plan.add_argument("--slot", required=True)
    rollout_dev_plan.set_defaults(func=cmd_rollout_dev_plan)
    rollout_dev_apply = rollout_sub.add_parser("dev-apply")
    rollout_dev_apply.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_dev_apply.add_argument("--release", required=True)
    rollout_dev_apply.add_argument("--slot", required=True)
    rollout_dev_apply.add_argument("--allow-first-apply", action="store_true")
    rollout_dev_apply.set_defaults(func=cmd_rollout_dev_apply)
    rollout_canary = rollout_sub.add_parser("canary")
    rollout_canary.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_canary.add_argument("--release", required=True)
    rollout_canary.add_argument("--slot", required=True)
    rollout_canary.add_argument("--allow-first-apply", action="store_true")
    rollout_canary.set_defaults(func=cmd_rollout_canary)
    rollout_promote = rollout_sub.add_parser("promote")
    rollout_promote.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_promote.add_argument("--release", required=True)
    rollout_promote.set_defaults(func=cmd_rollout_promote)
    rollout_rollback_canary = rollout_sub.add_parser("rollback-canary")
    rollout_rollback_canary.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    rollout_rollback_canary.set_defaults(func=cmd_rollout_rollback_canary)

    recipe = sub.add_parser("recipe")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_status = recipe_sub.add_parser("status")
    recipe_status.add_argument("slot")
    recipe_status.set_defaults(func=cmd_recipe_dev_status)
    recipe_apply_dev = recipe_sub.add_parser("apply-dev")
    recipe_apply_dev.add_argument("slot")
    recipe_apply_dev.add_argument("--recipe-name")
    source_group = recipe_apply_dev.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source-output")
    source_group.add_argument("--sync-from")
    recipe_apply_dev.add_argument("--build-command")
    recipe_apply_dev.add_argument("--allow-first-apply", action="store_true")
    recipe_apply_dev.add_argument("--no-apply", action="store_true")
    recipe_apply_dev.set_defaults(func=cmd_recipe_dev_apply)

    release = sub.add_parser("release")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    release_import = release_sub.add_parser("import")
    release_import.add_argument("name")
    release_import.add_argument("--family", required=True, choices=["hermes", "openclaw"])
    release_import.add_argument("--image")
    release_import.add_argument("--product-image")
    release_import.add_argument("--wrapper-image")
    release_import.add_argument("--image-name")
    release_import.add_argument(
        "--component",
        action="append",
        default=[],
        help="repeatable release recipe component in NAME=VALUE form, such as hermes-workspace=repo@sha",
    )
    release_import.add_argument("--compat-combined", action="store_true")
    release_import.add_argument("--replace", action="store_true")
    release_import.set_defaults(func=cmd_release_import)
    release_add = release_sub.add_parser("add")
    release_add.add_argument("name")
    release_add.add_argument("image")
    release_add.set_defaults(func=cmd_release_add)
    release_promote = release_sub.add_parser("promote")
    release_promote.add_argument("name")
    release_promote.add_argument("lane")
    release_promote.set_defaults(func=cmd_release_promote)

    runtime_secret = sub.add_parser("runtime-secret")
    runtime_secret_sub = runtime_secret.add_subparsers(dest="runtime_secret_command", required=True)
    runtime_secret_set = runtime_secret_sub.add_parser("set")
    runtime_secret_set.add_argument("slot")
    runtime_secret_set.add_argument("--env-file")
    runtime_secret_set.add_argument("--key")
    runtime_secret_set.add_argument("--value-stdin", action="store_true")
    runtime_secret_set.add_argument("--no-restart", action="store_true")
    runtime_secret_set.add_argument("--check", action="store_true")
    runtime_secret_set.set_defaults(func=cmd_runtime_secret_set)
    runtime_secret_status = runtime_secret_sub.add_parser("status")
    runtime_secret_status.add_argument("slot")
    runtime_secret_status.set_defaults(func=cmd_runtime_secret_status)

    handoff = sub.add_parser("handoff")
    handoff_sub = handoff.add_subparsers(dest="handoff_command", required=True)
    handoff_status = handoff_sub.add_parser("status")
    handoff_status.add_argument("slot")
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
    nas_credential_status.add_argument("slot")
    nas_credential_status.add_argument("share")
    nas_credential_status.set_defaults(func=cmd_nas_credential_status)
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
    nas_remove = nas_sub.add_parser("remove")
    nas_remove.add_argument("slot")
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
