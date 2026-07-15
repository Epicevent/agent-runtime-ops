from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import grp
import re
import secrets
import subprocess
import sys

from ..apache import apache_route_path, parse_apache_route
from ..domain.common import is_root as _is_root
from ..domain.common import state_root as _state_root
from ..domain.dev_recipe_runtime import upsert_runtime_env_file
from ..host.account_files import ensure_customer_agent_dirs, ensure_not_symlink_chain, runtime_ids, slot_uid_gid
from ..host.files import fsync_parent
from ..profiles import load_profile
from ..routing import (
    RuntimeBinding,
    load_runtime_bindings,
    validate_family,
    validate_instance_id,
    validate_linux_account,
    validate_public_host,
)
from ..runtime_secrets import (
    PROVIDER_SECRET_KEYS,
    WORKSPACE_AUTH_SECRET_KEYS,
    parse_secret_env_text,
    primary_profile_secret_file,
    render_upserted_secret_env,
    validate_runtime_secret_values,
)
from ..state import load_runtime_target
from ..yamlio import dump_yaml, load_yaml
from .binding import _write_runtime_bindings_file

SYSTEM_ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9_-]{0,35}$")


def cmd_admin_serve(args: argparse.Namespace) -> int:
    from ..admin_server import main as admin_main

    return admin_main(["--host", args.host, "--port", str(args.port)])


def _run(argv: list[str]) -> None:
    proc = subprocess.run(argv, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        raise RuntimeError(f"{argv[0]} failed: {detail[:240]}")


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def _safe_system_account_name(name: str) -> str:
    value = str(name or "").strip()
    if not SYSTEM_ACCOUNT_RE.match(value):
        raise ValueError(f"unsafe account/group name: {name}")
    return value


def _ensure_group(name: str, *, system: bool = False) -> str:
    group_name = _safe_system_account_name(name)
    if _group_exists(group_name):
        return "exists"
    argv = ["groupadd"]
    if system:
        argv.append("--system")
    argv.append(group_name)
    _run(argv)
    return "created"


def _ensure_user(
    name: str,
    *,
    primary_group: str,
    home: str,
    shell: str,
    system: bool = False,
    create_home: bool = False,
) -> str:
    user_name = _safe_system_account_name(name)
    if _user_exists(user_name):
        return "exists"
    argv = ["useradd", "--gid", primary_group, "--home-dir", home, "--shell", shell]
    if system:
        argv.append("--system")
        argv.append("--no-create-home")
    elif create_home:
        argv.append("--create-home")
    else:
        argv.append("--no-create-home")
    argv.append(user_name)
    _run(argv)
    return "created"


def _ensure_runtime_membership(runtime_user: str, data_group: str) -> None:
    _run(["usermod", "-a", "-G", data_group, runtime_user])


def _ensure_customer_data_membership(customer_user: str, data_group: str) -> None:
    _run(["usermod", "-a", "-G", data_group, customer_user])


def _write_owned_text(path: Path, text: str, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        fsync_parent(path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _render_apache_subdomain(binding: RuntimeBinding) -> str:
    return f"""# Subdomain VirtualHost - {binding.linux_account} (port {binding.gateway_port})
# Server: /etc/apache2/sites-available/{binding.public_host}.conf -> a2ensite -> reload
# DNS: {binding.public_host} -> server IP, or a wildcard ji-tech.co.kr A record
# OpenClaw: OPENCLAW_PROXY_MODE=subdomain
#           OPENCLAW_PROXY_PUBLIC_ORIGIN=https://{binding.public_host}
#           OPENCLAW_CONTROL_UI_BASEPATH=/

<VirtualHost *:443>
    ServerName {binding.public_host}

    SSLEngine on
    SSLCertificateFile      /etc/letsencrypt/live/ji-tech.co.kr/fullchain.pem
    SSLCertificateKeyFile   /etc/letsencrypt/live/ji-tech.co.kr/privkey.pem

    ProxyRequests Off
    ProxyPreserveHost On
    ProxyTimeout 3600

    RewriteEngine On
    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]
    RewriteCond %{{HTTP:Connection}} .*upgrade.* [NC]
    RewriteRule ^/(.*)$ ws://127.0.0.1:{binding.gateway_port}/$1 [P,L]

    <Location />
        ProxyPreserveHost On
        RequestHeader set X-Forwarded-Proto "https"
        RequestHeader set X-Forwarded-Host expr=%{{HTTP_HOST}}
    </Location>

    ProxyPass        / http://127.0.0.1:{binding.gateway_port}/ retry=0 timeout=3600
    ProxyPassReverse / http://127.0.0.1:{binding.gateway_port}/
</VirtualHost>
"""


def _ensure_apache_route(binding: RuntimeBinding) -> tuple[Path, str]:
    path = apache_route_path(binding.linux_account)
    if path.exists():
        route = parse_apache_route(binding.linux_account)
        if route.public_host != binding.public_host or route.gateway_port != binding.gateway_port:
            raise ValueError(
                "existing apache route mismatch: "
                f"host={route.public_host} port={route.gateway_port}"
            )
        return path, "exists"
    if path.is_symlink():
        raise ValueError(f"apache route file must not be symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = _render_apache_subdomain(binding)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o644)
    try:
        configtest = subprocess.run(["apache2ctl", "configtest"], text=True, capture_output=True, check=False)
        if configtest.returncode != 0:
            raise RuntimeError((configtest.stderr or configtest.stdout).strip() or "apache configtest failed")
        reload_proc = subprocess.run(["systemctl", "reload", "apache2"], text=True, capture_output=True, check=False)
        if reload_proc.returncode != 0:
            raise RuntimeError((reload_proc.stderr or reload_proc.stdout).strip() or "apache reload failed")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path, "created"


def _read_hermes_config_from_slot(slot: str) -> dict[str, object]:
    source_home = Path(pwd.getpwnam(slot).pw_dir).resolve(strict=False)
    path = source_home / ".hermes" / "config.yaml"
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"unsafe config source: {path}")
    data = load_yaml(path, default={})
    if not isinstance(data, dict):
        raise ValueError(f"source config must be a mapping: {path}")
    return dict(data)


def _read_openclaw_config_from_slot(slot: str) -> dict[str, object]:
    source_home = Path(pwd.getpwnam(slot).pw_dir).resolve(strict=False)
    path = source_home / ".openclaw" / "openclaw.json"
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"unsafe config source: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"source config must be a mapping: {path}")
    return dict(data)


def _clone_provider_secret_values(source_slot: str, state_root: Path, *, include_workspace_auth: bool = True) -> dict[str, str]:
    source = load_runtime_target(source_slot, state_root)
    source_profile = load_profile(source.runtime_profile)
    source_file = primary_profile_secret_file(source_profile, source.slot)
    if source_file.path.is_symlink() or not source_file.path.is_file():
        raise ValueError(f"unsafe provider secret source: {source_file.path}")
    values = parse_secret_env_text(source_file.path.read_text(encoding="utf-8", errors="replace"), source=str(source_file.path))
    cloned_secret_keys = PROVIDER_SECRET_KEYS | (WORKSPACE_AUTH_SECRET_KEYS if include_workspace_auth else set())
    cloned_values = {key: values[key] for key in sorted(cloned_secret_keys) if values.get(key)}
    return validate_runtime_secret_values(cloned_values) if cloned_values else {}


def _ensure_owned_dir(path: Path, *, home: Path, uid: int, gid: int, mode: int) -> None:
    ensure_not_symlink_chain(path, home)
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _ensure_hermes_app_dirs(home: Path, *, runtime_uid: int, data_gid: int) -> Path:
    hermes_dir = home / ".hermes"
    workspace_dir = hermes_dir / "workspace"
    for path in (hermes_dir, workspace_dir):
        _ensure_owned_dir(path, home=home, uid=runtime_uid, gid=data_gid, mode=0o750)
    return hermes_dir


def _ensure_openclaw_app_dirs(home: Path, *, runtime_uid: int, runtime_gid: int, data_gid: int) -> Path:
    openclaw_state_dir = home / ".openclaw"
    workspace_dir = openclaw_state_dir / "workspace"
    auth_profile_dir = home / ".openclaw-auth-profile-secrets"
    for path in (openclaw_state_dir, workspace_dir):
        _ensure_owned_dir(path, home=home, uid=runtime_uid, gid=data_gid, mode=0o750)
    _ensure_owned_dir(auth_profile_dir, home=home, uid=runtime_uid, gid=runtime_gid, mode=0o700)
    return openclaw_state_dir


def _empty_or_existing_env_text(path: Path) -> str:
    if not path.exists():
        return ""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"unsafe runtime secret file: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _ensure_target_dirs_and_secrets(
    target: str,
    *,
    family: str,
    gateway_port: int,
    bridge_port: int,
    clone_config_from: str | None,
    clone_provider_secrets_from: str | None,
    state_root: Path,
) -> tuple[str, str, str]:
    slot_uid, slot_gid = slot_uid_gid(target)
    runtime_uid, runtime_gid, data_gid = runtime_ids(target)
    home = Path("/home") / target
    ensure_not_symlink_chain(home, Path("/home"))
    home.mkdir(mode=0o750, exist_ok=True)
    os.chown(home, slot_uid, slot_gid)
    os.chmod(home, 0o750)

    runtime_dir = home / "openclaw"
    nas_docs_dir = home / "nas_docs"
    _ensure_owned_dir(runtime_dir, home=home, uid=slot_uid, gid=slot_gid, mode=0o750)
    if family == "hermes":
        hermes_dir = _ensure_hermes_app_dirs(home, runtime_uid=runtime_uid, data_gid=data_gid)
        profile_secret_path = hermes_dir / ".env"
    elif family == "openclaw":
        openclaw_state_dir = _ensure_openclaw_app_dirs(home, runtime_uid=runtime_uid, runtime_gid=runtime_gid, data_gid=data_gid)
        profile = load_profile("openclaw-customer")
        profile_secret_path = primary_profile_secret_file(profile, target).path
        ensure_not_symlink_chain(profile_secret_path.parent, home)
        if profile_secret_path.parent != runtime_dir:
            raise ValueError(f"unexpected OpenClaw secret path: {profile_secret_path}")
    else:
        raise ValueError(f"unsupported family: {family}")
    nas_docs_dir.mkdir(parents=True, exist_ok=True)
    os.chown(nas_docs_dir, 0, data_gid)
    os.chmod(nas_docs_dir, 0o750)
    # OCN workspace: the agent's own writable NAS folder mounts here, OUTSIDE
    # nas_docs, so the container's recursive read_only on nas_docs cannot freeze
    # it. Same root:data_gid 0750 as nas_docs — the rw comes from the CIFS mount
    # (forceuid=runtime); an absent mount leaves the local dir non-writable
    # (fail-loud) rather than silently swallowing writes.
    workspace_dir = home / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    os.chown(workspace_dir, 0, data_gid)
    os.chmod(workspace_dir, 0o750)
    ensure_customer_agent_dirs(target)

    existing_text = _empty_or_existing_env_text(profile_secret_path)
    existing_values = parse_secret_env_text(existing_text, source=str(profile_secret_path)) if existing_text else {}
    values: dict[str, str] = {}
    if clone_provider_secrets_from:
        values.update(
            _clone_provider_secret_values(
                clone_provider_secrets_from,
                state_root,
                include_workspace_auth=(family == "hermes"),
            )
        )
    api_server_key = ""
    if family == "hermes":
        api_server_key = existing_values.get("API_SERVER_KEY") or secrets.token_urlsafe(48)
        if not existing_values.get("API_SERVER_KEY"):
            values["API_SERVER_KEY"] = api_server_key
    runtime_env_updates = {
        "OPENCLAW_RUNTIME_FAMILY": family,
        "OPENCLAW_GATEWAY_PORT": str(gateway_port),
        "OPENCLAW_BRIDGE_PORT": str(bridge_port),
    }
    if api_server_key:
        runtime_env_updates["API_SERVER_KEY"] = api_server_key
    if family == "openclaw":
        openclaw_env_updates = dict(values)
        openclaw_env_updates.update(runtime_env_updates)
        _write_owned_text(
            profile_secret_path,
            render_upserted_secret_env(existing_text, openclaw_env_updates),
            0o600,
            slot_uid,
            slot_gid,
        )
    else:
        if values:
            _write_owned_text(
                profile_secret_path,
                render_upserted_secret_env(existing_text, values),
                0o600,
                runtime_uid,
                data_gid,
            )
        elif not profile_secret_path.exists():
            _write_owned_text(profile_secret_path, "", 0o600, runtime_uid, data_gid)
        upsert_runtime_env_file(runtime_dir / ".env", runtime_env_updates, slot_uid, slot_gid)

    config_status = "not_cloned"
    if clone_config_from:
        if family == "hermes":
            config = _read_hermes_config_from_slot(clone_config_from)
            _write_owned_text(hermes_dir / "config.yaml", dump_yaml(config), 0o600, runtime_uid, data_gid)
        else:
            config = _read_openclaw_config_from_slot(clone_config_from)
            _write_owned_text(
                openclaw_state_dir / "openclaw.json",
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                0o600,
                runtime_uid,
                data_gid,
            )
        config_status = "cloned"
    return ("present" if api_server_key else "not_applicable", config_status, "cloned" if clone_provider_secrets_from else "not_cloned")


def cmd_admin_create_image_dev(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl admin create-image-dev ...", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    target = str(args.target)
    try:
        linux_account = validate_linux_account(target)
        if not linux_account.startswith("dev-"):
            raise ValueError("image dev target must use a dev-* linux_account")
        public_host = validate_public_host(args.public_host)
        family = validate_family(args.family)
        gateway_port = int(args.gateway_port)
        bridge_port = int(args.bridge_port)
        if gateway_port < 1 or gateway_port > 65535 or bridge_port < 1 or bridge_port > 65535:
            raise ValueError("ports must be in 1..65535")
        if gateway_port == bridge_port:
            raise ValueError("gateway_port and bridge_port must differ")
        binding = RuntimeBinding(
            instance_id=validate_instance_id(getattr(args, "instance_id", "")),
            linux_account=linux_account,
            public_host=public_host,
            family=family,
            runtime_class="customer",
            gateway_port=gateway_port,
            bridge_port=bridge_port,
            enabled=True,
        )
        bindings = load_runtime_bindings(state_root)
        existing_binding = next((item for item in bindings if item.linux_account == linux_account), None)
        if existing_binding is not None:
            mismatches = []
            for field in ("public_host", "family", "runtime_class", "gateway_port", "bridge_port", "enabled"):
                if getattr(existing_binding, field) != getattr(binding, field):
                    mismatches.append(field)
            if mismatches:
                raise ValueError("existing image dev binding mismatch: " + ",".join(mismatches))
            binding = existing_binding
            binding_status = "exists"
        else:
            bindings.append(binding)
            binding_status = "created"
        # Validate uniqueness before mutating host state.
        from ..routing import dump_runtime_bindings

        dump_runtime_bindings(bindings)
        slot_group_status = _ensure_group(linux_account)
        runtime_group = f"{linux_account}_rt"
        data_group = f"{linux_account}_data"
        runtime_group_status = _ensure_group(runtime_group, system=True)
        data_group_status = _ensure_group(data_group)
        slot_user_status = _ensure_user(
            linux_account,
            primary_group=linux_account,
            home=f"/home/{linux_account}",
            shell="/bin/sh",
            create_home=True,
        )
        runtime_user_status = _ensure_user(
            runtime_group,
            primary_group=runtime_group,
            home="/nonexistent",
            shell="/usr/sbin/nologin",
            system=True,
        )
        _ensure_customer_data_membership(linux_account, data_group)
        _ensure_runtime_membership(runtime_group, data_group)
        secret_status, config_status, provider_secret_status = _ensure_target_dirs_and_secrets(
            linux_account,
            family=family,
            gateway_port=gateway_port,
            bridge_port=bridge_port,
            clone_config_from=getattr(args, "clone_config_from", None),
            clone_provider_secrets_from=getattr(args, "clone_provider_secrets_from", None),
            state_root=state_root,
        )
        apache_path, apache_status = _ensure_apache_route(binding)
        bindings_path = (
            _write_runtime_bindings_file(state_root, bindings)
            if binding_status == "created"
            else state_root / "runtime-bindings.json"
        )
    except Exception as exc:
        print(f"target={target}")
        print("admin_create_image_dev_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={linux_account}")
    print("runtime_class=customer")
    print("profile_mode=image")
    print(f"family={family}")
    print(f"public_host={public_host}")
    print(f"gateway_port={gateway_port}")
    print(f"bridge_port={bridge_port}")
    print(f"binding={binding_status}")
    print(f"slot_group={slot_group_status}")
    print(f"runtime_group={runtime_group_status}")
    print(f"data_group={data_group_status}")
    print(f"slot_user={slot_user_status}")
    print(f"runtime_user={runtime_user_status}")
    print(f"api_server_key={secret_status}")
    print(f"provider_config={config_status}")
    print(f"provider_secrets={provider_secret_status}")
    print("secret_value_printed=no")
    print(f"runtime_bindings={bindings_path}")
    print(f"apache_file={apache_path}")
    print(f"created_at={datetime.now(timezone.utc).astimezone().isoformat()}")
    print("admin_create_image_dev_status=ok")
    return 0
