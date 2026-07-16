from __future__ import annotations

from collections.abc import Callable
import json
import re
import shlex
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..apache import parse_apache_route
from ..compose_contract import validate_compose_contract
from ..host.mounts import (
    findmnt_tree as _findmnt_tree,
    findmnt_under as _findmnt_under,
    is_readonly_mount as _is_readonly_mount,
    propagation_satisfies as _propagation_satisfies,
)
from ..host.account_files import runtime_ids
from ..host.fstab import read_managed_fstab_entries, read_managed_workspace_binds
from ..nas import (
    check_nas_policy,
    mountpoint_for_share,
    nas_rw_root,
    parse_cifs_mount_source,
    parse_smb_share,
    share_is_writable,
    workspace_root,
)
from ..routing import get_runtime_binding
from ..runtime_secrets import parse_secret_env_text
from ..yamlio import load_yaml
from .common import is_dev_slot, is_root, run_text
from .image_specs import (
    allowed_image_ref,
    digest_from_image_ref,
    has_digest_ref,
    image_spec_config_contract,
    image_spec_profile_contract_checks,
    image_spec_recipe,
    image_spec_selftest_contract,
)
from .runtime_truth import find_gateway_container, live_runtime_truth
from .selftest_contract import run_image_selftest_contract
from .config_contract import CONFIG_VALID_CHECK, run_config_validate_in_container
from .image_approval_policy import approved_image_digest


def http_backend_smoke(slot: str, path: str, state_root: Path) -> tuple[bool, str]:
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


def run_public_route_probe(slot: str, state_root: Path, *, path: str = "/readyz", port: int = 443) -> tuple[bool, str]:
    """Probe the public customer route (Apache front -> gateway) the product cannot self-attest.

    Connects to the local Apache TLS front over loopback with SNI/Host set to the
    binding's public_host, so it exercises the real customer vhost and ProxyPass to the
    gateway without depending on external DNS/egress. A 200 from the gateway readiness
    path proves the public edge actually serves the customer. This is the one piece a
    product self-test cannot attest, because the container cannot see Apache from inside.
    """
    import socket
    import ssl

    try:
        binding = get_runtime_binding(slot, state_root)
    except Exception as exc:
        return False, f"binding_truth_missing reason={exc}"
    host = binding.public_host
    if not host:
        return False, "public_host_missing"
    probe_path = path if path.startswith("/") else f"/{path}"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=8)
    except Exception as exc:
        return False, f"connect_failed host={host} port={port} reason={exc}"
    try:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            request = (
                f"GET {probe_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: opsctl-selftest\r\n"
                "Connection: close\r\n\r\n"
            )
            tls.sendall(request.encode("ascii"))
            data = b""
            while len(data) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    except Exception as exc:
        try:
            raw.close()
        except Exception:
            pass
        return False, f"tls_request_failed host={host} reason={exc}"
    status_line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = status_line.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    return status == 200, f"host={host} path={probe_path} status={status or 'none'}"


def _slot_hermes_config(slot: str) -> tuple[str, str]:
    path = Path("/home") / slot / ".hermes" / "config.yaml"
    try:
        data = load_yaml(path, default={})
    except Exception:
        return "", ""
    if not isinstance(data, dict):
        return "", ""
    provider = str(data.get("provider") or "").strip()
    model_value = data.get("model")
    if isinstance(model_value, dict):
        nested_provider = str(model_value.get("provider") or provider).strip()
        nested_model = str(model_value.get("default") or model_value.get("model") or "").strip()
        return nested_provider, nested_model
    if isinstance(model_value, str):
        return provider, model_value.strip()
    return provider, ""


def _handoff_password(slot: str, state_root: Path) -> str:
    path = state_root / "handoff" / f"hermes-workspace-{slot}.env"
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        values = parse_secret_env_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    except Exception:
        return ""
    return values.get("password", "")


def _existing_workspace_session_cookie(slot: str) -> str:
    path = Path("/home") / slot / ".hermes" / "workspace-sessions.json"
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return ""
    if not isinstance(payload, dict):
        return ""
    tokens = payload.get("tokens")
    if not isinstance(tokens, dict):
        return ""
    now_ms = int(time.time() * 1000)
    for token, expiry in tokens.items():
        if not isinstance(token, str) or not token:
            continue
        try:
            expiry_ms = int(expiry)
        except (TypeError, ValueError):
            continue
        if expiry_ms > now_ms:
            return f"claude-auth={token}"
    return ""


def workspace_hermes_config_api_checks(slot: str, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    try:
        binding = get_runtime_binding(slot, state_root)
    except Exception as exc:
        return [(False, "live_workspace_hermes_config_api_binding_ok", str(exc))]
    base = f"http://127.0.0.1:{binding.gateway_port}"
    session_cookie = _existing_workspace_session_cookie(binding.linux_account)
    if session_cookie:
        checks.append((True, "live_workspace_session_cookie_present", "secret_value_printed=no"))
    else:
        password = _handoff_password(binding.linux_account, state_root)
        checks.append((bool(password), "live_workspace_handoff_password_present", "secret_value_printed=no"))
        if not password:
            return checks

        auth_body = json.dumps({"password": password}).encode("utf-8")
        auth_request = urllib.request.Request(
            f"{base}/api/auth",
            data=auth_body,
            headers={
                "Host": binding.public_host,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(auth_request, timeout=8) as response:
                status = int(response.getcode())
                cookie = response.headers.get("Set-Cookie", "")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            cookie = ""
        except Exception as exc:
            checks.append((False, "live_workspace_auth_login_ok", f"reason={exc}"))
            return checks

        session_cookie = cookie.split(";", 1)[0].strip()
        checks.append((status == 200 and session_cookie.startswith("claude-auth="), "live_workspace_auth_login_ok", f"status={status}"))
    if not session_cookie.startswith("claude-auth="):
        return checks

    config_request = urllib.request.Request(
        f"{base}/api/hermes-config",
        headers={
            "Host": binding.public_host,
            "Cookie": session_cookie,
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(config_request, timeout=8) as response:
            config_status = int(response.getcode())
            raw = response.read(128 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        config_status = int(exc.code)
        raw = exc.read(4096).decode("utf-8", errors="replace")
    except Exception as exc:
        checks.append((False, "live_workspace_hermes_config_api_ok", f"reason={exc}"))
        return checks

    try:
        payload = json.loads(raw)
    except Exception as exc:
        checks.append((False, "live_workspace_hermes_config_api_json_ok", f"status={config_status} reason={exc}"))
        return checks
    active_provider = str(payload.get("activeProvider") or "")
    active_model = str(payload.get("activeModel") or "")
    expected_provider, expected_model = _slot_hermes_config(binding.linux_account)
    checks.append(
        (
            config_status == 200 and payload.get("ok") is True,
            "live_workspace_hermes_config_api_ok",
            f"status={config_status} provider={active_provider or 'missing'} model={active_model or 'missing'}",
        )
    )
    if expected_model:
        checks.append(
            (
                active_model == expected_model,
                "live_workspace_hermes_config_model_matches_file",
                f"api={active_model or 'missing'} file={expected_model}",
            )
        )
    if expected_provider:
        provider_matches = active_provider == expected_provider or {active_provider, expected_provider} == {"google", "gemini"}
        checks.append(
            (
                provider_matches,
                "live_workspace_hermes_config_provider_matches_file",
                f"api={active_provider or 'missing'} file={expected_provider}",
            )
        )
    if "gemini" in expected_model.lower() or expected_provider in {"google", "gemini"}:
        providers = payload.get("providers")
        google = None
        if isinstance(providers, list):
            for item in providers:
                if isinstance(item, dict) and item.get("id") == "google":
                    google = item
                    break
        configured = bool(google and google.get("configured") is True and google.get("authenticated") is True)
        checks.append(
            (
                configured,
                "live_workspace_google_gemini_configured",
                f"provider=google configured={str(bool(google and google.get('configured'))).lower()} authenticated={str(bool(google and google.get('authenticated'))).lower()}",
            )
        )
    return checks


def contract_health_endpoints(desired, profile) -> dict[str, str]:
    image_recipe = image_spec_recipe(desired.image_spec)
    endpoints = image_recipe.get("health_endpoints")
    if isinstance(endpoints, dict):
        return {str(key): str(value) for key, value in endpoints.items() if str(key) and str(value)}
    profile_endpoints = profile.metadata.get("required_internal_http")
    if isinstance(profile_endpoints, dict):
        return {str(key): str(value) for key, value in profile_endpoints.items() if str(key) and str(value)}
    return {}


def internal_http_check_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip().lower()).strip("_")
    return safe or "endpoint"


def run_internal_http_check(nsenter: str, pid: int, name: str, url: str) -> tuple[bool, str, str]:
    check_name = f"live_internal_http_{internal_http_check_name(name)}_ok"
    curl = shutil.which("curl")
    if not curl:
        return False, check_name, "curl_missing"
    proc = run_text([nsenter, "-t", str(pid), "-n", curl, "-fsS", "--max-time", "5", url], timeout=8)
    if proc.returncode == 0:
        return True, check_name, f"url={url}"
    detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
    return False, check_name, f"url={url} error={detail[:160]}"


def run_workspace_node_checks(container: str, slot: str) -> list[tuple[bool, str, str | None]]:
    script = r'''
      node_pid="$(pgrep -f "node .*server-entry[.]js" 2>/dev/null | head -n1 || true)"
      if [ -z "$node_pid" ]; then
        node_pid="$(ps -eo pid=,args= 2>/dev/null | awk '/node .*server-entry[.]js/ {print $1; exit}')"
      fi
      test -n "$node_pid"

      uid="$(awk "/^Uid:/ {print \$2}" /proc/"$node_pid"/status)"
      gid="$(awk "/^Gid:/ {print \$2}" /proc/"$node_pid"/status)"
      groups="$(awk "/^Groups:/ {for (i=2; i<=NF; i++) printf \"%s%s\", (i == 2 ? \"\" : \",\"), \$i}" /proc/"$node_pid"/status)"
      printf "%s %s %s %s\n" "$node_pid" "$uid" "$gid" "$groups"
    '''
    proc = run_text(["docker", "exec", container, "sh", "-lc", script], timeout=10)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        return [(False, "live_workspace_node_process_present", detail[:200])]

    parts = proc.stdout.strip().split()
    if len(parts) < 3:
        return [(False, "live_workspace_node_process_present", f"unparseable_output={proc.stdout.strip()[:120]}")]

    node_pid, uid_text, gid_text = parts[:3]
    groups_text = parts[3] if len(parts) >= 4 else ""
    group_ids = {item for item in groups_text.split(",") if item}
    checks: list[tuple[bool, str, str | None]] = [
        (True, "live_workspace_node_process_present", f"pid={node_pid}"),
        (uid_text != "10000", "live_workspace_node_uid_not_default_10000", f"uid={uid_text}"),
        (gid_text != "10000", "live_workspace_node_gid_not_default_10000", f"gid={gid_text}"),
    ]
    try:
        expected_uid, expected_gid, data_gid = runtime_ids(slot)
        checks.extend(
            [
                (
                    uid_text == str(expected_uid),
                    "live_workspace_node_uid_matches_slot",
                    f"actual={uid_text} expected={expected_uid}",
                ),
                (
                    gid_text == str(expected_gid),
                    "live_workspace_node_gid_matches_slot",
                    f"actual={gid_text} expected={expected_gid}",
                ),
                (
                    str(data_gid) in group_ids,
                    "live_workspace_node_groups_include_data_gid",
                    f"groups={groups_text or 'none'} expected={data_gid}",
                ),
            ]
        )
    except Exception as exc:
        checks.append((False, "live_slot_runtime_ids_read_ok", str(exc)))
    return checks


def run_container_nas_docs_listing_check(container: str, container_nas_root: str) -> tuple[bool, str, str | None]:
    script = f'root={shlex.quote(container_nas_root)}; test -d "$root" && ls -la "$root" >/dev/null'
    proc = run_text(["docker", "exec", container, "sh", "-lc", script], timeout=15)
    if proc.returncode == 0:
        return True, "live_container_nas_docs_listing_ok", container_nas_root
    detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
    return False, "live_container_nas_docs_listing_ok", f"path={container_nas_root} error={detail[:160]}"


def run_workspace_user_nas_docs_listing_check(
    container: str,
    container_nas_root: str,
    *,
    runtime_user_mode: str = "image-managed",
    slot: str = "",
) -> tuple[bool, str, str | None]:
    quoted_root = shlex.quote(container_nas_root)
    if runtime_user_mode == "compose":
        try:
            uid, gid, _ = runtime_ids(slot)
        except Exception as exc:
            return False, "live_workspace_user_nas_docs_listing_ok", f"slot={slot} runtime_ids_error={exc}"
        script = f'root={quoted_root}; test -d "$root" && ls -la "$root" >/dev/null'
        proc = run_text(["docker", "exec", "--user", f"{uid}:{gid}", container, "sh", "-lc", script], timeout=15)
        if proc.returncode == 0:
            return True, "live_workspace_user_nas_docs_listing_ok", container_nas_root
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        return False, "live_workspace_user_nas_docs_listing_ok", f"path={container_nas_root} user={uid}:{gid} error={detail[:160]}"
    if runtime_user_mode != "image-managed":
        return False, "live_workspace_user_nas_docs_listing_ok", f"unsupported_runtime_user_mode={runtime_user_mode}"
    script = f'''
      root={quoted_root}
      if command -v s6-setuidgid >/dev/null 2>&1; then
        exec s6-setuidgid hermes sh -lc 'test -d "$1" && ls -la "$1" >/dev/null' sh "$root"
      fi
      if command -v runuser >/dev/null 2>&1; then
        exec runuser -u hermes -- sh -lc 'test -d "$1" && ls -la "$1" >/dev/null' sh "$root"
      fi
      echo "no supported setuid helper found" >&2
      exit 127
    '''
    proc = run_text(["docker", "exec", container, "sh", "-lc", script], timeout=15)
    if proc.returncode == 0:
        return True, "live_workspace_user_nas_docs_listing_ok", container_nas_root
    detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
    return False, "live_workspace_user_nas_docs_listing_ok", f"path={container_nas_root} error={detail[:160]}"


def run_workspace_api_smoke_checks(container: str) -> list[tuple[bool, str, str | None]]:
    script = r'''
const http = require('http');
const password = process.env.HERMES_PASSWORD || process.env.CLAUDE_PASSWORD || '';

function request(method, path, headers = {}, body = '') {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: 3000, method, path, headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error(`${method} ${path} timed out`)));
    if (body) req.write(body);
    req.end();
  });
}

function parseJson(label, response) {
  try {
    return JSON.parse(response.body);
  } catch {
    throw new Error(`${label} returned non-JSON status=${response.status}`);
  }
}

(async () => {
  let cookie = '';
  if (password) {
    const auth = await request('POST', '/api/auth', {'content-type': 'application/json'}, JSON.stringify({password}));
    if (auth.status !== 200) throw new Error(`/api/auth status=${auth.status}`);
    const setCookie = auth.headers['set-cookie'];
    cookie = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : String(setCookie || '').split(';')[0];
    if (!cookie) throw new Error('/api/auth missing cookie');
  }
  const headers = cookie ? {cookie} : {};

  const workspaceRes = await request('GET', '/api/workspace', headers);
  const workspace = parseJson('/api/workspace', workspaceRes);
  const rootRes = await request('GET', '/api/files?action=list', headers);
  const root = parseJson('/api/files?action=list', rootRes);
  const nasRes = await request('GET', '/api/files?path=nas_docs', headers);
  const nas = parseJson('/api/files?path=nas_docs', nasRes);

  const checks = [
    {
      name: 'live_workspace_api_status_ok',
      ok: workspaceRes.status === 200 && workspace.isValid === true && workspace.path === '/workspace' && workspace.source === 'env',
      detail: `status=${workspaceRes.status} isValid=${workspace.isValid} path=${workspace.path || ''} source=${workspace.source || ''}`,
    },
    {
      name: 'live_workspace_files_root_listing_ok',
      ok: rootRes.status === 200 && !root.error && Array.isArray(root.entries),
      detail: `status=${rootRes.status} entries_array=${Array.isArray(root.entries)} error=${root.error || 'none'}`,
    },
    {
      name: 'live_workspace_files_nas_docs_listing_ok',
      ok: nasRes.status === 200 && nas.root === 'nas_docs' && !nas.error && Array.isArray(nas.entries),
      detail: `status=${nasRes.status} root=${nas.root || ''} entries_array=${Array.isArray(nas.entries)} error=${nas.error || 'none'}`,
    },
  ];
  console.log(JSON.stringify(checks));
})().catch(error => {
  console.error(error.message);
  process.exit(1);
});
    '''
    names = [
        "live_workspace_api_status_ok",
        "live_workspace_files_root_listing_ok",
        "live_workspace_files_nas_docs_listing_ok",
    ]
    proc = run_text(["docker", "exec", container, "node", "-e", script], timeout=20)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip() or f"returncode={proc.returncode}"
        return [(False, name, detail[:200]) for name in names]
    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:
        return [(False, name, f"parse_failed:{exc}") for name in names]
    checks: list[tuple[bool, str, str | None]] = []
    seen: set[str] = set()
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if name not in names:
                continue
            seen.add(name)
            checks.append((bool(item.get("ok")), name, str(item.get("detail") or "")))
    for name in names:
        if name not in seen:
            checks.append((False, name, "missing_result"))
    return checks


def _child_cifs_mode_ok(rows: list[dict[str, str]], *, ro_always_ok: bool = False) -> tuple[bool, str]:
    """Each child CIFS mount must respect the mode its share class dictates.

    OCn artifact shares mount read-write (``share_is_writable`` — the single
    rule shared with fstab/mount emission in #22); every other customer-data
    share (kakao-work, hanpass_groupware, kakao views, …) stays ro-enforced.
    Keying on the share name makes this host-agnostic, so the same OCn share
    is writable on the old NAS and the new one during the migration. An
    unparseable source falls back to ro-required (safe default).

    Two judgments share this code (#28):
    - host side (``ro_always_ok=False``): exact match — the host mount must be
      in its class's mode, so OCn-as-ro and customer-as-rw both read unhealthy.
    - container side (``ro_always_ok=True``): ceiling match — the container's
      nas_docs bind is deliberately read-only (its own gate,
      live_container_nas_root_readonly), so host=rw ↔ container=ro is a normal
      combination and ro is always acceptable. What must never happen is the
      container seeing MORE writability than the share class grants: rw is a
      violation unless the class is writable.

    Returns ``(ok, detail)`` — ``detail`` names any offending mount so the
    verdict is legible in the one check line.
    """
    mismatches: list[str] = []
    ro = rw = 0
    for row in rows:
        source = row.get("source") or ""
        try:
            share, _subpath = parse_cifs_mount_source(source)
            want_rw = share_is_writable(share)
        except ValueError:
            want_rw = False
        is_ro = _is_readonly_mount(row)
        if is_ro:
            ro += 1
        else:
            rw += 1
        if is_ro and ro_always_ok:
            continue
        if is_ro == want_rw:
            mismatches.append(f"{source}:{'ro' if is_ro else 'rw'}!={'rw' if want_rw else 'ro'}")
    if mismatches:
        return False, f"count={len(rows)} mismatch={','.join(mismatches)}"
    return True, f"count={len(rows)} ro={ro} rw={rw}"


def _workspace_bind_stamp_ok(binds: list[dict[str, str]], slot: str) -> tuple[bool, str]:
    """The stamped workspace bind must point FROM a nas_rw mount TO the
    workspace — anything else recreates a wrong view at boot."""
    drift: list[str] = []
    mine = [bind for bind in binds if bind.get("slot") == slot]
    expected_target = workspace_root(slot).as_posix()
    rw_prefix = nas_rw_root(slot).as_posix() + "/"
    for bind in mine:
        target = bind.get("target") or ""
        source = bind.get("source") or ""
        if target != expected_target:
            drift.append(f"bind_target={target}!={expected_target}")
        if not source.startswith(rw_prefix):
            drift.append(f"bind_source_outside_nas_rw={source}")
    if drift:
        return False, f"binds={len(mine)} drift={','.join(drift)}"
    return True, f"binds={len(mine)}"


def _fstab_stamp_drift_ok(entries: list[dict[str, str]], slot: str) -> tuple[bool, str]:
    """The Q4 invariant, mechanized: a managed fstab entry is a STAMP of what
    the derivation code output when it was written. If the derivation changes
    and nobody migrates the stamps, boot recreates the old world (the OCn
    freeze zombie). This compares every stamp for the slot against what the
    tool would write TODAY, so a derivation change turns red on its own
    instead of living in someone's memory.

    Hard failures:
    - unparseable marker source (a stamp we cannot interpret is drift)
    - writable class (OCn): stamped mountpoint != today's derivation, or ro
    - ro class (corpus): stamped rw, or credential under /home/ (the
      customer-readable vault violation)
    Reported but NOT failed: ro-class placement differing from the canonical
    derivation — ro stamps from other lanes may legitimately live elsewhere;
    an unmeasured red is worse than a named note.
    """
    drift: list[str] = []
    notes: list[str] = []
    mine = [entry for entry in entries if entry.get("slot") == slot]
    for entry in mine:
        source = entry.get("source") or ""
        try:
            share = parse_smb_share(source)
        except ValueError:
            drift.append(f"{source}:unparseable_source")
            continue
        expected = mountpoint_for_share(slot, share).as_posix()
        stamped = entry.get("mountpoint") or ""
        if share_is_writable(share):
            if stamped != expected:
                drift.append(f"{source}:mountpoint={stamped}!={expected}")
            if entry.get("access") != "rw":
                drift.append(f"{source}:access={entry.get('access')}!=rw")
        else:
            if entry.get("access") != "ro":
                drift.append(f"{source}:access={entry.get('access')}!=ro")
            credentials = entry.get("credentials") or ""
            if credentials.startswith("/home/"):
                drift.append(f"{source}:credentials_under_home={credentials}")
            if stamped != expected:
                notes.append(f"{source}:placement={stamped}")
    if drift:
        return False, f"entries={len(mine)} drift={','.join(drift)}"
    detail = f"entries={len(mine)}"
    if notes:
        detail += f" placement_notes={','.join(notes)}"
    return True, detail


def _workspace_cifs_floor_ok(
    host_rows: list[dict[str, str]],
    container_rows: list[dict[str, str]] | None,
) -> tuple[bool, str]:
    """The workspace FLOOR: when the slot's OCn is mounted on the host, the
    container must see it AND be able to write it (per-mount rw).

    The ceiling judgment (``_child_cifs_mode_ok(ro_always_ok=True)``) can only
    say "never MORE writable than the class" — it tolerates a frozen (ro) OCn
    forever, which is how 17 slots sat frozen behind green checks (2026-07).
    This is the other half: never LESS writable than the intent.

    States (evaluated over cifs rows at/under the workspace root):
    - host absent                  -> ok (vacuous: slots without an OCn — oc1, dev)
    - host has any ro row          -> fail (rw is the class; host misconfig)
    - host rw, container unreadable-> fail (cannot prove the floor)
    - host rw, container absent    -> fail (bind missing / stale container)
    - host rw, container has ro    -> fail (the freeze class)
    - host rw, container rw        -> ok
    """
    if not host_rows:
        return True, "host=absent"
    host_ro = [row for row in host_rows if _is_readonly_mount(row)]
    if host_ro:
        return False, f"host_ro={','.join(row.get('target') or '?' for row in host_ro)}"
    if container_rows is None:
        return False, "host=rw container=unreadable"
    if not container_rows:
        return False, "host=rw container=absent"
    container_ro = [row for row in container_rows if _is_readonly_mount(row)]
    if container_ro:
        return False, f"host=rw container_ro={','.join(row.get('target') or '?' for row in container_ro)}"
    return True, f"host=rw container=rw count={len(container_rows)}"


def run_live_slot_checks(desired, profile, state_root: Path) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    if not is_root():
        return [(False, "live_check_requires_root", "run as root/admin or a restricted root helper")]

    binding = get_runtime_binding(desired.slot, state_root)
    container, container_lookup = find_gateway_container(binding, profile)
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

    inspect = run_text(["docker", "inspect", container])
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
        truth, truth_checks = live_runtime_truth(desired.slot, state_root)
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
        smoke_ok, smoke_detail = http_backend_smoke(desired.slot, smoke_path, state_root)
        checks.append((smoke_ok, "live_backend_http_smoke_ok", smoke_detail))

    for endpoint_name, endpoint_url in contract_health_endpoints(desired, profile).items():
        checks.append(run_internal_http_check(nsenter, pid, endpoint_name, endpoint_url))

    if str(profile.metadata.get("family") or "") == "hermes":
        checks.extend(run_workspace_node_checks(container, desired.slot))
        checks.extend(run_workspace_api_smoke_checks(container))
        checks.extend(workspace_hermes_config_api_checks(desired.slot, state_root))

    # Product-attested customer-truth: when the wrapper image declares a verified
    # selftest contract, invoke the in-image selftest and gate on its required checks,
    # then probe the public route the product cannot see from inside. Gated on the
    # contract so families without one (today: hermes) are unaffected.
    selftest_contract = image_spec_selftest_contract(desired.image_spec)
    if selftest_contract:
        checks.extend(run_image_selftest_contract(container, selftest_contract))
        public_path = str(profile.metadata.get("public_route_probe_path") or "/readyz")
        public_ok, public_detail = run_public_route_probe(desired.slot, state_root, path=public_path)
        checks.append((public_ok, "live_public_route_readyz_ok", public_detail))

    # Config drift detection: validate the on-disk config against the image this
    # container is actually running. A config that has drifted out of schema for its own
    # image is a latent crash-on-restart (the running process holds the old config in
    # memory) — this surfaces it before any restart, not after. Gated on the contract.
    config_contract = image_spec_config_contract(desired.image_spec)
    if config_contract:
        cfg_ok, cfg_detail = run_config_validate_in_container(container, config_contract)
        checks.append((cfg_ok, CONFIG_VALID_CHECK, cfg_detail))

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
        host_mode_ok, host_mode_detail = _child_cifs_mode_ok(host_cifs)
        checks.append((host_mode_ok, "live_host_child_cifs_readonly", host_mode_detail))

    if not container_nas_root:
        checks.append((False, "live_container_nas_root_configured", None))
        return checks

    checks.append(run_container_nas_docs_listing_check(container, container_nas_root))
    checks.append(
        run_workspace_user_nas_docs_listing_check(
            container,
            container_nas_root,
            runtime_user_mode=runtime_user_mode,
            slot=desired.slot,
        )
    )

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
        container_mode_ok, container_mode_detail = _child_cifs_mode_ok(container_cifs, ro_always_ok=True)
        checks.append((container_mode_ok, "live_container_child_cifs_readonly", container_mode_detail))

    # Workspace floor: the OCn own-folder mounts OUTSIDE nas_docs (flat at
    # {home}/workspace), so none of the nas_docs checks above ever see it.
    # Always emitted under one name so it can sit in the required sets: vacuous
    # pass when the host has no OCn (oc1, dev slots), hard floor once it does.
    host_workspace_root = f"{target_home}/workspace"
    container_workspace_root = str(profile.metadata.get("container_workspace_root") or "")
    ws_host_rc, _, ws_host_rows = _findmnt_under(host_workspace_root)
    ws_host_cifs = [row for row in ws_host_rows if row.get("fstype") == "cifs"] if ws_host_rc == 0 else []
    ws_container_cifs: list[dict[str, str]] | None
    if not ws_host_cifs:
        ws_container_cifs = []
    elif not container_workspace_root:
        ws_container_cifs = None  # cannot locate it in the container -> floor fails loud
    else:
        ws_rc, _, ws_container_mounts = _findmnt_tree(container_workspace_root, container_pid=pid)
        ws_container_cifs = (
            [row for row in ws_container_mounts if row.get("fstype") == "cifs"] if ws_rc == 0 else None
        )
    ws_ok, ws_detail = _workspace_cifs_floor_ok(ws_host_cifs, ws_container_cifs)
    if ws_host_cifs and not container_workspace_root:
        ws_detail = "missing_container_workspace_root"
    checks.append((ws_ok, "live_workspace_cifs_floor_ok", ws_detail))

    # Stamp-vs-derivation drift: boot replays /etc/fstab, so a stamped entry
    # that today's derivation would write differently is a zombie waiting for
    # the next reboot. Always emitted; entries=0 slots pass vacuously.
    try:
        drift_ok, drift_detail = _fstab_stamp_drift_ok(read_managed_fstab_entries(), desired.slot)
        bind_ok, bind_detail = _workspace_bind_stamp_ok(read_managed_workspace_binds(), desired.slot)
        drift_ok = drift_ok and bind_ok
        drift_detail = f"{drift_detail} {bind_detail}"
    except Exception as exc:
        drift_ok, drift_detail = False, f"fstab_read_failed={exc}"
    checks.append((drift_ok, "live_fstab_stamp_matches_derivation", drift_detail))

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


def run_static_slot_checks(
    desired, profile, rendered=None, *, state_root: Path | None = None
) -> list[tuple[bool, str, str | None]]:
    target_family = desired.family
    runtime_class = desired.runtime_class
    profile_family = profile.metadata.get("family")
    profile_runtime_class = profile.metadata.get("slot_class")
    profile_mode = profile.metadata.get("mode")
    image_family = desired.image_spec.get("family")
    wrapper_image = desired.image_spec.get("wrapper_image")
    product_image = desired.image_spec.get("product_image")
    image_digest = desired.image_spec.get("digest")
    wrapper_digest = digest_from_image_ref(wrapper_image)
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
        (has_digest_ref(wrapper_image), "wrapper_image_pinned_by_digest", str(wrapper_image) if wrapper_image else None),
        (has_digest_ref(product_image), "product_image_pinned_by_digest", str(product_image) if product_image else None),
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
            allowed_image_ref(target_family, "wrapper", wrapper_image),
            "wrapper_image_repository_allowed",
            str(wrapper_image) if wrapper_image else None,
        ),
        (
            allowed_image_ref(target_family, "product", product_image),
            "product_image_repository_allowed",
            str(product_image) if product_image else None,
        ),
    ]
    # Root-approved-digest gate (commit-addressed image trust, like `update approve`).
    # Progressive: enforced for a family/role only once an approval exists for it, so
    # deploying this is non-breaking and you opt a family in by approving its digest.
    # Scoped to PRODUCTION customer slots only: customer-class AND not a dev-* account.
    # Root approval protects real customers; a dev-owned image-mode canary (dev-*-img) is
    # the developer's own validation slot, so it must be deployable/validated BEFORE root
    # approval (build -> validate on dev-*-img -> approve -> promote). dev-* is the same
    # production boundary `image-promote` already trusts (`_is_dev_named_target`).
    if state_root is not None and runtime_class == "customer" and not is_dev_slot(desired.slot):
        for role, role_image in (("product", product_image), ("wrapper", wrapper_image)):
            approved = approved_image_digest(state_root, target_family, role)
            if approved:
                live_digest = digest_from_image_ref(role_image)
                checks.append(
                    (
                        bool(live_digest) and live_digest == approved,
                        f"{role}_image_digest_approved",
                        f"live={live_digest or 'missing'} approved={approved}",
                    )
                )
    checks.extend(image_spec_profile_contract_checks(desired.image_spec, profile))

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


def run_live_slot_checks_with_wait(
    desired,
    profile,
    state_root: Path,
    timeout_seconds: int = 90,
    progress: Callable[[list[tuple[bool, str, str | None]]], None] | None = None,
) -> list[tuple[bool, str, str | None]]:
    deadline = time.monotonic() + timeout_seconds
    last_checks: list[tuple[bool, str, str | None]] = []
    wait_names = {
        "live_container_running",
        "live_container_pid_present",
        "live_container_health_ok",
        "live_backend_http_smoke_ok",
        "live_workspace_node_process_present",
        "live_container_nas_docs_listing_ok",
        "live_workspace_user_nas_docs_listing_ok",
        "live_workspace_api_status_ok",
        "live_workspace_files_root_listing_ok",
        "live_workspace_files_nas_docs_listing_ok",
    }
    while True:
        checks = run_live_slot_checks(desired, profile, state_root)
        last_checks = checks
        failed_names = {name for ok, name, _ in checks if not ok}
        if progress is not None:
            progress(checks)
        if not failed_names:
            return checks
        if not (failed_names & wait_names) and not any(name.startswith("live_internal_http_") for name in failed_names):
            return checks
        if time.monotonic() >= deadline:
            return checks
        time.sleep(5)


def profile_startup_timeout_seconds(profile) -> int:
    raw_value = profile.metadata.get("startup_timeout_seconds", 90)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return 90
    return max(30, min(value, 600))
