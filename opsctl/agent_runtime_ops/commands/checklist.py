from __future__ import annotations

import argparse
import json
import shutil
import sys

from ..domain.common import check_line as _check_line
from ..domain.common import is_root as _is_root
from ..domain.common import run_text as _run_text
from ..domain.common import state_root as _state_root
from ..domain.runtime_checks import run_live_slot_checks as _run_live_slot_checks
from ..domain.runtime_targets import desired_from_live_image_truth as _desired_from_live_image_truth
from ..domain.runtime_truth import find_gateway_container
from ..runtime_secrets import parse_secret_env_text, primary_profile_secret_file
from ..commands.runtime_config import _current_model, _hermes_config_path, _read_config


HERMES_RUNTIME_REQUIRED_CHECKS = {
    "live_internal_http_dashboard_ok",
    "live_internal_http_gateway_ok",
    "live_internal_http_workspace_ok",
    "live_workspace_node_process_present",
    "live_workspace_node_uid_not_default_10000",
    "live_workspace_node_gid_not_default_10000",
    "live_workspace_node_uid_matches_slot",
    "live_workspace_node_gid_matches_slot",
    "live_workspace_node_groups_include_data_gid",
    "live_container_nas_docs_listing_ok",
    "live_workspace_user_nas_docs_listing_ok",
    "live_workspace_api_status_ok",
    "live_workspace_files_root_listing_ok",
    "live_workspace_files_nas_docs_listing_ok",
}


def _provider_state_checks(desired, profile) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    try:
        config_path = _hermes_config_path(desired.slot)
        config = _read_config(config_path)
        provider, model, source = _current_model(config)
        checks.extend(
            [
                (bool(provider), "checklist_provider_configured", f"provider={provider or 'missing'} source={source}"),
                (bool(model), "checklist_model_configured", f"model={model or 'missing'} source={source}"),
            ]
        )
    except Exception as exc:
        checks.extend(
            [
                (False, "checklist_provider_configured", str(exc)),
                (False, "checklist_model_configured", str(exc)),
            ]
        )
        provider = ""
    try:
        secret_file = primary_profile_secret_file(profile, desired.slot)
        values = parse_secret_env_text(secret_file.path.read_text(encoding="utf-8", errors="replace"), source=str(secret_file.path))
        checks.append((bool(values.get("API_SERVER_KEY")), "checklist_api_server_key_present", "secret_value_printed=no"))
        provider_name = str(provider or "").lower()
        if provider_name in {"google", "gemini"} or "gemini" in provider_name:
            gemini_present = bool(values.get("GEMINI_API_KEY") or values.get("GOOGLE_API_KEY"))
            checks.append((gemini_present, "checklist_gemini_secret_present", "secret_value_printed=no"))
    except Exception as exc:
        checks.append((False, "checklist_runtime_secret_file_readable", str(exc)))
    return checks


def _workspace_endpoint_checks(container: str, *, gemini_chat_smoke: bool) -> list[tuple[bool, str, str | None]]:
    script = r'''
const http = require('http');
const runChatSmoke = process.env.CHECKLIST_GEMINI_CHAT_SMOKE === '1';
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
    req.setTimeout(15000, () => req.destroy(new Error(`${method} ${path} timed out`)));
    if (body) req.write(body);
    req.end();
  });
}

function parseJson(label, response) {
  try {
    return JSON.parse(response.body || '{}');
  } catch {
    throw new Error(`${label} returned non-JSON status=${response.status}`);
  }
}

(async () => {
  const checks = [];
  let cookie = '';
  if (password) {
    const auth = await request('POST', '/api/auth', {'content-type': 'application/json'}, JSON.stringify({password}));
    if (auth.status !== 200) throw new Error(`/api/auth status=${auth.status}`);
    const setCookie = auth.headers['set-cookie'];
    cookie = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : String(setCookie || '').split(';')[0];
    if (!cookie) throw new Error('/api/auth missing cookie');
  }
  const headers = cookie ? {cookie} : {};

  const modelInfoRes = await request('GET', '/api/model/info', headers);
  const modelInfo = parseJson('/api/model/info', modelInfoRes);
  checks.push({
    name: 'checklist_model_info_ok',
    ok: modelInfoRes.status === 200 && !modelInfo.error,
    detail: `status=${modelInfoRes.status} gatewayMode=${modelInfo.gatewayMode || ''} error=${modelInfo.error || 'none'}`
  });

  const modelsRes = await request('GET', '/api/claude-proxy/v1/models', headers);
  const models = parseJson('/api/claude-proxy/v1/models', modelsRes);
  const hasModels = Array.isArray(models.data) || Array.isArray(models.models);
  checks.push({
    name: 'checklist_claude_proxy_models_ok',
    ok: modelsRes.status === 200 && hasModels,
    detail: `status=${modelsRes.status} models_array=${hasModels} error=${models.error || 'none'}`
  });

  if (!runChatSmoke) {
    checks.push({
      name: 'checklist_gemini_chat_smoke_skipped',
      ok: true,
      detail: 'not_requested'
    });
    console.log(JSON.stringify(checks));
    return;
  }

  const body = JSON.stringify({
    sessionKey: `ops-smoke-${Date.now()}`,
    message: 'Reply with exactly: OK',
    history: []
  });
  const chatRes = await request('POST', '/api/send-stream', {...headers, 'content-type': 'application/json'}, body);
  const chatOk = chatRes.status === 200 && (/event: (chunk|done)/.test(chatRes.body) || /data:/.test(chatRes.body));
  checks.push({
    name: 'checklist_gemini_chat_smoke_ok',
    ok: chatOk,
    detail: `status=${chatRes.status} stream_event=${chatOk}`
  });
  console.log(JSON.stringify(checks));
})().catch(error => {
  console.error(error.message);
  process.exit(1);
});
'''
    names = [
        "checklist_model_info_ok",
        "checklist_claude_proxy_models_ok",
        "checklist_gemini_chat_smoke_ok" if gemini_chat_smoke else "checklist_gemini_chat_smoke_skipped",
    ]
    argv = ["docker", "exec"]
    if gemini_chat_smoke:
        argv.extend(["-e", "CHECKLIST_GEMINI_CHAT_SMOKE=1"])
    argv.extend([container, "node", "-e", script])
    proc = _run_text(argv, timeout=120 if gemini_chat_smoke else 30)
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
            if name in names:
                seen.add(name)
                checks.append((bool(item.get("ok")), name, str(item.get("detail") or "")))
    for name in names:
        if name not in seen:
            checks.append((False, name, "missing_result"))
    return checks


def _hermes_runtime_pack_checks(desired, profile, *, gemini_chat_smoke: bool) -> list[tuple[bool, str, str | None]]:
    checks: list[tuple[bool, str, str | None]] = []
    checks.extend(_provider_state_checks(desired, profile))
    docker = shutil.which("docker")
    checks.append((bool(docker), "checklist_docker_cli_available", docker))
    if not docker:
        return checks
    container, lookup = find_gateway_container(desired.route, profile)
    checks.append((bool(container), "checklist_container_lookup", lookup))
    if not container:
        return checks
    checks.extend(_workspace_endpoint_checks(container, gemini_chat_smoke=gemini_chat_smoke))
    return checks


def cmd_checklist_pack(args: argparse.Namespace) -> int:
    if not _is_root():
        print("error: run as root/admin: sudo /usr/local/bin/opsctl checklist pack TARGET", file=sys.stderr)
        return 2
    state_root = _state_root(args)
    try:
        desired, profile = _desired_from_live_image_truth(args.slot, state_root)
        if desired.family != "hermes":
            raise ValueError(f"checklist pack is only supported for hermes targets: family={desired.family}")
        checks = list(_run_live_slot_checks(desired, profile, state_root))
        seen = {name for _ok, name, _detail in checks}
        for name in sorted(HERMES_RUNTIME_REQUIRED_CHECKS - seen):
            checks.append((False, name, "missing_from_live_check"))
        checks.extend(
            _hermes_runtime_pack_checks(
                desired,
                profile,
                gemini_chat_smoke=bool(getattr(args, "gemini_chat_smoke", False)),
            )
        )
    except Exception as exc:
        print(f"target={args.slot}")
        print("checklist_status=fail")
        print(f"reason={exc}")
        return 1

    print(f"target={desired.slot}")
    print(f"checklist_pack={args.pack}")
    print(f"runtime_profile={profile.name}")
    print(f"gemini_chat_smoke={'enabled' if getattr(args, 'gemini_chat_smoke', False) else 'not_run'}")
    failed = 0
    for ok, name, detail in checks:
        _check_line(ok, name, detail)
        if not ok:
            failed += 1
    print(f"checklist_status={'pass' if failed == 0 else 'fail'} failed={failed}")
    return 0 if failed == 0 else 1
