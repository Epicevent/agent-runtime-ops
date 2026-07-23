from __future__ import annotations

import json

from .common import run_text


def run_hermes_http_smoke(
    container: str, *, chat_smoke: bool, model_attest: bool = False
) -> list[tuple[bool, str, str | None]]:
    run_chat = chat_smoke or model_attest
    script = r'''
const http = require('http');
const runChatSmoke = process.env.HERMES_CHAT_SMOKE === '1';
const attestModel = process.env.HERMES_MODEL_ATTEST === '1';
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

  const configRes = await request('GET', '/api/hermes-config', headers);
  const config = parseJson('/api/hermes-config', configRes);
  checks.push({
    name: 'hermes_smoke_config_ok',
    ok: configRes.status === 200 && !config.error,
    detail: `status=${configRes.status} error=${config.error || 'none'}`
  });

  const modelInfoRes = await request('GET', '/api/model/info', headers);
  const modelInfo = parseJson('/api/model/info', modelInfoRes);
  checks.push({
    name: 'hermes_smoke_model_info_ok',
    ok: modelInfoRes.status === 200 && !modelInfo.error,
    detail: `status=${modelInfoRes.status} gatewayMode=${modelInfo.gatewayMode || ''} error=${modelInfo.error || 'none'}`
  });

  const modelsRes = await request('GET', '/api/claude-proxy/v1/models', headers);
  const models = parseJson('/api/claude-proxy/v1/models', modelsRes);
  const hasModels = Array.isArray(models.data) || Array.isArray(models.models);
  checks.push({
    name: 'hermes_smoke_claude_proxy_models_ok',
    ok: modelsRes.status === 200 && hasModels,
    detail: `status=${modelsRes.status} models_array=${hasModels} error=${models.error || 'none'}`
  });

  if (!runChatSmoke) {
    checks.push({
      name: 'hermes_smoke_chat_not_required',
      ok: true,
      detail: 'not_required'
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
    name: 'hermes_smoke_chat_ok',
    ok: chatOk,
    detail: `status=${chatRes.status} stream_event=${chatOk}`
  });
  if (attestModel) {
    const receipts = [];
    for (const line of chatRes.body.split(/\r?\n/)) {
      if (!line.startsWith('data:')) continue;
      const raw = line.slice(5).trim();
      if (!raw || raw === '[DONE]') continue;
      try { receipts.push(JSON.parse(raw)); } catch {}
    }
    const versions = [];
    function collect(value) {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) { for (const item of value) collect(item); return; }
      for (const [key, item] of Object.entries(value)) {
        if (key === 'modelVersion' && typeof item === 'string') versions.push(item);
        else collect(item);
      }
    }
    for (const receipt of receipts) collect(receipt);
    const configuredRaw = typeof config.model === 'string'
      ? config.model
      : ((config.model && config.model.default) || '');
    const configured = String(configuredRaw).replace(/^models\//, '');
    const normalized = [...new Set(versions.map(value => String(value).replace(/^models\//, '')))];
    const matched = configured && normalized.includes(configured);
    checks.push({
      name: 'hermes_smoke_model_attested',
      ok: Boolean(chatOk && matched),
      detail: `configured=${configured || 'missing'} receipt_model_versions=${normalized.length ? normalized.join(',') : 'missing'} source=provider_response_modelVersion`
    });
  }
  console.log(JSON.stringify(checks));
})().catch(error => {
  console.error(error.message);
  process.exit(1);
});
'''
    names = [
        "hermes_smoke_config_ok",
        "hermes_smoke_model_info_ok",
        "hermes_smoke_claude_proxy_models_ok",
        "hermes_smoke_chat_ok" if run_chat else "hermes_smoke_chat_not_required",
    ]
    if model_attest:
        names.append("hermes_smoke_model_attested")
    argv = ["docker", "exec"]
    if run_chat:
        argv.extend(["-e", "HERMES_CHAT_SMOKE=1"])
    if model_attest:
        argv.extend(["-e", "HERMES_MODEL_ATTEST=1"])
    argv.extend([container, "node", "-e", script])
    proc = run_text(argv, timeout=120 if run_chat else 30)
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
