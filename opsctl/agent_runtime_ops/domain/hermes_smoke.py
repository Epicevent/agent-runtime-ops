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
  const chatContentType = String(chatRes.headers['content-type'] || '').toLowerCase();
  const chatOk = chatRes.status === 200 && chatContentType.includes('text/event-stream')
    && (/event: (chunk|done)/.test(chatRes.body) || /data:/.test(chatRes.body));
  checks.push({
    name: 'hermes_smoke_chat_ok',
    ok: chatOk,
    detail: `status=${chatRes.status} stream_event=${chatOk}`
  });
  if (attestModel) {
    const donePayloads = [];
    for (const record of chatRes.body.split(/\r?\n\r?\n/)) {
      let eventType = '';
      const dataLines = [];
      for (const line of record.split(/\r?\n/)) {
        if (line.startsWith('event:')) eventType = line.slice(6).trim();
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
      }
      const raw = dataLines.join('\n');
      if (eventType !== 'done' || !raw || raw === '[DONE]') continue;
      try { donePayloads.push(JSON.parse(raw)); } catch {}
    }
    function evidenceAtAllowedPointer(payload) {
      const evidence = payload && payload.providerModelEvidence;
      const receipt = payload && payload.providerReceipt;
      if (!evidence || typeof evidence !== 'object' || !receipt || typeof receipt !== 'object') return null;
      const usage = receipt.usageMetadata;
      const tokenCounts = usage && typeof usage === 'object'
        ? Object.values(usage).filter(item => Number.isInteger(item))
        : [];
      const configuredModel = typeof evidence.configuredModel === 'string'
        ? evidence.configuredModel.replace(/^models\//, '') : '';
      const actualModel = typeof evidence.actualModel === 'string'
        ? evidence.actualModel.replace(/^models\//, '') : '';
      const receiptModel = typeof receipt.modelVersion === 'string'
        ? receipt.modelVersion.replace(/^models\//, '') : '';
      return receipt.provider === 'gemini'
        && evidence.evidenceSource === 'gemini_response.modelVersion'
        && configuredModel && actualModel
        && typeof evidence.responseId === 'string' && evidence.responseId
        && receipt.responseId === evidence.responseId
        && receiptModel === actualModel
        && tokenCounts.length > 0
        && typeof receipt.finishReason === 'string' && receipt.finishReason
        ? {configuredModel, actualModel, evidenceSource: evidence.evidenceSource, responseId: evidence.responseId}
        : null;
    }
    const receipts = donePayloads.map(evidenceAtAllowedPointer).filter(Boolean);
    const configuredRaw = config.activeModel || (typeof config.model === 'string'
      ? config.model
      : ((config.model && config.model.default) || ''));
    const configured = String(configuredRaw).replace(/^models\//, '');
    const configuredProvider = String(config.activeProvider || config.provider || '').toLowerCase();
    const providerOk = configuredProvider === 'gemini' || configuredProvider === 'google';
    const requested = [...new Set(receipts.map(value => value.configuredModel))];
    const normalized = [...new Set(receipts.map(value => value.actualModel))];
    const responseIds = [...new Set(receipts.map(value => String(value.responseId)))];
    const evidenceSources = [...new Set(receipts.map(value => value.evidenceSource))];
    const actualRelation = normalized.length !== 1 ? 'unknown'
      : normalized[0] === configured ? 'exact'
      : normalized[0].startsWith(`${configured}-`) && /^\d{3,}$/.test(normalized[0].slice(configured.length + 1))
        ? 'provider_revision' : 'different';
    const matched = providerOk && configured && receipts.length === donePayloads.length
      && receipts.length > 0 && requested.length === 1 && requested[0] === configured
      && normalized.length === 1 && evidenceSources.length === 1
      && evidenceSources[0] === 'gemini_response.modelVersion'
      && (actualRelation === 'exact' || actualRelation === 'provider_revision');
    checks.push({
      name: 'hermes_smoke_model_attested',
      ok: Boolean(chatOk && matched),
      detail: `configured_provider=${configuredProvider || 'missing'} configured_model=${configured || 'missing'} done_events=${donePayloads.length} complete_provider_receipts=${receipts.length} evidence_requested_models=${requested.length ? requested.join(',') : 'missing'} receipt_model_versions=${normalized.length ? normalized.join(',') : 'missing'} actual_model_relation=${actualRelation} receipt_response_ids=${responseIds.length ? responseIds.join(',') : 'missing'} receipt_fields=responseId,modelVersion,usageMetadata,finishReason source=done_event_providerModelEvidence+providerReceipt evidence_source=${evidenceSources.length === 1 ? evidenceSources[0] : 'missing'}`
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
