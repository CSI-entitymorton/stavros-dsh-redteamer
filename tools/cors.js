#!/usr/bin/env node
// CORS misconfiguration checker (zero-dep, scope-guarded).
//   node tools/cors.js --url <u> [--origins "https://evil.example,null,https://trusted.example"]
//                       [--header "K: V"] [--method GET|POST] [--show-body]
// For each candidate origin it sends Origin (and for POST an OPTIONS preflight) and reports
// the Access-Control-* response headers + a verdict:
//   ok           -> no ACAO, or ACAO only for an allowlisted origin
//   reflected    -> ACAO echoes the attacker origin (misconfig if credentials allowed)
//   wildcard     -> ACAO: * (safe only when Access-Control-Allow-Credentials is absent)
//   null_origin  -> ACAO: null accepted (exploitable from sandboxed iframes when credentials)
// Verdict is CRITICAL when an untrusted/reflected/null origin is combined with
// Access-Control-Allow-Credentials: true.
const http = require('http');
const https = require('https');
const { loadScope, inScope } = require('./scope-guard');
const { wait } = require('./pace');

const TRUSTED_HINT = ['https://trusted.example', 'https://same-origin.example'];

function verdict(origin, acao, creds) {
  const trusted = TRUSTED_HINT.includes(origin);
  if (!acao) return { severity: 'info', message: 'no Access-Control-Allow-Origin header' };
  const acaoVal = Array.isArray(acao) ? acao[0] : acao;
  if (acaoVal === '*') {
    return creds
      ? { severity: 'high', message: 'ACAO:* WITH Access-Control-Allow-Credentials:true (invalid per spec)' }
      : { severity: 'low', message: 'ACAO:* without credentials (usually acceptable)' };
  }
  if (acaoVal === 'null') {
    return creds
      ? { severity: 'high', message: 'ACAO:null with credentials — exploitable from sandboxed iframe' }
      : { severity: 'medium', message: 'ACAO:null accepted' };
  }
  if (acaoVal === origin) {
    return creds
      ? { severity: 'critical', message: 'reflects attacker-controlled origin WITH credentials' }
      : { severity: 'medium', message: 'reflects arbitrary Origin header (no credentials)' };
  }
  if (trusted && acaoVal === origin) {
    return { severity: 'info', message: 'allowlisted origin echoed' };
  }
  return { severity: 'info', message: 'ACAO set to non-reflected value: ' + acaoVal };
}

function request(url, method, headers, timeoutMs) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const t0 = Date.now();
    let done = false;
    const fin = (r) => { if (!done) { done = true; resolve(r); } };
    const req = lib.request(url, { method, headers, timeout: timeoutMs }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => fin({ status: res.statusCode, headers: res.headers, body: d, ms: Date.now() - t0 }));
    });
    req.on('timeout', () => { req.destroy(); fin({ timeout: true, ms: Date.now() - t0 }); });
    req.on('error', (e) => fin({ error: e.message, ms: Date.now() - t0 }));
    req.end();
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const val = (name) => { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] != null ? argv[i + 1] : undefined; };
  const url = val('url');
  const origins = (val('origins') || 'https://evil.example,null,https://trusted.example').split(',');
  const method = val('method') || 'GET';
  const headers = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--header' && argv[i + 1]) headers.push(argv[i + 1]);
  const showBody = argv.includes('--show-body');
  const timeout = +val('timeout') || 10000;

  if (!url) {
    console.error('usage: node tools/cors.js --url <u> [--origins ...] [--method M] [--header "K: V"]');
    process.exit(2);
  }
  const scope = loadScope();
  const rps = Math.max(0.1, scope.max_requests_per_second || 2);
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }

  const baseHeaders = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0' };
  for (const h of headers) {
    const i = h.indexOf(':');
    if (i > 0) baseHeaders[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }

  const out = [];
  for (const origin of origins) {
    wait(rps);
    const r1 = await request(url, method, Object.assign({ Origin: origin }, baseHeaders), timeout);
    const acao = r1.headers && r1.headers['access-control-allow-origin'];
    const creds = (r1.headers && r1.headers['access-control-allow-credentials']) === 'true';
    let preflight = null;
    if (method !== 'GET' && method !== 'HEAD') {
      wait(rps);
      const r2 = await request(url, 'OPTIONS', Object.assign({
        Origin: origin,
        'Access-Control-Request-Method': method,
        'Access-Control-Request-Headers': 'authorization,content-type',
      }, baseHeaders), timeout);
      preflight = {
        status: r2.status,
        acao: r2.headers && r2.headers['access-control-allow-origin'] || null,
        methods: r2.headers && r2.headers['access-control-allow-methods'] || null,
        allow_headers: r2.headers && r2.headers['access-control-allow-headers'] || null,
        max_age: r2.headers && r2.headers['access-control-max-age'] || null,
      };
    }
    out.push({
      origin,
      status: r1.status,
      access_control_allow_origin: acao || null,
      access_control_allow_credentials: r1.headers && r1.headers['access-control-allow-credentials'] || null,
      preflight,
      verdict: verdict(origin, acao, creds),
      body: showBody && r1.body ? r1.body.slice(0, 2048) : undefined,
    });
  }
  console.log(JSON.stringify({ target: url, results: out }, null, 2));
}

module.exports = { verdict };
if (require.main === module) main();
