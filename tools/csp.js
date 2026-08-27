#!/usr/bin/env node
// CSP checker (zero-dep).
//   node tools/csp.js --url <u>          -> fetch page, read Content-Security-Policy header(s)
//   node tools/csp.js --header "policy"  -> analyze a policy string directly
//   node tools/csp.js --file <path>      -> analyze a saved raw policy string
// Flags weaknesses deterministically (no network beyond the one fetch):
//   missing CSP entirely, unsafe-inline / unsafe-eval, wildcard or scheme sources,
//   no frame-ancestors (clickjacking), no object-src, no base-uri, no upgrade-insecure-requests,
//   missing default-src, nonce present in script-src (often bypassable)...
const http = require('http');
const https = require('https');
const fs = require('fs');
const { loadScope, inScope } = require('./scope-guard');

function parsePolicy(policy) {
  // directive names are case-insensitive; values are space-separated, may contain quotes/schemes
  const out = [];
  for (const part of String(policy).split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const sp = trimmed.indexOf(' ');
    const name = (sp < 0 ? trimmed : trimmed.slice(0, sp)).toLowerCase();
    const values = sp < 0 ? [] : trimmed.slice(sp + 1).trim().split(/\s+/).filter(Boolean);
    out.push({ name, values });
  }
  return out;
}

function hasValue(dir, v) {
  return dir.values.some((x) => x.toLowerCase() === v);
}

function flag(policy) {
  const dirs = parsePolicy(policy);
  const byName = {};
  for (const d of dirs) (byName[d.name] = byName[d.name] || []).push(d);
  const get = (n) => (byName[n] || [])[0];
  const flags = [];

  if (!policy || !policy.trim()) {
    return { directives: [], flags: [{ severity: 'medium', issue: 'No Content-Security-Policy header at all' }] };
  }
  if (!get('default-src')) flags.push({ severity: 'medium', issue: 'missing default-src fallback' });

  const script = get('script-src');
  if (script) {
    if (hasValue(script, "'unsafe-inline'")) flags.push({ severity: 'medium', issue: "script-src allows 'unsafe-inline'" });
    if (hasValue(script, "'unsafe-eval'")) flags.push({ severity: 'medium', issue: "script-src allows 'unsafe-eval'" });
    if (script.values.some((v) => v === '*' || v === 'http:' || v === 'https:' || v === 'data:' || v === 'blob:'))
      flags.push({ severity: 'medium', issue: 'script-src contains wildcard/scheme source: ' + script.values.join(' ') });
    if (script.values.some((v) => /^https?:$/.test(v)))
      flags.push({ severity: 'low', issue: 'script-src allows cleartext http: — downgrade/mitm risk' });
  }
  const style = get('style-src');
  if (style && hasValue(style, "'unsafe-inline'")) flags.push({ severity: 'low', issue: "style-src allows 'unsafe-inline'" });

  if (!get('frame-ancestors')) flags.push({ severity: 'low', issue: 'no frame-ancestors (clickjacking not mitigated by CSP)' });
  if (!get('object-src')) flags.push({ severity: 'low', issue: 'no object-src (plugins/objects unrestricted)' });
  if (!get('base-uri')) flags.push({ severity: 'low', issue: 'no base-uri (DOM clobbering / base-tag injection surface)' });
  if (!get('upgrade-insecure-requests')) flags.push({ severity: 'info', issue: 'no upgrade-insecure-requests' });

  // nonce-only scripts: a single static nonce is often reusable; worth a manual look
  if (script && script.values.some((v) => /^'nonce-/.test(v)) && !script.values.some((v) => v.startsWith("'sha")))
    flags.push({ severity: 'info', issue: "script-src uses nonce(s) but no hash sources — check nonce rotation" });

  return { directives: dirs, flags };
}

function request(url, timeoutMs) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
    req.on('error', (e) => resolve({ error: e.message }));
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const val = (name) => { const i = argv.indexOf('--' + name); return i >= 0 && argv[i + 1] != null ? argv[i + 1] : undefined; };
  const url = val('url');
  const header = val('header');
  const file = val('file');
  const timeout = +val('timeout') || 10000;

  let policy = null;
  let source = null;
  if (header) {
    policy = header;
    source = '--header';
  } else if (file) {
    try {
      policy = fs.readFileSync(file, 'utf8');
      source = file;
    } catch (e) {
      console.error(JSON.stringify({ error: e.message }));
      process.exit(2);
    }
  } else if (url) {
    const scope = loadScope();
    const g = inScope(url, scope);
    if (!g.ok) {
      console.error(JSON.stringify({ blocked: url, reason: g.reason }));
      process.exit(1);
    }
    const r = await request(url, timeout);
    if (r.error) {
      console.error(JSON.stringify({ error: r.error }));
      process.exit(1);
    }
    const csp = r.headers['content-security-policy'];
    policy = Array.isArray(csp) ? csp.join('; ') : csp || '';
    source = url + ' (status ' + r.status + ')';
  } else {
    console.error('usage: node tools/csp.js --url <u> | --header "<policy>" | --file <path>');
    process.exit(2);
  }

  const res = flag(policy);
  console.log(JSON.stringify({ source, policy: policy || null, ...res }, null, 2));
}

module.exports = { parsePolicy, flag };
if (require.main === module) main();
