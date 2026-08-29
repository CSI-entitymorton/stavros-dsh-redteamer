#!/usr/bin/env node
// Security headers + cookie-flags hardening checker (zero-dep, deterministic).
//   node tools/header-check.js <url>            # fetch one page, evaluate headers + cookies
//   node tools/header-check.js <url> --json     # same, machine-readable
//   node tools/header-check.js <url> --record   # write a recordable finding JSON to stdout
// Maps to OWASP Top 10:2025 A02 (Security Misconfiguration) + WSTG-CONF / WSTG-SESS-04.
// Every header is a deterministic LOW/MEDIUM/INFO finding; nothing here is destructive.
// Purpose: A02 rose to #2 in 2025 largely because of config drift between deploys — this is
// the single quick check that catches missing/weak hardening headers and cookie flags.
//
// Uses the shared DNS-rebinding-safe request path (net.js resolveAndGuard + scope-guard), so
// a hostname that resolves to a private/link-local IP is refused unless its subnet is in
// scope.json allowed_ips.
const http = require('http');
const https = require('https');
const { loadScope, inScope } = require('./scope-guard');
const { resolveAndGuard } = require('./net');

function hdrs(res) { return (res.headers || {}); }
function one(h) {
  // some headers arrive as arrays (set-cookie, sometimes warning); join consistently
  if (Array.isArray(h)) return h.join('; ');
  return String(h == null ? '' : h);
}

// Cookie flag evaluation per WSTG-SESS-04: Secure, HttpOnly, SameSite, Domain overbreadth.
function cookieFindings(setCookie) {
  const out = [];
  const cookies = Array.isArray(setCookie) ? setCookie : [];
  for (const raw of cookies) {
    const namePart = String(raw).split(';')[0];
    const name = namePart.split('=')[0].trim();
    if (!name) continue;
    const lower = String(raw).toLowerCase();
    if (!/\bsecure\b/.test(lower))
      out.push({ severity: 'medium', issue: `cookie '${name}' missing Secure flag`, evidence: name });
    if (!/\bhttponly\b/.test(lower))
      out.push({ severity: 'low', issue: `cookie '${name}' missing HttpOnly flag (JS-readable)`, evidence: name });
    // SameSite: None without Secure is actively dangerous (CSWSH/CSRF); absent = lenient on legacy defaults
    if (!/\bsamesite=/i.test(lower))
      out.push({ severity: 'low', issue: `cookie '${name}' has no SameSite attribute`, evidence: name });
    else if (/\bsamesite=none\b/i.test(lower) && !/\bsecure\b/.test(lower))
      out.push({ severity: 'medium', issue: `cookie '${name}' is SameSite=None but NOT Secure — accepted cross-site`, evidence: name });
    if (/\bdomain=/i.test(lower))
      out.push({ severity: 'info', issue: `cookie '${name}' sets a Domain scope — overbroad cookie scope`, evidence: name });
  }
  return out;
}

function evaluate(url, res) {
  const h = hdrs(res);
  const findings = [];
  const setCookie = res.headers['set-cookie'];

  // CSP — reuse csp.js's deterministic flags if the header is present.
  if (h['content-security-policy']) {
    try {
      const { parsePolicy } = require('./csp');
      const p = one(h['content-security-policy']);
      const f = require('./csp').flag(p);
      for (const fl of f.flags) {
        findings.push({ severity: fl.severity, issue: 'CSP: ' + fl.issue, evidence: p.slice(0, 200) });
      }
      findings.push({ severity: 'info', issue: 'Content-Security-Policy present', evidence: p.slice(0, 120) });
    } catch (_) {
      findings.push({ severity: 'info', issue: 'Content-Security-Policy present' });
    }
  } else {
    findings.push({ severity: 'medium', issue: 'Missing Content-Security-Policy header', evidence: '—' });
  }

  // Strict-Transport-Security
  if (!h['strict-transport-security'])
    findings.push({ severity: 'medium', issue: 'Missing Strict-Transport-Security (HSTS) header', evidence: '—' });
  else {
    const s = one(h['strict-transport-security']);
    if (!/max-age=(\d+)/i.test(s) || +(/max-age=(\d+)/i.exec(s) || [])[1] < 15552000)
      findings.push({ severity: 'low', issue: 'HSTS max-age absent or < 180 days', evidence: s });
    findings.push({ severity: 'info', issue: 'Strict-Transport-Security present', evidence: s.slice(0, 120) });
  }

  // Frame / clickjacking
  if (!h['x-frame-options'] && !h['content-security-policy']?.toLowerCase().includes('frame-ancestors'))
    findings.push({ severity: 'medium', issue: 'No X-Frame-Options and CSP lacks frame-ancestors (clickjacking)', evidence: '—' });
  else if (h['x-frame-options'])
    findings.push({ severity: 'info', issue: 'X-Frame-Options present', evidence: one(h['x-frame-options']) });

  // MIME sniffing
  if (!h['x-content-type-options'] || !/nosniff/i.test(one(h['x-content-type-options'])))
    findings.push({ severity: 'low', issue: 'Missing or non-nosniff X-Content-Type-Options (MIME sniffing)', evidence: one(h['x-content-type-options']) || '—' });

  // Referrer policy
  if (!h['referrer-policy'])
    findings.push({ severity: 'low', issue: 'Missing Referrer-Policy header', evidence: '—' });
  else if (/\bunsafe-url\b|\bno-referrer-when-downgrade\b/i.test(one(h['referrer-policy'])))
    findings.push({ severity: 'info', issue: 'Referrer-Policy leaks path on downgrade/unsafe-url', evidence: one(h['referrer-policy']) });

  // Permissions-Policy
  if (!h['permissions-policy'])
    findings.push({ severity: 'info', issue: 'Missing Permissions-Policy header', evidence: '—' });

  // Server header / verbose banners (A02 verbose errors/info)
  if (h['server'])
    findings.push({ severity: 'info', issue: 'Server banner exposed', evidence: one(h['server']).slice(0, 120) });

  // Cookies
  findings.push(...cookieFindings(setCookie));

  const worst = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const hasMedia = findings.some((f) => worst[f.severity] >= 2);
  return {
    url,
    status: res.statusCode,
    header_findings: findings,
    cookie_flags: cookieFindings(setCookie).length,
    verdict: hasMedia ? 'attention' : 'ok',
    summary: findings.map((f) => `${f.severity}: ${f.issue}`),
  };
}

function request(url, timeoutMs) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https:') ? https : http;
    const scope = loadScope();
    // authoritative scope-first: the URL itself must be in scope
    const g = inScope(url, scope);
    if (!g.ok) return resolve({ blocked: g.reason });
    // then DNS-rebinding-safe: pin the resolved address
    resolveAndGuard(url, scope).then((pin) => {
      if (pin.blocked) return resolve({ blocked: pin.reason });
      const reqOpts = new URL(url);
      const opts = {
        hostname: pin.address,
        port: reqOpts.port || (reqOpts.protocol === 'https:' ? 443 : 80),
        path: reqOpts.pathname + reqOpts.search,
        method: 'GET',
        headers: { 'User-Agent': 'stavros-header-check/0.1', Host: reqOpts.hostname, Accept: '*/*' },
        timeout: timeoutMs,
        lookup: (host, o, cb) => cb(null, pin.address, pin.family), // force the pinned address
      };
      const req = lib.request(opts, (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve({ res, body: d }));
      });
      req.on('timeout', () => { req.destroy(); resolve({ blocked: 'timeout' }); });
      req.on('error', (e) => resolve({ blocked: e.message }));
      req.end();
    });
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const url = argv[0];
  const timeoutIdx = argv.indexOf('--timeout');
  const timeout = timeoutIdx >= 0 && argv[timeoutIdx + 1] != null ? +argv[timeoutIdx + 1] : 10000;
  if (!url || !/^https?:\/\//i.test(url)) {
    console.error('usage: node tools/header-check.js <url> [--json] [--record] [--timeout <ms>]');
    process.exit(2);
  }
  const scope = loadScope();
  const g = inScope(url, scope);
  if (!g.ok) {
    console.error(JSON.stringify({ blocked: url, reason: g.reason }));
    process.exit(1);
  }
  const r = await request(url, timeout);
  if (r.blocked) {
    console.error(JSON.stringify({ blocked: true, url, reason: r.blocked }));
    process.exit(1);
  }
  const out = evaluate(url, r.res);

  if (argv.includes('--record')) {
    // Emit a record-finding.js candidate for the worst issue only (keeps findings deduped).
    const worst = out.header_findings
      .filter((f) => f.severity !== 'info')
      .sort((a, b) => ({ high: 3, medium: 2, low: 1 })[b.severity] - ({ high: 3, medium: 2, low: 1 })[a.severity]);
    const top = worst[0];
    if (top) {
      console.log(JSON.stringify({
        severity: top.severity === 'medium' ? 'Medium' : top.severity === 'low' ? 'Low' : 'Info',
        title: `Hardening: ${top.issue}`,
        host: new URL(url).hostname,
        endpoint: new URL(url).pathname,
        class: 'config',
        cwe: 'CWE-16',
        cvss: 5.3,
        cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
        poc: `curl -sI ${url}`,
        remediation: 'Add the missing security headers (CSP, HSTS, X-Frame-Options, frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy); set Secure/HttpOnly/SameSite on cookies.',
        notes: 'Ran via tools/header-check.js — full finding list at stdout.',
      }));
    } else {
      console.log(JSON.stringify({ ok: true }));
    }
    process.exit(0);
  }
  console.log(JSON.stringify(out, null, argv.includes('--json') ? 2 : 0));
  process.exit(0);
}

module.exports = { evaluate, cookieFindings };
if (require.main === module) main();