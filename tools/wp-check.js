#!/usr/bin/env node
// WordPress fingerprint + version-gated CVE applicability (repo-vet churchofmalware plan,
// QW3 — wp2shell model). DETECTION-ONLY: it fingerprints the core version from public,
// unauthenticated sources and reports which known WP-core CVEs are APPLICABLE to that
// version. It never sends an exploit payload; PoC validation happens in an isolated lab.
//
//   node tools/wp-check.js https://target.example            # full check, scope-guarded
//   node tools/wp-check.js https://target.example --json     # same, single-line JSON
//
// Version intel baked in (from the vetted wp2shell research):
//   CVE-2026-63030 — REST API batch route confusion → unauthenticated RCE (WP core 6.9–7.0.1)
//   CVE-2026-60137 — SQL injection via WP_Query (WP core 6.9–7.0.1)
//
// Output is record-finding-ready JSON: { wordpress:{detected,version,sources}, checks:[...],
// cves:[...] }. Scope-guard hard: out-of-scope URL -> refusal before any request.
const { loadScope, inScope } = require('./scope-guard');

// CVE id -> applicability predicate over a parsed core version + probe hints.
const KNOWN_CVES = [
  {
    id: 'CVE-2026-63030',
    title: 'WordPress core REST batch route confusion (unauthenticated RCE chain entry)',
    affected: { min: '6.9', max: '7.0.1' },
    cwe: 'CWE-94',
    hint: 'REST enabled (/wp-json/ reachable) raises exposure; exploit PoC lives only in the vetted wp2shell artifacts — validate in lab, never against out-of-scope hosts.',
  },
  {
    id: 'CVE-2026-60137',
    title: 'WordPress core SQL injection via WP_Query (unauthenticated)',
    affected: { min: '6.9', max: '7.0.1' },
    cwe: 'CWE-89',
    hint: 'Version-gated only; detection here stops at fingerprinting. Lab-validate any PoC before authorized use.',
  },
];

function parseVersion(s) {
  const m = String(s || '').match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3] || 0)];
}

function cmpVersions(a, b) {
  const pa = parseVersion(a); const pb = parseVersion(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

function versionInRange(v, min, max) {
  const p = parseVersion(v);
  if (!p) return false;
  return cmpVersions(v, min) >= 0 && cmpVersions(v, max) <= 0;
}

// Pure: extract the core version from common public artifacts. Returns { version, source }.
// The version is normalized to x.y[.z] so gating comparisons and reports stay clean.
function extractVersion(body, kind) {
  const text = String(body == null ? '' : body);
  const norm = (s) => {
    const p = parseVersion(s);
    return p ? p.join('.') : null;
  };
  let m;
  if ((m = text.match(/<meta name="generator" content="WordPress ([0-9][^"]*)"/i))) {
    return { version: norm(m[1]), source: kind === 'feed' ? 'feed generator' : 'meta generator' };
  }
  if ((m = text.match(/<generator>[^<]*\?v=([0-9][^<]*)<\/generator>/i))) {
    return { version: norm(m[1]), source: kind === 'feed' ? 'feed generator' : 'generator' };
  }
  if ((m = text.match(/Version\s*:?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i)) && /wordpress/i.test(text)) {
    return { version: norm(m[1]), source: 'readme.html' };
  }
  return null;
}

// Pure: does this homepage HTML look like WordPress?
function looksLikeWp(homeHtml) {
  const t = String(homeHtml == null ? '' : homeHtml);
  return /\/wp-content\/|\/wp-includes\//i.test(t) || /<meta name="generator" content="WordPress/i.test(t);
}

async function fetchText(ctx, url, timeoutMs) {
  const fetchFn = ctx.fetch || global.fetch;
  try {
    const r = await fetchFn(url, {
      headers: { 'User-Agent': ctx.userAgent || 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36' },
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs || 8000),
    });
    const body = await r.text();
    return { status: r.status, body };
  } catch (e) {
    return { status: 0, body: '', error: e.message };
  }
}

// Full check. ctx = { fetch, scope, userAgent } injectable for offline tests.
async function check(baseUrl, ctx) {
  ctx = ctx || {};
  let url;
  try { url = new URL(/^https?:\/\//i.test(baseUrl) ? baseUrl : 'https://' + baseUrl); } catch {
    return { ok: false, error: 'invalid base URL: ' + baseUrl };
  }
  url.hash = ''; url.search = '';
  const target = url.origin + (url.pathname.replace(/\/+$/, '') === '' ? '' : url.pathname.replace(/\/+$/, ''));
  // scope-guard hard gate BEFORE anything touches the network
  const scope = ctx.scope != null ? ctx.scope : (() => { try { return loadScope(); } catch { return null; } })();
  const verdict = inScope(target, scope);
  if (!verdict.ok) return { ok: false, blocked: true, reason: verdict.reason || 'target out of scope', target };

  const probes = [];
  const home = await fetchText(ctx, target + '/', 8000);
  probes.push({ probe: '/', status: home.status });
  let detected = looksLikeWp(home.body);
  let ver = extractVersion(home.body, 'home');
  let sources = ver ? [ver.source] : [];

  const feed = await fetchText(ctx, target + '/?feed=rss2', 8000);
  probes.push({ probe: '/?feed=rss2', status: feed.status });
  const feedVer = extractVersion(feed.body, 'feed');
  if (!ver && feedVer) { ver = feedVer; sources = [feedVer.source]; }

  const restRoot = await fetchText(ctx, target + '/wp-json/', 8000);
  probes.push({ probe: '/wp-json/', status: restRoot.status });
  let restRoutes = null;
  try { restRoutes = Object.keys(JSON.parse(restRoot.body).routes || {}).length; } catch {}
  const restEnabled = restRoot.status >= 200 && restRoot.status < 300;

  const readme = await fetchText(ctx, target + '/readme.html', 8000);
  probes.push({ probe: '/readme.html', status: readme.status });
  if (!ver) {
    const rv = extractVersion(readme.body, 'readme');
    if (rv && /wordpress/i.test(readme.body)) { ver = rv; sources = [rv.source]; detected = true; }
  }

  const version = ver ? ver.version : null;
  const checks = KNOWN_CVES.map((c) => ({
    id: c.id,
    title: c.title,
    cwe: c.cwe,
    applicable: !!version && versionInRange(version, c.affected.min, c.affected.max),
    reason: version
      ? (versionInRange(version, c.affected.min, c.affected.max)
        ? `core ${version} within affected range ${c.affected.min}–${c.affected.max}`
        : `core ${version} outside affected range ${c.affected.min}–${c.affected.max}`)
      : 'core version unknown — cannot gate',
    note: c.hint,
  }));

  const applicableCves = checks.filter((c) => c.applicable).map((c) => c.id);
  return {
    ok: true,
    detection_only: true,
    target,
    probes,
    wordpress: {
      detected: detected || restEnabled || !!version,
      version,
      sources,
      rest_enabled: restEnabled,
      rest_routes: restRoutes,
    },
    checks,
    cves: applicableCves,
    next_step: applicableCves.length
      ? 'Applicable CVEs found: confirm impact ONLY on an authorized/lab instance; record via record-finding.js with verify_level suspected until proven.'
      : 'No applicable known CVE at the detected version.',
  };
}

if (require.main === module) {
  const argv = process.argv.slice(2).filter((a) => a !== '--json');
  const asJson = process.argv.includes('--json');
  if (!argv[0]) {
    console.error('usage: node tools/wp-check.js <base-url> [--json]');
    process.exit(2);
  }
  check(argv[0]).then((r) => {
    console.log(asJson ? JSON.stringify(r) : JSON.stringify(r, null, 2));
    process.exit(r.ok ? 0 : 1);
  });
}

module.exports = { check, extractVersion, looksLikeWp, parseVersion, versionInRange, KNOWN_CVES };
