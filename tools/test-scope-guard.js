// Offline self-check for the scope guard (security path -> must have a test).
// Run: node tools/test-scope-guard.js
const assert = require('assert');
const { inScope, hostOf, hostAllowed, ipAllowed, cidrParse, ipv4ToInt } = require('./scope-guard');

assert.strictEqual(hostOf('https://a.example.com/x?y=1'), 'a.example.com');
assert.strictEqual(hostOf('example.com'), 'example.com');
assert.strictEqual(hostOf('not a url'), null);

assert.ok(hostAllowed('example.com', ['example.com']));
assert.ok(hostAllowed('app.example.com', ['example.com'])); // subdomain allowed
assert.ok(!hostAllowed('evil.com', ['example.com']));
assert.ok(!hostAllowed('notexample.com', ['example.com'])); // no partial/suffix trick

// empty scope blocks everything
assert.strictEqual(inScope('https://example.com', { allowed_hosts: [], allowed_url_prefixes: [] }).ok, false);
// allowlisted host passes
assert.strictEqual(inScope('https://example.com/x', { allowed_hosts: ['example.com'] }).ok, true);
// out-of-scope host blocked even with a filled list
assert.strictEqual(inScope('https://evil.com', { allowed_hosts: ['example.com'] }).ok, false);
// url prefix allowlist
assert.strictEqual(inScope('https://x.com/app/', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com/app/'] }).ok, true);
assert.strictEqual(inScope('https://x.com/other', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com/app/'] }).ok, false);
// prefix must anchor on a boundary: no suffix-host bypass, no partial-path bypass
assert.strictEqual(inScope('https://x.com.evil.com/', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com'] }).ok, false);
assert.strictEqual(inScope('https://x.com/apple', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com/app'] }).ok, false);
assert.strictEqual(inScope('https://x.com/app', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com/app'] }).ok, true); // exact
assert.strictEqual(inScope('https://x.com/app/x', { allowed_hosts: [], allowed_url_prefixes: ['https://x.com/app'] }).ok, true); // boundary '/'

// --- allowed_ips: literal IPs and CIDRs (authorized SSRF-internal / lab targets) ---
assert.strictEqual(ipv4ToInt('127.0.0.1'), 0x7f000001);
assert.strictEqual(ipv4ToInt('999.1.1.1'), null);
assert.deepStrictEqual(cidrParse('10.0.0.0/8'), { net: 0x0a000000, mask: 0xff000000 });
assert.deepStrictEqual(cidrParse('127.0.0.1'), { net: 0x7f000001, mask: 0xffffffff });
assert.strictEqual(cidrParse('nope'), null);
assert.ok(ipAllowed('10.1.2.3', ['10.0.0.0/8']));
assert.ok(ipAllowed('127.0.0.1', ['127.0.0.1']));
assert.ok(ipAllowed('localhost', ['127.0.0.1'])); // localhost -> 127.0.0.1
assert.ok(!ipAllowed('11.1.2.3', ['10.0.0.0/8']));
assert.ok(!ipAllowed('example.com', ['10.0.0.0/8'])); // hostnames are NOT matched by IP rules
const ipScope = { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['169.254.169.254', '192.168.1.0/24'] };
assert.strictEqual(inScope('http://169.254.169.254/latest/meta-data', ipScope).ok, true);
assert.strictEqual(inScope('http://192.168.1.50/x', ipScope).ok, true);
assert.strictEqual(inScope('http://192.168.2.50/x', ipScope).ok, false);
assert.strictEqual(inScope('http://localhost:8080/x', ipScope).ok, false); // localhost not in this scope
const localScope = { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['127.0.0.1'] };
assert.strictEqual(inScope('http://localhost:3000/x', localScope).ok, true);

console.log('scope-guard: all tests passed');

// ============================================================================
// Ondata 1 (SA2) — estensioni IN CODA (righe originali sopra NON modificate):
// dual schema {targets,exclusions} + exclusions hard-deny + time_window.
// Tutto offline/deterministico (scope file in temp, orologio iniettato).
// ============================================================================
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadScope, cidrInScope } = require('./scope-guard');

// --- dual schema: normalization targets -> allowed_hosts/allowed_ips + exclusions ---
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-dual-'));
  const p = path.join(dir, 'scope.json');
  fs.writeFileSync(p, JSON.stringify({
    project: 'dual-schema-test',
    targets: ['192.168.0.0/24', 'lab.example.local'],
    exclusions: ['192.168.0.1'],
  }));
  const s = loadScope(p);
  assert.deepStrictEqual(s.allowed_ips, ['192.168.0.0/24'], 'targets cidr -> allowed_ips');
  assert.deepStrictEqual(s.allowed_hosts, ['lab.example.local'], 'targets hostname -> allowed_hosts');
  assert.strictEqual(s.exclusions.length, 1, 'exclusions normalized');
  assert.ok(s.raw && Array.isArray(s.raw.targets), 'raw kept');
  assert.strictEqual(inScope('http://192.168.0.5/', s).ok, true);
  const exRes = inScope('http://192.168.0.1/', s);
  assert.strictEqual(exRes.ok, false, 'exclusion hard-deny on ip target');
  assert.ok(/excluded/.test(exRes.reason), 'reason mentions exclusion');
  assert.strictEqual(inScope('http://10.0.0.5/', s).ok, false, 'outside targets denied');
  // CIDR richiesta che INTERSECA un'exclusion -> negata (scelta conservativa)
  assert.strictEqual(cidrInScope('192.168.0.0/30', s).ok, false, 'intersecting CIDR denied');
  assert.strictEqual(cidrInScope('192.168.0.8/29', s).ok, true, 'disjoint CIDR allowed');

  // harness schema storico: passthrough + exclusions additive anche qui
  const p2 = path.join(dir, 'scope-harness.json');
  fs.writeFileSync(p2, JSON.stringify({
    allowed_hosts: ['h.example'], allowed_url_prefixes: [], allowed_ips: ['10.0.0.0/8'],
    exclusions: ['10.9.9.9'],
  }));
  const s2 = loadScope(p2);
  assert.strictEqual(inScope('http://10.8.8.8/', s2).ok, true);
  assert.strictEqual(inScope('http://10.9.9.9/', s2).ok, false, 'exclusion works on harness schema too');
  assert.strictEqual(inScope('https://sub.h.example/x', s2).ok, true);
}

// --- time_window: valutata a ogni call; orologio iniettabile (opts.now / env SCOPE_NOW) ---
{
  const past = '2026-01-01T00:00:00Z';
  const inside = '2026-06-15T12:00:00Z';
  const future = '2027-01-01T00:00:00Z';
  const tw = (extra) => Object.assign({ allowed_hosts: ['example.com'] }, extra);

  assert.strictEqual(inScope('https://example.com/', tw({ time_window: { start: past, end: future } }), { now: inside }).ok, true);
  const before = inScope('https://example.com/', tw({ time_window: { start: past, end: future } }), { now: '2025-06-01T00:00:00Z' });
  assert.strictEqual(before.ok, false, 'before start denied');
  assert.strictEqual(before.reason, 'outside engagement time_window', 'exact reason');
  const after = inScope('https://example.com/', tw({ time_window: { start: past, end: future } }), { now: '2027-06-01T00:00:00Z' });
  assert.strictEqual(after.ok, false, 'after end denied');
  assert.strictEqual(after.reason, 'outside engagement time_window');
  // finestra aperta / assente / null = sempre autorizzabile (retrocompatibile)
  assert.strictEqual(inScope('https://example.com/', tw(), { now: '2030-01-01T00:00:00Z' }).ok, true);
  assert.strictEqual(inScope('https://example.com/', tw({ time_window: { start: null, end: null } }), { now: '2030-01-01T00:00:00Z' }).ok, true);
  // bound malformato -> deny conservativo
  assert.strictEqual(inScope('https://example.com/', tw({ time_window: { start: 'not-a-date', end: null } }), { now: inside }).ok, false);
  // clock iniettabile via env SCOPE_NOW (per i caller CLI che non passano opts)
  process.env.SCOPE_NOW = '2025-06-01T00:00:00Z';
  try {
    assert.strictEqual(inScope('https://example.com/', tw({ time_window: { start: past, end: future } })).ok, false, 'SCOPE_NOW honored');
    process.env.SCOPE_NOW = inside;
    assert.strictEqual(inScope('https://example.com/', tw({ time_window: { start: past, end: future } })).ok, true, 'SCOPE_NOW inside window');
  } finally {
    delete process.env.SCOPE_NOW;
  }
  // cidrInScope eredita la time_window
  const cScope = tw({ allowed_ips: ['10.0.0.0/8'], time_window: { start: past, end: future } });
  assert.strictEqual(cidrInScope('10.0.0.0/24', cScope, { now: inside }).ok, true);
  assert.strictEqual(cidrInScope('10.0.0.0/24', cScope, { now: '2030-01-01T00:00:00Z' }).ok, false);
}

// missing scope file => fail-closed (empty scope, nothing authorized)
assert.strictEqual(inScope('https://example.com', loadScope('/nonexistent/__no_scope__.json')).ok, false);

console.log('scope-guard: extensions passed (dual schema/exclusions/time_window)');
