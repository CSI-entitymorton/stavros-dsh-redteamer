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
