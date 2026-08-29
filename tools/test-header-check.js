// Self-check: header-check.js flags are deterministic and correct for both good and bad
// header/cookie configurations. No network.
// Run: node tools/test-header-check.js
const assert = require('assert');
const H = require('./header-check');

// cookieFindings: a well-hardened cookie yields no findings for that cookie
const clean = H.cookieFindings(['sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict']);
assert.strictEqual(clean.length, 0, 'hardened cookie should produce no flags');

// missing Secure = medium
const noSecure = H.cookieFindings(['sid=abc; HttpOnly; SameSite=Strict']);
assert.strictEqual(noSecure.length, 1);
assert.strictEqual(noSecure[0].severity, 'medium');
assert.ok(/Secure/i.test(noSecure[0].issue));

// missing HttpOnly = low
const noHttpOnly = H.cookieFindings(['sid=abc; Secure; SameSite=Strict']);
assert.strictEqual(noHttpOnly.length, 1);
assert.strictEqual(noHttpOnly[0].severity, 'low');

// SameSite=None without Secure = medium (CSWSH)
const noneUnsafe = H.cookieFindings(['sid=abc; SameSite=None; Path=/']);
assert.strictEqual(noneUnsafe.length, 3, 'missing Secure, missing HttpOnly, SameSite=None-without-Secure');
assert.ok(noneUnsafe.some((f) => /SameSite=None but NOT Secure/i.test(f.issue)));

// evaluate(): a mock response with zero security headers -> attention
const mockRes = { statusCode: 200, headers: {} };
const zero = H.evaluate('https://h.test/', mockRes);
assert.strictEqual(zero.status, 200);
assert.ok(zero.header_findings.length >= 5, 'expect the core header findings');
assert.ok(zero.header_findings.some((f) => /Missing Content-Security-Policy/i.test(f.issue)));
assert.ok(zero.header_findings.some((f) => /Missing Strict-Transport-Security/i.test(f.issue)));
assert.ok(zero.header_findings.some((f) => /X-Frame-Options/.test(f.issue)));
assert.ok(['attention', 'ok'].includes(zero.verdict));

// evaluate(): a well-hardened response -> fewer, ok verdict
const mockGood = {
  statusCode: 200,
  headers: {
    'content-security-policy': "default-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'; upgrade-insecure-requests",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'geolocation=()',
  },
};
const good = H.evaluate('https://h.test/', mockGood);
assert.strictEqual(good.verdict, 'ok', 'fully hardened headers -> ok');
assert.ok(!good.header_findings.some((f) => /Missing Content-Security-Policy/i.test(f.issue)));
assert.ok(!good.header_findings.some((f) => /Missing Strict-Transport-Security/i.test(f.issue)));
assert.ok(!good.header_findings.some((f) => /nosniff/i.test(f.issue)));

// a weak CSP propagates from csp.flag
const mockWeak = {
  statusCode: 200,
  headers: { 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline' https:" },
};
const weak = H.evaluate('https://h.test/', mockWeak);
assert.ok(weak.header_findings.some((f) => /unsafe-inline/i.test(f.issue)), 'weak CSP flagged');

console.log('header-check: all tests passed');