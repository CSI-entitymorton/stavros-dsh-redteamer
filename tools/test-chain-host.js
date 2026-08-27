// Self-check: chain.js links a web foothold to host privesc/lateral on the same host.
// Run: node tools/test-chain-host.js
const assert = require('assert');
const { buildChains, classify } = require('./chain');

assert.strictEqual(classify('Local privilege escalation via unquoted service path'), 'privesc');
assert.strictEqual(classify('Lateral movement to DC via pass-the-hash'), 'lateral');
assert.strictEqual(classify('Remote code execution via deserialization'), 'foothold');

// existing web classes must NOT regress
assert.strictEqual(classify('IDOR on /api/Order allows reading other users'), 'authz');
assert.strictEqual(classify('Hardcoded API key in bundle'), 'leak');

const findings = [
  { host: '10.0.0.5', title: 'RCE via deserialization', severity: 'Critical', poc: 'x' },
  { host: '10.0.0.5', title: 'Local privilege escalation via SUID binary', severity: 'High', poc: 'x' },
];
const chains = buildChains(findings);
const names = chains.flatMap((c) => c.chains.map((x) => x.name));
assert.ok(names.some((n) => /foothold.*escalation|host takeover/i.test(n)), 'expected a foothold->privesc chain: ' + names.join(','));

console.log('chain-host: all tests passed');
