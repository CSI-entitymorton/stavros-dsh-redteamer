// Offline self-check for the C2 action-tier guard + pivot scope (security path).
// Run: node tools/test-c2-guard.js
const assert = require('assert');
const G = require('./c2-guard');

const scope = {
  allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['10.0.0.0/24'],
  host_ops: { auto: ['enum', 'loot_read', 'privesc_check'], confirm: ['persist', 'lateral', 'exfil', 'cred_dump', 'destructive'] },
};

// classification: known auto commands
assert.strictEqual(G.classify('ps').tier, 'auto');
assert.strictEqual(G.classify('ls C:\\Users').tier, 'auto');
assert.strictEqual(G.classify('download /etc/passwd').actionClass, 'loot_read');
assert.strictEqual(G.classify('getprivs').tier, 'auto');

// classification: known confirm commands
assert.strictEqual(G.classify('persistence -m registry').tier, 'confirm');
assert.strictEqual(G.classify('psexec 10.0.0.9').actionClass, 'lateral');
assert.strictEqual(G.classify('hashdump').actionClass, 'cred_dump');
assert.strictEqual(G.classify('rm -rf /').tier, 'confirm');

// FAIL-CLOSED: unknown command -> confirm, never auto
assert.strictEqual(G.classify('frobnicate --wibble').tier, 'confirm');

// enforce: auto passes without --confirm
assert.strictEqual(G.enforce('ps', {}).ok, true);
// enforce: confirm-tier BLOCKED without flag
assert.strictEqual(G.enforce('persistence -m registry', {}).ok, false);
// enforce: confirm-tier passes WITH flag
assert.strictEqual(G.enforce('persistence -m registry', { confirm: 'user approved persistence for report PoC' }).ok, true);

// pivot host extraction + scope check
assert.deepStrictEqual(G.pivotTargets('psexec 10.0.0.9 -u admin'), ['10.0.0.9']);
assert.strictEqual(G.pivotInScope('psexec 10.0.0.9', scope).ok, true);   // in 10.0.0.0/24
assert.strictEqual(G.pivotInScope('psexec 10.0.1.9', scope).ok, false);  // out of scope -> blocked
assert.deepStrictEqual(G.pivotInScope('psexec 10.0.1.9', scope).badHosts, ['10.0.1.9']);

console.log('c2-guard: all tests passed');
