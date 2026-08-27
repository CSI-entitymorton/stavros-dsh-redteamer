// Self-check: sliver.js enforces tier gate, pivot scope, artifact tracking, and teardown.
// Run: node tools/test-sliver.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
process.env.SESSIONS_JSON = path.join(os.tmpdir(), 'stavros-slv-sess-' + process.pid + '.json');
try { fs.unlinkSync(process.env.SESSIONS_JSON); } catch {}

const SV = require('./sliver');
const S = require('./sessions');
const scope = { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: ['10.0.0.0/24'],
  host_ops: { auto: ['enum', 'loot_read', 'privesc_check'], confirm: ['persist', 'lateral', 'exfil', 'cred_dump', 'destructive'] } };

S.upsertSession({ id: 'impl-1', host: '10.0.0.5', status: 'active' });
const runs = [];
const fakeExec = (sid, cmd) => { runs.push(cmd); return { stdout: 'ok', status: 0 }; };

// auto-tier command runs
assert.strictEqual(SV.runCmd('impl-1', 'ps', { exec: fakeExec, scope }).ok, true);

// confirm-tier WITHOUT --confirm is blocked, exec not called for it
const before = runs.length;
const blk = SV.runCmd('impl-1', 'persistence -m registry', { exec: fakeExec, scope });
assert.strictEqual(blk.ok, false);
assert.strictEqual(runs.length, before, 'blocked command must not exec');

// confirm-tier WITH --confirm runs AND records an artifact
const okp = SV.runCmd('impl-1', 'persistence -m registry', { confirm: 'user ok', exec: fakeExec, scope });
assert.strictEqual(okp.ok, true);
assert.strictEqual(S.openArtifacts('impl-1').length, 1);

// lateral to OUT-OF-SCOPE host blocked even with --confirm
const lat = SV.runCmd('impl-1', 'psexec 10.0.1.9', { confirm: 'ok', exec: fakeExec, scope });
assert.strictEqual(lat.blocked, true);

// teardown walks artifacts, runs removal, marks them removed
const clean = SV.cleanup('impl-1', { exec: fakeExec });
assert.strictEqual(clean.remaining, 0);
assert.strictEqual(S.openArtifacts('impl-1').length, 0);

fs.unlinkSync(process.env.SESSIONS_JSON);
console.log('sliver: all tests passed');
