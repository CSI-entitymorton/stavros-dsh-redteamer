// Offline self-check for the session registry / teardown ledger.
// Run: node tools/test-sessions.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const tmp = path.join(os.tmpdir(), 'stavros-sessions-test-' + process.pid + '.json');
process.env.SESSIONS_JSON = tmp;
try { fs.unlinkSync(tmp); } catch {}

const S = require('./sessions');

// empty registry
assert.deepStrictEqual(S.loadRegistry(), { sessions: {} });

// upsert defaults status to 'pending'
const sess = S.upsertSession({ id: 's1', host: '10.0.0.5', obtained_via: 'web-rce' });
assert.strictEqual(sess.status, 'pending');
assert.strictEqual(S.loadRegistry().sessions.s1.host, '10.0.0.5');

// status lifecycle
S.setStatus('s1', 'active');
assert.strictEqual(S.loadRegistry().sessions.s1.status, 'active');

// artifacts append + open list
S.addArtifact('s1', { type: 'persist', location: 'HKCU\\Run\\x', removal: 'reg delete ...' });
S.addArtifact('s1', { type: 'file', location: '/tmp/impl', removal: 'rm /tmp/impl' });
assert.strictEqual(S.openArtifacts('s1').length, 2);

// mark one removed -> open list shrinks
S.markArtifactRemoved('s1', 0);
assert.strictEqual(S.openArtifacts('s1').length, 1);
assert.strictEqual(S.loadRegistry().sessions.s1.artifacts[0].removed, true);

fs.unlinkSync(tmp);
console.log('sessions: all tests passed');
