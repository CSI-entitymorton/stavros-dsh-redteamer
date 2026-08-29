// Self-check: looted secrets go to a cleartext vault, only a fingerprint lands in findings.
// Run: node tools/test-loot.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpFind = path.join(os.tmpdir(), 'stavros-find-' + process.pid + '.jsonl');
const tmpLoot = path.join(os.tmpdir(), 'stavros-loot-' + process.pid + '.jsonl');
process.env.FINDINGS_JSONL = tmpFind;
process.env.LOOT_JSONL = tmpLoot;
for (const f of [tmpFind, tmpLoot]) try { fs.unlinkSync(f); } catch {}

const { record } = require('./record-finding');

const res = record(JSON.stringify({
  severity: 'High', title: 'Domain admin hash dumped', host: '10.0.0.5', status: 'inconclusive',
  poc: 'hashdump on WIN-DC01', secret: 'Administrator:500:aad3b435:31d6cfe0d16ae931b73c59d7e0c089c0:::',
}));
assert.ok(res.ok, JSON.stringify(res));

// finding line must NOT contain the cleartext hash; must carry a fingerprint + loot_id
const findLine = fs.readFileSync(tmpFind, 'utf8').trim();
assert.ok(!findLine.includes('31d6cfe0d16ae931b73c59d7e0c089c0'), 'cleartext leaked into findings.jsonl');
const finding = JSON.parse(findLine);
assert.ok(finding.secret_fingerprint && finding.loot_id, 'missing fingerprint/loot_id');
assert.strictEqual(finding.secret, undefined, 'raw secret field must be stripped from finding');

// loot vault MUST contain the cleartext, keyed by the same loot_id
const lootLine = fs.readFileSync(tmpLoot, 'utf8').trim();
const loot = JSON.parse(lootLine);
assert.ok(loot.secret.includes('31d6cfe0d16ae931b73c59d7e0c089c0'), 'vault missing cleartext');
assert.strictEqual(loot.loot_id, finding.loot_id);

for (const f of [tmpFind, tmpLoot]) fs.unlinkSync(f);
console.log('loot: all tests passed');
