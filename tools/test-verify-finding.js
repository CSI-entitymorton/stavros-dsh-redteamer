// Offline self-check for the oracle verifier (security/correctness path -> must have a test).
// Run: node tools/test-verify-finding.js
const assert = require('assert');
const fs = require('fs'), os = require('os'), path = require('path');
const { verifyOne, checkExpect } = require('./verify-finding');

// mock exec: returns canned responses in order, repeating the last one.
const mk = (responses) => { let i = 0; return async () => responses[i++] || responses[responses.length - 1]; };

(async () => {
  // status + body_contains, N/N pass -> verified
  let r = await verifyOne(
    { verify: { url: 'https://h/x', expect: { status: 200, body_contains: 'marker' } } },
    { times: 2, exec: mk([{ status: 200, body: 'has marker here' }, { status: 200, body: 'has marker here' }]) });
  assert.strictEqual(r.verified, true, 'N/N pass -> verified');
  assert.strictEqual(r.runs.length, 2);

  // one run fails expect.status -> not verified (fails fast)
  r = await verifyOne(
    { verify: { url: 'https://h/x', expect: { status: 200 } } },
    { times: 2, exec: mk([{ status: 200, body: '' }, { status: 500, body: '' }]) });
  assert.strictEqual(r.verified, false, 'a failing run -> not verified');

  // body_contains missing -> not verified
  r = await verifyOne(
    { verify: { url: 'https://h/x', expect: { status: 200, body_contains: 'secret' } } },
    { times: 1, exec: mk([{ status: 200, body: 'nope' }]) });
  assert.strictEqual(r.verified, false);

  // body_similarity_to: exec is called once for baseline, then per run
  r = await verifyOne(
    { verify: { url: 'https://h/2', expect: { status: 200, body_similarity_to: 'https://h/1' } } },
    { times: 1, exec: mk([{ status: 200, body: 'alpha beta gamma delta' }, { status: 200, body: 'alpha beta gamma omega' }]) });
  assert.strictEqual(r.verified, true, 'similar bodies (0.75 >= 0.6) pass');

  // no verify block -> verified:false, clear reason
  r = await verifyOne({ title: 'x' }, {});
  assert.strictEqual(r.verified, false);
  assert.match(r.reason, /no verify/);

  // verifyFile: in-place update of findings that carry a verify block (mock exec)
  const { verifyFile } = require('./verify-finding');
  const vtmp = path.join(os.tmpdir(), 'vf-' + process.pid + '.jsonl');
  fs.writeFileSync(vtmp,
    JSON.stringify({ title: 'a', verify: { url: 'https://h/x', expect: { status: 200 } } }) + '\n' +
    JSON.stringify({ title: 'b' }) + '\n');
  const res = await verifyFile(vtmp, { exec: async () => ({ status: 200, body: '' }) });
  assert.strictEqual(res.updated, 1, 'one finding verified');
  const after = fs.readFileSync(vtmp, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert.strictEqual(after[0].status, 'verified');
  assert.ok(after[0].verified_at, 'verified_at stamped');
  assert.strictEqual(after[1].status, undefined, 'finding without verify block untouched');
  fs.rmSync(vtmp, { force: true });

  // record-finding inline verify hook (offline, injected verifier + temp findings file)
  const { recordWithVerify } = require('./record-finding');
  const ftmp = path.join(os.tmpdir(), 'rf-' + process.pid + '.jsonl');
  process.env.FINDINGS_JSONL = ftmp;
  const passing = { severity: 'High', title: 'idor', host: 'h', poc: 'x', verify: { url: 'https://h/x', expect: { status: 200 } } };
  const ok = await recordWithVerify(JSON.stringify(passing), async () => ({ verified: true, runs: [], reason: '2/2' }));
  assert.ok(ok.ok, 'recorded');
  const rec = fs.readFileSync(ftmp, 'utf8').split('\n').filter(Boolean).map(JSON.parse).find((x) => x.title === 'idor');
  assert.strictEqual(rec.status, 'verified', 'passing verify -> status verified');

  const failing = { severity: 'Low', title: 'idor2', host: 'h', poc: 'x', verify: { url: 'https://h/y', expect: { status: 200 } } };
  await recordWithVerify(JSON.stringify(failing), async () => ({ verified: false, runs: [], reason: 'boom' }));
  const rec2 = fs.readFileSync(ftmp, 'utf8').split('\n').filter(Boolean).map(JSON.parse).find((x) => x.title === 'idor2');
  assert.strictEqual(rec2.status, 'confirmed', 'failing verify -> stays confirmed');
  assert.strictEqual(rec2.verify_failed, true);
  fs.rmSync(ftmp, { force: true });
  delete process.env.FINDINGS_JSONL;

  console.log('verify-finding: all tests passed');
})();
