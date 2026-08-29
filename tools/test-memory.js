// Offline self-check for the lessons-memory layer (zero-dep).
// Run: node tools/test-memory.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const mem = require('./memory');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'memory-test-'));
process.env.STAVROS_MEMORY_DIR = dir; // CLI parity if spawned later
// Sanitizer fixture: the sanitizer fingerprints engagement hosts/IPs from <ws>/scope.json
// (SCOPE_JSON override — hermetic, never reads a real engagement file). The 'in-scope host'
// case below must be denied because example.com is in this fixture.
const scopeFile = path.join(dir, 'scope.json');
fs.writeFileSync(scopeFile, JSON.stringify({ allowed_hosts: ['example.com'], allowed_ips: [] }));
process.env.SCOPE_JSON = scopeFile;

// --- add: validation + id assignment ---
const a = mem.addLesson(dir, {
  class: 'web', stack: ['wordpress'], waf: 'cloudflare',
  technique: 'time-based sqli via cache-busting param survives cloudflare rate limit',
  outcome: 'worked', evidence_ref: 'reports/1-sqli.md', tags: ['sqli', 'time-based'],
});
assert.strictEqual(a.id, 'LES-0001', 'first id LES-0001');
assert.strictEqual(a.sanitized, true, 'clean lesson marked sanitized');

const b = mem.addLesson(dir, {
  class: 'web', stack: ['nginx'],
  technique: 'jwt alg confusion none rejected; jku header injection worked on custom parser',
  outcome: 'failed', cause: 'library pins alg allowlist server-side, jku fetch disabled',
  evidence_ref: 'EV-42',
});
assert.strictEqual(b.id, 'LES-0002');
assert.ok(b.confidence.worked === 0 && b.confidence.seen === 1);

// --- add: schema errors ---
assert.throws(() => mem.addLesson(dir, { class: 'nope', technique: 'x y z w', outcome: 'worked', evidence_ref: 'e' }), /class deve essere/, 'bad class rejected');
assert.throws(() => mem.addLesson(dir, { class: 'web', technique: 'short', outcome: 'worked', evidence_ref: 'e' }), /technique/, 'short technique rejected');
assert.throws(() => mem.addLesson(dir, { class: 'web', technique: 'some technique here ok', outcome: 'worked' }), /evidence_ref/, 'missing provenance rejected');
assert.throws(() => mem.addLesson(dir, { class: 'web', technique: 'some technique here ok', outcome: 'blocked', evidence_ref: 'e' }), /cause obbligatoria/, 'blocked without cause rejected');

// --- sanitizer: engagement data must not enter the store ---
for (const [label, payload] of [
  ['in-scope host', { note: 'works on example.com staging' }],
  ['ip literal', { note: 'pivot via 203.0.113.10 ssh' }],
  ['email', { note: 'admin contact admin@example.com leaked' }],
  ['jwt', { note: 'replay token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 works' }],
  ['cred kv', { note: 'default creds {"password":"hunter2secret"} on panel' }],
]) {
  const base = { class: 'web', technique: payload.note + ' padded to pass length check', outcome: 'worked', evidence_ref: 'x' };
  assert.throws(() => mem.addLesson(dir, base), /sanitizer/, `sanitizer rejects ${label}`);
}

// --- search: ranking + filters ---
mem.rebuildIndex(dir);
let hits = mem.searchLessons(dir, 'wordpress sqli time-based');
assert.ok(hits.length >= 1 && hits[0].rec.id === 'LES-0001', 'tag/stack match ranks first');
hits = mem.searchLessons(dir, 'jwt');
assert.ok(hits.some((h) => h.rec.id === 'LES-0002'), 'failure lesson retrievable too');
assert.deepStrictEqual(mem.searchLessons(dir, 'zzz-nonexistent-topic'), [], 'no match -> empty');

// --- reinforce / contradict / review / retire lifecycle ---
const r1 = mem.contradict(dir, 'LES-0001');
assert.strictEqual(r1.status, 'active', 'one contradiction keeps active');
const r2 = mem.contradict(dir, 'LES-0001');
assert.strictEqual(r2.status, 'review', 'two contradictions force review');
assert.deepStrictEqual(mem.searchLessons(dir, 'wordpress sqli').map((h) => h.rec.id), [], 'review lessons excluded from search');
assert.ok(mem.searchLessons(dir, 'wordpress sqli', { all: true }).length, '--all includes review');
const r3 = mem.reinstate(dir, 'LES-0001');
assert.strictEqual(r3.status, 'active');
const r4 = mem.retire(dir, 'LES-0002', 'superseded by library fix');
assert.strictEqual(r4.status, 'retired');
assert.deepStrictEqual(mem.searchLessons(dir, 'jwt').map((h) => h.rec.id), [], 'retired excluded from search');

// --- env profiles ---
const e1 = mem.addEnvProfile(dir, {
  class: 'web', waf: 'cloudflare',
  note: 'tolerates ~1 rps sustained; bursts above 3 rps trigger managed challenge for 10 min',
  quirks: ['cache hit returns stale 403 page', 'real ip via cf-connecting-ip only on origin'],
  rate_notes: 'safe pace 1 rps',
  evidence_ref: 'EV-50',
});
assert.strictEqual(e1.id, 'ENV-0001');
const envHits = mem.searchLessons(dir, 'cloudflare challenge rate', { envOnly: true });
assert.ok(envHits.length === 1 && envHits[0].rec.id === 'ENV-0001', 'env-only search works');
assert.throws(() => mem.addEnvProfile(dir, { class: 'web', note: 'waf on 10.0.0.7 blocks scanners' }), /IP literal/, 'env profile sanitized too');

// --- promote flow ---
const promo = mem.promote(dir, 'LES-0001');
assert.ok(fs.existsSync(promo.promoFile) && fs.readFileSync(promo.promoFile, 'utf8').includes('LES-0001'), 'promotions.md gets candidate edit');
const st = mem.stats(dir);
assert.strictEqual(st.lessons_total, 2);
assert.strictEqual(st.review + st.retired, 2 - st.active, 'status accounting coherent');
assert.strictEqual(st.promoted, 1);

// --- INDEX.md regenerated and grep-able ---
const idx = fs.readFileSync(path.join(dir, mem.INDEX_FILE), 'utf8');
assert.ok(idx.includes('LES-0001') && idx.includes('ENV-0001') && idx.includes('# Memory index'), 'index contains ids');

fs.rmSync(dir, { recursive: true, force: true });
console.log('test-memory.js: ALL PASS');
