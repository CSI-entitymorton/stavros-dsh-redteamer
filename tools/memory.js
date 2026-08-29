#!/usr/bin/env node
// memory.js — durable, sanitized lessons-learned store for cross-engagement self-improvement.
//
// Three-layer memory model of the harness:
//   episodic   -> reports/ + evidence-index.md + findings DB (raw, client-bound, gitignored)
//   distilled  -> memory/lessons.jsonl + memory/env-profiles.jsonl  (THIS tool; committed, sanitized)
//   procedural -> playbook edits + reusable tools/templates (promote flow)
//
// Commands:
//   add      --file lesson.json | --stdin [--allow-sensitive]
//   add-env  --file env.json    | --stdin
//   search   "<query>" [--class web] [--tag x] [--outcome worked] [--env] [--all] [--limit 5] [--json]
//   review   list | --contradict LES-0007 | --retire LES-0007 [--reason s] | --reinstate LES-0007
//   promote  LES-0007            # mark promoted, append candidate playbook edit to memory/promotions.md
//   stats
//
// Sanitizer (add-time, enforced): rejects in-scope hosts from scope.json, ANY IP literal
// (except 127.0.0.1/0.0.0.0), emails, JWTs, long hex/base64 blobs, cred-like JSON keys.
// Lessons must be abstractions (class/stack/technique), never engagement data.
//
// Zero-dep. Self-test: node tools/test-memory.js
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MEMORY_DIR = process.env.STAVROS_MEMORY_DIR || path.join(ROOT, 'memory');
const LESSONS_FILE = 'lessons.jsonl';
const ENV_FILE = 'env-profiles.jsonl';
const INDEX_FILE = 'INDEX.md';
const PROMO_FILE = 'promotions.md';

const CLASSES = ['web', 'api', 'mobile', 'network', 'cloud', 'wifi', 'ad', 'generic'];
const OUTCOMES = ['worked', 'failed', 'blocked'];
const CONTRADICT_REVIEW_THRESHOLD = 2;

// ---------- io helpers ----------
function ensureDir(dir) { fs.mkdirSync(dir, { recursive: true }); }
function memPath(dir, name) { return path.join(dir, name); }

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  const out = [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch (e) {
      process.stderr.write(`[memory] WARN ${path.basename(file)}:${i + 1} bad json skipped\n`);
    }
  }
  return out;
}

function appendJsonl(file, obj) {
  fs.appendFileSync(file, JSON.stringify(obj) + '\n');
}

function rewriteJsonl(file, records) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, records.map((r) => JSON.stringify(r)).join('\n') + (records.length ? '\n' : ''));
  fs.renameSync(tmp, file);
}

function nextId(records, prefix) {
  let max = 0;
  for (const r of records) {
    const m = /^([A-Z]+)-(\d+)$/.exec(r.id || '');
    if (m && m[1] === prefix) max = Math.max(max, parseInt(m[2], 10));
  }
  return `${prefix}-${String(max + 1).padStart(4, '0')}`;
}

// ---------- sanitizer ----------
function scopeFingerprints() {
  const fps = new Set();
  // SCOPE_JSON: override per i test (fixture in mkdtemp); default = <workspace>/scope.json
  const p = process.env.SCOPE_JSON || path.join(ROOT, 'scope.json');
  if (fs.existsSync(p)) {
    try {
      const sc = JSON.parse(fs.readFileSync(p, 'utf8'));
      for (const h of sc.allowed_hosts || []) {
        const host = String(h).toLowerCase();
        fps.add(host);
        const labels = host.replace(/^\*\./, '').split('.');
        if (labels.length >= 2) fps.add(labels.slice(-2).join('.')); // base domain
        if (labels.length >= 3) fps.add(labels.slice(-3).join('.')); // co.uk-style safety
      }
      for (const ip of sc.allowed_ips || []) fps.add(String(ip).split('/')[0]);
    } catch (_) { /* scope unreadable: proceed with generic checks only */ }
  }
  return [...fps].filter((x) => x.length >= 4);
}

function sanitizeViolations(record) {
  const text = JSON.stringify(record).toLowerCase().replace(/\\"/g, '"');
  const v = [];
  for (const fp of scopeFingerprints()) {
    if (text.includes(fp.toLowerCase())) v.push(`in-scope fingerprint: "${fp}"`);
  }
  const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
  for (const ip of new Set(ips)) {
    if (ip !== '127.0.0.1' && ip !== '0.0.0.0') v.push(`IP literal: ${ip} — generalizza a classe di target`);
  }
  const emails = text.match(/\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b/g) || [];
  for (const e of new Set(emails)) v.push(`email: ${e}`);
  const jwts = text.match(/\beyj[a-z0-9_-]{10,}/g) || [];
  for (const j of new Set(jwts)) v.push(`JWT/token fragment: ${j.slice(0, 18)}…`);
  const blobs = text.match(/\b[a-f0-9]{32,}\b|\b[a-z0-9+/]{40,}={0,2}\b/g) || [];
  for (const b of new Set(blobs)) v.push(`long secret-like blob: ${b.slice(0, 16)}…`);
  const credKv = text.match(/"(?:password|passwd|secret|api[_-]?key|apikey|authorization|cookie)"\s*:\s*"[^"]{4,}"/g) || [];
  for (const c of new Set(credKv)) v.push(`credential-like key/value: ${c.slice(0, 30)}…`);
  return v;
}

// ---------- validation ----------
function validateLesson(l) {
  const errs = [];
  if (!CLASSES.includes(l.class)) errs.push(`class deve essere una di: ${CLASSES.join('|')}`);
  if (typeof l.technique !== 'string' || l.technique.trim().length < 8) errs.push('technique: stringa descrittiva (>=8 char)');
  if (!OUTCOMES.includes(l.outcome)) errs.push(`outcome deve essere: ${OUTCOMES.join('|')}`);
  if (typeof l.evidence_ref !== 'string' || !l.evidence_ref.trim()) errs.push('evidence_ref obbligatoria (provenance: report/EV/sessione)');
  if ((l.outcome === 'failed' || l.outcome === 'blocked') && !(typeof l.cause === 'string' && l.cause.trim().length >= 8)) {
    errs.push('cause obbligatoria (>=8 char) per failed/blocked — il perché è il valore della lezione');
  }
  if (l.tags != null && !Array.isArray(l.tags)) errs.push('tags: array di stringhe');
  if (l.stack != null && !Array.isArray(l.stack)) errs.push('stack: array di stringhe');
  return errs;
}

// ---------- core ops (exported, dir-injectable for tests) ----------
function addLesson(dir, input, { allowSensitive = false } = {}) {
  const rec = {
    id: null,
    ts: new Date().toISOString(),
    class: input.class,
    stack: Array.isArray(input.stack) ? input.stack.map(String) : [],
    waf: typeof input.waf === 'string' ? input.waf : 'unknown',
    technique: String(input.technique || '').trim(),
    outcome: input.outcome,
    cause: typeof input.cause === 'string' ? input.cause.trim() : '',
    confidence: {
      worked: input.outcome === 'worked' ? 1 : 0,
      seen: 1,
      contradicted: 0,
    },
    evidence_ref: String(input.evidence_ref || '').trim(),
    source_session: typeof input.source_session === 'string' ? input.source_session : '',
    tags: Array.isArray(input.tags) ? input.tags.map((t) => String(t).toLowerCase()) : [],
    status: 'active',
    promoted: false,
    sanitized: true,
  };
  const errs = validateLesson(rec);
  if (errs.length) throw new Error('validazione fallita:\n  - ' + errs.join('\n  - '));
  const violations = sanitizeViolations({ ...rec, id: undefined, ts: undefined });
  if (violations.length && !allowSensitive) {
    throw new Error('sanitizer: dati di engagement rilevati — generalizza la lezione prima di salvare:\n  - ' +
      violations.map((s) => s.replace(/\n/g, ' ')).join('\n  - ') +
      '\n  (bypass esplicito: --allow-sensitive — NON usare per dati cliente)');
  }
  rec.sanitized = violations.length === 0;
  const lessons = readJsonl(memPath(dir, LESSONS_FILE));
  rec.id = nextId(lessons, 'LES');
  ensureDir(dir);
  appendJsonl(memPath(dir, LESSONS_FILE), rec);
  rebuildIndex(dir);
  return rec;
}

function addEnvProfile(dir, input) {
  const rec = {
    id: null,
    ts: new Date().toISOString(),
    class: CLASSES.includes(input.class) ? input.class : 'generic',
    waf: typeof input.waf === 'string' ? input.waf : 'unknown',
    note: String(input.note || '').trim(),
    quirks: Array.isArray(input.quirks) ? input.quirks.map(String) : [],
    rate_notes: typeof input.rate_notes === 'string' ? input.rate_notes : '',
    evidence_ref: String(input.evidence_ref || '').trim() || 'unrecorded',
    status: 'active',
  };
  if (rec.note.length < 8) throw new Error('note: descrizione ambiente (>=8 char)');
  const violations = sanitizeViolations({ note: rec.note, quirks: rec.quirks, rate_notes: rec.rate_notes });
  if (violations.length) {
    throw new Error('sanitizer: ' + violations.map((s) => s.replace(/\n/g, ' ')).join('; '));
  }
  const profiles = readJsonl(memPath(dir, ENV_FILE));
  rec.id = nextId(profiles, 'ENV');
  ensureDir(dir);
  appendJsonl(memPath(dir, ENV_FILE), rec);
  rebuildIndex(dir);
  return rec;
}

function tokenize(s) {
  return String(s || '').toLowerCase().match(/[a-z0-9_.+-]{2,}/g) || [];
}

const FIELD_WEIGHTS = [
  ['tags', 3], ['class', 2.5], ['stack', 2.5], ['waf', 2],
  ['technique', 1.5], ['cause', 1], ['note', 1.5], ['quirks', 2],
];

function fieldTokens(rec, field) {
  const v = rec[field];
  if (Array.isArray(v)) return tokenize(v.join(' '));
  return tokenize(v);
}

function matchScore(rec, qTokens) {
  let score = 0;
  const bags = FIELD_WEIGHTS.map(([f, w]) => [fieldTokens(rec, f), w]).filter(([bag]) => bag.length);
  for (const qt of qTokens) {
    let best = 0;
    for (const [bag, w] of bags) {
      if (bag.includes(qt)) best = Math.max(best, w);
      else if (qt.length >= 4 && bag.some((t) => t.startsWith(qt))) best = Math.max(best, w * 0.5);
    }
    score += best;
  }
  return score;
}

function scoreRecord(rec, qTokens) {
  let score = matchScore(rec, qTokens);
  if (rec.confidence) score += 0.3 * Math.min(rec.confidence.worked || 0, 3);
  if (rec.ts) {
    const ageDays = (Date.now() - Date.parse(rec.ts)) / 86400000;
    if (Number.isFinite(ageDays) && ageDays < 90) score += 0.2;
  }
  return score;
}

function searchLessons(dir, query, opts = {}) {
  const limit = opts.limit || 5;
  const qTokens = tokenize(query);
  const pools = [];
  if (!opts.envOnly) pools.push(...readJsonl(memPath(dir, LESSONS_FILE)).map((r) => ({ kind: 'lesson', rec: r })));
  if (opts.env || opts.envOnly) pools.push(...readJsonl(memPath(dir, ENV_FILE)).map((r) => ({ kind: 'env', rec: r })));
  const hits = pools
    .filter(({ rec }) => (opts.all ? true : rec.status === 'active'))
    .filter(({ rec }) => (opts.cls ? rec.class === opts.cls : true))
    .filter(({ rec }) => (opts.tag ? (rec.tags || []).includes(opts.tag.toLowerCase()) : true))
    .filter(({ rec }) => (opts.outcome ? rec.outcome === opts.outcome : true))
    .filter(({ rec }) => (opts.env || opts.envOnly ? true : !qTokens.length || matchScore(rec, qTokens) > 0))
    .map(({ kind, rec }) => ({ kind, rec, score: scoreRecord(rec, qTokens) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
  return hits;
}

function updateLesson(dir, id, mutator) {
  const file = memPath(dir, LESSONS_FILE);
  const lessons = readJsonl(file);
  const idx = lessons.findIndex((r) => r.id === id);
  if (idx === -1) throw new Error(`${id} non trovata`);
  mutator(lessons[idx]);
  rewriteJsonl(file, lessons);
  rebuildIndex(dir);
  return lessons[idx];
}

function contradict(dir, id) {
  return updateLesson(dir, id, (r) => {
    r.confidence.contradicted = (r.confidence.contradicted || 0) + 1;
    r.confidence.seen = (r.confidence.seen || 1) + 1;
    if (r.confidence.contradicted >= CONTRADICT_REVIEW_THRESHOLD && r.status === 'active') {
      r.status = 'review';
    }
  });
}

function reinforce(dir, id) {
  return updateLesson(dir, id, (r) => {
    r.confidence.seen = (r.confidence.seen || 1) + 1;
    if (r.outcome === 'worked') r.confidence.worked = (r.confidence.worked || 0) + 1;
  });
}

function retire(dir, id, reason) {
  return updateLesson(dir, id, (r) => { r.status = 'retired'; r.retire_reason = reason || ''; });
}

function reinstate(dir, id) {
  return updateLesson(dir, id, (r) => { r.status = 'active'; r.retire_reason = ''; });
}

function promote(dir, id) {
  const file = memPath(dir, LESSONS_FILE);
  const lessons = readJsonl(file);
  const rec = lessons.find((r) => r.id === id);
  if (!rec) throw new Error(`${id} non trovata`);
  if (!rec.promoted) {
    rec.promoted = true;
    rewriteJsonl(file, lessons);
  }
  ensureDir(dir);
  const block = [
    `## Candidate playbook edit — ${rec.id} (${new Date().toISOString().slice(0, 10)})`,
    `- Class: ${rec.class} | Stack: ${(rec.stack || []).join(', ') || '—'} | WAF: ${rec.waf}`,
    `- Technique: ${rec.technique}`,
    `- Outcome: ${rec.outcome}${rec.cause ? ` — ${rec.cause}` : ''} [worked×${rec.confidence.worked}, seen×${rec.confidence.seen}]`,
    `- Provenance: ${rec.evidence_ref}`,
    ``,
  ].join('\n');
  fs.appendFileSync(memPath(dir, PROMO_FILE), block);
  rebuildIndex(dir);
  return { rec, promoFile: memPath(dir, PROMO_FILE) };
}

// ---------- index / stats / formatting ----------
function fmtRec(kind, rec, score) {
  if (kind === 'env') {
    return `${rec.id} ▸ env │ ${rec.class}/${rec.waf} │ ${rec.note}` +
      (rec.rate_notes ? ` │ rate: ${rec.rate_notes}` : '');
  }
  const conf = rec.confidence || {};
  const flag = rec.status !== 'active' ? ` ⚠${rec.status}` : '';
  return `${rec.id} ▸ ${rec.outcome}[worked×${conf.worked || 0},seen×${conf.seen || 1}]${flag} │ ` +
    `${rec.class}/${(rec.stack || []).join('+') || '-'}+${rec.waf} │ ${rec.technique}` +
    (rec.tags && rec.tags.length ? ` │ tags:${rec.tags.join(',')}` : '') +
    ` │ ev:${rec.evidence_ref}` +
    (score != null ? ` │ score=${score.toFixed(1)}` : '');
}

function rebuildIndex(dir) {
  ensureDir(dir);
  const lessons = readJsonl(memPath(dir, LESSONS_FILE));
  const envs = readJsonl(memPath(dir, ENV_FILE));
  const byClass = {};
  for (const l of lessons) (byClass[l.class] = byClass[l.class] || []).push(l);
  let md = '# Memory index — lezioni distillate (grep-first)\n\n';
  md += '> Rigenerato da `tools/memory.js` ad ogni mutazione. Non editare a mano.\n';
  md += '> Recupero: `node tools/memory.js search "<classe> <tech>"`. Lezioni retired/review escluse dal search.\n\n';
  for (const cls of Object.keys(byClass).sort()) {
    md += `## ${cls} (${byClass[cls].length})\n`;
    for (const l of byClass[cls]) {
      const flag = l.status !== 'active' ? ` ⚠${l.status}` : '';
      md += `- ${l.id}${flag} [${l.outcome}×${(l.confidence && l.confidence.worked) || 0}] ${l.technique.slice(0, 110)}\n`;
    }
    md += '\n';
  }
  if (envs.length) {
    md += `## env-profiles (${envs.length})\n`;
    for (const e of envs) md += `- ${e.id} (${e.class}/${e.waf}) ${e.note.slice(0, 110)}\n`;
    md += '\n';
  }
  if (!lessons.length && !envs.length) md += '_Vuoto: nessuna lezione ancora distillata._\n';
  fs.writeFileSync(memPath(dir, INDEX_FILE), md);
}

function stats(dir) {
  const lessons = readJsonl(memPath(dir, LESSONS_FILE));
  const envs = readJsonl(memPath(dir, ENV_FILE));
  const count = (fn) => lessons.filter(fn).length;
  return {
    lessons_total: lessons.length,
    active: count((l) => l.status === 'active'),
    review: count((l) => l.status === 'review'),
    retired: count((l) => l.status === 'retired'),
    worked: count((l) => l.outcome === 'worked'),
    failed_or_blocked: count((l) => l.outcome !== 'worked'),
    promoted: count((l) => l.promoted),
    unsanitized: count((l) => l.sanitized === false),
    env_profiles: envs.length,
  };
}

// ---------- CLI ----------
function readInputJson(argv) {
  const fi = argv.indexOf('--file');
  if (fi !== -1 && argv[fi + 1]) return JSON.parse(fs.readFileSync(argv[fi + 1], 'utf8'));
  if (argv.includes('--stdin')) return JSON.parse(fs.readFileSync(0, 'utf8'));
  throw new Error('serve --file <json> oppure --stdin (JSON su stdin)');
}

function optValue(argv, flag, dflt) {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : dflt;
}
function hasFlag(argv, f) { return argv.includes(f); }

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const dir = MEMORY_DIR;
  try {
    switch (cmd) {
      case 'add': {
        const rec = addLesson(dir, readInputJson(argv), { allowSensitive: hasFlag(argv, '--allow-sensitive') });
        console.log(JSON.stringify({ ok: true, id: rec.id, sanitized: rec.sanitized }, null, 2));
        break;
      }
      case 'add-env': {
        const rec = addEnvProfile(dir, readInputJson(argv));
        console.log(JSON.stringify({ ok: true, id: rec.id }, null, 2));
        break;
      }
      case 'search': {
        const query = argv[1] && !argv[1].startsWith('--') ? argv[1] : '';
        const hits = searchLessons(dir, query, {
          cls: optValue(argv, '--class', null),
          tag: optValue(argv, '--tag', null),
          outcome: optValue(argv, '--outcome', null),
          limit: parseInt(optValue(argv, '--limit', '5'), 10),
          env: hasFlag(argv, '--env'),
          envOnly: hasFlag(argv, '--env-only'),
          all: hasFlag(argv, '--all'),
        });
        if (hasFlag(argv, '--json')) {
          console.log(JSON.stringify(hits.map(({ kind, rec, score }) => ({ kind, score: +score.toFixed(2), ...rec })), null, 2));
        } else {
          if (!hits.length) { console.log('nessuna lezione corrispondente'); break; }
          for (const h of hits) console.log(fmtRec(h.kind, h.rec, h.score));
        }
        break;
      }
      case 'review': {
        const rest = argv.slice(1);
        if (rest.includes('--contradict')) {
          const r = contradict(dir, optValue(rest, '--contradict', null));
          console.log(`${r.id}: contradicted×${r.confidence.contradicted} status=${r.status}`);
        } else if (rest.includes('--reinforce')) {
          const r = reinforce(dir, optValue(rest, '--reinforce', null));
          console.log(`${r.id}: worked×${r.confidence.worked} seen×${r.confidence.seen}`);
        } else if (rest.includes('--retire')) {
          const r = retire(dir, optValue(rest, '--retire', null), optValue(rest, '--reason', ''));
          console.log(`${r.id}: retired (${r.retire_reason || 'no reason'})`);
        } else if (rest.includes('--reinstate')) {
          const r = reinstate(dir, optValue(rest, '--reinstate', null));
          console.log(`${r.id}: active`);
        } else { // list non-active first
          const all = readJsonl(memPath(dir, LESSONS_FILE));
          const sorted = [...all].sort((a, b) => (a.status === 'active') - (b.status === 'active'));
          if (!sorted.length) { console.log('nessuna lezione'); break; }
          for (const r of sorted) console.log(fmtRec('lesson', r));
        }
        break;
      }
      case 'promote': {
        const { rec, promoFile } = promote(dir, argv[1]);
        console.log(`${rec.id}: marcata promoted — candidate edit aggiunta a ${path.relative(ROOT, promoFile)} (applica dopo review umana)`);
        break;
      }
      case 'stats':
        console.log(JSON.stringify(stats(dir), null, 2));
        break;
      case 'index':
        rebuildIndex(dir);
        console.log(`INDEX rigenerato: ${path.relative(ROOT, memPath(dir, INDEX_FILE))}`);
        break;
      default:
        console.log([
          'usage:',
          '  node tools/memory.js add --file lesson.json | --stdin [--allow-sensitive]',
          '  node tools/memory.js add-env --file env.json | --stdin',
          '  node tools/memory.js search "<query>" [--class c] [--tag t] [--outcome o] [--env] [--all] [--limit n] [--json]',
          '  node tools/memory.js review [list | --contradict ID | --reinforce ID | --retire ID [--reason r] | --reinstate ID]',
          '  node tools/memory.js promote ID',
          '  node tools/memory.js stats | index',
        ].join('\n'));
        process.exit(cmd ? 1 : 0);
    }
  } catch (e) {
    process.stderr.write(`[memory] ERRORE: ${e.message}\n`);
    process.exit(1);
  }
}

module.exports = {
  addLesson, addEnvProfile, searchLessons, contradict, reinforce, retire, reinstate,
  promote, stats, rebuildIndex, sanitizeViolations, validateLesson, readJsonl,
  LESSONS_FILE, ENV_FILE, INDEX_FILE, PROMO_FILE,
};

if (require.main === module) main();
