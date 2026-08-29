#!/usr/bin/env node
// Append one structured finding to reports/findings.jsonl (deterministic, dedupable).
//   node tools/record-finding.js '{"severity":"High","title":"...","host":"...","endpoint":"...","poc":"...","status":"confirmed"}'
// Optional fields: cvss (0-10 number), cvss_vector, cwe, impact, remediation, reference,
// cve/cves (CVE id(s)), epss (0-1), usage (F8, Ondata 4 — ADDITIVO sui record NUOVI:
// {tokens_in,tokens_out,cost} forniti dall'operatore via cli/env, mai API di pricing;
// i record esistenti restano intoccati, hash-chain A3 invariata). If cve/cves are present
// and epss is absent, epss is auto-filled (cached-live FIRST-EPSS score when
// tools/threatintel.js has refreshed it, else
// the offline map); CISA KEV membership (kev:true), a precise CWE and reference URLs are
// attached from the same threatintel cache. The reporter attaches CVSS + EPSS
// to the report (CVSS via tools/cvss.js). Validates severity + required fields. Dedupes on
// (host|endpoint|title).
//
// Ondata1 A1/A2/A3 (fail-closed quality gates — see tools/oracle.js / tools/evidence-quote.js):
//   A1 MECHANICAL ORACLE: status is NEVER defaulted anymore. Every finding sets an explicit
//     status. Reality claims (status confirmed|verified, or verify_level exploited|proven_impact)
//     REQUIRE a valid mechanical oracle: {type:'oob'|'http-diff'|'console'|'script', ref, token}
//     re-validated against disk (oracle log line, artifacts/oracle/*.json, or OOB markers/hits).
//     Hypothesis lanes without an oracle: status 'inconclusive' or verify_level
//     'suspected'|'triggered'. Missing status → REJECT with the valid roads listed.
//   A2 EXACT QUOTE: reality claims also require evidence_quote {file,text} where text is a
//     byte-per-byte substring of the workspace artifact `file`. Model summaries go in
//     f.diagnostics (free-form, documented NON-evidence; never checked).
//   A3 TAMPER-EVIDENT CHAIN: every appended line carries chain:{seq,prev_sha256,ts} where
//     prev_sha256 = sha256 of the previous non-empty RAW line ('0'*64 at genesis); record()
//     refuses to append when the existing chain is broken. Legacy unchained lines are anchored
//     (never failed retroactively) and reported as 'unchained-legacy'.
//   Ondata 6 — EXTERNAL HEAD ANCHORING (mitigation of the A3 whole-file-rewrite limit): after
//     every successful chained append the new head hash is recorded in an append-only side log
//     (env FINDINGS_HEAD_ANCHOR_FILE, default reports/tmp/findings-head-anchor.jsonl);
//     verifyHeadAnchor() re-hashes the anchored seq line so a regenerated chain, a truncated
//     or a wiped findings.jsonl can no longer match the anchored history. Anchor write is
//     best-effort but LOUD: failures surface in the record() result (head_anchor.ok=false).
// recordWithVerify() synthesizes a machine receipt (artifacts/oracle/<token>.json, type
// 'http-diff') for its N/N repeater re-fire — passed AND failed outcomes both get a receipt so
// a confirmed-with-verify_failed row still leaves a disk-backed mechanical trace.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { lookupMaxBestEpss, normCve, normCwe } = require('./epss');
const { claimingReality, validateOracle, GENESIS } = require('./oracle');
const { validateQuote } = require('./evidence-quote');

const SEV = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const REQUIRED = ['severity', 'title', 'host', 'poc'];
// Verification-level taxonomy (from the pentest persona, SeaOf0/dsh-redteam-model MIT):
//   suspected     → 疑似          (theoretical — reported as such, never overrated)
//   triggered     → 已触发未利用   (triggered, not exploited)
//   exploited     → 完整利用链     (full exploit chain)
//   proven_impact → 影响证明       (proven impact — requires status verified)
// Severity ceiling per level: a finding's severity must never exceed its verification level.
const VERIFY_LEVELS = ['suspected', 'triggered', 'exploited', 'proven_impact'];
const SEVERITY_CEILING = { suspected: 'Low', triggered: 'Medium', exploited: 'High', proven_impact: 'Critical' };
function severityAllowedAt(level, severity) {
  const cap = SEVERITY_CEILING[level];
  if (!cap) return false;
  // SEV is ordered most-severe first (Critical=0): a severity is allowed iff it is NOT more
  // severe than the level's ceiling, i.e. its index is >= the ceiling's index.
  return SEV.indexOf(severity) >= SEV.indexOf(cap);
}
const OUT = () => process.env.FINDINGS_JSONL || path.join(__dirname, '..', 'reports', 'findings.jsonl');
const LOOT = () => process.env.LOOT_JSONL || path.join(__dirname, '..', 'reports', 'loot.jsonl');
// Free-text fields that may carry captured request/response evidence; scrubbed before disk.
const REDACT_FIELDS = ['poc', 'impact', 'remediation', 'reference', 'notes'];

// Strip secrets/tokens from evidence so findings.jsonl never persists live JWTs, cookies,
// or API keys while keeping the structural proof intact.
function redact(s) {
  if (typeof s !== 'string') return s;
  return s
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?/g, 'JWT_REDACTED')
    .replace(/(Authorization\s*:\s*Bearer\s+)[^\s,;"']+/gi, '$1REDACTED')
    .replace(/(set-cookie\s*:\s*)[^\r\n]+/gi, '$1REDACTED')
    .replace(/(cookie\s*:\s*)[^\r\n]+/gi, '$1REDACTED')
    .replace(/\b(sk_live_[A-Za-z0-9]+)/g, 'STRIPE_KEY_REDACTED')
    .replace(/\b(AKIA[0-9A-Z]{16})\b/g, 'AWS_KEY_REDACTED')
    .replace(/\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, 'SLACK_TOKEN_REDACTED')
    .replace(/\b(ghp_[A-Za-z0-9]{20,})\b/g, 'GITHUB_TOKEN_REDACTED')
    .replace(/\b(AIza[0-9A-Za-z_-]{35})\b/g, 'GOOGLE_KEY_REDACTED');
}

// ---- standards registry (REDflare pattern, repo-vet plan QW7) ----
// A finding may carry `class` (a test-registry key, e.g. "idor"); valid classes are enriched
// with WSTG/ASVS/CWE/OWASP-API pointers. Without an explicit class we reverse-map from cwe.
const REGISTRY = (() => {
  try {
    const reg = JSON.parse(fs.readFileSync(path.join(__dirname, 'test-registry.json'), 'utf8'));
    return (reg && reg.classes) || {};
  } catch { return {}; }
})();

function registryClasses() {
  return Object.keys(REGISTRY).filter((k) => !k.startsWith('_'));
}

function standardsFor(f) {
  if (typeof f.standards === 'object' && f.standards !== null) return f.standards; // operator wins
  let cls = null;
  if (f.class && REGISTRY[f.class]) cls = f.class;
  else if (f.cwe) {
    const want = normCwe(f.cwe);
    cls = registryClasses().find((k) => Array.isArray(REGISTRY[k].cwe) && REGISTRY[k].cwe.includes(want)) || null;
  }
  if (!cls) return undefined;
  const r = REGISTRY[cls];
  return {
    class: cls,
    wstg: r.wstg || [],
    asvs: r.asvs || [],
    owasp_api: r.owasp_api || [],
    ...(r.cwe && r.cwe.length ? { cwe: r.cwe } : {}),
  };
}

// `class` is optional but, when present, must be a known registry key (keeps the taxonomy
// honest so standards enrichment and reporting can rely on it).
function validate(f) {
  for (const k of REQUIRED) if (!f[k] || String(f[k]).trim() === '') return `missing field: ${k}`;
  if (f.class && !REGISTRY[f.class])
    return `unknown class '${f.class}' (use one of test-registry classes: ${registryClasses().join('/')})`;
  if (!SEV.includes(f.severity)) return `severity must be one of ${SEV.join('/')}`;
  if (f.status && !['confirmed', 'inconclusive', 'verified'].includes(f.status)) return 'status must be confirmed|inconclusive|verified';
  if (f.verify_level && !VERIFY_LEVELS.includes(f.verify_level))
    return `verify_level must be one of ${VERIFY_LEVELS.join('|')} (suspected|triggered|exploited|proven_impact)`;
  // Coherence: severity must never exceed the verification level (pentest persona rule).
  if (f.verify_level && f.severity && !severityAllowedAt(f.verify_level, f.severity))
    return `severity ${f.severity} exceeds verify_level ${f.verify_level}: proven_impact→Critical, exploited→High max, triggered→Medium max, suspected→Low max`;
  // Coherence: status vs verify_level — proven_impact requires verified; suspected forbids verified.
  if (f.verify_level === 'proven_impact' && f.status && f.status !== 'verified')
    return 'verify_level proven_impact requires status verified (proof of impact must be re-verified)';
  if (f.verify_level === 'suspected' && f.status === 'verified')
    return 'verify_level suspected cannot have status verified (suspected = unverified by definition)';
  // ── A1: mechanical oracle discipline (fail-closed; no silent status default anywhere) ──
  if (!f.status)
    return 'status is required (no default): record an hypothesis {"status":"inconclusive"} or '
      + '{"verify_level":"suspected"|"triggered"}, or claim reality explicitly with '
      + '{"status":"confirmed"|"verified"|"inconclusive"...} plus a mechanical oracle '
      + '{"oracle":{"type":"oob|http-diff|console|script","ref":"<reports/tmp/oracle-log.jsonl#N | artifacts/oracle/<f>.json | OOB markers/hits>","token":"<8-256 chars>"}}';
  if (f.oracle != null) {
    const oerr = validateOracle(f.oracle);
    if (oerr) return `invalid oracle: ${oerr}`;
  }
  if (claimingReality(f) && f.oracle == null)
    return `reality claim (status=${f.status}${f.verify_level ? '/verify_level=' + f.verify_level : ''}) requires a mechanical oracle {type,ref,token} validated against disk (node tools/oracle.js record ... → usable ref); hypothesis levels (inconclusive/suspected/triggered) are exempt`;
  // ── A2: evidence = exact quote of a workspace artifact ──
  const qerr = validateQuote(f);
  if (qerr) return qerr;
  if (f.cvss != null && (typeof f.cvss !== 'number' || isNaN(f.cvss) || f.cvss < 0 || f.cvss > 10))
    return 'cvss must be a number 0..10';
  if (f.cvss_vector && !/^(?:AV:[NALP]\/)?AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/.test(f.cvss_vector))
    return 'cvss_vector must look like AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  if (f.epss != null && (typeof f.epss !== 'number' || isNaN(f.epss) || f.epss < 0 || f.epss > 1))
    return 'epss must be a number 0..1';
  // F8 (Ondata 4, ADDITIVO): campo usage opzionale sui record NUOVI ({tokens_in,tokens_out,
  // cost}). Mai toccato sui record esistenti (hash-chain A3 intatta); semantica: token forniti
  // dall'operatore via cli/env (MAI API di pricing), cost "se noto". Il campo entra nella
  // catena come qualsiasi altro (JSON serializzato + chain).
  if (f.usage != null) {
    if (typeof f.usage !== 'object' || Array.isArray(f.usage)) return 'usage must be an object {tokens_in,tokens_out,cost}';
    const u = f.usage;
    for (const k of ['tokens_in', 'tokens_out']) {
      if (u[k] !== undefined && u[k] !== null && (!Number.isInteger(u[k]) || u[k] < 0))
        return `usage.${k} must be a non-negative int`;
    }
    if (u.cost !== undefined && u.cost !== null && (typeof u.cost !== 'number' || !Number.isFinite(u.cost) || u.cost < 0))
      return 'usage.cost must be a non-negative number';
  }
  return null;
}

function key(f) {
  return `${f.host}|${f.endpoint || ''}|${f.title}`.toLowerCase();
}

// Canonicalize cve/cves into a single `cves` array (normalized, deduped) and drop the scalar
// `cve` form. Returns the list. Used by record() to attach an offline EPSS score when missing.
function normalizeCves(f) {
  const raw = [];
  if (Array.isArray(f.cves)) raw.push(...f.cves);
  if (typeof f.cve === 'string' && f.cve.trim()) raw.push(f.cve);
  const seen = new Set();
  const out = [];
  for (const c of raw) {
    const id = normCve(c);
    if (id && id !== 'CVE-' && !seen.has(id)) { seen.add(id); out.push(id); }
  }
  if (out.length) { f.cves = out; delete f.cve; }
  return out;
}

// If the finding names CVEs but has no explicit epss, attach the best EPSS score available:
// cached-live (FIRST EPSS API via tools/threatintel.js refresh) when warmed, else the embedded
// snapshot. Unknown CVEs simply get no epss (never fabricated as 0.0).
function enrichEpss(f) {
  const cves = normalizeCves(f);
  if (cves.length && f.epss == null) {
    const best = lookupMaxBestEpss(cves);
    if (best) {
      f.epss = best.epss;
      f.epss_percentile = best.percentile;
      f.epss_source = best.source;
    }
  }
  return f;
}

// CVE intel enrichment from the threatintel disk cache (synchronous, deterministic — the live
// fetch is an explicit `node tools/threatintel.js refresh <CVE>` step). Attaches:
//   kev:true (+ date/ransomware flag) when any CVE is in CISA KEV,
//   a precise CWE from NVD when the finding has none of its own,
//   reference URLs (capped) when the finding has none of its own.
// Never overwrites operator-provided values, never fabricates a negative as certainty when the
// catalog is missing (kev:false only when a catalog is actually cached).
function enrichCveIntel(f) {
  const cves = Array.isArray(f.cves) ? f.cves : [];
  if (!cves.length) return f;
  let ti;
  try { ti = require('./threatintel'); } catch { return f; }
  const perCve = [];
  for (const c of cves) {
    const intel = ti.lookupCached(c);
    if (intel) perCve.push(intel);
  }
  if (!perCve.length) return f;
  const kevHit = perCve.find((i) => i.kev === true);
  if (kevHit) {
    f.kev = true;
    if (kevHit.kev_date_added) f.kev_date_added = kevHit.kev_date_added;
    if (kevHit.kev_ransomware) f.kev_ransomware_use = true;
  } else if (perCve.some((i) => i.kev === false)) {
    f.kev = false;
  }
  if (!f.cwe) {
    const counts = {};
    for (const i of perCve) for (const w of i.cwes || []) counts[w] = (counts[w] || 0) + 1;
    const top = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
    if (top) f.cwe = top;
  }
  if (!f.reference) {
    const refs = [];
    for (const i of perCve) for (const r of i.refs || []) if (!refs.includes(r)) refs.push(r);
    if (refs.length) f.reference = refs.slice(0, 5).join(', ');
  }
  return f;
}

// Cleartext secrets (hashes, keys, tokens) never live in findings.jsonl. Move them to a
// gitignored vault (reports/loot.jsonl), leaving a fingerprint + loot_id in the finding.
function vaultSecret(f) {
  if (typeof f.secret !== 'string' || !f.secret.trim()) return;
  const raw = f.secret;
  const loot_id = crypto.randomBytes(6).toString('hex');
  const secret_fingerprint = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 12);
  fs.mkdirSync(path.dirname(LOOT()), { recursive: true });
  fs.appendFileSync(LOOT(), JSON.stringify({
    loot_id, secret_fingerprint, host: f.host, title: f.title, secret: raw, ts: new Date().toISOString(),
  }) + '\n');
  delete f.secret;
  f.secret_fingerprint = secret_fingerprint;
  f.loot_id = loot_id;
}

// Best-effort mirror into the DSH "Findings" tab (dsh-redteam-results SQLite store) so every
// finding recorded to findings.jsonl also shows up in the chat UI without a separate
// redteam_finding_register call. Idempotent: the row id is derived from the same dedup key,
// so re-runs UPDATE the existing row instead of duplicating it. Never fails the recording.
const TAB_DB = () => process.env.FINDINGS_TAB_DB || path.join(os.homedir(), '.dsh', 'redteam-results', 'results.db');
const TAB_SEVERITY = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Info: 'low' };

function tabTarget(f) {
  const h = String(f.host || '').trim();
  const ep = String(f.endpoint || '').trim();
  if (!ep) return h;
  if (/^https?:\/\//i.test(ep)) return ep;
  const joiner = ep.startsWith('/') ? '' : '/';
  if (/^https?:\/\//i.test(h)) return h.replace(/\/+$/, '') + joiner + ep;
  return h ? h + joiner + ep : ep;
}

function tabStatusOf(f) {
  // (status, evidenceLevel) — never overrates: only exploited/proven/verified count as verified.
  if (f.status === 'verified' || f.verified || f.verify_level === 'proven_impact' || f.verify_level === 'exploited')
    return ['verified', 'confirmed'];
  if (f.verify_level === 'triggered' || f.status === 'confirmed' || f.status === 'inconclusive')
    return ['pending', 'partial'];
  return ['pending', 'unknown'];
}

function syncToFindingsTab(f, opts) {
  const out = { tab_synced: false };
  try {
    const DatabaseSync = require('node:sqlite').DatabaseSync;
    const dbFile = (opts && opts.dbFile) || TAB_DB();
    if (/^\/(?:proc|sys|dev)\//.test(dbFile)) throw new Error('unusable FINDINGS_TAB_DB path: ' + dbFile);
    const sessionId = (opts && opts.sessionId) || process.env.DSH_SESSION_ID || 'session-cli';
    const mode = (opts && opts.mode) || process.env.FINDINGS_TAB_MODE || 'pentest'; // pentest page layout (vuln-report archetype)
    const id = 'st-' + crypto.createHash('sha256').update(key(f)).digest('hex').slice(0, 12);
    const [status, evidenceLevel] = tabStatusOf(f);
    const descBits = [];
    if (f.notes) descBits.push(String(f.notes));
    if (Array.isArray(f.cves) && f.cves.length) descBits.push('CVEs: ' + f.cves.join(', '));
    if (f.epss != null) descBits.push('EPSS: ' + f.epss + (f.epss_percentile != null ? ' (p' + f.epss_percentile + ')' : ''));
    if (f.verify_level) descBits.push('Verify level: ' + f.verify_level);
    if (f.verify_reason) descBits.push('Verify note: ' + f.verify_reason);
    if (f.secret_fingerprint) descBits.push('Secret fingerprint: ' + f.secret_fingerprint + ' (value vaulted)');
    const dbDir = path.dirname(dbFile);
    if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
    const db = new DatabaseSync(dbFile);
    db.exec('PRAGMA busy_timeout = 3000');
    db.exec(`CREATE TABLE IF NOT EXISTS findings (
	session_id TEXT NOT NULL, id TEXT NOT NULL, seq INTEGER NOT NULL, mode TEXT NOT NULL,
	title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, evidence_level TEXT NOT NULL DEFAULT 'unknown',
	type TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
	poc TEXT NOT NULL DEFAULT '', chain TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '', fix TEXT NOT NULL DEFAULT '',
	verify_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, verified_at TEXT NOT NULL DEFAULT '',
	cvss TEXT NOT NULL DEFAULT '', cwe TEXT NOT NULL DEFAULT '', PRIMARY KEY (session_id, id))`);
    const now = new Date().toISOString();
    const seq = db.prepare('SELECT COALESCE(MAX(seq),0)+1 AS n FROM findings WHERE session_id = ? AND mode = ?').get(sessionId, mode).n;
    db.prepare(`INSERT INTO findings (session_id,id,seq,mode,title,severity,status,evidence_level,type,target,summary,description,poc,evidence,fix,cvss,cwe,created_at,updated_at,verified_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(session_id, id) DO UPDATE SET
        title=excluded.title, severity=excluded.severity, status=excluded.status, evidence_level=excluded.evidence_level,
        type=excluded.type, target=excluded.target, summary=excluded.summary, description=excluded.description,
        poc=excluded.poc,
        cvss=CASE WHEN excluded.cvss<>'' THEN excluded.cvss ELSE findings.cvss END,
        cwe=CASE WHEN excluded.cwe<>'' THEN excluded.cwe ELSE findings.cwe END,
        evidence=CASE WHEN excluded.evidence<>'' THEN excluded.evidence ELSE findings.evidence END,
        fix=CASE WHEN excluded.fix<>'' THEN excluded.fix ELSE findings.fix END,
        updated_at=excluded.updated_at,
        verified_at=CASE WHEN excluded.status='verified' AND findings.status<>'verified' THEN excluded.updated_at ELSE findings.verified_at END`).run(
      sessionId, id, seq, mode, String(f.title), TAB_SEVERITY[f.severity] || 'medium', status, evidenceLevel,
      '', tabTarget(f),
      String(f.impact || '').slice(0, 300), descBits.join('\n'),
      String(f.poc || ''), String(f.reference || ''), String(f.remediation || ''),
      [f.cvss_vector, f.cvss != null ? 'score ' + f.cvss : ''].filter(Boolean).join(' | '), String(f.cwe || ''),
      now, now, status === 'verified' ? now : ''
    );
    db.close();
    out.tab_synced = true;
    out.tab_id = id;
    out.tab_session = sessionId;
  } catch (e) {
    out.tab_error = e && e.message ? e.message : String(e);
  }
  return out;
}

// ── A3: tamper-evident append-only chain over findings.jsonl ──
// Each appended line carries chain:{seq, prev_sha256, ts}; prev_sha256 is the sha256 hex of
// the previous NON-EMPTY line EXACTLY as written on disk (newline excluded). Genesis anchors
// to '0'*64. Lines predating the chain (no chain field) form an informational 'unchained-legacy'
// prefix: they are anchored by the first chained line but never failed retroactively. Once a
// chained line exists, the chain must be CONTINUOUS — a stripped chain after a chained line is
// treated as tampering (fail closed).
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// ── Ondata 6: external HEAD anchoring (mitigates the A3 whole-file-rewrite limit) ──
// A3 detects mid-chain flips, but a WHOLESALE rewrite of findings.jsonl (chain regenerated
// from scratch) would be internally consistent again. After every successful chained append
// the new head hash lands in an append-only side log; verifyHeadAnchor() re-hashes the
// anchored seq line so regeneration/truncation/wipe is detectable. Fail-loud, not fail-silent.
const ANCHOR_FILE = () => process.env.FINDINGS_HEAD_ANCHOR_FILE
  || path.join(__dirname, '..', 'reports', 'tmp', 'findings-head-anchor.jsonl');

function appendHeadAnchor(headSha256, seq) {
  try {
    const file = ANCHOR_FILE();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, JSON.stringify({
      kind: 'findings-head-anchor', ts: new Date().toISOString(), seq, head_sha256: headSha256,
    }) + '\n');
    return { ok: true, file };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

// Head of the chained suffix: {seq, head_sha256} — or null when no chained line exists.
function chainHead(lines) {
  for (let i = (lines || []).length - 1; i >= 0; i--) {
    let f = null;
    try { f = JSON.parse(lines[i]); } catch { continue; }
    if (f && f.chain && typeof f.chain === 'object') return { seq: f.chain.seq, head_sha256: sha256Hex(lines[i]) };
  }
  return null;
}

// Compare the latest head anchor against the current findings.jsonl on disk. Fail-closed on
// every tamper shape: broken chain, anchors-without-chain (wipe), anchored-line hash mismatch.
function verifyHeadAnchor(opts) {
  const anchorFile = (opts && opts.anchorFile) || ANCHOR_FILE();
  const findingsFile = (opts && opts.findingsFile) || OUT();
  let anchors = [];
  try {
    anchors = fs.readFileSync(anchorFile, 'utf8').split('\n').filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } })
      .filter((a) => a && a.kind === 'findings-head-anchor' && typeof a.head_sha256 === 'string');
  } catch { /* no anchors yet */ }
  if (!anchors.length) return { ok: true, detail: 'no head anchors recorded yet — nothing to compare (informational)' };
  let lines = [];
  try { lines = fs.readFileSync(findingsFile, 'utf8').split('\n').filter(Boolean); } catch { /* missing file */ }
  const chainState = verifyFindingsChain(lines);
  if (!chainState.ok) return { ok: false, detail: `findings chain broken: ${chainState.reason}` };
  if (!chainState.chained)
    return { ok: false, detail: `${anchors.length} head anchor(s) exist but findings.jsonl has no chained lines — possible wipe/tampering` };
  const last = anchors[anchors.length - 1];
  const anchoredLine = Number.isInteger(last.seq) ? lines[last.seq - 1] : undefined;
  if (anchoredLine != null && sha256Hex(anchoredLine) === last.head_sha256)
    return { ok: true, detail: `head anchor #${anchors.length} (seq ${last.seq}) matches findings.jsonl line ${last.seq}` };
  return { ok: false, detail: `head anchor mismatch: anchor seq=${last.seq} head=${String(last.head_sha256).slice(0, 12)}… does not hash-match findings.jsonl line ${last.seq} — chain was rewritten, truncated or wiped after anchoring` };
}

// Verify a raw (non-empty) findings.jsonl line array. Returns
//   { ok:true, chained, legacy } | { ok:false, index, reason }
function verifyFindingsChain(lines) {
  let chained = 0, legacy = 0;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    let f = null;
    try { f = JSON.parse(raw); } catch { /* unparseable lines still hash-chain via raw text */ }
    if (!f || typeof f.chain !== 'object' || f.chain === null) {
      if (chained > 0)
        return { ok: false, index: i, reason: `chain sequence interrupted: unchained line ${i + 1} follows a chained line` };
      legacy++;
      continue;
    }
    const expectedPrev = i === 0 ? '0'.repeat(64) : sha256Hex(lines[i - 1]);
    if (f.chain.prev_sha256 !== expectedPrev)
      return { ok: false, index: i, seq: f.chain.seq, reason: `prev_sha256 mismatch at line ${i + 1} (expected ${expectedPrev.slice(0, 12)}…)` };
    if (f.chain.seq !== i + 1)
      return { ok: false, index: i, seq: f.chain.seq, reason: `seq gap at line ${i + 1}: chain.seq=${f.chain.seq}, expected ${i + 1}` };
    chained++;
  }
  return { ok: true, chained, legacy };
}

function record(raw) {
  let f;
  try {
    f = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: 'invalid JSON: ' + e.message };
  }
  const err = validate(f);
  if (err) return { ok: false, error: err };
  if (typeof f.secret === 'string') f.secret = require('./privacy').rehydrate(f.secret);
  vaultSecret(f);
  for (const k of REDACT_FIELDS) if (typeof f[k] === 'string') f[k] = redact(require('./privacy').rehydrate(f[k]));
  enrichEpss(f);
  enrichCveIntel(f);
  const standards = standardsFor(f);
  if (standards) f.standards = standards;
  // A1: status is NEVER defaulted. validate() already rejected a missing status with the
  // valid roads listed; nothing is silently promoted to 'confirmed' here anymore.
  f.ts = new Date().toISOString();

  const existing = fs.existsSync(OUT()) ? fs.readFileSync(OUT(), 'utf8').split('\n').filter(Boolean) : [];
  if (existing.some((l) => { try { return key(JSON.parse(l)) === key(f); } catch { return false; } })) {
    // Already in findings.jsonl — still upsert the tab row (backfills DBs from before the sync existed; idempotent).
    return Object.assign({ ok: true, deduped: true, key: key(f) }, syncToFindingsTab(f));
  }

  // A3: refuse to extend a broken chain (fail closed), then anchor the new line to the last
  // raw line on disk (genesis '0'*64; legacy unchained lines are anchored transparently).
  const chainState = verifyFindingsChain(existing);
  if (!chainState.ok)
    return { ok: false, error: `findings.jsonl hash-chain broken at line ${chainState.index + 1}: ${chainState.reason} — refusing to append; investigate/restore reports/findings.jsonl before recording` };
  const line = buildChainedLine(f, existing);
  const selfCheck = verifyFindingsChain([...existing, line]);
  if (!selfCheck.ok)
    return { ok: false, error: `internal chain self-check failed (${selfCheck.reason}) — nothing written` };

  fs.appendFileSync(OUT(), line + '\n');
  // Ondata 6: external head anchoring — record the new head hash right after the append.
  const chained = JSON.parse(line);
  const headAnchor = appendHeadAnchor(sha256Hex(line), chained.chain.seq);
  return Object.assign({ ok: true, recorded: key(f), seq: chained.chain.seq, head_anchor: headAnchor }, syncToFindingsTab(f));
}

// Serialize the finding deterministically and attach its chain entry: hash input is the exact
// string written to disk minus the trailing newline.
function buildChainedLine(f, existingRawLines) {
  f.chain = {
    seq: existingRawLines.length + 1,
    prev_sha256: existingRawLines.length ? sha256Hex(existingRawLines[existingRawLines.length - 1]) : GENESIS,
    ts: f.ts,
  };
  return JSON.stringify(f);
}

// Optional inline oracle: if the finding carries a `verify` block, re-fire it and set status
// accordingly BEFORE recording. Async; keeps the plain sync record() path untouched for the
// 14 agents + tests that depend on it. verifier is injectable for offline tests.
//
// A1/A2 bridge: the N/N repeater re-fire IS a mechanical oracle, so both outcomes are receipted
// to disk (artifacts/oracle/<token>.json, type http-diff) and attached as f.oracle +
// f.evidence_quote (exact anchor quote). Passed AND failed re-fires leave a machine trace:
// a failed re-fire keeps the claimed status but carries verify_failed/verify_reason plus a
// receipt documenting the failure — it can never surface as verified downstream
// (tabStatusOf maps it to pending/partial; report gates re-validate the oracle).
// If writing the receipt fails, recording FAILS (fail-closed — no unreceipted reality claims).
async function recordWithVerify(raw, verifier) {
  let f;
  try { f = JSON.parse(raw); } catch (e) { return { ok: false, error: 'invalid JSON: ' + e.message }; }
  if (f.verify) {
    verifier = verifier || ((finding) => require('./verify-finding').verifyOne(finding));
    const r = await verifier(f);
    if (r.verified) { f.status = 'verified'; f.verified = true; f.verified_at = new Date().toISOString(); }
    else { f.status = f.status || 'confirmed'; f.verify_failed = true; f.verify_reason = r.reason; }
    if (!f.oracle) {
      // Keep the anchor JSON-safe so evidence_quote stays a byte-exact substring of the receipt.
      const safe = String(r.reason == null ? '' : r.reason).replace(/["\\\u0000-\u001F]/g, '');
      const anchor = `outcome ${r.verified ? 'passed' : 'failed'}: ${safe}`;
      const rec = require('./oracle').writeReceipt({
        type: 'http-diff',
        anchor,
        data: {
          detail: 'verify-refire',
          finding_key: key(f),
          url: f.verify.url,
          method: f.verify.method || 'GET',
          runs: Array.isArray(r.runs) ? r.runs : [],
          verify_reason: safe,
          source: 'recordWithVerify/verify-finding.js mechanical re-fire',
        },
      });
      if (!rec.ok) return { ok: false, error: `reality claim blocked: verify re-fire receipt could not be written (${rec.error})` };
      f.oracle = { type: 'http-diff', ref: rec.ref, token: rec.token };
      f.evidence_quote = { file: rec.ref, text: anchor };
    }
  }
  return record(JSON.stringify(f));
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args[0] === 'verify-head-anchor') {
    const r = verifyHeadAnchor();
    console.log(JSON.stringify(r));
    process.exit(r.ok ? 0 : 1);
  }
  const doVerify = args.includes('--verify');
  const raw = args.find((a) => a !== '--verify') || '';
  (async () => {
    const res = doVerify ? await recordWithVerify(raw) : record(raw);
    console.log(JSON.stringify(res));
    process.exit(res.ok ? 0 : 1);
  })();
}
module.exports = { record, recordWithVerify, validate, key, redact, vaultSecret, normalizeCves, enrichEpss, enrichCveIntel, standardsFor, registryClasses, syncToFindingsTab, VERIFY_LEVELS, SEVERITY_CEILING, severityAllowedAt, verifyFindingsChain, sha256Hex, buildChainedLine, appendHeadAnchor, chainHead, verifyHeadAnchor, ANCHOR_FILE };
