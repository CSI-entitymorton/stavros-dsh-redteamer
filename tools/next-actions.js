#!/usr/bin/env node
// Tier 1-B — Finding-driven orchestration (additive planner).
//
// Reads the normalized asset graph (tools/target-model.snapshot) and derives the NEXT
// actions from what is actually known about the target: an open SMB port proposes SMB
// enumeration, an LDAP port proposes the read-only LDAP workflow, an HTTP service proposes
// fingerprint+probe then a targeted nuclei scan, a discovered SQLi proposes sqlmap
// confirmation, a captured credential proposes authenticated enumeration. The agent stops
// relying on memory to decide "what next" — the model decides, deterministically.
//
// WHY a separate module (not a rewrite of workflow.js): this is PURELY ADDITIVE. It never
// runs anything itself unless explicitly told to, and when it does it goes through the
// EXISTING guarded entry points (tools/run.js, tools/workflow.js) so scope-guard / enforce /
// tier / rate-limit / gate all still apply. The planner cannot bypass any control:
//   - every proposed action is tagged with the scope-guard verdict for its host; a
//     host that is out of scope (or a scope.json that will not load) is marked blocked
//     and excluded from the executable set (fail-closed);
//   - intrusive-tier actions (sqlmap, authenticated netexec) are marked requires_optin and
//     are NEVER auto-executed without --include-intrusive;
//   - secrets are NEVER emitted: a credential-driven command prints "<secret>", not the value.
//
// CLI:
//   node tools/next-actions.js plan [--all] [--json]        # dry-run: propose next actions (default)
//   node tools/next-actions.js run --yes [--include-intrusive]  # execute the allowed, non-covered set
//
// Env: STATE_DB (asset graph, via target-model/state), SCOPE_JSON (via scope-guard).
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const tm = require('./target-model');

const WS = path.join(__dirname, '..');

// ------------------------------------------------------------------ scope predicate
// Fail-closed: if scope.json will not load, EVERY action is blocked. A planner that
// silently "allows" when it cannot read the scope would be a bypass — we refuse instead.
function scopePredicate() {
  let sg; let scope;
  try {
    sg = require('./scope-guard');
    scope = sg.loadScope();
  } catch (e) {
    return () => ({ ok: false, reason: `scope.json non caricabile (${e.message}): azione bloccata` });
  }
  return (host) => {
    try { return sg.inScope(host, scope); }
    catch (e) { return { ok: false, reason: `scope check error: ${e.message}` }; }
  };
}

// ------------------------------------------------------------------ pure planner
// plan(snapshot, opts) -> { generated_at, actions[], summary }. No I/O; fully unit-testable.
//   opts.inScope(host) -> {ok, reason}   (defaults to allow-with-note if not provided)
//   opts.all           -> also propose actions for surfaces already enumerated (covered)
function plan(snapshot, opts) {
  opts = opts || {};
  const all = !!opts.all;
  const inScope = opts.inScope || (() => ({ ok: true, reason: 'scope check non fornito' }));
  const actions = [];

  for (const t of (snapshot.targets || [])) {
    const host = t.host;
    const sc = inScope(host);
    const blocked = !sc.ok;
    const add = (a) => actions.push({ host, blocked, scope_reason: sc.reason, ...a });

    const hostObjs = t.hosts || [];
    const openPorts = hostObjs.flatMap((h) => (h.ports || []).filter((p) => p.state === 'open'));
    const httpEndpoints = (t.endpoints || []).filter((e) => /^https?:/i.test(e.url));
    const smbEnumerated = (t.endpoints || []).some((e) => e.method === 'SMB');
    const vulns = t.vulns || [];
    const creds = t.creds || [];
    const hasPort = (nums, svcRe) => openPorts.some((p) => nums.includes(p.port) || (svcRe && svcRe.test(p.service || '')));

    // 0. host with no known open ports -> baseline recon (host/port discovery)
    if (openPorts.length === 0) {
      add({ surface: 'network', port: null, reason: 'host senza porte note: baseline recon (discovery + top ports)',
        kind: 'workflow', ref: 'workflows/recon-baseline.yaml',
        cmd: `node tools/workflow.js run workflows/recon-baseline.yaml -t ${host}`,
        tier: 'active', requires_optin: false, priority: 10, covered: false });
    }

    // SMB enumeration
    if (hasPort([445, 139], /microsoft-ds|netbios|smb/i)) {
      const covered = smbEnumerated;
      if (!covered || all) add({ surface: 'smb', port: 445, reason: 'porta SMB aperta: enumerazione share/sessioni',
        kind: 'workflow', ref: 'workflows/enum-smb.yaml',
        cmd: `node tools/workflow.js run workflows/enum-smb.yaml -t ${host}`,
        tier: 'active', requires_optin: false, priority: 20, covered });
    }
    // LDAP enumeration (read-only)
    if (hasPort([389, 636, 3268], /ldap/i)) {
      add({ surface: 'ldap', port: 389, reason: 'porta LDAP aperta: rootDSE + naming contexts (read-only)',
        kind: 'workflow', ref: 'workflows/enum-ldap.yaml',
        cmd: `node tools/workflow.js run workflows/enum-ldap.yaml -t ${host}`,
        tier: 'read', requires_optin: false, priority: 15, covered: false });
    }
    // HTTP fingerprint/probe, then targeted nuclei
    if (hasPort([80, 443, 8080, 8443, 8000], /https?|http-proxy/i)) {
      const covered = httpEndpoints.length > 0;
      if (!covered || all) add({ surface: 'http', port: 80, reason: 'servizio HTTP: fingerprint + probe (httpx/whatweb)',
        kind: 'workflow', ref: 'workflows/enum-http.yaml',
        cmd: `node tools/workflow.js run workflows/enum-http.yaml -t ${host}`,
        tier: 'active', requires_optin: false, priority: 20, covered });
      if (httpEndpoints.length > 0 && vulns.length === 0) {
        add({ surface: 'http', port: 80, reason: 'endpoint noti, nessuna vuln testata: scan nuclei mirato',
          kind: 'cmd', ref: 'nuclei',
          cmd: `node tools/run.js nuclei -u ${httpEndpoints[0].url} -jsonl`,
          tier: 'active', requires_optin: false, priority: 25, covered: false });
      }
    }

    // finding-driven: endpoints WITH query params but no SQLi tested yet -> injection probe
    for (const e of httpEndpoints) {
      if (e.url.includes('?') && !vulns.some((v) => v.class === 'sqli' && v.url === e.url)) {
        add({ surface: 'http-param', port: 80, reason: `endpoint con parametri (${e.url}): test injection`,
          kind: 'cmd', ref: 'sqlmap',
          cmd: `node tools/run.js sqlmap -u ${e.url} --batch --level 1 --risk 1`,
          tier: 'intrusive', requires_optin: true, priority: 40, covered: false });
      }
    }
    // finding-driven: confirmed SQLi -> deeper confirmation/extraction
    for (const v of vulns.filter((v) => v.class === 'sqli' && v.url)) {
      add({ surface: 'sqli', port: 80, reason: `SQLi rilevata (${v.template_id || 'nuclei'}) su ${v.url}: conferma/estrazione`,
        kind: 'cmd', ref: 'sqlmap',
        cmd: `node tools/run.js sqlmap -u ${v.url} --batch --dbs`,
        tier: 'intrusive', requires_optin: true, priority: 45, covered: false });
    }
    // finding-driven: captured credential -> authenticated enumeration (secret MASKED)
    for (const c of creds) {
      add({ surface: 'creds', port: 445, reason: `credenziale ${c.username} su ${c.host}: enumerazione autenticata`,
        kind: 'cmd', ref: 'netexec',
        cmd: `node tools/run.js netexec smb ${c.host} -u '${c.username}' -p '<secret>' --shares`,
        tier: 'intrusive', requires_optin: true, priority: 35, covered: false });
    }
    // Ondata 6 (E6 applicato al planner): WAF rilevato nel grafo (whatweb/tech) → probe a rate
    // ridotto. La decisione è CODIFICATA qui, non affidata alla memoria dell'agente.
    const wafRe = /cloudflare|aws[- ]?waf|sucuri|akamai|imperva|incapsula|barracuda|modsecurity|f5\b|big[- ]?ip/i;
    const wafTech = (t.technologies || []).find((tech) => wafRe.test(String(tech.name || '')));
    if (wafTech && httpEndpoints.length > 0) {
      const probeUrl = httpEndpoints[0].url;
      add({ surface: 'http-waf', port: 80, reason: `WAF rilevato (${wafTech.name}): nuclei a rate ridotto (-rl 5)`,
        kind: 'cmd', ref: 'nuclei',
        cmd: `node tools/run.js nuclei -u ${probeUrl} -rl 5 -jsonl`,
        tier: 'active', requires_optin: false, priority: 30, covered: vulns.some((v) => v.url === probeUrl) });
    }
  }

  // non-blocked first, then by priority (read/active before intrusive by construction).
  actions.sort((a, b) => (Number(a.blocked) - Number(b.blocked)) || (a.priority - b.priority));
  return { generated_at: (snapshot && snapshot.generated_at) || null, actions, summary: summarize(actions) };
}

function summarize(actions) {
  const bySurface = {};
  const byTier = {};
  let executable = 0;
  for (const a of actions) {
    bySurface[a.surface] = (bySurface[a.surface] || 0) + 1;
    byTier[a.tier] = (byTier[a.tier] || 0) + 1;
    if (!a.blocked && !a.covered && !a.requires_optin) executable++;
  }
  return { total: actions.length, executable, by_surface: bySurface, by_tier: byTier };
}

// planFromDb(db, opts) — read the model, tag with the real scope-guard verdict, plan.
function planFromDb(db, opts) {
  opts = opts || {};
  const snap = tm.snapshot(db);
  return plan(snap, { all: opts.all, inScope: opts.inScope || scopePredicate() });
}

// ------------------------------------------------------------------ optional execution
// Executes the ALLOWED, non-covered actions through the existing guarded entry points.
// Fail-closed: refuses without opts.yes; skips blocked/covered always; skips intrusive
// unless opts.includeIntrusive. This runs REAL commands — offline tests do not call it.
function runPlan(db, opts) {
  opts = opts || {};
  if (!opts.yes) return { ok: false, reason: 'esecuzione rifiutata: manca --yes (fail-closed)' };
  const p = planFromDb(db, opts);
  const results = [];
  for (const a of p.actions) {
    if (a.blocked) { results.push({ cmd: a.cmd, skipped: 'out-of-scope' }); continue; }
    if (a.covered) { results.push({ cmd: a.cmd, skipped: 'gia-coperto' }); continue; }
    if (a.requires_optin && !opts.includeIntrusive) { results.push({ cmd: a.cmd, skipped: 'intrusive-opt-in' }); continue; }
    if (a.requires_optin) { results.push({ cmd: a.cmd, skipped: 'intrusive-con-segreto: eseguire a mano' }); continue; }
    // Only non-intrusive, in-scope, uncovered actions are auto-run.
    const argv = a.cmd.replace(/^node\s+/, '').split(/\s+/);
    const r = spawnSync('node', argv.map((x) => (x.startsWith('tools/') ? path.join(WS, x) : x)), { encoding: 'utf8', cwd: WS });
    results.push({ cmd: a.cmd, status: r.status, err: r.stderr ? r.stderr.slice(0, 200) : null });
  }
  return { ok: true, ran: results.filter((r) => r.status !== undefined).length, results };
}

module.exports = { plan, planFromDb, runPlan, summarize, scopePredicate };

// ------------------------------------------------------------------ CLI
if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0] && !args[0].startsWith('--') ? args[0] : 'plan';
  const has = (f) => args.includes(f);
  const db = tm.open();
  try {
    if (cmd === 'plan') {
      const p = planFromDb(db, { all: has('--all') });
      console.log(JSON.stringify(p, null, has('--json') ? 0 : 2));
    } else if (cmd === 'run') {
      const res = runPlan(db, { yes: has('--yes'), includeIntrusive: has('--include-intrusive') });
      console.log(JSON.stringify(res, null, 2));
      process.exit(res.ok ? 0 : 2);
    } else {
      console.error('usage: next-actions.js <plan [--all] [--json] | run --yes [--include-intrusive]>');
      process.exit(2);
    }
  } finally {
    if (db && typeof db.close === 'function') db.close();
  }
}
