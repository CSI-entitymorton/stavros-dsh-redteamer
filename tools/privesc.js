#!/usr/bin/env node
// Privesc orchestrator for controlled host sessions (Sliver OR SSH channel).
// - `checks` runs the curated AUTO-TIER recon catalog (privesc-catalog.json) on a
//   session. Catalog checks cross the channel BY ID ONLY — never as freeform
//   strings — so the channel layer can execute them verbatim without weakening
//   its generic command classifier.
// - `exploit` runs ONE operator-approved escalation command. It is CONFIRM-TIER by
//   construction: refuses without --confirm AND re-classifies through c2-guard
//   before dispatching; the channel layer classifies again (defense in depth).
// The catalog holds REFERENCES and DETECTORS only — no exploit code lives in this
// repo. Escalation binaries (SKELETONKEY, chimera, potato-family, ...) are
// OPERATOR-SUPPLIED, vetted artifacts; this tool gates and audits their invocation.
//
// ponytail: regex detectors, not a real parser. Vectors can be missed or stale
// (patch levels change). Every hit is a LEAD: verify on the box, then record
// findings honestly per the verify_level discipline in knowledge.md.
const fs = require('fs');
const path = require('path');
const G = require('./c2-guard');

const CATALOG_PATH = path.join(__dirname, 'privesc-catalog.json');

function auditFile(file) {
  return file || process.env.HOSTOPS_AUDIT || path.join(__dirname, '..', 'reports', 'tmp', 'hostops-audit.jsonl');
}
function outDir(dir) {
  return dir || process.env.STAVROS_PRIVESC_DIR || path.join(__dirname, '..', 'reports', 'privesc');
}
function audit(entry, file) {
  const p = auditFile(file);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.appendFileSync(p, JSON.stringify(Object.assign({ ts: new Date().toISOString() }, entry)) + '\n');
}

function loadCatalog(os) {
  const cat = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));
  return {
    checks: cat.checks.filter((e) => !os || os === 'auto' || e.os === os),
    refs: cat.refs,
  };
}
function findRef(id) { return JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8')).refs[id] || null; }
function findCheck(id) { return JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8')).checks.find((e) => e.id === id) || null; }

// OS probes are deliberately commands that classify AUTO on the generic channel
// guard: `cat ...` -> loot_read, `dir`/`whoami /groups`/`id` -> enum.
async function detectOs(runner, target) {
  const r = await runner(target, 'cat /etc/os-release 2>&1', {});
  if (/Linux|ID=|NAME=/i.test(r.output || '')) return 'linux';
  const r2 = await runner(target, 'dir C:\\', {});
  if (/Directory of|Volume|File Not Found|<DIR>|\.exe/i.test(r2.output || '')) return 'windows';
  const r3 = await runner(target, 'id', {});
  if (/\buid=\d+/.test(r3.output || '')) return 'linux';
  return null;
}

// Run every catalog check for `os` and rank detected escalation vectors.
// opts.checkRunner(target, checkId) MUST be provided on real runs — it resolves the
// exact command from privesc-catalog.json inside the channel layer (by ID).
// opts.runner(sessionOrHost, cmd, ctx) is used only for the two OS probes above.
async function runChecks(target, opts) {
  opts = opts || {};
  if (!opts.checkRunner) throw new Error('runChecks requires opts.checkRunner(target, checkId)');
  if (!opts.runner) throw new Error('runChecks requires opts.runner(target, cmd, ctx)');
  let os = opts.os;
  if (!os || os === 'auto') os = await detectOs(opts.runner, target);
  if (!os) return { ok: false, reason: 'could not detect target OS (linux|windows)' };
  const results = [], vectors = [];
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const transcript = path.join(outDir(opts.dir), `${String(target).replace(/[^a-z0-9_.@-]/gi, '_')}-${ts}.jsonl`);
  fs.mkdirSync(path.dirname(transcript), { recursive: true });
  for (const entry of loadCatalog(os).checks) {
    const res = await opts.checkRunner(target, entry.id);
    const output = String(res.output || '');
    audit({ tool: 'privesc', op: 'check', target, id: entry.id, status: res.status });
    results.push({ id: entry.id, title: entry.title, status: res.status, output: output.slice(-8000) });
    for (const [reStr, vecId, sev] of entry.detect || []) {
      let re;
      try { re = new RegExp(reStr, 'mi'); } catch { continue; }
      if (re.test(output)) {
        vectors.push({ check: entry.id, vector: vecId, severity: sev, title: entry.title });
        break; // strongest detector per entry wins
      }
    }
  }
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  vectors.sort((a, b) => order[a.severity] - order[b.severity]);
  fs.writeFileSync(transcript, results.map((r) => JSON.stringify(r)).join('\n'));
  return { ok: true, os, target, transcript, vectors, checks_run: results.length };
}

// Execute ONE escalation command. Double-gated: local confirm requirement + c2-guard
// classification here, then the channel re-classifies with the forwarded --confirm.
async function exploit(target, req, opts) {
  opts = opts || {};
  const runner = opts.runner;
  if (!runner) throw new Error('exploit requires opts.runner(target, cmd, ctx)');
  const cmd = String(req.cmd || '').trim();
  if (!cmd) return { ok: false, blocked: true, reason: 'empty command (fail closed)' };
  if (!req.confirm || !String(req.confirm).trim())
    return { ok: false, blocked: true, reason: 'escalation is confirm-tier: pass --confirm "<reason>" (explicit in-session user approval)' };
  const g = G.enforce(cmd, { confirm: req.confirm }, opts.scope);
  if (!g.ok) return { ok: false, blocked: true, reason: g.reason, actionClass: g.actionClass };
  const ref = req.ref ? findRef(req.ref) : null;
  const res = await runner(target, cmd, { confirm: req.confirm });
  audit({
    tool: 'privesc', op: 'exploit', target, ref: req.ref || null, cmd,
    actionClass: g.actionClass, status: res.status, confirmed_by: String(req.confirm).slice(0, 120),
  });
  let verified = null;
  const osGuess = (ref && ref.os) || opts.os;
  if (osGuess && POSTCHECK[osGuess]) {
    const pc = POSTCHECK[osGuess];
    const pv = await runner(target, pc.cmd, {});
    verified = { cmd: pc.cmd, escalated: pc.ok(String(pv.output || '')), output: String(pv.output || '').slice(-2000) };
  }
  return { ok: res.status === 0, blocked: false, output: String(res.output || '').slice(-8000), ref: req.ref || null, refNote: ref ? ref.note : null, verified };
}

// Post-escalation verification probes (also auto-safe on the channel guard).
const POSTCHECK = {
  linux: { cmd: 'id', ok: (out) => /\buid=0\b|\(root\)/.test(out) },
  windows: { cmd: 'whoami /groups', ok: (out) => /S-1-16-12288/.test(out) },
};

module.exports = { loadCatalog, findRef, findCheck, detectOs, runChecks, exploit, POSTCHECK, auditFile };

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
if (require.main === module) {
  const args = process.argv.slice(2);
  const opt = {};
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--confirm') opt.confirm = args[++i];
    else if (args[i] === '--os') opt.os = args[++i];
    else if (args[i] === '--channel') opt.channel = args[++i];
    else if (args[i] === '--ref') opt.ref = args[++i];
    else if (args[i] === '--cmd') opt.cmd = args[++i];
    else pos.push(args[i]);
  }
  const [op, target] = pos;
  const usage = () => {
    console.log(`usage:
  node tools/privesc.js catalog [--os linux|windows]
  node tools/privesc.js checks <session> [--os auto|linux|windows] [--channel sliver|ssh]
  node tools/privesc.js exploit <session> --ref <ref-id> --cmd "<escalation command>" --confirm "<reason>" [--channel sliver|ssh]

channels: sliver (default) routes via sliver.js; ssh routes via sshx.js. Both enforce
scope + tiers themselves; this tool adds its own confirm gate on top.`);
    process.exit(op === 'help' ? 0 : 2);
  };
  if (!op || op === 'help') usage();
  if (op === 'catalog') {
    const { checks, refs } = loadCatalog(opt.os !== 'auto' ? opt.os : undefined);
    for (const c of checks) console.log(`[${c.os}] ${c.id.padEnd(18)} ${c.title}`);
    console.log('\nescalation refs:');
    for (const [k, v] of Object.entries(refs)) console.log(`  ${k.padEnd(16)} ${String(v.os).padEnd(8)} ${v.cve || ''} :: ${v.note.slice(0, 80)}`);
    process.exit(0);
  }
  (async () => {
    let runner, checkRunner;
    if ((opt.channel || 'sliver') === 'ssh') {
      const sshx = require('./sshx');
      runner = (t, cmd, o) => Promise.resolve(sshx.exec(t, cmd, { confirm: o && o.confirm }));
      checkRunner = (t, id) => Promise.resolve(sshx.execCheck(t, id));
    } else {
      const sliver = require('./sliver');
      runner = (t, cmd, o) => Promise.resolve(sliver.runCmd(t, cmd, { confirm: o && o.confirm }));
      checkRunner = (t, id) => Promise.resolve(sliver.execCheck(t, id));
    }
    if (op === 'checks') {
      const r = await runChecks(target, { runner, checkRunner, os: opt.os });
      console.log(JSON.stringify(r, null, 2));
      process.exit(r.ok ? 0 : 1);
    }
    if (op === 'exploit') {
      if (!opt.ref || !opt.cmd) { console.error('--ref and --cmd are required'); usage(); }
      const r = await exploit(target, { cmd: opt.cmd, ref: opt.ref, confirm: opt.confirm }, { runner });
      console.log(JSON.stringify(r, null, 2));
      process.exit(r.ok ? 0 : 1);
    }
    usage();
  })().catch((e) => { console.error(e.message); process.exit(1); });
}
