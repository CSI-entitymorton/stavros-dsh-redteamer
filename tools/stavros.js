#!/usr/bin/env node
// Deterministic Kali pipeline (Fase 1): the LLM no longer drives recon/scan/enumerate by
// hand — this orchestrator does the mechanical work, writes results to reports/state.db
// (SQLite via node:sqlite), and supports resuming an interrupted run.
//
//   node tools/stavros.js recon <host>       subfinder|amass|dnsx → katana|gau|waybackurls → httpx -json
//   node tools/stavros.js scan <host|cidr>   naabu/rustscan → nmap -sC -sV -oX - → ports/services
//   node tools/stavros.js enumerate <host>   ffuf/feroxbuster + arjun (+ noauth_finder when installed) → endpoints/params
//   node tools/stavros.js fuzz <host>        OPTIONAL post-scan service fuzzing via APT++ (tcp/udp/http), operator-installed
//   node tools/stavros.js status [<host>]    summary of state.db
//   node tools/stavros.js resume             re-drive the last incomplete run, skipping done phases
//   node tools/stavros.js report             consolidate state.db + findings.jsonl (and close the run)
//
// Principles (see the plan): "i tool eseguono, la pipeline orchestra, gli agenti decidono".
// - Every third-party binary runs through runBin (default = scope-check + audit + streaming
//   runBinary from run.js). Inject a fake runBin in tests to run the phase logic offline.
// - Independent tools run with Promise.all at a small concurrency; global pacing stays in
//   pace.js/scope.json (runBin waits on it before each spawn).
// - Phases are tracked per-run in state.db (pending → running → done/failed) so `resume`
//   skips what's already done.
const fs = require('fs');
const os = require('os');
const path = require('path');
const state = require('./state');
const { loadScope, inScope, cidrInScope } = require('./scope-guard');
const { collectHosts, isCidr, runBinary } = require('./run');
const pace = require('./pace');
const parsers = require('./parsers');

const PHASES = ['recon', 'scan', 'enumerate'];

// ---- small pure helpers ----

function loadScopeSafe() {
  try {
    return loadScope();
  } catch {
    return null;
  }
}

function rpsOf(scope) {
  return (scope && scope.max_requests_per_second) || 2;
}

function writeAtomic(file, data) {
  const tmp = file + '.' + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

function sanitize(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]+/g, '_');
}

// "https://host/x" | "host:8080" | "host" -> "host"
function normalizeHost(host) {
  const t = String(host == null ? '' : host).trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      return new URL(t).hostname || t;
    } catch {
      return t;
    }
  }
  return t.toLowerCase();
}

function hostnameOfUrl(url) {
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

function baseUrl(host) {
  const t = String(host == null ? '' : host).trim();
  if (/^https?:\/\//i.test(t)) return t.replace(/\/+$/, '');
  return 'https://' + t;
}

function defaultTmpDir() {
  return process.env.STAVROS_TMP || path.join(os.tmpdir(), 'stavros');
}

// Extract a hostname from one recon-tool output line (subfinder/dnsx emit bare hosts,
// katana/gau/waybackurls emit URLs). Returns null for junk.
function extractHostFromLine(line) {
  const t = String(line == null ? '' : line).trim();
  if (!t) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    try {
      return new URL(t).hostname || null;
    } catch {
      return null;
    }
  }
  // bare hostname (dotted, real TLD); drop IPs and free-form junk
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) return null;
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t) && !/\s/.test(t)) return t.toLowerCase();
  return null;
}

// ---- audit trail (same evidence convention as run.js) ----
function audit(entry) {
  try {
    const dir = path.join(__dirname, '..', 'reports', 'tmp');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'run-audit.jsonl'), JSON.stringify(entry) + '\n');
  } catch {}
}

// ---- runBin: injectable, default = scope-check + audit + runBinary (capture) ----
async function defaultRunBin(bin, args, opts) {
  opts = opts || {};
  const scope = loadScopeSafe();
  if (!scope) {
    const e = new Error('scope.json missing - nothing is authorized yet');
    e.blocked = true;
    throw e;
  }
  const hosts = collectHosts(args, opts.input);
  if (hosts.length === 0) {
    const e = new Error('no target host found (fail closed)');
    e.blocked = true;
    e.reason = 'no target host found';
    throw e;
  }
  const bad = hosts.filter((h) => (isCidr(h) ? !cidrInScope(h, scope).ok : !inScope('http://' + h, scope).ok));
  if (bad.length) {
    const e = new Error('out-of-scope host(s): ' + bad.join(', '));
    e.blocked = true;
    e.reason = 'out-of-scope host(s)';
    e.bad = bad;
    throw e;
  }
  await pace.wait(rpsOf(scope));
  audit({ ts: new Date().toISOString(), bin, args, hosts });
  const r = await runBinary(bin, args, { capture: true, input: opts.input, timeoutMs: opts.timeoutMs });
  audit({ ts: new Date().toISOString(), bin, args, hosts, exit: r.status, ok: r.status === 0, error: r.error });
  return r;
}

// Concurrency-limited Promise.all (zero-dep).
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let idx = 0;
  const n = Math.max(1, Math.min(limit, items.length));
  const workers = Array.from({ length: n }, async () => {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

// ---- phase bookkeeping ----

function ensureRun(db, target, cmd) {
  const last = state.lastRun(db);
  if (last && last.status === 'running' && last.target === target) return last.id;
  return state.addRun(db, cmd, target);
}

async function runPhase(db, runId, name, fn) {
  const existing = state.getPhase(db, runId, name);
  if (existing && existing.status === 'done') return { skipped: true };
  state.setPhase(db, runId, name, 'running');
  try {
    const out = await fn();
    state.setPhase(db, runId, name, 'done');
    return out;
  } catch (e) {
    state.setPhase(db, runId, name, 'failed');
    throw e;
  }
}

// ---- concrete command lists (kept pure for tests) ----

function reconCommands(host) {
  const h = normalizeHost(host);
  return [
    { bin: 'subfinder', args: ['-d', h, '-silent'] },
    { bin: 'amass', args: ['enum', '-passive', '-d', h, '-silent'] },
    { bin: 'dnsx', args: ['-d', h, '-silent'] },
    { bin: 'katana', args: ['-u', 'https://' + h, '-silent'] },
    { bin: 'gau', args: [h] },
    { bin: 'waybackurls', args: [h] },
  ];
}

// naabu prints one "ip:port" per line.
function parseNaabu(text) {
  const ports = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
    if (m) ports.push(Number(m[2]));
  }
  return ports;
}

// rustscan -g prints "ip -> [22,80,443]".
function parseRustscan(text) {
  const ports = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*\[([0-9,\s]*)\]/);
    if (m) {
      for (const p of m[2].split(',')) {
        const n = Number(String(p).trim());
        if (n) ports.push(n);
      }
    }
  }
  return ports;
}

// ponytail: arjun output is human text; grab the most common "params: [...]" shapes.
function parseArjun(text) {
  const s = String(text || '');
  const json = s.match(/\{[^{}]*"params"\s*:\s*(\[[^\]]*\])[^{}]*\}/);
  if (json) {
    try {
      return JSON.parse(json[1]).map(String);
    } catch {}
  }
  const m = s.match(/Parameters?\s*(?:found)?\s*[:=]\s*\[([^\]]*)\]/i);
  if (!m) return [];
  return m[1].split(',').map((p) => p.trim().replace(/['"]/g, '')).filter(Boolean);
}

// ---- operator-installed vetted tools (repo-vet churchofmalware integrations) ----
// Third-party tools live OUTSIDE this repo (vendor/tools/<name>/ or an env-provided path).
// Resolution is pure and injectable; absence degrades to null and phases skip gracefully.

function fileExists(p) {
  try { return !!p && fs.existsSync(p); } catch { return false; }
}

// Env override wins; then vendor/tools/<rel>. Returns the absolute path or null.
function resolveOperatorTool(envVar, relPath, opts) {
  const envPath = process.env[envVar];
  if (fileExists(envPath)) return path.resolve(envPath);
  const vendorPath = path.join(__dirname, '..', 'vendor', 'tools', relPath);
  if (!(opts && opts.noVendorDefaults) && fileExists(vendorPath)) return vendorPath;
  return null;
}

// noauth_finder argv for one authorized target. `--allow-public` is ALWAYS passed because the
// scope-guard in runBin has already authorized this exact host — the tool's own public-gate is
// therefore satisfied by our stronger gate, not bypassed by it.
function noauthCommand(scriptPath, target, opts) {
  const args = [scriptPath, target, '--allow-public'];
  if (opts && opts.outputDir) args.push('--output-dir', opts.outputDir);
  return { bin: 'python3', args };
}

// Unique http(s) URLs mentioned in a tool's stdout (any export shape), capped.
function parseDiscoveredUrls(text, cap) {
  const urls = [];
  const seen = new Set();
  const re = /\bhttps?:\/\/[^\s"'<>()\[\]{}]+/gi;
  for (const m of String(text == null ? '' : text).match(re) || []) {
    const u = m.replace(/[.,;]+$/, '');
    if (!seen.has(u)) { seen.add(u); urls.push(u); }
    if (urls.length >= (cap || 200)) break;
  }
  return urls;
}

// APT++ (Amish-Persistent-Threat) fuzz invocations for discovered services. Mode choice:
// udp protocol -> udp; http-ish service -> http; everything else -> tcp. Pure + injectable.
function buildFuzzJobs(ports, opts) {
  opts = opts || {};
  const script = opts.script;
  const outRoot = opts.outRoot || 'fuzz';
  const jobs = [];
  for (const p of ports || []) {
    const svc = String((p.service || '') + ' ' + (p.version || '')).toLowerCase();
    const mode = p.protocol === 'udp' ? 'udp' : (/http|https|proxy|rest|api/.test(svc) ? 'http' : 'tcp');
    jobs.push({
      mode,
      port: p.port,
      host: p.host,
      bin: 'python3',
      args: [script, mode, '-H', p.host, '-p', String(p.port), '-o', path.join(outRoot, p.host + '-' + p.port)],
    });
  }
  return jobs;
}

// Count crash artifacts APT++ left behind (<out>/crashes/*.json metadata files).
function countFuzzCrashes(outRoot) {
  let crashes = 0;
  const crashFiles = [];
  try {
    const walk = (d) => {
      for (const f of fs.readdirSync(d)) {
        const full = path.join(d, f);
        const st = fs.statSync(full);
        if (st.isDirectory()) walk(full);
        else if (full.endsWith('.json')) { crashes++; crashFiles.push(full); }
      }
    };
    walk(outRoot);
  } catch {}
  return { crashes, crashFiles: crashFiles.slice(0, 20) };
}

// ---- phases ----

async function recon(db, host, opts) {
  opts = opts || {};
  const runBin = opts.runBin || defaultRunBin;
  const tmpDir = opts.tmpDir || defaultTmpDir();
  const target = normalizeHost(host);
  const runId = opts.runId || ensureRun(db, target, 'recon ' + target);
  return runPhase(db, runId, 'recon', async () => {
    // 1) subdomain/URL discovery (parallel, small concurrency)
    const results = await mapLimit(reconCommands(target), opts.concurrency || 4, async (c) => {
      const r = await runBin(c.bin, c.args, {});
      return { cmd: c, r };
    });
    const hosts = new Set([target]);
    for (const { r } of results) {
      if (!r || r.status !== 0) continue;
      for (const line of String(r.stdout || '').split(/\r?\n/)) {
        const h = extractHostFromLine(line);
        if (h) hosts.add(h);
      }
    }
    // 2) write the candidate list, then httpx it for liveness/tech
    const list = [...hosts].sort();
    fs.mkdirSync(tmpDir, { recursive: true });
    const subsFile = path.join(tmpDir, 'subs-' + sanitize(target) + '.txt');
    writeAtomic(subsFile, list.join('\n') + '\n');

    const httpxR = await runBin('httpx', ['-l', subsFile, '-silent', '-json'], {});
    const targetId = state.upsertTarget(db, target);
    if (httpxR && httpxR.status === 0) {
      for (const line of String(httpxR.stdout || '').split(/\r?\n/)) {
        const rec = parsers.parseHttpxJson(line);
        if (!rec) continue;
        const ip = rec.host || null;
        const name = rec.input || hostnameOfUrl(rec.url) || null;
        if (ip) state.upsertHost(db, targetId, ip, { hostname: name });
        state.upsertEndpoint(db, targetId, 'GET', rec.url, { tech: (rec.tech || []).join(',') });
      }
    }
    return { target, hosts: list.length };
  });
}

async function scan(db, target, opts) {
  opts = opts || {};
  const runBin = opts.runBin || defaultRunBin;
  const t = String(target);
  const runId = opts.runId || ensureRun(db, t, 'scan ' + t);
  return runPhase(db, runId, 'scan', async () => {
    const targetId = state.upsertTarget(db, t);
    // port pre-scan (best-effort narrowing); nmap is the authoritative record below.
    let ports = [];
    const naabu = await runBin('naabu', ['-host', t, '-silent'], {});
    if (naabu && naabu.status === 0) ports = parseNaabu(naabu.stdout || '');
    if (ports.length === 0) {
      const rust = await runBin('rustscan', ['-a', t, '--ulimit', '5000', '-g'], {});
      if (rust && rust.status === 0) ports = parseRustscan(rust.stdout || '');
    }
    // authoritative service/version scan
    const nmapR = await runBin('nmap', ['-sC', '-sV', '-oX', '-', t], {});
    if (nmapR && nmapR.status === 0) {
      for (const h of parsers.parseNmapXml(nmapR.stdout || '')) {
        const hostId = state.upsertHost(db, targetId, h.address, { hostname: h.hostname, os: h.os });
        for (const p of h.ports) {
          state.upsertPort(db, hostId, p.port, p.protocol, p.service, p.version, p.state);
        }
      }
    }
    return { target: t, ports: ports.length };
  });
}

async function enumerate(db, host, opts) {
  opts = opts || {};
  const runBin = opts.runBin || defaultRunBin;
  const target = normalizeHost(host);
  const runId = opts.runId || ensureRun(db, target, 'enumerate ' + target);
  return runPhase(db, runId, 'enumerate', async () => {
    const targetId = state.upsertTarget(db, target);
    const base = baseUrl(target);
    const wordlist = opts.wordlist || '/usr/share/wordlists/dirb/common.txt';
    // ffuf (fallback feroxbuster --json, parsed with the same ffuf-compatible shape)
    let hits = [];
    const ffuf = await runBin('ffuf', ['-u', base + '/FUZZ', '-w', wordlist, '-mc', 'all', '-json'], {});
    if (ffuf && ffuf.status === 0) {
      for (const line of String(ffuf.stdout || '').split(/\r?\n/)) {
        const rec = parsers.parseFfufJson(line);
        if (rec) hits.push(rec);
      }
    }
    if (hits.length === 0) {
      const ferox = await runBin('feroxbuster', ['-u', base, '--json'], {});
      if (ferox && ferox.status === 0) {
        for (const line of String(ferox.stdout || '').split(/\r?\n/)) {
          const rec = parsers.parseFfufJson(line);
          if (rec) hits.push(rec);
        }
      }
    }
    for (const rec of hits) state.upsertEndpoint(db, targetId, 'GET', rec.url, {});
    // parameter discovery (best-effort)
    const arjun = await runBin('arjun', ['-u', base], {});
    if (arjun && arjun.status === 0) {
      const params = parseArjun(arjun.stdout || '');
      if (params.length) state.upsertEndpoint(db, targetId, 'GET', base, { params });
    }
    // unauthenticated-surface probe (repo-vet plan QW5): noauth_finder when the operator has it
    // installed (env STAVROS_NOAUTH_FINDER or vendor/tools/noauth_finder/). Best-effort: absent
    // or failing tool never fails the phase. Every URL it surfaces lands in endpoints.
    const out = { target, endpoints: hits.length };
    const noauthScript = opts.noauthScript != null ? opts.noauthScript : resolveOperatorTool('STAVROS_NOAUTH_FINDER', 'noauth_finder/noauth_finder.py');
    if (!noauthScript) {
      out.noauth = { skipped: 'not installed (STAVROS_NOAUTH_FINDER / vendor/tools/noauth_finder/)' };
    } else {
      try {
        const auditDir = path.join(__dirname, '..', 'reports', 'tmp');
        fs.mkdirSync(auditDir, { recursive: true });
        const rawFile = path.join(auditDir, 'noauth-' + sanitize(target) + '.log');
        const cmd = noauthCommand(noauthScript, target);
        const r = await runBin(cmd.bin, cmd.args, { timeoutMs: opts.noauthTimeoutMs || 15 * 60 * 1000 });
        fs.writeFileSync(rawFile, String((r && r.stdout) || '') + '\n---stderr---\n' + String((r && r.stderr) || ''));
        const urls = parseDiscoveredUrls(r && r.stdout);
        for (const u of urls) state.upsertEndpoint(db, targetId, 'GET', u, { tech: 'unauth-surface' });
        out.noauth = { ran: true, script: noauthScript, exit: r && r.status, discovered: urls.length, raw: path.relative(process.cwd(), rawFile) };
      } catch (e) {
        out.noauth = { error: e.message };
      }
    }
    return out;
  });
}

// Optional post-SCAN phase (repo-vet plan QW6): fuzz network services with APT++ when the
// operator has it installed (env STAVROS_APTPP or vendor/tools/aptpp/apt++.py). NOT part of
// the auto-resume PHASES list — an operator runs `fuzz` deliberately after `scan`. Targets come
// from state.db (scan results) unless --ports overrides. Always via runBin (scope-checked).
async function fuzz(db, target, opts) {
  opts = opts || {};
  const runBin = opts.runBin || defaultRunBin;
  const t = String(target);
  const runId = opts.runId || ensureRun(db, t, 'fuzz ' + t);
  return runPhase(db, runId, 'fuzz', async () => {
    const script = opts.script != null ? opts.script : resolveOperatorTool('STAVROS_APTPP', 'aptpp/apt++.py');
    if (!script) {
      return { target: t, skipped: 'APT++ not installed (STAVROS_APTPP / vendor/tools/aptpp/apt++.py)' };
    }
    // service inventory: explicit --ports wins, else everything scan found for this target
    let jobs;
    if (opts.ports && opts.ports.length) {
      jobs = buildFuzzJobs(opts.ports.map((p) => (typeof p === 'object'
        ? { host: t, port: Number(p.port), protocol: p.protocol || 'tcp', service: p.service }
        : { host: t, port: Number(p), protocol: 'tcp', service: null })), { script, outRoot: fuzzOutRoot(t) });
    } else {
      const targetId = state.upsertTarget(db, t);
      const ports = [];
      for (const h of state.listHosts(db, targetId)) {
        for (const p of state.listPorts(db, h.id)) {
          if (p.state !== 'open') continue;
          ports.push({ host: h.address, port: p.port, protocol: p.protocol, service: p.service, version: p.version });
        }
      }
      jobs = buildFuzzJobs(ports, { script, outRoot: fuzzOutRoot(t) });
    }
    if (!jobs.length) return { target: t, skipped: 'no open ports known for this target (run scan first or pass --ports)' };

    const results = [];
    for (const job of jobs.slice(0, opts.maxJobs || 16)) {
      try {
        const r = await runBin(job.bin, job.args, { timeoutMs: opts.jobTimeoutMs || 10 * 60 * 1000 });
        const tally = countFuzzCrashes(path.join(fuzzOutRoot(t), job.host + '-' + job.port));
        results.push({ ...job, args: undefined, exit: r && r.status, crashes: tally.crashes, crash_files: tally.crashFiles });
      } catch (e) {
        results.push({ mode: job.mode, host: job.host, port: job.port, error: e.message });
      }
    }
    return {
      target: t,
      fuzzed: results.filter((r) => !r.error).length,
      total_crashes: results.reduce((n, r) => n + (r.crashes || 0), 0),
      results,
    };
  });
}

function fuzzOutRoot(target) {
  return process.env.STAVROS_FUZZ_OUT || path.join(__dirname, '..', 'reports', 'tmp', 'fuzz-' + sanitize(target));
}

// ---- status / resume / report ----

function status(db, host) {
  const targets = host
    ? (() => { const t = state.getTarget(db, normalizeHost(host)); return t ? [t] : []; })()
    : state.listTargets(db);
  const run = state.lastRun(db);
  return {
    run: run && { id: run.id, status: run.status, command: run.command, target: run.target, phases: state.listPhases(db, run.id) },
    targets: targets.map((t) => {
      const hosts = state.listHosts(db, t.id);
      const portCount = hosts.reduce((n, h) => n + state.listPorts(db, h.id).length, 0);
      return {
        target: t.host,
        first_seen: t.first_seen,
        last_seen: t.last_seen,
        hosts: hosts.length,
        ports: portCount,
        endpoints: state.listEndpoints(db, t.id).length,
      };
    }),
  };
}

async function resume(db, opts) {
  opts = opts || {};
  const run = state.lastRun(db);
  if (!run) return { resumed: false, reason: 'no runs yet' };
  if (run.status === 'done') return { resumed: false, reason: 'last run already done', run: run.id };
  if (!run.target) return { resumed: false, reason: 'last run has no target', run: run.id };
  const results = {};
  for (const name of PHASES) {
    const ph = state.getPhase(db, run.id, name);
    if (ph && ph.status === 'done') {
      results[name] = 'skipped';
      continue;
    }
    const phaseOpts = Object.assign({}, opts, { runId: run.id });
    if (name === 'recon') await recon(db, run.target, phaseOpts);
    else if (name === 'scan') await scan(db, run.target, phaseOpts);
    else await enumerate(db, run.target, phaseOpts);
    results[name] = 'done';
  }
  state.finishRun(db, run.id, 'done');
  return { resumed: true, run: run.id, target: run.target, results };
}

function report(db, opts) {
  opts = opts || {};
  const run = state.lastRun(db);
  if (run && run.status === 'running') state.finishRun(db, run.id, 'done');
  const targets = state.listTargets(db).map((t) => ({
    target: t.host,
    hosts: state.listHosts(db, t.id).map((h) => ({
      address: h.address, hostname: h.hostname, os: h.os,
      ports: state.listPorts(db, h.id),
    })),
    endpoints: state.listEndpoints(db, t.id),
  }));
  const findingsFile = opts.findingsFile || process.env.FINDINGS_JSONL || path.join(__dirname, '..', 'reports', 'findings.jsonl');
  let findings = [];
  try {
    findings = fs.readFileSync(findingsFile, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
  } catch {}
  return {
    run: run && { id: run.id, status: 'done', command: run.command, target: run.target, phases: state.listPhases(db, run.id) },
    targets,
    findings_count: findings.length,
    findings,
  };
}

// ---- CLI ----

function usage() {
  console.error(
    'usage: node tools/stavros.js recon <host> | scan <host|cidr> | enumerate <host> | fuzz <host> [--ports N,N] | status [<host>] | resume | report'
  );
  process.exit(2);
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd) usage();
  const db = state.open();
  const opts = { scope: loadScopeSafe() };
  // --ports 80,443 / --ports 53:udp for fuzz
  const portsIdx = rest.indexOf('--ports');
  if (portsIdx >= 0 && rest[portsIdx + 1]) {
    opts.ports = String(rest[portsIdx + 1]).split(',').map((s) => {
      const [p, proto] = s.split(':');
      return { port: Number(p), protocol: proto || 'tcp' };
    }).filter((p) => p.port > 0);
  }
  try {
    let out;
    switch (cmd) {
      case 'recon':
        if (!rest[0]) usage();
        out = await recon(db, rest[0], opts);
        break;
      case 'scan':
        if (!rest[0]) usage();
        out = await scan(db, rest[0], opts);
        break;
      case 'enumerate':
        if (!rest[0]) usage();
        out = await enumerate(db, rest[0], opts);
        break;
      case 'fuzz':
        if (!rest[0]) usage();
        out = await fuzz(db, rest[0], opts);
        break;
      case 'status':
        out = status(db, rest[0] || null);
        break;
      case 'resume':
        out = await resume(db, opts);
        break;
      case 'report':
        out = report(db, opts);
        break;
      default:
        usage();
    }
    console.log(JSON.stringify(out, null, 2));
  } catch (e) {
    console.error(JSON.stringify({ error: e.message, blocked: e.blocked || undefined, reason: e.reason, bad: e.bad }));
    process.exit(1);
  } finally {
    db.close();
  }
}

if (require.main === module) main();

module.exports = {
  recon, scan, enumerate, fuzz, status, resume, report,
  reconCommands, parseNaabu, parseRustscan, parseArjun,
  normalizeHost, baseUrl, extractHostFromLine, mapLimit,
  defaultRunBin, PHASES,
  resolveOperatorTool, noauthCommand, parseDiscoveredUrls, buildFuzzJobs, countFuzzCrashes,
};
