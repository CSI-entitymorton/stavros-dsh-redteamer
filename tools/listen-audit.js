#!/usr/bin/env node
// A4 mitigazione-S (Ondata 3) — periodic READ-ONLY audit of listening sockets vs scope.json.
//
// What it does: collects every LISTENING socket (ss, fallback netstat, final fallback a
// pure /proc parser), enriches with pid+cmdline when the kernel exposes them, classifies
// each listener against the SAME scope.json used by run.js/repeater.js, and reports:
//   in_scope     — listening address is an authorized target/IP/CIDR
//   wildcard     — 0.0.0.0 / :: / * : reachable on ALL interfaces (always worth review)
//   local_only   — 127.0.0.0/8 or ::1 only
//   out_of_scope — specific address NOT covered by scope (the interesting case)
//
// Hard guarantees (spec): strictly read-only — this tool NEVER kills/signals/writes to any
// process; its only optional write is ONE appended row to evidence-index.md (--evidence-index,
// single-writer E-numbering, same convention as workflow/poc-replay).
//
// Usage:
//   node tools/listen-audit.js [--json] [--scope <file>]
//        [--ss-file <fixture>]            # canned `ss -tulnH` output (tests/offline)
//        [--loop <sec> --max-runs <n>]    # periodic audit; default single shot
//        [--evidence-index <file>]        # append summary row (opt-in)
//   Exit: 0 ok · 2 usage/internal error (findings NEVER affect the exit code)
'use strict';
const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawnSync } = require('child_process');
const { loadScope, inScope, cidrInScope, normalizeScope } = require('./scope-guard');

const WS_ROOT = path.join(__dirname, '..');
const DEFAULT_EI = path.join(WS_ROOT, 'evidence-index.md');

// ---------------------------------------------------------------- listeners collection

/** Parse one line of `ss -tulnH`: Netid State Recv-Q Send-Q Local-Address:Port Peer:Port */
function parseSsLine(line) {
  const parts = String(line).trim().split(/\s+/);
  if (parts.length < 5) return null;
  const proto = parts[0];
  const state = parts[1];
  // `ss -tulnH` columns: Netid State Recv-Q Send-Q Local Peer; some builds without -H
  // print a header we skip; udp has State 'UNCONN'.
  if (!/^(tcp|udp)/.test(proto)) return null;
  if (!/^(LISTEN|UNCONN)$/i.test(state)) return null;
  let local = parts[4] != null ? parts[4] : parts[2];
  // Robustness: if parts[4] exists use it, else fall back (older ss layouts).
  if (parts.length >= 6) local = parts[4];
  const m = local.match(/^(.*):(\d+|\*)$/);
  if (!m) return null;
  let addr = m[1];
  if (addr.startsWith('[') && addr.endsWith(']')) addr = addr.slice(1, -1);
  return { proto: proto.toLowerCase(), addr: addr === '*' ? '0.0.0.0' : addr, port: m[2] };
}

function collectFromSsText(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim() || /^(Netid|Netid\s)/.test(line.trim())) continue;
    const rec = parseSsLine(line);
    if (rec) out.push(rec);
  }
  return out;
}

function trySs() {
  for (const bin of ['/usr/sbin/ss', '/bin/ss', '/usr/bin/ss']) {
    if (!fs.existsSync(bin)) continue;
    const r = spawnSync(bin, ['-tulnH'], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout) return { source: 'ss', listeners: collectFromSsText(r.stdout) };
  }
  const w = spawnSync('/usr/bin/which', ['ss'], { encoding: 'utf8' });
  if (w.status === 0 && w.stdout.trim()) {
    const r = spawnSync(w.stdout.trim(), ['-tulnH'], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout) return { source: 'ss', listeners: collectFromSsText(r.stdout) };
  }
  return null;
}

function tryNetstat() {
  const w = spawnSync('/usr/bin/which', ['netstat'], { encoding: 'utf8' });
  if (w.status !== 0 || !w.stdout.trim()) return null;
  const r = spawnSync(w.stdout.trim(), ['-tuln'], { encoding: 'utf8' });
  if (r.status !== 0 || !r.stdout) return null;
  const listeners = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    // Linux netstat: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN
    const m = line.trim().match(/^(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+):(\d+|\*)\s+\S+\s+(LISTEN|UNCONN)/i);
    if (!m) continue;
    let addr = m[2];
    if (addr.startsWith('[') && addr.endsWith(']')) addr = addr.slice(1, -1);
    listeners.push({ proto: m[1].toLowerCase(), addr: addr === '*' ? '0.0.0.0' : addr, port: m[3] });
  }
  return listeners.length ? { source: 'netstat', listeners } : null;
}

// Final fallback: parse /proc/net/{tcp,tcp6,udp,udp6} directly (no external binary).
function hexToIp(h) {
  // /proc stores little-endian words for IPv4, big byte-order hex groups for IPv6.
  if (h.length === 8) {
    const b = [h.slice(6, 8), h.slice(4, 6), h.slice(2, 4), h.slice(0, 2)].map((x) => parseInt(x, 16));
    return b.join('.');
  }
  const groups = [];
  for (let i = 0; i < 16; i += 4) groups.push(h.slice(i, i + 4).replace(/^0+(?=.)/, ''));
  return groups.join(':').toLowerCase();
}

function collectFromProc(root) {
  const listeners = [];
  const files = [['tcp', 'tcp'], ['tcp6', 'tcp'], ['udp', 'udp'], ['udp6', 'udp']];
  for (const [fname, proto] of files) {
    let text;
    try { text = fs.readFileSync(path.join(root, 'net', fname), 'utf8'); } catch { continue; }
    const lines = text.split(/\r?\n/).filter(Boolean);
    for (const line of lines.slice(1)) {
      const c = line.trim().split(/\s+/);
      // /proc/net/tcp columns: sl local_address rem_address st ... uid timeout inode
      if (c.length < 10 || !c[1] || !c[1].includes(':')) continue;
      const [localHex, localPortHex] = c[1].split(':');
      const st = (c[3] || '').toUpperCase();
      const isListen = proto === 'tcp' ? st === '0A' : true; // TCP_LISTEN=0A; udp has no state
      if (!isListen) continue;
      listeners.push({
        proto,
        addr: hexToIp(localHex),
        port: String(parseInt(localPortHex, 16)),
        inode: c[9],
      });
    }
  }
  return listeners;
}

/** Index /proc once: "addr|port" -> { pids:[], cmdlines:[] }. Read-only walk. */
function buildProcIndex(procRoot) {
  procRoot = procRoot || '/proc';
  const inodeToPids = new Map();
  let pids = [];
  try { pids = fs.readdirSync(procRoot).filter((d) => /^\d+$/.test(d)); } catch { /* no /proc */ }
  for (const pid of pids) {
    let fds = [];
    try { fds = fs.readdirSync(path.join(procRoot, pid, 'fd')); } catch { continue; }
    for (const fd of fds) {
      let link = '';
      try { link = fs.readlinkSync(path.join(procRoot, pid, 'fd', fd)); } catch { continue; }
      const m = link.match(/^socket:\[(\d+)\]$/);
      if (!m) continue;
      if (!inodeToPids.has(m[1])) inodeToPids.set(m[1], []);
      inodeToPids.get(m[1]).push(Number(pid));
    }
  }
  const cmdlineCache = new Map();
  const cmdlineOf = (pid) => {
    if (cmdlineCache.has(pid)) return cmdlineCache.get(pid);
    let cmd = null;
    try {
      cmd = fs.readFileSync(path.join(procRoot, String(pid), 'cmdline'), 'utf8')
        .split('\0').filter(Boolean).join(' ').slice(0, 160) || null;
    } catch {}
    cmdlineCache.set(pid, cmd);
    return cmd;
  };
  // port index from /proc/net/* (works even when the socket table came from ss/netstat)
  const byKey = new Map();
  for (const l of collectFromProc(procRoot)) {
    const k = `${l.addr}|${l.port}`;
    if (!byKey.has(k)) byKey.set(k, { pids: [], cmdlines: [] });
    for (const pid of inodeToPids.get(l.inode) || []) {
      if (!byKey.get(k).pids.includes(pid)) {
        byKey.get(k).pids.push(pid);
        byKey.get(k).cmdlines.push(cmdlineOf(pid));
      }
    }
  }
  return byKey;
}

/** Enrich listeners with pid+cmdline when the kernel exposes them (best effort). */
function enrichWithProcs(listeners, procRoot) {
  let index = null;
  try { index = buildProcIndex(procRoot); } catch {}
  if (!index) return listeners;
  return listeners.map((l) => {
    const hit = index.get(`${l.addr}|${l.port}`);
    if (hit && hit.pids.length) {
      return { ...l, procs: hit.pids.map((p, i) => ({ pid: p, cmdline: hit.cmdlines[i] })) };
    }
    return l;
  });
}

// ---------------------------------------------------------------- classification

function classify(addr, scope) {
  if (addr === '0.0.0.0' || addr === '::' || addr === '*') return 'wildcard';
  if (net.isIP(addr) === 6 && /^::1$/.test(addr)) return 'local_only';
  if (/^127\./.test(addr)) return 'local_only';
  // exact-IP authorization via inScope (dual-schema: allowed_hosts/targets) ...
  try {
    const url = net.isIP(addr) === 6 ? `http://[${addr}]/` : `http://${addr}/`;
    if (inScope(url, scope).ok) return 'in_scope';
  } catch {}
  // ... or any covering CIDR in allowed_ips.
  try {
    if (cidrInScope(`${addr}/32`, scope).ok) return 'in_scope';
  } catch {}
  return 'out_of_scope';
}

// ---------------------------------------------------------------- evidence-index append

function nextEvidenceNumber(eiFile) {
  try {
    let max = 0;
    for (const m of fs.readFileSync(eiFile, 'utf8').matchAll(/^\|\s*E-(\d+)\s*\|/gm)) max = Math.max(max, parseInt(m[1], 10));
    return max + 1;
  } catch { return 1; }
}

function appendEvidenceRow(eiFile, summary) {
  const n = nextEvidenceNumber(eiFile);
  const date = new Date().toISOString().slice(0, 10);
  const oos = summary.out_of_scope.map((l) => `${l.addr}:${l.port}`).slice(0, 5).join(', ') || 'nessuno';
  const line = `| E-${String(n).padStart(3, '0')} | ${date} | \`reports/tmp/listen-audit-latest.json\` | listen-audit read-only: ${summary.total} ascolti (${summary.source}) → in_scope=${summary.counts.in_scope} wildcard=${summary.counts.wildcard} local_only=${summary.counts.local_only} out_of_scope=${summary.counts.out_of_scope} [${oos}] | listen-audit |`;
  fs.mkdirSync(path.dirname(eiFile), { recursive: true });
  fs.appendFileSync(eiFile, line + '\n');
  return n;
}

// ---------------------------------------------------------------- main

function runOnce(opts) {
  let collected = null;
  let source = null;
  if (opts.ssFile) {
    collected = collectFromSsText(fs.readFileSync(opts.ssFile, 'utf8'));
    source = `fixture:${path.basename(opts.ssFile)}`;
  } else {
    const ss = trySs();
    if (ss) { collected = ss.listeners; source = ss.source; }
    else {
      const ns = tryNetstat();
      if (ns) { collected = ns.listeners; source = ns.source; }
      else { collected = collectFromProc('/proc'); source = '/proc'; }
    }
  }
  const scope = opts.scopeObj != null ? normalizeScope(opts.scopeObj) : loadScope(opts.scopeFile);
  const seen = new Set();
  const unique = [];
  for (const l of collected) {
    const key = `${l.proto}|${l.addr}|${l.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(l);
  }
  const enriched = opts.noProc ? unique : enrichWithProcs(unique, opts.procRoot);
  const rows = enriched.map((l) => ({ ...l, verdict: classify(l.addr, scope) }));
  const counts = { in_scope: 0, wildcard: 0, local_only: 0, out_of_scope: 0 };
  for (const r of rows) counts[r.verdict]++;
  return {
    ts: new Date().toISOString(),
    source,
    total: rows.length,
    counts,
    in_scope: rows.filter((r) => r.verdict === 'in_scope'),
    wildcard: rows.filter((r) => r.verdict === 'wildcard'),
    local_only: rows.filter((r) => r.verdict === 'local_only'),
    out_of_scope: rows.filter((r) => r.verdict === 'out_of_scope'),
    note: 'read-only audit: nessun processo è stato toccato',
  };
}

function parseArgs(argv) {
  const o = { json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--scope') o.scopeFile = argv[++i];
    else if (a === '--ss-file') o.ssFile = argv[++i];
    else if (a === '--proc-root') o.procRoot = argv[++i]; // tests only
    else if (a === '--no-proc') o.noProc = true;          // skip pid enrichment (offline determinism)
    else if (a === '--loop') o.loopSec = Math.max(1, parseInt(argv[++i], 10) || 0);
    else if (a === '--max-runs') o.maxRuns = Math.max(1, parseInt(argv[++i], 10) || 0);
    else if (a === '--evidence-index') o.evidenceIndex = argv[++i];
    else if (a === '--out') o.out = argv[++i];            // mirror JSON to file (reports/tmp)
    else { console.error('argomento sconosciuto: ' + a); process.exit(2); }
  }
  return o;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  let runs = 0;
  const tick = () => {
    let result;
    try { result = runOnce(opts); } catch (e) {
      console.error(JSON.stringify({ error: 'listen-audit failed: ' + e.message }));
      process.exit(2);
    }
    runs++;
    if (opts.out) {
      try {
        fs.mkdirSync(path.dirname(opts.out), { recursive: true });
        fs.writeFileSync(opts.out, JSON.stringify(result, null, 2) + '\n');
      } catch {}
    }
    if (opts.evidenceIndex && runs === 1) result.evidence_row = appendEvidenceRow(opts.evidenceIndex, result);
    console.log(JSON.stringify(result, null, opts.json ? 2 : 2));
    return result;
  };
  if (!opts.loopSec) { tick(); return 0; }
  const limit = opts.maxRuns || Infinity;
  const timer = setInterval(() => {
    tick();
    if (runs >= limit) { clearInterval(timer); process.exit(0); }
  }, opts.loopSec * 1000);
  tick();
  return 0;
}

if (require.main === module) process.exit(main());
module.exports = { parseSsLine, collectFromSsText, collectFromProc, hexToIp, buildProcIndex, enrichWithProcs, classify, runOnce, parseArgs };
