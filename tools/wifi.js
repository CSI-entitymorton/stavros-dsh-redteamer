#!/usr/bin/env node
// Wireless scope-enforcing runner + orchestration (Fase 4). Wireless is a SEPARATE mode from
// the web/network pipeline (tools/stavros.js): targets are BSSID/ESSID/station/channel, NOT
// IPs, so run.js/scope-guard.js don't apply here — this is the wireless analog of run.js.
//
//   node tools/wifi.js check <target>                      scope verdict (exit 0 = in scope)
//   node tools/wifi.js scan <iface>                        monitor mode + passive airodump-ng (auto)
//   node tools/wifi.js capture <bssid> [--channel N] [--write <cap>] [--pmkid] [--confirm "reason"]
//   node tools/wifi.js crack <cap> [--wordlist <w>]        offline aircrack-ng (auto)
//   node tools/wifi.js wps <bssid> [--channel N] [--confirm "reason"]
//   node tools/wifi.js status                              summary of reports/wifi-aps.jsonl
//
// Every third-party wireless binary runs through runWifi (default = scope-check + tier-check +
// audit + streaming runBinary). Inject a fake runWifi in tests to exercise the command assembly
// offline. Disruptive actions (deauth, WPS, wifite2 automation, hcxdumptool PMKID) are
// confirm-tier: refused without --confirm "<reason>" (explicit in-session approval), mirroring
// c2-guard.js for host ops. Passive listening (airodump-ng/wash) and offline cracking
// (aircrack-ng) are auto-tier.
//
// ponytail: aircrack-ng/wifite2/reaver/hcxdumptool output is human text (not a stable machine
// format); airodump-ng CSV is parsed best-effort (ESSID may contain commas). The monitor-mode
// interface name convention (<iface>mon) is not universal — verify on the real NIC.
const fs = require('fs');
const path = require('path');
const wg = require('./wifi-guard');
const { runBinary } = require('./run');
const pace = require('./pace');

const APS_FILE = () => process.env.WIFI_APS_JSONL || path.join(__dirname, '..', 'reports', 'wifi-aps.jsonl');
const AUDIT_FILE = () => process.env.WIFI_AUDIT_JSONL || path.join(__dirname, '..', 'reports', 'tmp', 'wifi-audit.jsonl');

// ---- target extraction (BSSID / ESSID / channel from a wireless tool's argv) ----
const MAC_RE = /\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b|\b[0-9a-fA-F]{12}\b/g;
const ESSID_FLAGS = new Set(['-e', '--essid', '--essid-regex']);
const CHANNEL_FLAGS = new Set(['-c', '--channel']);

function extractTargets(args) {
  const bssids = new Set();
  const essids = new Set();
  const channels = new Set();
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    for (const m of a.match(MAC_RE) || []) {
      const n = wg.normalizeMac(m);
      if (n) bssids.add(n);
    }
    if (ESSID_FLAGS.has(a) && args[i + 1] != null) essids.add(String(args[i + 1]));
    if (CHANNEL_FLAGS.has(a) && wg.isChannel(args[i + 1])) channels.add(Number(args[i + 1]));
  }
  return { bssids: [...bssids], essids: [...essids], channels: [...channels] };
}

// ---- action classification (bin + args -> action class) ----
const RULES = [
  [/\baireplay-ng\b|\bmdk[34]\b|\bmacchanger\b/i, 'deauth'],
  [/\breaver\b|\bbully\b|\bpixiewps\b/i, 'wps'],
  [/\bwifite2?\b|\bfluxion\b|\bairgeddon\b/i, 'automated'],
  [/\bhcxdumptool\b|\bhcxpcapngtool\b/i, 'capture'],
  [/\bairodump-ng\b|\bairmon-ng\b|\bwash\b/i, 'scan'],
  [/\baircrack-ng\b/i, 'crack'],
];

function classifyRaw(bin, args) {
  const text = [bin].concat(args).join(' ');
  for (const [re, cls] of RULES) if (re.test(text)) return cls;
  return null;
}

function loadTiers(scope) {
  const wo = (scope && scope.wireless_ops) || {};
  return {
    auto: new Set(wo.auto || ['scan', 'crack']),
    confirm: new Set(wo.confirm || ['deauth', 'capture', 'wps', 'automated']),
  };
}

function classify(bin, args, scope) {
  const tiers = loadTiers(scope);
  const cls = classifyRaw(bin, args);
  if (cls && tiers.auto.has(cls)) return { actionClass: cls, tier: 'auto' };
  return { actionClass: cls || 'unknown', tier: 'confirm' }; // unknown -> confirm (fail closed)
}

// ---- audit trail (same evidence convention as run.js) ----
function auditWifi(entry) {
  try {
    const p = AUDIT_FILE();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify(entry) + '\n');
  } catch {}
}

function writeAtomic(file, data) {
  const tmp = file + '.' + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

// ---- discovered APs (reports/wifi-aps.jsonl, deduped on bssid) ----
function readAps() {
  try {
    return fs.readFileSync(APS_FILE(), 'utf8').split(/\r?\n/).filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
  } catch {
    return [];
  }
}

function appendAps(recs) {
  const existing = readAps();
  const seen = new Set(existing.map((a) => a.bssid));
  let n = 0;
  const lines = [];
  for (const r of recs) {
    if (!r || !r.bssid || seen.has(r.bssid)) continue;
    seen.add(r.bssid);
    lines.push(JSON.stringify(Object.assign({ first_seen: new Date().toISOString() }, r)));
    n++;
  }
  if (lines.length) {
    const p = APS_FILE();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    writeAtomic(p, existing.map((a) => JSON.stringify(a)).concat(lines).join('\n') + '\n');
  }
  return n;
}

// ---- runWifi: injectable, default = scope-check + tier-check + audit + runBinary ----
async function defaultRunWifi(bin, args, opts) {
  opts = opts || {};
  let scope;
  try {
    scope = wg.loadWifiScope();
  } catch {
    const e = new Error('wifi-scope.json missing - nothing is authorized yet');
    e.blocked = true;
    throw e;
  }
  if (wg.scopeEmpty(scope)) {
    const e = new Error('wifi-scope.json empty - nothing is authorized yet');
    e.blocked = true;
    throw e;
  }
  const { bssids, essids, channels } = extractTargets(args);
  const { tier, actionClass } = classify(bin, args, scope);
  const confirm = opts.confirm && String(opts.confirm).trim();
  if (tier === 'confirm' && !confirm) {
    const e = new Error(`action '${actionClass}' is confirm-tier: pass --confirm "<reason>" (requires explicit in-session user approval)`);
    e.blocked = true; e.tier = tier; e.actionClass = actionClass;
    throw e;
  }
  // scope-check every extracted target (fail closed)
  const bad = [];
  for (const b of bssids) if (!wg.bssidInScope(b, scope).ok && !wg.stationInScope(b, scope).ok) bad.push(b);
  for (const e2 of essids) if (!wg.essidInScope(e2, scope).ok) bad.push(JSON.stringify(e2));
  for (const c of channels) if (!wg.channelInScope(c, scope).ok) bad.push('channel ' + c);
  // No live target in argv: only auto-tier actions (passive scan / offline crack) may proceed —
  // they don't touch a live AP. Confirm-tier actions with no target are meaningless-or-dangerous
  // and fail closed (unknown bins classify as confirm, so they're covered too).
  const noTargets = bssids.length === 0 && essids.length === 0 && channels.length === 0;
  if (noTargets && tier !== 'auto') {
    const e = new Error('no in-scope wireless target found in args (fail closed)');
    e.blocked = true; e.reason = 'no wireless target found';
    throw e;
  }
  if (bad.length) {
    const e = new Error('out-of-scope wireless target(s): ' + bad.join(', '));
    e.blocked = true; e.bad = bad;
    throw e;
  }
  const rps = (scope && scope.max_requests_per_second) || 1;
  await pace.wait(rps);
  auditWifi({ ts: new Date().toISOString(), bin, args, bssids, essids, channels, action: actionClass, tier, confirmed: !!confirm });
  const exec = opts.runBinary || runBinary;
  const r = await exec(bin, args, { capture: true, input: opts.input, timeoutMs: opts.timeoutMs });
  auditWifi({ ts: new Date().toISOString(), bin, args, action: actionClass, exit: r.status, ok: r.status === 0, error: r.error });
  return r;
}

// ---- concrete command lists (kept pure for tests) ----

function scanCommands(iface) {
  const mon = iface + 'mon';
  return [
    { bin: 'airmon-ng', args: ['start', iface] },
    { bin: 'airodump-ng', args: [mon, '--output-format', 'csv', '-w', path.join('reports', 'wifi', 'scan')] },
  ];
}

function captureCommands(bssid, opts) {
  opts = opts || {};
  const b = wg.normalizeMac(bssid) || String(bssid);
  const mon = opts.iface ? opts.iface + 'mon' : 'wlan0mon';
  const cap = opts.write || path.join('reports', 'wifi', 'capture-' + b.replace(/:/g, ''));
  if (opts.pmkid) {
    return [{ bin: 'hcxdumptool', args: ['-i', mon, '--filterlist_ap=' + b, '--filtermode=2', '-w', cap] }];
  }
  const cmds = [{ bin: 'airodump-ng', args: ['-c', String(opts.channel), '--bssid', b, '-w', cap, mon] }];
  cmds.push({ bin: 'aireplay-ng', args: ['-0', '3', '-a', b, mon] });
  return cmds;
}

function crackCommands(cap, opts) {
  opts = opts || {};
  const w = opts.wordlist || '/usr/share/wordlists/rockyou.txt';
  return [{ bin: 'aircrack-ng', args: [cap, '-w', w] }];
}

function wpsCommands(bssid, opts) {
  opts = opts || {};
  const b = wg.normalizeMac(bssid) || String(bssid);
  const mon = opts.iface ? opts.iface + 'mon' : 'wlan0mon';
  return [{ bin: 'reaver', args: ['-i', mon, '-b', b, '-c', String(opts.channel), '-vv'] }];
}

// ---- airodump-ng CSV parser (pure; AP section only) ----
// ponytail: the airodump CSV layout is fixed but the ESSID column may contain commas, so it is
// re-joined from column 13 onward. A changed layout degrades to [] instead of wrong records.
function parseAirodumpCsv(text) {
  const aps = [];
  if (text == null || typeof text !== 'string') return aps;
  let inAp = false;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (/^BSSID,/.test(line)) { inAp = true; continue; }
    if (/^Station MAC,/.test(line)) { inAp = false; continue; } // station section follows the APs
    if (!inAp) continue;
    const cols = line.split(',').map((c) => String(c).trim());
    const bssid = wg.normalizeMac(cols[0]);
    if (!bssid) continue;
    // ESSID is column 13; the empty Key column follows, so join from 13 and drop the trailing
    // empty field. (An ESSID containing unquoted commas would still split — ponytail.)
    const essid = cols.slice(13).join(',').replace(/,\s*$/, '') || null;
    aps.push({
      bssid,
      channel: cols[3] ? Number(cols[3]) : null,
      privacy: cols[5] || null,
      cipher: cols[6] || null,
      auth: cols[7] || null,
      essid,
    });
  }
  return aps;
}

// ---- subcommands ----

async function scan(iface, opts) {
  opts = opts || {};
  const runWifi = opts.runWifi || defaultRunWifi;
  const results = [];
  for (const c of scanCommands(iface)) {
    const r = await runWifi(c.bin, c.args, opts);
    results.push({ cmd: c.bin, args: c.args, status: r && r.status, stdout: r && r.stdout });
  }
  let aps = [];
  if (opts.csvText) {
    aps = parseAirodumpCsv(opts.csvText);
  } else {
    const dir = path.join(__dirname, '..', 'reports', 'wifi');
    try {
      const files = fs.readdirSync(dir).filter((f) => /\.csv$/.test(f) && f.startsWith('scan')).sort();
      for (const f of files.slice(-3)) {
        const recs = parseAirodumpCsv(fs.readFileSync(path.join(dir, f), 'utf8'));
        aps = aps.concat(recs.filter((a) => !aps.some((x) => x.bssid === a.bssid)));
      }
    } catch {}
  }
  const added = aps.length ? appendAps(aps) : 0;
  return { iface, results, aps: added };
}

async function capture(bssid, opts) {
  opts = opts || {};
  const runWifi = opts.runWifi || defaultRunWifi;
  const results = [];
  for (const c of captureCommands(bssid, opts)) {
    const r = await runWifi(c.bin, c.args, opts);
    results.push({ cmd: c.bin, args: c.args, status: r && r.status, stdout: r && r.stdout });
  }
  return { bssid: wg.normalizeMac(bssid), results };
}

async function crack(cap, opts) {
  opts = opts || {};
  const runWifi = opts.runWifi || defaultRunWifi;
  const cmd = crackCommands(cap, opts)[0];
  const r = await runWifi(cmd.bin, cmd.args, opts);
  return { cap, status: r && r.status, stdout: r && r.stdout };
}

async function wps(bssid, opts) {
  opts = opts || {};
  const runWifi = opts.runWifi || defaultRunWifi;
  const cmd = wpsCommands(bssid, opts)[0];
  const r = await runWifi(cmd.bin, cmd.args, opts);
  return { bssid: wg.normalizeMac(bssid), status: r && r.status, stdout: r && r.stdout };
}

function status() {
  const aps = readAps();
  return { aps: aps.length, list: aps };
}

// ---- CLI ----

function usage() {
  console.error(
    'usage: node tools/wifi.js check <target> | scan <iface> | capture <bssid> [--channel N] [--write <cap>] [--pmkid] [--confirm "<reason>"] | crack <cap> [--wordlist <w>] | wps <bssid> [--channel N] [--confirm "<reason>"] | status'
  );
  process.exit(2);
}

function parseArgs(rest) {
  const opts = {};
  const pos = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--channel') opts.channel = Number(rest[++i]);
    else if (a === '--write') opts.write = rest[++i];
    else if (a === '--wordlist') opts.wordlist = rest[++i];
    else if (a === '--iface') opts.iface = rest[++i];
    else if (a === '--pmkid') opts.pmkid = true;
    else if (a === '--confirm') opts.confirm = rest[++i];
    else pos.push(a);
  }
  return { opts, pos };
}

async function main() {
  const argv = process.argv.slice(2);
  const [cmd, ...rest] = argv;
  if (!cmd) usage();
  if (cmd === 'check') {
    let scope;
    try { scope = wg.loadWifiScope(); } catch (e) {
      console.log(JSON.stringify({ ok: false, reason: 'wifi-scope.json missing - nothing is authorized yet' }));
      process.exit(1);
    }
    if (wg.scopeEmpty(scope)) {
      console.log(JSON.stringify({ ok: false, reason: 'wifi-scope.json empty - nothing is authorized yet' }));
      process.exit(1);
    }
    const res = wg.inWifiScope(rest[0], scope);
    console.log(JSON.stringify(res));
    process.exit(res.ok ? 0 : 1);
  }
  if (cmd === 'status') {
    console.log(JSON.stringify(status(), null, 2));
    process.exit(0);
  }
  const { opts, pos } = parseArgs(rest);
  try {
    let out;
    switch (cmd) {
      case 'scan':
        if (!pos[0]) usage();
        out = await scan(pos[0], opts);
        break;
      case 'capture':
        if (!pos[0]) usage();
        out = await capture(pos[0], opts);
        break;
      case 'crack':
        if (!pos[0]) usage();
        out = await crack(pos[0], opts);
        break;
      case 'wps':
        if (!pos[0]) usage();
        out = await wps(pos[0], opts);
        break;
      default:
        usage();
    }
    console.log(JSON.stringify(out, null, 2));
  } catch (e) {
    console.error(JSON.stringify({ error: e.message, blocked: e.blocked || undefined, tier: e.tier, action: e.actionClass, bad: e.bad }));
    process.exit(1);
  }
}

if (require.main === module) main();

module.exports = {
  scan, capture, crack, wps, status,
  scanCommands, captureCommands, crackCommands, wpsCommands,
  extractTargets, classify, classifyRaw, loadTiers,
  parseAirodumpCsv, readAps, appendAps,
  defaultRunWifi,
};
