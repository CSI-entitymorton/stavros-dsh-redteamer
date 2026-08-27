#!/usr/bin/env node
// Scope-enforcing wrapper for the Obscura headless browser (Rust engine, CDP-compatible).
//   https://github.com/h4ckf0r0day/obscura  (Apache-2.0)
//
//   node tools/obscura.js check <url>                       scope verdict only (exit 0 = in scope)
//   node tools/obscura.js fetch <url> [--stealth] [--dump html|text|links|markdown]
//         [--eval js] [--screenshot f] [--timeout s] [--wait-until ev] [--selector css] [--output f]
//   node tools/obscura.js scrape <url...> [--concurrency n] [--stealth] [--format json|text]
//   node tools/obscura.js serve [--port 9222] [--stealth] [--workers n]    CDP server per dom-check.js
//   node tools/obscura.js status                            binary/version/server/egress summary
//
// Security model (same philosophy as run.js/wifi.js — HARD, in code):
//   - fetch/scrape: every positional URL is scope-checked via scope-guard.js BEFORE exec;
//     zero hosts found -> refuse (fail closed), any out-of-scope host -> refuse. Every invocation
//     is audited to reports/tmp/run-audit.jsonl (same evidence trail as run.js).
//   - serve: no target exists at launch, so per-target enforcement stays with the callers
//     (dom-check.js scope-checks every URL it navigates). When the egress gateway is running,
//     obscura is PINNED to it (--proxy http://127.0.0.1:<port>) so even manual navigation cannot
//     leave the allowlist — the same opt-in enforcement run.js applies via HTTP_PROXY.
//   - Pacing: pace.wait(rps) once per invocation. NOTE: obscura's internal scrape workers are
//     invisible to pace.js, so concurrency is clamped hard (default 2, max 8) — raise only via
//     OBSCURA_MAX_CONCURRENCY and keep max_requests_per_second honest.
//
// Binary resolution: $STAVROS_OBSCURA_BIN > vendor/tools/obscura/obscura[.exe] > $PATH
// (install: ./install-tools.sh downloads a version-pinned release into vendor/tools/obscura/).
//
// ponytail: obscura is a YOUNG project (v0.2.x) — flags may shift between releases; this wrapper
// pins behavior against v0.2.0 CLI. The engine is NOT Chromium: DOM/CSS edge cases differ from a
// real browser, so use it to EXPLORE surface and CONFIRM DOM-XSS findings on real Chrome.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { loadScope, inScope } = require('./scope-guard');
const { runBinary, bareHost } = require('./run');
const pace = require('./pace');

// Read fresh on every call so OBSCURA_EGRESS_STATE can be pointed elsewhere after load.
function egressStatePath() {
  return process.env.OBSCURA_EGRESS_STATE
    || path.join(__dirname, '..', 'reports', 'tmp', 'egress-proxy.json');
}
const AUDIT_FILE = () => process.env.OBSCURA_AUDIT_JSONL
  || path.join(__dirname, '..', 'reports', 'tmp', 'run-audit.jsonl');
const VENDOR_BIN = () => path.join(__dirname, '..', 'vendor', 'tools', 'obscura',
  process.platform === 'win32' ? 'obscura.exe' : 'obscura');

// Concurrency clamp for `scrape`: pace.js cannot see obscura's internal workers.
function maxConcurrency() {
  const n = parseInt(process.env.OBSCURA_MAX_CONCURRENCY || '', 10);
  return Number.isFinite(n) && n > 0 ? Math.min(n, 64) : 8;
}

// ---- binary resolution ------------------------------------------------------
function resolveBin() {
  if (process.env.STAVROS_OBSCURA_BIN && fs.existsSync(process.env.STAVROS_OBSCURA_BIN))
    return { bin: process.env.STAVROS_OBSCURA_BIN, source: 'env' };
  if (fs.existsSync(VENDOR_BIN())) return { bin: VENDOR_BIN(), source: 'vendor' };
  if (spawnSync('which', ['obscura'], { stdio: 'ignore' }).status === 0)
    return { bin: 'obscura', source: 'path' };
  return null;
}

// ---- egress gateway pinning (same state file as run.js/proxy-route.js) ------
function loadEgress() {
  try {
    const s = JSON.parse(fs.readFileSync(egressStatePath(), 'utf8'));
    if (s && s.port) return { port: s.port, socks5: s.socks5 || null };
  } catch {}
  return null;
}

// Effective proxy URL for an invocation: explicit --proxy wins, else the running
// egress gateway (allowlist + optional SOCKS5/TOR chain), else none.
function effectiveProxy(opts) {
  if (opts.proxy) return opts.proxy;
  const eg = loadEgress();
  return eg ? 'http://127.0.0.1:' + eg.port : null;
}

// ---- argv helpers -----------------------------------------------------------
// Flags that consume the following token as their value (obscura v0.2.0 CLI).
const VALUE_FLAGS = new Set([
  '--dump', '--eval', '--timeout', '--wait-until', '--selector', '--output',
  '--screenshot', '-s', '--concurrency', '--format', '--port', '--workers',
  '--proxy', '--v8-flags', '--user-agent',
]);
// Everything else that starts with '-' is a boolean flag (--stealth, --quiet, ...):
// its value is NEVER eaten, so `scrape --stealth https://x` keeps the URL positional.
const SHORT_ALIAS = { s: 'screenshot' };

function normKey(tok) {
  const k = tok.replace(/^-+/, '');
  return SHORT_ALIAS[k] || k;
}

// Split raw args into { flags: Map, urls: [positional targets] }. Flag VALUES are never
// treated as targets (an --output filename is not a host to scope-check).
function parseArgs(args) {
  const flags = new Map();
  const urls = [];
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a.startsWith('-')) {
      if (VALUE_FLAGS.has(a)) {
        if (args[i + 1] != null) flags.set(normKey(a), String(args[++i]));
        else flags.set(normKey(a), true);
      } else {
        flags.set(normKey(a), true);
      }
      continue;
    }
    urls.push(a);
  }
  return { flags, urls };
}

function clampConcurrency(n) {
  const v = parseInt(n, 10);
  if (!Number.isFinite(v) || v < 1) return 2;
  return Math.min(v, maxConcurrency());
}

// Push "--flag value" only for real string values (a bare `--eval` flag must not
// leak the boolean `true` into the child's argv).
function pushVal(arr, flag, v) {
  if (v != null && v !== true) arr.push(flag, String(v));
}

// Assemble the final obscura argv (pure; unit-tested). Global flags (--proxy, --stealth for
// scrape) go BEFORE the subcommand; per-command flags AFTER it, matching the v0.2.0 README:
//   obscura --proxy socks5://h:p fetch https://x --dump text
//   obscura serve --port 9222 --stealth        |  obscura --stealth scrape u1 u2 ...
function buildArgs(cmd, urls, opts) {
  const o = opts || {};
  const g = [];
  const proxy = effectiveProxy(o);
  if (proxy) g.push('--proxy', proxy);
  const a = [];
  if (cmd === 'fetch') {
    a.push('fetch', urls[0]);
    pushVal(a, '--dump', o.dump);
    pushVal(a, '--eval', o.eval);
    pushVal(a, '--timeout', o.timeout);
    pushVal(a, '--wait-until', o.waitUntil);
    pushVal(a, '--selector', o.selector);
    pushVal(a, '--output', o.output);
    pushVal(a, '--screenshot', o.screenshot);
    if (o.stealth) a.push('--stealth');
  } else if (cmd === 'scrape') {
    if (o.stealth) g.push('--stealth'); // documented as a GLOBAL flag for scrape
    a.push('scrape', ...urls, '--quiet', '--format', o.format || 'json',
      '--concurrency', String(clampConcurrency(o.concurrency)));
    pushVal(a, '--eval', o.eval);
  } else if (cmd === 'serve') {
    a.push('serve', '--port', String(o.port || 9222));
    if (o.workers) a.push('--workers', String(o.workers));
    if (o.stealth) a.push('--stealth');
  } else {
    throw new Error('buildArgs: unknown command ' + cmd);
  }
  return [...g, ...a];
}

// ---- scope gate (pure apart from scope loading; unit-tested via SCOPE_JSON) --
// Returns { ok, reason?, hosts?, bad?, targets? } where targets are ONLY the positional
// tokens that parsed as URL/host (stray filenames never reach the child's argv).
// fetch/scrape fail closed on zero URLs.
function gateFor(cmd, rawArgs, scope) {
  if (cmd === 'serve' || cmd === 'status' || cmd === 'help')
    return { ok: true, hosts: [], targets: [], kind: cmd };
  if (cmd !== 'fetch' && cmd !== 'scrape' && cmd !== 'check')
    return { ok: false, reason: 'unknown command: ' + cmd };
  const { urls } = parseArgs(rawArgs);
  const candidates = cmd === 'check' ? urls.slice(0, 1) : urls;
  const hosts = new Set();
  const valid = [];
  for (const t of candidates) {
    let h = null;
    if (t.includes('://')) { try { h = new URL(t).hostname.toLowerCase(); } catch {} }
    // Bare-host fallback via run.js's battle-tested rule (dotted names / localhost; filenames
    // and extensions rejected). NOTE: WHATWG URL is slash-tolerant for special schemes —
    // 'http:///tmp/x.html' parses with hostname 'tmp'! — so scheme-less tokens must go
    // through bareHost(), never through a blind 'http://' prefix.
    if (!h) {
      const b = bareHost(t);
      if (b && !b.includes('/')) h = b; // CIDR-looking tokens are not browser targets
    }
    if (!h) continue; // not a target: filename or junk positional
    hosts.add(h);
    valid.push(t);
  }
  if (!hosts.size)
    return { ok: false, reason: `no target URL found in args (fail closed) — usage: obscura.js ${cmd} <url...>` };
  if (cmd === 'fetch' && valid.length !== 1)
    return { ok: false, reason: 'fetch takes exactly one URL (use scrape for many)' };
  const bad = [...hosts].filter((h) => !inScope('http://' + h, scope).ok);
  if (bad.length) return { ok: false, reason: 'out-of-scope host(s)', bad, hosts: [...hosts] };
  return { ok: true, hosts: [...hosts], targets: valid, kind: cmd };
}

// ---- audit (same file/convention as run.js: one evidence trail) -------------
function audit(entry) {
  try {
    const p = AUDIT_FILE();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, JSON.stringify(entry) + '\n');
  } catch {}
}

// ---- runner -----------------------------------------------------------------
async function runObscura(bin, argv, opts) {
  const o = opts || {};
  pace.wait(o.rps || 2);
  const capture = process.env.STAVROS_PRIVACY === '1';
  const r = await runBinary(bin, argv, {
    stdio: capture ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'inherit', 'inherit'],
    capture,
    timeoutMs: o.timeoutMs,
  });
  if (capture) {
    const privacy = require('./privacy');
    process.stdout.write(privacy.tokenize(r.stdout || ''));
    process.stderr.write(privacy.tokenize(r.stderr || ''));
  }
  return r;
}

// Probe whether a CDP endpoint answers on 127.0.0.1:port (/json/version).
function cdpVersion(port, timeoutMs) {
  return new Promise((resolve) => {
    const http = require('http');
    const req = http.get('http://127.0.0.1:' + port + '/json/version', { timeout: timeoutMs || 1500 }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);

  if (!cmd || cmd === 'help') {
    console.error(fs.readFileSync(__filename, 'utf8').split('\n').slice(1, 26).join('\n'));
    process.exit(cmd ? 0 : 2);
  }

  const scope = loadScope();

  if (cmd === 'check') {
    const url = rest[0];
    if (!url) { console.error('usage: node tools/obscura.js check <url>'); process.exit(2); }
    const g = inScope(url, scope);
    console.log(JSON.stringify(g));
    process.exit(g.ok ? 0 : 1);
  }

  if (cmd === 'status') {
    const { flags } = parseArgs(rest);
    const port = parseInt(flags.get('port'), 10) || 9222;
    const bin = resolveBin();
    let version = null;
    if (bin) {
      const v = spawnSync(bin.bin, ['--version'], { encoding: 'utf8', timeout: 5000 });
      version = (v.stdout || '').trim().split('\n')[0] || null;
    }
    const server = await cdpVersion(port);
    const eg = loadEgress();
    console.log(JSON.stringify({
      binary: bin ? { path: bin.bin, source: bin.source, version } : null,
      server: server ? { up: true, port, product: server.Browser || server['User-Agent'] || null } : { up: false, port },
      egress_gateway: eg ? { running: true, port: eg.port, socks5: eg.socks5 } : { running: false },
      hint: bin ? null : 'not installed — run ./install-tools.sh or set STAVROS_OBSCURA_BIN',
    }, null, 2));
    return;
  }

  if (cmd === 'serve') {
    const { flags } = parseArgs(rest);
    const port = parseInt(flags.get('port'), 10) || 9222;
    const already = await cdpVersion(port);
    if (already) {
      console.log(JSON.stringify({ already_listening: true, port, product: already.Browser || null }));
      return; // idempotent: dom-check can attach to whatever is already there
    }
    const bin = resolveBin();
    if (!bin) {
      console.error(JSON.stringify({ error: 'obscura binary not found', hint: './install-tools.sh, or download from https://github.com/h4ckf0r0day/obscura/releases and set STAVROS_OBSCURA_BIN' }));
      process.exit(1);
    }
    const proxy = effectiveProxy({});
    const childArgs = buildArgs('serve', [], {
      port, stealth: !!flags.get('stealth'), workers: flags.get('workers'),
    });
    audit({ ts: new Date().toISOString(), bin: 'obscura', args: childArgs, hosts: [], cmd: 'serve', ok: true, egress_proxy: proxy || undefined });
    if (proxy) console.error(JSON.stringify({ note: 'egress gateway detected — obscura pinned to it', proxy }));
    else console.error(JSON.stringify({ note: 'NO egress gateway running — network enforcement relies on callers (dom-check scope-checks each URL)' }));
    console.error(JSON.stringify({ serving: true, port, stealth: !!flags.get('stealth'), stop: 'Ctrl-C' }));
    // Foreground streaming server (the operator keeps it alive; dom-check spawns its own when needed).
    const { spawn } = require('child_process');
    const child = spawn(bin.bin, childArgs, { stdio: 'inherit' });
    child.on('exit', (code) => process.exit(code == null ? 1 : code));
    return;
  }

  // fetch / scrape: gate first, then exec through the audited runner.
  const gate = gateFor(cmd, rest, scope);
  const entry = { ts: new Date().toISOString(), bin: 'obscura', args: [cmd, ...rest], hosts: gate.hosts || [] };
  if (!gate.ok) {
    entry.blocked = true;
    entry.reason = gate.reason;
    if (gate.bad) entry.bad = gate.bad;
    audit(entry);
    console.error(JSON.stringify({ blocked: true, reason: gate.reason, bad: gate.bad || undefined }));
    process.exit(1);
  }
  const bin = resolveBin();
  if (!bin) {
    console.error(JSON.stringify({ error: 'obscura binary not found', hint: './install-tools.sh, or set STAVROS_OBSCURA_BIN' }));
    process.exit(1);
  }
  const { flags } = parseArgs(rest);
  const opts = {
    dump: flags.get('dump'), eval: flags.get('eval'), timeout: flags.get('timeout'),
    waitUntil: flags.get('wait-until'), selector: flags.get('selector'), output: flags.get('output'),
    screenshot: typeof flags.get('screenshot') === 'string' ? flags.get('screenshot') : null,
    format: flags.get('format'), concurrency: flags.get('concurrency'),
    stealth: !!flags.get('stealth'), proxy: flags.get('proxy') || undefined,
    rps: scope.max_requests_per_second || 2,
  };
  const fullArgs = buildArgs(cmd, gate.targets, opts);
  entry.args = fullArgs;
  const proxy = effectiveProxy(opts);
  if (proxy) entry.egress_proxy = proxy;
  const r = await runObscura(bin.bin, fullArgs, opts);
  entry.exit = r.status;
  entry.ok = r.status === 0;
  audit(entry);
  process.exit(r.status);
}

module.exports = {
  resolveBin, buildArgs, gateFor, parseArgs, effectiveProxy, loadEgress,
  clampConcurrency, maxConcurrency, cdpVersion, runObscura, audit,
};
if (require.main === module) main();
