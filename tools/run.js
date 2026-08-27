#!/usr/bin/env node
// Scope-enforcing wrapper for third-party binaries.
//   node tools/run.js [--dry-run] [--run-timeout <ms>] <binary> [args...]
// Extracts every host from args (URLs of ANY scheme, bare host/IP/CIDR tokens, and the
// DOMAIN of email tokens like user@dom.tld — e.g. h8mail -t user@example.com), from
// -l/-list/-iL list files (plus h8mail's -t/--targets file), AND from a piped stdin
// (a target list in this harness), scope-checks each, and refuses to exec if ANY host is
// out-of-scope OR if no host is found (fail closed). Every invocation is appended to
// reports/tmp/run-audit.jsonl (evidence/audit trail). --dry-run prints the verdict and
// hosts without executing.
//
// Streaming: the binary runs via async spawn with stdout/stderr inherited, so long
// scanners (nmap/masscan/nuclei) stream progress live instead of buffering. --run-timeout
// optionally kills a runaway scan after N ms. Route sqlmap/nuclei/ffuf/httpx/nmap/netexec/
// impacket/... through this so the scope guard covers them too.
//
// ponytail: covers argv URLs + bare-host/CIDR args + common list-file flags + piped stdin.
// A tool that reads targets only from an exotic flag or config file can still slip a host
// past. Upgrade path: an allowlisting egress proxy that all tools are forced through
// (tools/egress-proxy.js does exactly this for HTTP(S)-aware binaries).
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { loadScope, inScope, hostOf, cidrInScope } = require('./scope-guard');
const { scanAll } = require('./enforce');
const privacy = require('./privacy');
const EGRESS_STATE = path.join(__dirname, '..', 'reports', 'tmp', 'egress-proxy.json');

// Append an audit record of every wrapper invocation (bin, args, extracted hosts, verdict).
// Evidence trail + a way to see exactly what the harness tried to run.
function audit(entry) {
  try {
    const dir = path.join(__dirname, '..', 'reports', 'tmp');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'run-audit.jsonl'), JSON.stringify(entry) + '\n');
  } catch {}
}

// Any scheme:// (http, https, ldap, smb, ssh, mysql, ftp, rdp, ...) — network scanners use
// more than just http(s). hostOf() already parses all of them via new URL().
const URL_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"]+/gi;
// Emails (h8mail -t user@dom, theHarvester email lists, ...): the domain after '@' is the
// host to scope-check. Requires a TLD of 2+ letters, so IP-ish tails don't false-positive.
const EMAIL_RE = /[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/gi;
const FILE_EXT = /\.(txt|json|js|ts|xml|html?|md|csv|log|py|ya?ml|conf|cfg|zip|har|list|nse|rc)$/i;
const BARE_HOST = /^[a-z0-9.-]+$/i;
const CIDR_RE = /^(\d{1,3})(?:\.(\d{1,3})){3}\/\d{1,2}$/;

function isCidr(tok) {
  return CIDR_RE.test(String(tok || '').trim());
}

function hostsFromString(s) {
  const hosts = new Set();
  for (const m of s.match(URL_RE) || []) {
    const h = hostOf(m);
    if (h) hosts.add(h);
  }
  // Emails in the same text: the domain after '@' is a host. Fresh regex per call so
  // the global flag never carries lastIndex state across invocations.
  const re = new RegExp(EMAIL_RE.source, 'gi');
  let m;
  while ((m = re.exec(String(s == null ? '' : s)))) {
    if (m[1]) hosts.add(m[1].toLowerCase());
  }
  return hosts;
}

// A whole token counts as a host only if it's dotted (or 'localhost'), not a filename, and
// parses. CIDR range tokens (10.0.0.0/24) are kept whole so cidrInScope() can check them.
function bareHost(tok) {
  tok = String(tok == null ? '' : tok).trim();
  if (!tok) return null;
  if (isCidr(tok)) return tok;
  if (FILE_EXT.test(tok) || !BARE_HOST.test(tok)) return null;
  if (!tok.includes('.')) {
    // single-label hosts: only 'localhost' is a valid target (loopback, matches allowed_ips).
    if (tok.toLowerCase() !== 'localhost') return null;
  }
  return hostOf(tok);
}

function hostsFromText(text) {
  const hosts = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    for (const h of hostsFromString(line)) hosts.add(h);
    const b = bareHost(line);
    if (b) hosts.add(b);
  }
  return hosts;
}

function collectHosts(args, stdinText, bin) {
  const hosts = new Set();
  const listFlags = new Set(['-l', '-list', '-iL', '-il', '--list']);
  // h8mail reads a target FILE from -t/--targets (emails/URLs): scan its contents for
  // hosts so a file of emails is scope-checked too. Inline emails/URLs are already
  // covered by the per-arg scan below. (NOT -c/-k: config files hold API keys and
  // would false-positive on the emails embedded in them.)
  if (bin === 'h8mail') {
    listFlags.add('-t');
    listFlags.add('--targets');
  }
  for (let i = 0; i < args.length; i++) {
    for (const h of hostsFromString(args[i])) hosts.add(h);
    const bh = bareHost(args[i]);
    if (bh) hosts.add(bh);
    // list-file flags: read hosts from the referenced FILE (skip '-' — that is stdin, handled below)
    if (listFlags.has(args[i]) && args[i + 1] && args[i + 1] !== '-') {
      const val = args[i + 1];
      if (fs.existsSync(val)) {
        try {
          for (const h of hostsFromText(fs.readFileSync(val, 'utf8'))) hosts.add(h);
        } catch {}
      }
    }
  }
  // Piped stdin is a target list (nuclei -l -, httpx default, --stdin, ffuf -w -): always scan it.
  if (stdinText != null) {
    for (const h of hostsFromText(stdinText)) hosts.add(h);
  }
  return [...hosts];
}

// Run a binary to completion with async streaming (no buffering). Returns
// { status, stdout, stderr, timedOut?, error? }. opts.capture=true collects stdout/stderr
// (privacy tokenization); otherwise they inherit the parent's fds (live progress).
function runBinary(bin, args, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const child = spawn(bin, args, opts);
    let out = '';
    let err = '';
    let timedOut = false;
    if (opts.capture) {
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => (err += d));
    }
    if (child.stdin) {
      if (opts.input != null) child.stdin.write(opts.input);
      child.stdin.end();
    }
    const timer = opts.timeoutMs ? setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, opts.timeoutMs) : null;
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      resolve({ status: 1, stdout: out, stderr: err, error: e.message });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ status: code == null ? 1 : code, stdout: out, stderr: err, timedOut: timedOut || undefined });
    });
  });
}

async function main() {
  const argv = process.argv.slice(2);
  let dryRun = false;
  let runTimeoutMs = null;
  const binArgs = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dry-run') { dryRun = true; continue; }
    if (argv[i] === '--run-timeout') { runTimeoutMs = parseInt(argv[++i], 10) || null; continue; }
    binArgs.push(argv[i]);
  }
  const [bin, ...args] = binArgs;
  if (!bin) {
    console.error('usage: node run.js [--dry-run] [--run-timeout <ms>] <binary> [args...]');
    process.exit(2);
  }

  const scope = loadScope();
  // Read piped stdin up front (target lists like `... | httpx`, `nuclei -l -`) so its hosts are
  // scope-checked too; forward the same bytes to the child. isTTY is undefined (not false) when piped.
  let stdinText = null;
  if (!process.stdin.isTTY) {
    try {
      stdinText = fs.readFileSync(0, 'utf8');
    } catch {}
  }
  const hosts = collectHosts(args, stdinText, bin);

  const entry = { ts: new Date().toISOString(), bin, args, hosts, dry_run: dryRun };
  if (hosts.length === 0) {
    entry.blocked = true;
    entry.reason = 'no target host found in args (fail closed)';
    audit(entry);
    console.error(JSON.stringify({ blocked: true, reason: entry.reason }));
    process.exit(1);
  }
  const bad = hosts.filter((h) => (isCidr(h) ? !cidrInScope(h, scope).ok : !inScope('http://' + h, scope).ok));
  if (bad.length) {
    entry.blocked = true;
    entry.reason = 'out-of-scope host(s)';
    entry.bad = bad;
    audit(entry);
    console.error(JSON.stringify({ blocked: true, reason: entry.reason, hosts: bad }));
    process.exit(1);
  }
  // Deterministic dangerous/rate scan (ported from dsh-sec-enforce, MIT): after the scope check,
  // before exec. Fail-closed: an uncertain verdict = refusal with a remediation. The verdict is
  // shown in --dry-run too so the agent can see the safety gate without executing.
  const fullCmd = [bin, ...args].join(' ');
  const enforceReason = scanAll(fullCmd);
  if (enforceReason) {
    entry.blocked = true;
    entry.gate = 'enforce';
    entry.reason = enforceReason.split('. ')[0];
    audit(entry);
    console.error(JSON.stringify({ blocked: true, gate: 'enforce', reason: enforceReason }));
    process.exit(1);
  }
  if (dryRun) {
    entry.ok = true;
    audit(entry);
    console.log(JSON.stringify({ dry_run: true, bin, args, hosts, verdict: 'in scope', enforce: 'allowed' }, null, 2));
    process.exit(0);
  }
  // If the egress proxy daemon is running, force HTTP(S)-aware binaries through it (opt-in enforcement).
  let childEnv = process.env;
  try {
    const s = JSON.parse(fs.readFileSync(EGRESS_STATE, 'utf8'));
    if (s && s.port) {
      const p = 'http://127.0.0.1:' + s.port;
      childEnv = Object.assign({}, process.env, { HTTP_PROXY: p, HTTPS_PROXY: p, ALL_PROXY: p, http_proxy: p, https_proxy: p });
      entry.egress_proxy = s.port;
    }
  } catch {}

  const capture = process.env.STAVROS_PRIVACY === '1';
  const r = await runBinary(bin, args, {
    stdio: capture ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'inherit', 'inherit'],
    input: stdinText || undefined,
    capture,
    env: childEnv,
    timeoutMs: runTimeoutMs || undefined,
  });
  if (capture) {
    process.stdout.write(privacy.tokenize(r.stdout || ''));
    process.stderr.write(privacy.tokenize(r.stderr || ''));
  }
  entry.exit = r.status;
  entry.ok = r.status === 0;
  entry.timed_out = r.timedOut || undefined;
  if (r.error) entry.error = r.error;
  audit(entry);
  process.exit(r.status);
}

if (require.main === module) main();
module.exports = { collectHosts, bareHost, hostsFromText, runBinary, isCidr };
