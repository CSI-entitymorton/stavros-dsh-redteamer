#!/usr/bin/env node
// Scope-enforcing wrapper for third-party binaries.
//   node tools/run.js [--dry-run] [--run-timeout <ms>] [--tokens <in,out>] [--tokens-cost <n>] <binary> [args...]
//
// F8 (Ondata 4, ADDITIVO): accounting token/costo per invocazione.
//   --tokens <in>,<out>  oppure env RUN_TOKENS_IN / RUN_TOKENS_OUT (int ≥ 0)
//   --tokens-cost <n>    oppure env RUN_TOKENS_COST (float ≥ 0, "costo se noto")
//   L'entry di audit guadagna usage:{tokens_in,tokens_out,cost,source} + agent
//   (AGENT_NAME|AGENT_CLASS) + duration_ms. Zero rete, zero API di pricing: i token
//   arrivano SOLO dall'operatore (cli/env/file); valori malformati = FATALI (fail-closed,
//   mai un fallback silenzioso). Record esistenti MAI modificati (coerente con A3).
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
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadScope, inScope, hostOf, cidrInScope } = require('./scope-guard');
const { scanAll } = require('./enforce');
const privacy = require('./privacy');
const { hasBin } = require('./tool-plane');
const EGRESS_STATE = path.join(__dirname, '..', 'reports', 'tmp', 'egress-proxy.json');

// ─── Ondata 2 additions (D2/B8/E10 + budget hook) ─────────────────────────────
// All additions are SUPERSET: original behavior, exit codes and audit fields are kept;
// new fields are additive (error_class/recovery/registry/cache_*/budget_*).

// D2: declarative tool registry. Validated shape; unregistered bins are a WARNING,
// never a block (rule: do NOT weaken the existing flow).
const REGISTRY_DEFAULT = path.join(__dirname, 'tool-registry.json');
function loadRegistry(file) {
  const f = file || process.env.TOOL_REGISTRY || REGISTRY_DEFAULT;
  let map = null;
  let loaded = false;
  let errors = [];
  try {
    map = JSON.parse(fs.readFileSync(f, 'utf8'));
    loaded = true;
  } catch (e) {
    errors = [`cannot read/parse registry ${f}: ${e.message}`];
  }
  return { file: f, loaded, map, errors };
}
function validateRegistry(map) {
  const errors = [];
  const TIERS = ['read', 'active', 'intrusive'];
  const RATES = ['slow', 'normal', 'aggressive'];
  if (!map || typeof map !== 'object' || Array.isArray(map)) return ['registry root must be an object mapping bin -> spec'];
  for (const [bin, spec] of Object.entries(map)) {
    if (bin.startsWith('_')) continue; // comment keys allowed
    if (!spec || typeof spec !== 'object') { errors.push(`${bin}: spec must be an object`); continue; }
    if (!TIERS.includes(spec.risk_tier)) errors.push(`${bin}: risk_tier must be one of ${TIERS.join('|')}`);
    if (!RATES.includes(spec.rate_class)) errors.push(`${bin}: rate_class must be one of ${RATES.join('|')}`);
    if (typeof spec.read_only !== 'boolean') errors.push(`${bin}: read_only must be boolean`);
    if (spec.timeout_ms != null && !(Number.isInteger(spec.timeout_ms) && spec.timeout_ms > 0)) errors.push(`${bin}: timeout_ms must be positive int`);
    if (spec.args_schema != null && typeof spec.args_schema !== 'string') errors.push(`${bin}: args_schema must be string`);
    if (spec.alternative != null && typeof spec.alternative !== 'string') errors.push(`${bin}: alternative must be string|null`);
    if (spec.requires_key != null) {
      if (!Array.isArray(spec.requires_key) || spec.requires_key.length === 0 ||
          spec.requires_key.some((k) => typeof k !== 'string' || k.trim() === '')) {
        errors.push(`${bin}: requires_key must be a non-empty array of env-var name strings`);
      }
    }
    const allowed = ['args_schema', 'risk_tier', 'timeout_ms', 'rate_class', 'alternative', 'read_only', 'requires_key'];
    for (const k of Object.keys(spec)) if (!allowed.includes(k)) errors.push(`${bin}: unknown field "${k}"`);
  }
  return errors;
}

// B8: typed error taxonomy post-exit. Every failure gets a class + suggested recovery.
const ERROR_TAXONOMY = {
  timeout: { recovery: 'retry_backoff', hint: 'raise --run-timeout / pace the tool and retry with backoff' },
  rate_limited: { recovery: 'retry_backoff_rate', hint: 'back off and lower the request rate (aggressive -> slow)' },
  dns_fail: { recovery: 'verify_dns_pin', hint: 'check resolution / scope-guard resolvePin divergence log' },
  conn_refused: { recovery: 'verify_service_port', hint: 'confirm the service/port is open before retrying' },
  auth_failed: { recovery: 'check_credentials', hint: 'verify credentials; never brute-force without tier approval' },
  tool_not_found: { recovery: 'alternative_tool', hint: 'use the registry alternative or degrade (script/MCP/ask_user)' },
  key_missing: { recovery: 'configure_api_key', hint: 'set the missing env key(s) (see missing_keys); never fall back silently' },
  scope_blocked: { recovery: 'reduce_scope', hint: 'drop out-of-scope hosts; scope changes go through the operator' },
  enforce_blocked: { recovery: 'escalate_operator', hint: 'the gate verdict is final: NEVER bypass; escalate to the operator' },
  parse_fail: { recovery: 'inspect_output_format', hint: 'malformed tool output for downstream parsing; inspect raw output' },
  unknown: { recovery: 'reflector_advise', hint: 'node tools/reflector.js advise --tool <bin>' },
};
function classifyFailure({ exitCode, timedOut, spawnError, text }) {
  if (timedOut) return 'timeout';
  if (spawnError && /enoent/i.test(String(spawnError))) return 'tool_not_found';
  const t = String(text || '');
  if (/rate.?limit|\b429\b|too many requests/i.test(t)) return 'rate_limited';
  if (/getaddrinfo|enotfound|name or service not known|nxdomain|no such host/i.test(t)) return 'dns_fail';
  if (/econnrefused|connection refused/i.test(t)) return 'conn_refused';
  if (/authentication failed|auth(?:entication)? failed|login failed|access denied|invalid credentials|permission denied \(publickey|401 unauthorized/i.test(t)) return 'auth_failed';
  if (/parse error|failed to parse|invalid json|unexpected (?:token|end of json)/i.test(t)) return 'parse_fail';
  if (exitCode !== 0) return 'unknown';
  return null;
}
function taxonomyEntry(errorClass) {
  if (!errorClass) return { error_class: null, recovery: null };
  const t = ERROR_TAXONOMY[errorClass] || ERROR_TAXONOMY.unknown;
  return { error_class: errorClass, recovery: { action: t.recovery, hint: t.hint } };
}

// E10: response cache — STRICTLY opt-in (--cache-ttl), ONLY for registry entries marked
// read_only:true AND never for active scanners regardless of what the registry says.
const CACHE_DIR = process.env.CACHE_DIR || path.join(__dirname, '..', 'reports', 'tmp', 'cache');
const CACHE_SCAN_NEVER = new Set(['nmap', 'masscan', 'nuclei', 'httpx', 'ffuf', 'gobuster', 'dirsearch', 'nikto', 'sqlmap', 'hydra', 'netexec']);
function cacheEligible(bin, map) {
  if (!map) return { ok: false, reason: 'registry absent/unreadable' };
  const e = map[bin];
  if (!e) return { ok: false, reason: `${bin} not in registry` };
  if (CACHE_SCAN_NEVER.has(bin)) return { ok: false, reason: `${bin} is an active scanner (never cached)` };
  if (e.read_only !== true) return { ok: false, reason: `${bin} risk_tier=${e.risk_tier} read_only=false` };
  return { ok: true };
}
function cacheKey(bin, args, stdinText) {
  return crypto.createHash('sha256').update(JSON.stringify({ bin, args, stdin: stdinText || '' })).digest('hex');
}
function cacheRead(file, ttlSec) {
  try {
    const o = JSON.parse(fs.readFileSync(file, 'utf8'));
    const age = (Date.now() - Date.parse(o.ts)) / 1000;
    if (!(age >= 0 && age <= ttlSec)) return null;
    return o;
  } catch { return null; }
}
function cacheWrite(file, obj) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    const tmp = file + '.' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(obj) + '\n');
    fs.renameSync(tmp, file);
  } catch {}
}

// E12: TOOL_REQUIRES_KEY — gating per env-key per bin. Risoluzione ADDITIVA (union) di:
//   - registry[bin].requires_key  (campo opzionale: array di nomi env-var)
//   - env TOOL_REQUIRES_KEY       (coppie "bin=ENV[,ENV...]" separate da virgola; può SOLO
//                                  AGGIUNGERE requisiti, mai rimuoverli)
// Una env MALFORMATA è un errore chiaro e FATALE, mai un fallback silenzioso.
function parseToolRequiresKeyEnv(text) {
  if (text == null || String(text).trim() === '') return { ok: true, pairs: {} };
  const pairs = {};
  for (const part of String(text).split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq <= 0) return { ok: false, error: `TOOL_REQUIRES_KEY: coppia malformata "${part}" (atteso bin=ENV[,ENV...])` };
    const bin = part.slice(0, eq).trim();
    const keys = part.slice(eq + 1).split(',').map((s) => s.trim()).filter(Boolean);
    if (!bin) return { ok: false, error: `TOOL_REQUIRES_KEY: nome bin vuoto in "${part}"` };
    if (keys.length === 0) return { ok: false, error: `TOOL_REQUIRES_KEY: nessuna env per "${bin}" in "${part}"` };
    pairs[bin] = [...new Set([...(pairs[bin] || []), ...keys])];
  }
  return { ok: true, pairs };
}

// Chiavi richieste per un bin: union(registry.requires_key, env TOOL_REQUIRES_KEY).
// Ritorna {ok:false,error} se l'env è malformata (fatal), altrimenti {ok:true,keys}.
function resolveRequiredKeys(bin, reg, envText) {
  const parsed = parseToolRequiresKeyEnv(envText);
  if (!parsed.ok) return parsed;
  const set = new Set();
  if (reg && reg.map && reg.map[bin] && Array.isArray(reg.map[bin].requires_key)) {
    for (const k of reg.map[bin].requires_key) set.add(k);
  }
  if (parsed.pairs[bin]) for (const k of parsed.pairs[bin]) set.add(k);
  return { ok: true, keys: [...set] };
}

// Budget integration (SA3 contract): check() pre-exec — exit 3/4 BLOCKS execution.
// AGENT_CLASS env (when set) is forwarded so per-class halts (exit 4) can fire too.
function budgetPrecheck() {
  try {
    const extra = process.env.AGENT_CLASS ? ['--agent-class', process.env.AGENT_CLASS] : [];
    return spawnSync(process.execPath, [path.join(__dirname, 'budget.js'), 'check', ...extra], { encoding: 'utf8' });
  } catch { return null; }
}

// Append an audit record of every wrapper invocation (bin, args, extracted hosts, verdict).
// Evidence trail + a way to see exactly what the harness tried to run.
// Ondata 2: RUN_AUDIT_FILE overrides the destination (integration point from ondata-1 §5.1 —
// lets budget/loop-watch/reflector and tests redirect the stream without touching code).
// Ondata 4 (C5w): la STESSA invocazione viene accodata anche al trail ISOLATO append-only
// artifacts/audit/<giorno>.jsonl (tools/audit-trail.js, hash-chain leggera coerente con A3,
// env AUDIT_DIR per i test). Un errore sul trail NON blocca mai il wrapper (additivo).
function audit(entry) {
  try {
    const file = process.env.RUN_AUDIT_FILE || path.join(__dirname, '..', 'reports', 'tmp', 'run-audit.jsonl');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch {}
  try {
    require('./audit-trail').append(entry);
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
// { status, stdout, stderr, ms, pid, timedOut?, error? }. opts.capture=true collects
// stdout/stderr (privacy tokenization); otherwise they inherit the parent's fds (live progress).
// E9 (rimandati): opts.taskId registra il figlio nel process-registry a SPAWN-TIME (un altro
// processo può fare pause/terminate a scan in corso); alla chiusura viene marcato exited.
// Il registry non blocca mai l'esecuzione (additivo).
function runBinary(bin, args, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(bin, args, opts);
    if (opts.taskId) {
      try {
        require('./proc-registry').register({ taskId: opts.taskId, pid: child.pid, bin, args, via: 'run.js' });
      } catch {}
    }
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
      if (opts.taskId) { try { require('./proc-registry').markExited(opts.taskId, 1); } catch {} }
      resolve({ status: 1, stdout: out, stderr: err, ms: Date.now() - t0, pid: child.pid, error: e.message });
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (opts.taskId) { try { require('./proc-registry').markExited(opts.taskId, code); } catch {} }
      resolve({ status: code == null ? 1 : code, stdout: out, stderr: err, ms: Date.now() - t0, pid: child.pid, timedOut: timedOut || undefined });
    });
  });
}

async function main() {
  const argv = process.argv.slice(2);
  let dryRun = false;
  let runTimeoutMs = null;
  let registryCheck = false;
  let errorReport = false;
  let cacheTtl = 0;
  let regFile = null;
  let tokensIn = null;
  let tokensOut = null;
  let tokensCost = null;
  let taskId = null;
  const binArgs = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dry-run') { dryRun = true; continue; }
    if (argv[i] === '--run-timeout') { runTimeoutMs = parseInt(argv[++i], 10) || null; continue; }
    if (argv[i] === '--registry-check') { registryCheck = true; continue; }
    if (argv[i] === '--registry') { regFile = argv[++i]; continue; }
    if (argv[i] === '--error-report') { errorReport = true; continue; }
    if (argv[i] === '--cache-ttl') { cacheTtl = parseInt(argv[++i], 10) || 0; continue; }
    if (argv[i] === '--tokens') { const p = String(argv[++i] || '').split(','); tokensIn = parseInt(p[0], 10); tokensOut = parseInt(p[1], 10); continue; }
    if (argv[i] === '--tokens-cost') { tokensCost = parseFloat(argv[++i]); continue; }
    if (argv[i] === '--task-id') { taskId = argv[++i]; continue; } // E9: process-registry hook
    binArgs.push(argv[i]);
  }
  // F8: env override (RUN_TOKENS_IN/OUT/COST) — valido SOLO se il flag CLI non l'ha già dato;
  // valori malformati sono FATALI (fail-closed), mai interpretazioni silenziose.
  if (tokensIn == null && process.env.RUN_TOKENS_IN !== undefined) tokensIn = parseInt(process.env.RUN_TOKENS_IN, 10);
  if (tokensOut == null && process.env.RUN_TOKENS_OUT !== undefined) tokensOut = parseInt(process.env.RUN_TOKENS_OUT, 10);
  if (tokensCost == null && process.env.RUN_TOKENS_COST !== undefined) tokensCost = parseFloat(process.env.RUN_TOKENS_COST);
  const badTokens = (tokensIn != null && !(Number.isInteger(tokensIn) && tokensIn >= 0)) ||
    (tokensOut != null && !(Number.isInteger(tokensOut) && tokensOut >= 0)) ||
    (tokensCost != null && !(Number.isFinite(tokensCost) && tokensCost >= 0));
  if (badTokens) {
    console.error('[run.js] FATAL: --tokens/RUN_TOKENS_IN/OUT must be non-negative ints, --tokens-cost/RUN_TOKENS_COST a non-negative number (fail-closed, no silent fallback)');
    process.exit(2);
  }
  const usageField = (tokensIn != null || tokensOut != null || tokensCost != null)
    ? { ...(tokensIn != null ? { tokens_in: tokensIn } : {}), ...(tokensOut != null ? { tokens_out: tokensOut } : {}), ...(tokensCost != null ? { cost: tokensCost } : {}), source: 'cli/env' }
    : null;
  const agentField = process.env.AGENT_NAME || process.env.AGENT_CLASS || null;
  // D2: standalone registry validation mode (offline, no scope needed).
  if (registryCheck) {
    const reg = loadRegistry(regFile);
    const errors = reg.loaded ? validateRegistry(reg.map) : reg.errors;
    const presence = {};
    if (reg.map) for (const b of Object.keys(reg.map)) if (!b.startsWith('_')) presence[b] = hasBin(b);
    console.log(JSON.stringify({ ok: errors.length === 0, registry: reg.file, loaded: reg.loaded, bins: Object.keys(presence).length, errors, presence }, null, 2));
    process.exit(errors.length ? 1 : 0);
  }
  const [bin, ...args] = binArgs;
  if (!bin) {
    console.error('usage: node run.js [--dry-run] [--run-timeout <ms>] [--registry <file>] [--registry-check] [--cache-ttl <sec>] [--error-report] <binary> [args...]');
    process.exit(2);
  }

  const errReportLine = (obj) => { if (errorReport) console.log(JSON.stringify(Object.assign({ error_report: true }, obj))); };
  const reg = loadRegistry(regFile);
  const registered = !!(reg.map && reg.map[bin]);
  if (reg.loaded && !registered) {
    console.error(`[run.js] WARNING: '${bin}' is not registered in ${reg.file} (non-blocking warning — consider adding it via D2 registry)`);
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
  if (agentField) entry.agent = agentField;
  if (usageField) entry.usage = usageField;
  entry.registry = { loaded: reg.loaded, registered, risk_tier: registered ? reg.map[bin].risk_tier : null, rate_class: registered ? reg.map[bin].rate_class : null };
  if (hosts.length === 0) {
    entry.blocked = true;
    entry.reason = 'no target host found in args (fail closed)';
    Object.assign(entry, taxonomyEntry('scope_blocked'));
    audit(entry);
    console.error(JSON.stringify({ blocked: true, reason: entry.reason, error_class: entry.error_class, recovery: entry.recovery }));
    errReportLine({ bin, error_class: entry.error_class, recovery: entry.recovery, detail: entry.reason });
    process.exit(1);
  }
  const bad = hosts.filter((h) => (isCidr(h) ? !cidrInScope(h, scope).ok : !inScope('http://' + h, scope).ok));
  if (bad.length) {
    entry.blocked = true;
    entry.reason = 'out-of-scope host(s)';
    entry.bad = bad;
    Object.assign(entry, taxonomyEntry('scope_blocked'));
    audit(entry);
    console.error(JSON.stringify({ blocked: true, reason: entry.reason, hosts: bad, error_class: entry.error_class, recovery: entry.recovery }));
    errReportLine({ bin, error_class: entry.error_class, recovery: entry.recovery, detail: `${entry.reason}: ${bad.join(', ')}` });
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
    Object.assign(entry, taxonomyEntry('enforce_blocked'));
    audit(entry);
    console.error(JSON.stringify({ blocked: true, gate: 'enforce', reason: enforceReason, error_class: entry.error_class, recovery: entry.recovery }));
    errReportLine({ bin, error_class: entry.error_class, recovery: entry.recovery, detail: enforceReason });
    process.exit(1);
  }
  // E12: TOOL_REQUIRES_KEY gating — mancanza di env-key BLOCCA l'esecuzione (e il dry-run:
  // il check è PRIMA dell'early-exit dry-run). Fail-closed, mai fallback silenziosi.
  // 1) env malformata = FATALE (exit 2), anche se il bin non ha requisiti propri.
  const req = resolveRequiredKeys(bin, reg.loaded ? reg : null, process.env.TOOL_REQUIRES_KEY);
  if (!req.ok) {
    entry.blocked = true;
    entry.gate = 'tool_requires_key';
    entry.reason = req.error;
    Object.assign(entry, taxonomyEntry('key_missing'));
    audit(entry);
    console.error(JSON.stringify({ blocked: true, gate: 'tool_requires_key', reason: req.error, error_class: entry.error_class, recovery: entry.recovery }));
    errReportLine({ bin, error_class: entry.error_class, recovery: entry.recovery, detail: req.error });
    process.exit(2);
  }
  // 2) chiavi dichiarate ma assenti dall'ambiente = blocco con elenco chiaro (exit 1).
  const missingKeys = req.keys.filter((k) => !(k in process.env));
  if (missingKeys.length > 0) {
    entry.blocked = true;
    entry.gate = 'tool_requires_key';
    entry.missing_keys = missingKeys;
    entry.reason = 'missing required env key(s)';
    Object.assign(entry, taxonomyEntry('key_missing'));
    audit(entry);
    console.error(JSON.stringify({ blocked: true, gate: 'tool_requires_key', missing_keys: missingKeys, error_class: entry.error_class, recovery: entry.recovery }));
    errReportLine({ bin, error_class: entry.error_class, recovery: entry.recovery, detail: `missing env: ${missingKeys.join(', ')}` });
    process.exit(1);
  }
  if (dryRun) {
    entry.ok = true;
    audit(entry);
    console.log(JSON.stringify({ dry_run: true, bin, args, hosts, verdict: 'in scope', enforce: 'allowed' }, null, 2));
    process.exit(0);
  }
  // Budget integration (SA3 hook): engagement/class caps BLOCK execution before spawn.
  // Exit codes mirror budget.js (3 = engagement halt, 4 = class halt) so the contract stays.
  if (!dryRun) {
    const b = budgetPrecheck();
    if (b && (b.status === 3 || b.status === 4)) {
      entry.budget_blocked = true;
      entry.budget_exit = b.status;
      entry.reason = 'budget cap reached (pre-exec check)';
      audit(entry);
      process.stderr.write(b.stderr || '');
      errReportLine({ bin, error_class: 'budget_blocked', recovery: { action: 'operator_reset', hint: 'budget.js reset --reason (operator only)' }, detail: `budget exit ${b.status}` });
      process.exit(b.status);
    }
  }

  // E10 cache: opt-in via --cache-ttl; eligible ONLY for registry read_only:true bins that
  // are not active scanners. A refused cache never blocks the command — it just warns.
  let cacheState = null;
  if (!dryRun && cacheTtl > 0) {
    const elig = cacheEligible(bin, reg.loaded ? reg.map : null);
    if (!elig.ok) {
      console.error(`[run.js] cache refused: ${elig.reason} (--cache-ttl ignored)`);
      entry.cache_refused = elig.reason;
    } else {
      const key = cacheKey(bin, args, stdinText);
      const file = path.join(CACHE_DIR, `${key}.json`);
      const hit = cacheRead(file, cacheTtl);
      if (hit) {
        entry.cache_hit = true;
        entry.cache_key = key;
        Object.assign(entry, { exit: hit.exit, ok: hit.exit === 0 });
        audit(entry);
        process.stderr.write(`[cache-hit] ${file}\n`);
        const tok = process.env.STAVROS_PRIVACY === '1';
        process.stdout.write(tok ? privacy.tokenize(hit.stdout || '') : (hit.stdout || ''));
        process.stderr.write(tok ? privacy.tokenize(hit.stderr || '') : (hit.stderr || ''));
        errReportLine({ bin, error_class: null, recovery: null, detail: `cache-hit ${key} (age ${(Date.now() - Date.parse(hit.ts)) / 1000 | 0}s <= ttl ${cacheTtl}s)` });
        process.exit(hit.exit);
      }
      cacheState = { key, file };
      entry.cache_key = key;
    }
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

  // Capture when privacy mode is on, when caching (need the payload), or when an error
  // report was requested (--error-report implies classification over captured output).
  const capture = process.env.STAVROS_PRIVACY === '1' || !!cacheState || errorReport;
  const r = await runBinary(bin, args, {
    stdio: capture ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'inherit', 'inherit'],
    input: stdinText || undefined,
    capture,
    env: childEnv,
    timeoutMs: runTimeoutMs || undefined,
    taskId: taskId || undefined, // E9: registra nel process-registry a spawn-time
  });
  if (capture) {
    process.stdout.write(privacy.tokenize(r.stdout || ''));
    process.stderr.write(privacy.tokenize(r.stderr || ''));
  }
  entry.exit = r.status;
  entry.ok = r.status === 0;
  entry.timed_out = r.timedOut || undefined;
  if (r.error) entry.error = r.error;
  if (r.ms != null) entry.duration_ms = r.ms; // F8: durata per il calcolo costo/azione
  // B8 taxonomy post-exit (+ store the response on cache miss).
  const capturedText = capture ? `${r.stdout || ''}\n${r.stderr || ''}` : '';
  Object.assign(entry, taxonomyEntry(classifyFailure({ exitCode: r.status, timedOut: r.timedOut, spawnError: r.error, text: capturedText })));
  if (r.error) entry.recovery = Object.assign({}, entry.recovery, alternativeFor(bin, reg));
  if (cacheState) {
    cacheWrite(cacheState.file, { ts: new Date().toISOString(), ttl: cacheTtl, bin, exit: r.status, stdout: r.stdout || '', stderr: r.stderr || '' });
    entry.cache_stored = true;
  }
  // Optional budget tick producer (SA3): opt-in via RUNJS_BUDGET_TICK_CLASS.
  if (!dryRun && process.env.RUNJS_BUDGET_TICK_CLASS) {
    try { spawnSync(process.execPath, [path.join(__dirname, 'budget.js'), 'tick', '--agent-class', process.env.RUNJS_BUDGET_TICK_CLASS], { stdio: 'ignore' }); } catch {}
  }
  audit(entry);
  errReportLine({ bin, args, exit: r.status, error_class: entry.error_class, recovery: entry.recovery });
  process.exit(r.status);
}

function alternativeFor(bin, reg) {
  const alt = reg.map && reg.map[bin] && reg.map[bin].alternative;
  return alt ? { action: 'alternative_tool', hint: `try '${alt}' instead` } : {};
}

if (require.main === module) main();
module.exports = { collectHosts, bareHost, hostsFromText, runBinary, isCidr,
  // ondata-2 additions
  loadRegistry, validateRegistry, classifyFailure, taxonomyEntry, cacheEligible, cacheKey, ERROR_TAXONOMY,
  // ondata-3 (E12) additions
  parseToolRequiresKeyEnv, resolveRequiredKeys };
