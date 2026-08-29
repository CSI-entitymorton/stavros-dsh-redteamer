// Scope guard: single source of truth for "am I allowed to touch this target".
// Used HARD (in code) by repeater.js/run.js/oob.js; used procedurally by agents via
//   node tools/scope-guard.js check <url|host>
// Exit 0 = in scope, 1 = out of scope/blocked, 2 = usage error.
//
// scope.json — TWO accepted schemas (loadScope() normalizes to one in-memory shape):
//
//   1) harness (storico):
//     allowed_hosts: ["example.com"]            -> host + subdomains
//     allowed_url_prefixes: ["https://x.com/app/"]
//     allowed_ips: ["127.0.0.1", "10.0.0.0/8"]  -> literal IP hosts (and 'localhost' -> 127.0.0.1),
//                                                  CIDR ranges allowed. Use ONLY for authorized
//                                                  SSRF-internal / lab targets; keep it minimal.
//
//   2) locale (questo workspace):
//     targets:    ["192.168.0.0/24", "lab.example.local", "10.0.0.5", "https://x.com/app/"]
//                 -> hostname | ip | cidr (| URL prefix). Normalized into allowed_hosts /
//                    allowed_ips / allowed_url_prefixes at load time.
//     exclusions: ["192.168.0.1", "admin.example.local"]  -> HARD-DENY list (hostname | ip | cidr),
//                    evaluated FIRST by inScope(), inside ipAllowed() and cidrInScope().
//                    A requested CIDR that merely INTERSECTS an exclusion is denied outright:
//                    conservative choice — a scan range touching an excluded host is refused,
//                    not trimmed (we never silently narrow what the operator asked to scan).
//
//   Both schemas may carry optional hardening fields (honored from either):
//     time_window: { start: "ISO-8601"|null, end: "ISO-8601"|null }
//                    -> evaluated on EVERY call; outside the window everything is denied with
//                       reason 'outside engagement time_window'. Absent/null bounds = open window.
//                       Deterministic tests: pass opts.now to inScope/cidrInScope/validatePlan or
//                       set env SCOPE_NOW="ISO". An unparseable configured bound denies (fail-closed).
//
// The original exports keep their exact semantics (run.js/repeater.js/net.js/verify-finding.js
// depend on them); everything below is an additive superset. Deny-by-default and fail-closed are
// unchanged and strengthened.

const fs = require('fs');
const path = require('path');
const dns = require('dns');
const net = require('net');
const { domainToASCII } = require('url');

// ---------------------------------------------------------------------------
// Scope loading + dual-schema normalization
// ---------------------------------------------------------------------------

function loadScope(scopePath) {
  // SCOPE_JSON env override: lets tests (and multi-project setups) point at another file.
  const p = scopePath || process.env.SCOPE_JSON || path.join(__dirname, '..', 'scope.json');
  let raw;
  try { raw = fs.readFileSync(p, 'utf8'); }
  catch { return normalizeScope({}); } // no scope file => fail-closed (nothing authorized yet)
  return normalizeScope(JSON.parse(raw));
}

// target/exclusion token classification (local schema): hostname | ip | cidr | url-prefix.
const CIDR_TOK_RE = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;

function classifyToken(tok) {
  const t = String(tok == null ? '' : tok).trim();
  if (!t) return null;
  if (CIDR_TOK_RE.test(t) && cidrParse(t)) return 'cidr';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return 'url';
  if (ipv4ToInt(t) != null || t.toLowerCase() === 'localhost') return 'ip';
  return 'host';
}

function normalizeExclusions(list) {
  if (!Array.isArray(list)) return [];
  return list.map((x) => {
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      return { kind: x.kind || classifyToken(x.value) || 'host', value: String(x.value) };
    }
    return { kind: classifyToken(x) || 'host', value: String(x).trim().toLowerCase() };
  }).filter((x) => x.value);
}

// Normalize either schema into ONE in-memory shape; unknown fields (project,
// rules_of_engagement, max_requests_per_second, ...) pass through untouched. `raw` keeps the
// pristine parsed file for provenance. Deny-by-default unchanged: an empty/absent scope still
// authorizes nothing.
function normalizeScope(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    return { allowed_hosts: [], allowed_url_prefixes: [], allowed_ips: [], exclusions: [], raw };
  const scope = Object.assign({}, raw);
  scope.raw = raw;
  // copy the arrays we may extend so `raw` stays pristine
  scope.allowed_hosts = Array.isArray(raw.allowed_hosts) ? raw.allowed_hosts.slice() : [];
  scope.allowed_url_prefixes = Array.isArray(raw.allowed_url_prefixes) ? raw.allowed_url_prefixes.slice() : [];
  scope.allowed_ips = Array.isArray(raw.allowed_ips) ? raw.allowed_ips.slice() : [];

  if (Array.isArray(raw.targets)) {
    scope.targets = raw.targets.slice(); // keep the raw local-schema field too
    for (let t of raw.targets) {
      t = String(t == null ? '' : t).trim();
      const kind = classifyToken(t);
      if (kind === 'cidr' || kind === 'ip') {
        if (!scope.allowed_ips.includes(t)) scope.allowed_ips.push(t);
      } else if (kind === 'url') {
        // narrower than host-allowlisting: only that path prefix, never the whole domain
        if (!scope.allowed_url_prefixes.includes(t)) scope.allowed_url_prefixes.push(t);
      } else if (kind === 'host') {
        const h = t.toLowerCase();
        if (!scope.allowed_hosts.includes(h)) scope.allowed_hosts.push(h);
      } // kind null (empty/garbage entry): ignored here, still denied at check time
    }
  }

  // exclusions work in BOTH schemas (additive hard-deny)
  scope.exclusions = normalizeExclusions(raw.exclusions);
  return scope;
}

// ---------------------------------------------------------------------------
// Host matching primitives (unchanged semantics)
// ---------------------------------------------------------------------------

function hostOf(target) {
  try {
    const u = target.includes('://') ? new URL(target) : new URL('http://' + target);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

// host matches if it equals an allowed host or is a subdomain of one.
function hostAllowed(host, allowed) {
  return allowed.some((a) => {
    a = String(a).toLowerCase();
    return host === a || host.endsWith('.' + a);
  });
}

// A prefix match must end on a real boundary, else "https://example.com" would allow
// "https://example.com.evil.com" (suffix-host bypass) and ".../app" would allow ".../apple".
function prefixAllowed(target, pre) {
  if (!target.startsWith(pre)) return false;
  const rest = target.slice(pre.length);
  return rest === '' || '/?#'.includes(rest[0]) || '/?#'.includes(pre[pre.length - 1]);
}

// --- IPv4/CIDR helpers (allowed_ips) ---
function ipv4ToInt(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    if (!/^\d{1,3}$/.test(o) || +o > 255) return null;
    n = (n << 8) | +o;
  }
  return n >>> 0;
}

// "10.0.0.0/8" -> { net, mask } | "127.0.0.1" -> { net, mask: 32 } | null
function cidrParse(s) {
  s = String(s).trim();
  const m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const netInt = ipv4ToInt(m[1]);
  if (netInt == null) return null;
  const bits = m[2] == null ? 32 : Math.min(32, Math.max(0, +m[2]));
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { net: netInt & mask, mask };
}

// Prefix length of a CIDR string ("10.0.0.0/24" -> 24; bare IP -> 32).
function cidrBits(s) {
  const m = String(s).trim().match(/\/(\d{1,2})$/);
  return m ? Math.min(32, Math.max(0, +m[1])) : 32;
}

// ---------------------------------------------------------------------------
// Exclusion matching (hard-deny, conservative)
// ---------------------------------------------------------------------------

// Does a HOSTNAME/IP-literal hit any exclusion? hostnames: exact-or-subdomain (same rule as
// the allowlist); ips/cidrs: membership. Returns the matched exclusion or null.
function exclusionMatchesHost(host, exclusions) {
  const h = String(host || '').toLowerCase();
  let n = ipv4ToInt(h === 'localhost' ? '127.0.0.1' : h);
  for (const x of normalizeExclusions(exclusions)) {
    if (x.kind === 'cidr' || x.kind === 'ip') {
      const c = cidrParse(x.value);
      if (c && n != null && ((n & c.mask) >>> 0) === (c.net >>> 0)) return x;
    } else if (h === x.value || h.endsWith('.' + x.value)) {
      return x;
    }
  }
  return null;
}

// Does a requested CIDR overlap ANY exclusion? Conservative: INTERSECTION = deny (we refuse
// ranges touching an excluded address instead of trimming them). Overlap iff either range's
// base falls inside the other's block (OR, not AND — containment counts too).
function cidrIntersectsExclusion(cidrStr, exclusions) {
  const c = cidrParse(cidrStr);
  if (!c) return null;
  for (const x of normalizeExclusions(exclusions)) {
    const xc = cidrParse(x.value);
    if (!xc) continue;
    if (((c.net & xc.mask) >>> 0) === (xc.net >>> 0) ||
        ((xc.net & c.mask) >>> 0) === (c.net >>> 0)) return x;
  }
  return null;
}

// ---------------------------------------------------------------------------
// B10a — engagement time_window (evaluated on EVERY call; deterministic clock injection)
// ---------------------------------------------------------------------------

// Returns a deny object when outside the window, null when the window is open/absent.
function timeWindowCheck(scope, now) {
  const tw = scope && scope.time_window;
  if (!tw || typeof tw !== 'object' || (!tw.start && !tw.end)) return null; // open window
  const clock = now != null ? String(now) : (process.env.SCOPE_NOW || new Date().toISOString());
  const t = Date.parse(clock);
  if (Number.isNaN(t))
    return { ok: false, reason: 'outside engagement time_window', detail: `unparseable clock value (${clock})` };
  if (tw.start) {
    const s = Date.parse(String(tw.start));
    if (Number.isNaN(s) || t < s)
      return { ok: false, reason: 'outside engagement time_window', detail: Number.isNaN(s) ? 'unparseable start bound (fail-closed)' : 'before start', window: tw };
  }
  if (tw.end) {
    const e = Date.parse(String(tw.end));
    if (Number.isNaN(e) || t > e)
      return { ok: false, reason: 'outside engagement time_window', detail: Number.isNaN(e) ? 'unparseable end bound (fail-closed)' : 'after end', window: tw };
  }
  return null;
}

// ---------------------------------------------------------------------------
// IP/CIDR decisions (exclusion-aware; original signatures preserved, params purely additive)
// ---------------------------------------------------------------------------

function ipAllowed(host, allowedIps, exclusions) {
  if (exclusionMatchesHost(host, exclusions)) return false; // hard-deny first
  if (!allowedIps || allowedIps.length === 0) return false;
  let ip = String(host).toLowerCase();
  if (ip === 'localhost') ip = '127.0.0.1';
  const n = ipv4ToInt(ip);
  if (n == null) return false; // not an IP literal -> host allowlist only
  return allowedIps.some((a) => {
    const c = cidrParse(a);
    return c != null && (((n & c.mask) >>> 0) === (c.net >>> 0));
  });
}

// Is a CIDR target (e.g. "10.0.0.0/24") entirely inside allowed_ips? Used by run.js for
// network scanners (nmap/netexec/masscan) that take range targets. Fail closed: the target
// range must be a SUBSET of at least one authorized CIDR. Hardening: an exclusion intersecting
// the range denies it, and the engagement time_window applies here too.
function cidrInScope(cidr, scope, opts) {
  const c = cidrParse(cidr);
  if (!c) return { ok: false, reason: 'unparseable CIDR: ' + cidr };
  const ex = cidrIntersectsExclusion(cidr, scope && scope.exclusions);
  if (ex) return { ok: false, reason: `CIDR ${cidr} intersects excluded ${ex.value}` };
  const tw = timeWindowCheck(scope, opts && opts.now);
  if (tw) return tw;
  const bits = cidrBits(cidr);
  const allowed = (scope && scope.allowed_ips) || [];
  if (!allowed.length) return { ok: false, reason: 'CIDR target but allowed_ips is empty' };
  for (const a of allowed) {
    const ac = cidrParse(a);
    if (!ac) continue;
    // c is a subset of ac iff its network falls in ac's network AND it is equally/more specific.
    // (masks/nets are compared as unsigned so ranges >=128.0.0.0 behave like ipAllowed().)
    if (((c.net & ac.mask) >>> 0) === (ac.net >>> 0) && bits >= cidrBits(a))
      return { ok: true, reason: `CIDR within allowed_ips (${a})` };
  }
  return { ok: false, reason: `CIDR ${cidr} not within allowed_ips` };
}

// Main decision. opts (optional, purely additive): { now } for deterministic time_window tests.
// Order: parse -> exclusions HARD-DENY -> empty-scope -> time_window -> allowlists -> deny.
function inScope(target, scope, opts) {
  opts = opts || {};
  const host = hostOf(target);
  if (!host) return { ok: false, reason: 'unparseable target' };
  const ex = exclusionMatchesHost(host, scope && scope.exclusions);
  if (ex) return { ok: false, reason: `host ${host} excluded by scope.json exclusions (${ex.value})` };
  const hosts = scope.allowed_hosts || [];
  const prefixes = scope.allowed_url_prefixes || [];
  const ips = scope.allowed_ips || [];
  if (hosts.length === 0 && prefixes.length === 0 && ips.length === 0)
    return { ok: false, reason: 'scope.json empty - nothing is authorized yet' };
  const tw = timeWindowCheck(scope, opts.now);
  if (tw) return tw;
  if (hostAllowed(host, hosts)) return { ok: true, reason: 'host allowlisted' };
  if (ips.length && ipAllowed(host, ips)) return { ok: true, reason: 'ip/cidr allowlisted' };
  if (prefixes.some((pre) => prefixAllowed(target, pre)))
    return { ok: true, reason: 'url-prefix allowlisted' };
  return { ok: false, reason: `host ${host} not in allowed_hosts/allowed_ips` };
}

// ---------------------------------------------------------------------------
// B5 — canonTarget(): strict pre-spawn canonicalization (compile_plan layer).
// STRICT (reject): userinfo/credentials-in-URL, whitespace/control chars (\r\n\t\x00...),
// backslash, percent-encoded hosts (%65vil.com — WHATWG would silently decode+accept them),
// non-ASCII labels that do not convert cleanly via url.domainToASCII (xn-- passes through,
// already canonical), unresolved dot-segments (/../, /./ — raw OR percent-encoded: some
// servers/proxies do NOT normalize them the way the URL parser does, so rewriting could
// change what the backend sees — refusing is the conservative anti-traversal choice),
// port outside 1..65535, empty host, double scheme / colon-without-port in authority,
// invalid percent-encoding, encoded control chars (CRLF smuggling).
// NORMALIZE: lowercase host, strip trailing dots, drop default port, strip fragment, resolve
// path via the WHATWG parser (inputs carrying dot-segments never get this far), scheme http://
// assumed when absent (host extraction). IPv6 in brackets: minimal documented support —
// validated as an IPv6 literal, no zone-id (%), no IPv4-mapped shortcuts beyond what net.isIP accepts.
// Returns {ok:true, canonical, host} | {ok:false, reason}.
// ---------------------------------------------------------------------------

function canonTarget(raw) {
  const fail = (reason) => ({ ok: false, reason });
  raw = String(raw == null ? '' : raw);
  if (!raw.trim()) return fail('empty target');
  if (/[\s\x00-\x1f\x7f]/.test(raw)) return fail('whitespace/control character in target');
  if (raw.includes('\\')) return fail('backslash in target');

  // split scheme
  const sm = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  const scheme = sm ? sm[1].toLowerCase() : 'http';
  const rest = sm ? raw.slice(sm[0].length) : raw;
  if (!rest || /^[/?#]/.test(rest)) return fail('empty host');

  // authority span (before any parsing that could rewrite it)
  const aEnd = rest.search(/[/?#]/);
  const authority = aEnd === -1 ? rest : rest.slice(0, aEnd);
  const tail = aEnd === -1 ? '' : rest.slice(aEnd);

  if (authority.includes('@')) return fail('credentials/userinfo in URL not allowed');
  if (authority.includes('%')) return fail('percent-encoded host not allowed');

  // host/port split (or IPv6 bracket form)
  let hostRaw, portRaw = null, ipv6 = false;
  if (authority.startsWith('[')) {
    ipv6 = true;
    const close = authority.indexOf(']');
    if (close === -1) return fail('malformed IPv6 literal (missing "]")');
    hostRaw = authority.slice(1, close);
    const after = authority.slice(close + 1);
    if (after && !/^:\d{1,5}$/.test(after)) return fail('malformed authority after IPv6 literal');
    portRaw = after ? after.slice(1) : null;
    if (hostRaw.includes('%')) return fail('IPv6 zone-id (%) not supported (conservative)');
    if (net.isIP(hostRaw) !== 6) return fail('invalid IPv6 literal');
  } else {
    const ci = authority.indexOf(':');
    if (ci !== -1) {
      hostRaw = authority.slice(0, ci);
      portRaw = authority.slice(ci + 1);
      if (!/^\d{1,5}$/.test(portRaw))
        return fail('malformed authority (colon without numeric port — double scheme?)');
      const pn = Number(portRaw);
      if (pn < 1 || pn > 65535) return fail('port out of range (1..65535)');
    } else {
      hostRaw = authority;
    }
    if (!hostRaw) return fail('empty host');
  }

  // dot-segments / percent hygiene on the RAW tail BEFORE any parser can rewrite it
  const qIdx = tail.indexOf('?');
  const pathPart = qIdx === -1 ? tail : tail.slice(0, qIdx);
  if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(pathPart))
    return fail('unresolved dot-segment in path (anti-traversal)');
  if (/%(?![0-9A-Fa-f]{2})/.test(tail)) return fail('invalid percent-encoding in path');
  let decoded = tail;
  try {
    decoded = decodeURIComponent(tail);
  } catch {
    return fail('undecodable percent-sequence in path');
  }
  if (/[\x00-\x1f\x7f]/.test(decoded)) return fail('encoded control character (CRLF smuggling)');
  const dQ = decoded.indexOf('?');
  const dPath = dQ === -1 ? decoded : decoded.slice(0, dQ);
  if (/(?:^|\/)\.{1,2}(?:\/|$)/.test(dPath))
    return fail('percent-encoded dot-segment in path (anti-traversal)');

  // host canonicalization: lowercase, strip trailing dots, IDNA only when needed
  let ascii = hostRaw.toLowerCase().replace(/\.+$/, '');
  if (!ascii) return fail('empty host');
  if (/[^\x00-\x7f]/.test(ascii)) {
    const conv = domainToASCII(ascii);
    if (!conv) return fail('non-ASCII host does not convert cleanly (IDNA)');
    ascii = conv.toLowerCase();
  } // pure-ASCII (incl. existing xn-- punycode) already canonical: pass through

  // rebuild + reparse as belt-and-braces sanity (fail closed on ANY surprise)
  const hostPart = ipv6 ? '[' + ascii + ']' : ascii;
  let u;
  try {
    u = new URL(scheme + '://' + hostPart + (portRaw ? ':' + Number(portRaw) : '') + tail);
  } catch (e) {
    return fail('unparseable target: ' + (e.message || e));
  }
  if (!ipv6 && u.hostname.toLowerCase() !== ascii)
    return fail('host changed during normalization (fail closed)');
  // NB: Node's WHATWG URL keeps the brackets in .hostname for IPv6 ("[::1]")
  if (ipv6 && net.isIP(u.hostname.replace(/^\[|\]$/g, '')) !== 6)
    return fail('IPv6 literal rejected by URL parser (fail closed)');
  if (u.protocol.toLowerCase() !== scheme + ':')
    return fail('scheme changed during normalization (fail closed)');

  const canonical = scheme + '://' + hostPart + (u.port ? ':' + u.port : '') + u.pathname + u.search;
  return { ok: true, canonical, host: ascii };
}

// ---------------------------------------------------------------------------
// B5 — validatePlan(plan): deterministic pre-spawn validation (PentestGPT compile_plan idea).
// plan = { targets: [url|host|ip|cidr], commands?: ["..."] }. EVERY element must pass canon +
// scope-check; command strings have their hosts extracted LOCALLY (regexes mirroring run.js,
// reimplemented here — run.js is NOT imported) and each extracted host is scope-checked too.
// Returns { ok, results[] }; ok=false if even ONE element fails (fail-closed). A plan without
// targets, or a command yielding no extractable host, fails closed as well.
// opts (optional): { scope?, now?, } — scope defaults to loadScope().
// ---------------------------------------------------------------------------

const PLAN_URL_RE_SRC = '[a-z][a-z0-9+.-]*://[^\\s\'"<>]+';
const PLAN_EMAIL_RE_SRC = '[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,})';
const PLAN_FILE_EXT_RE = /\.(txt|json|js|ts|xml|html?|md|csv|log|py|ya?ml|conf|cfg|zip|har|list|nse|rc)$/i;
const PLAN_BARE_HOST_RE = /^[a-z0-9.-]+$/i;

function planExtractHosts(cmd) {
  const out = [];
  const seen = new Set();
  const push = (h) => { if (h && !seen.has(h)) { seen.add(h); out.push(h); } };
  const s = String(cmd == null ? '' : cmd);
  for (const m of s.match(new RegExp(PLAN_URL_RE_SRC, 'gi')) || []) push(hostOf(m));
  const em = new RegExp(PLAN_EMAIL_RE_SRC, 'gi');
  let mm;
  while ((mm = em.exec(s))) push(mm[1].toLowerCase());
  for (const tok of s.split(/\s+/)) {
    const t = tok.trim();
    if (!t) continue;
    if (isCidrTok(t)) { push(t); continue; } // keep CIDRs whole for cidrInScope()
    if (PLAN_FILE_EXT_RE.test(t) || !PLAN_BARE_HOST_RE.test(t)) continue;
    if (!t.includes('.') && t.toLowerCase() !== 'localhost') continue;
    push(hostOf(t));
  }
  return out.filter(Boolean);
}

function isCidrTok(t) {
  return CIDR_TOK_RE.test(String(t == null ? '' : t).trim()) && !!cidrParse(t);
}

function validatePlan(plan, opts) {
  opts = opts || {};
  const results = [];
  let allOk = true;
  const rec = (e) => { results.push(e); if (!e.ok) allOk = false; };
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) {
    return { ok: false, results: [{ kind: 'plan', ok: false, reason: 'plan must be an object {targets:[], commands?:[]}' }] };
  }
  const scope = opts.scope || loadScope();

  const targets = plan.targets;
  if (!Array.isArray(targets) || targets.length === 0) {
    rec({ kind: 'targets', ok: false, reason: 'plan has no targets (fail closed)' });
  } else {
    for (const rawT of targets) {
      const t = String(rawT == null ? '' : rawT).trim();
      if (!t) { rec({ target: t, kind: 'target', ok: false, reason: 'empty target' }); continue; }
      if (isCidrTok(t)) {
        const r = cidrInScope(t, scope, { now: opts.now });
        rec({ target: t, kind: 'cidr', ok: !!r.ok, reason: r.reason });
      } else {
        const c = canonTarget(t);
        if (!c.ok) { rec({ target: t, kind: 'target', ok: false, reason: c.reason }); continue; }
        const s = inScope(c.canonical, scope, { now: opts.now });
        rec({ target: c.canonical, kind: 'target', host: c.host, ok: !!s.ok, reason: s.reason });
      }
    }
  }

  if (plan.commands != null) {
    if (!Array.isArray(plan.commands)) {
      rec({ kind: 'commands', ok: false, reason: 'plan.commands must be an array of strings' });
    } else {
      for (const rawC of plan.commands) {
        const cmd = String(rawC == null ? '' : rawC);
        const hosts = planExtractHosts(cmd);
        if (!hosts.length) {
          rec({ command: cmd, kind: 'command', ok: false, reason: 'no target host found in command (fail closed)' });
          continue;
        }
        const details = [];
        const bad = [];
        for (const h of hosts) {
          // same convention as run.js: bare hosts ride http:// for the scope decision
          const r = isCidrTok(h) ? cidrInScope(h, scope, { now: opts.now })
                                 : inScope('http://' + h, scope, { now: opts.now });
          details.push({ host: h, ok: !!r.ok, reason: r.reason });
          if (!r.ok) bad.push(h);
        }
        rec(bad.length
          ? { command: cmd, kind: 'command', ok: false, hosts, out_of_scope: bad, details }
          : { command: cmd, kind: 'command', ok: true, hosts, details });
      }
    }
  }

  return { ok: allOk, results };
}

// ---------------------------------------------------------------------------
// B10b — DNS pinning resolve-once (anti-rebinding). NOT yet wired into run.js/repeater.js
// (later wave): integration points are documented in reports/migliorie/ondata1-scope-guard.md.
//   resolvePin(host, opts) -> resolves once, pins {host:{ip,first_seen}} into
//     reports/tmp/dns-pins.json (atomic tmp+rename write), and NEGATES with reason
//     'dns-pin-divergence' (+ append to reports/tmp/dns-divergence.log) when a later view of
//     the same host resolves elsewhere. opts: { resolver?(host)->ip, pinsFile?, divergenceLog? }.
//   checkPin(host, ip, pins) -> PURE comparator (no fs, no dns) for tests/embedders.
// Tests NEVER use real DNS: always inject opts.resolver.
// ---------------------------------------------------------------------------

const PINS_FILE = () => process.env.SCOPE_PINS_FILE || path.join(__dirname, '..', 'reports', 'tmp', 'dns-pins.json');
const DIVERGENCE_LOG = () => process.env.SCOPE_DIVERGENCE_LOG || path.join(__dirname, '..', 'reports', 'tmp', 'dns-divergence.log');

function defaultLookup(host) {
  return dns.promises.lookup(host).then((r) => r.address);
}

function readJsonSafe(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

function writeAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

// PURE: no fs/dns. First sight (no pin) is ok:true with note — the caller decides whether to pin.
function checkPin(host, ip, pins) {
  const h = String(host || '').toLowerCase();
  const p = (pins || {})[h];
  const a = String(ip == null ? '' : ip).toLowerCase();
  if (!p) return { ok: true, note: 'no prior pin' };
  if (String(p.ip).toLowerCase() === a) return { ok: true, pinned: p.ip };
  return { ok: false, reason: 'dns-pin-divergence', pinned: p.ip, resolved: a };
}

async function resolvePin(host, opts) {
  opts = opts || {};
  const h = String(host == null ? '' : host).trim().toLowerCase();
  if (!h) return { ok: false, reason: 'empty host' };
  if (net.isIP(h)) return { ok: true, pinned: h, resolved: h, note: 'IP literal — DNS not consulted' };

  const pinsFile = opts.pinsFile || PINS_FILE();
  const divLog = opts.divergenceLog || DIVERGENCE_LOG();
  const lookup = opts.resolver || defaultLookup;

  const pins = readJsonSafe(pinsFile);
  let addr;
  try {
    addr = await lookup(h);
  } catch (e) {
    return { ok: false, reason: 'resolve failed: ' + (e.message || e) }; // fail closed
  }
  addr = addr == null ? '' : String(addr).trim();
  if (!addr) return { ok: false, reason: 'resolver returned no address' }; // fail closed

  const cp = checkPin(h, addr, pins);
  if (!cp.ok) {
    try {
      fs.mkdirSync(path.dirname(divLog), { recursive: true });
      fs.appendFileSync(divLog, JSON.stringify({
        ts: new Date().toISOString(), host: h, pinned: cp.pinned, resolved: cp.resolved,
      }) + '\n');
    } catch {}
    return { ok: false, reason: 'dns-pin-divergence', pinned: cp.pinned, resolved: cp.resolved };
  }
  if (!pins[h]) {
    const firstSeen = new Date().toISOString();
    pins[h] = { ip: addr, first_seen: firstSeen };
    try {
      writeAtomic(pinsFile, JSON.stringify(pins, null, 2) + '\n');
    } catch {}
    return { ok: true, pinned: addr, resolved: addr, first_seen: firstSeen };
  }
  return { ok: true, pinned: cp.pinned, resolved: addr, first_seen: pins[h].first_seen };
}

// ---------------------------------------------------------------------------

module.exports = {
  // original API (semantics unchanged)
  loadScope, inScope, hostOf, hostAllowed, prefixAllowed, ipAllowed, cidrInScope, cidrParse, ipv4ToInt,
 // ondata-1 superset
  normalizeScope, normalizeExclusions, timeWindowCheck,
  canonTarget, validatePlan, planExtractHosts,
  resolvePin, checkPin,
  cidrBits, cidrIntersectsExclusion, exclusionMatchesHost,
};

if (require.main === module) {
  const [cmd, arg] = process.argv.slice(2);
  const usage = 'usage: node scope-guard.js <check <url|host> | canon <url> | plan-check <planfile> | pin <host>>';
  const done = (res) => {
    console.log(JSON.stringify(res)); // mono-line JSON ALWAYS
    process.exit(res.ok ? 0 : 1);
  };
  if (!cmd || !arg) {
    console.error(usage);
    process.exit(2);
  }
  try {
    if (cmd === 'check') done(inScope(arg, loadScope()));
    else if (cmd === 'canon') done(canonTarget(arg));
    else if (cmd === 'pin') resolvePin(arg).then(done).catch((e) => { console.error(JSON.stringify({ error: String(e.message || e) })); process.exit(2); });
    else if (cmd === 'plan-check') {
      const plan = JSON.parse(fs.readFileSync(arg, 'utf8'));
      done(validatePlan(plan));
    } else {
      console.error(usage);
      process.exit(2);
    }
  } catch (e) {
    console.error(JSON.stringify({ error: String((e && e.message) || e) }));
    process.exit(2);
  }
}
