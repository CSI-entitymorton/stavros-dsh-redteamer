// Scope guard: single source of truth for "am I allowed to touch this target".
// Used HARD (in code) by repeater.js/run.js/oob.js; used procedurally by agents via
//   node tools/scope-guard.js check <url|host>
// Exit 0 = in scope, 1 = out of scope/blocked, 2 = usage error.
//
// scope.json:
//   allowed_hosts: ["example.com"]         -> host + subdomains
//   allowed_url_prefixes: ["https://x.com/app/"]
//   allowed_ips: ["127.0.0.1", "10.0.0.0/8"]  -> literal IP hosts (and 'localhost' -> 127.0.0.1),
//                                            CIDR ranges allowed. Use ONLY for authorized
//                                            SSRF-internal / lab targets; keep it minimal.
const fs = require('fs');
const path = require('path');

function loadScope(scopePath) {
  // SCOPE_JSON env override: lets tests (and multi-project setups) point at another file.
  const p = scopePath || process.env.SCOPE_JSON || path.join(__dirname, '..', 'scope.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

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
  const net = ipv4ToInt(m[1]);
  if (net == null) return null;
  const bits = m[2] == null ? 32 : Math.min(32, Math.max(0, +m[2]));
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { net: net & mask, mask };
}

// Prefix length of a CIDR string ("10.0.0.0/24" -> 24; bare IP -> 32).
function cidrBits(s) {
  const m = String(s).trim().match(/\/(\d{1,2})$/);
  return m ? Math.min(32, Math.max(0, +m[1])) : 32;
}

function ipAllowed(host, allowedIps) {
  if (!allowedIps || allowedIps.length === 0) return false;
  let ip = host.toLowerCase();
  if (ip === 'localhost') ip = '127.0.0.1';
  const n = ipv4ToInt(ip);
  if (n == null) return false; // not an IP literal -> host allowlist only
  return allowedIps.some((a) => {
    const c = cidrParse(a);
    return c != null && (n & c.mask) === c.net;
  });
}

// Is a CIDR target (e.g. "10.0.0.0/24") entirely inside allowed_ips? Used by run.js for
// network scanners (nmap/netexec/masscan) that take range targets. Fail closed: the target
// range must be a SUBSET of at least one authorized CIDR.
function cidrInScope(cidr, scope) {
  const c = cidrParse(cidr);
  if (!c) return { ok: false, reason: 'unparseable CIDR: ' + cidr };
  const bits = cidrBits(cidr);
  const allowed = (scope && scope.allowed_ips) || [];
  if (!allowed.length) return { ok: false, reason: 'CIDR target but allowed_ips is empty' };
  for (const a of allowed) {
    const ac = cidrParse(a);
    if (!ac) continue;
    // c is a subset of ac iff its network falls in ac's network AND it is equally/more specific.
    // (net/mask come from cidrParse() as signed int32 — compare them raw, like ipAllowed().)
    if ((c.net & ac.mask) === ac.net && bits >= cidrBits(a))
      return { ok: true, reason: `CIDR within allowed_ips (${a})` };
  }
  return { ok: false, reason: `CIDR ${cidr} not within allowed_ips` };
}

// A prefix match must end on a real boundary, else "https://example.com" would allow
// "https://example.com.evil.com" (suffix-host bypass) and ".../app" would allow ".../apple".
function prefixAllowed(target, pre) {
  if (!target.startsWith(pre)) return false;
  const rest = target.slice(pre.length);
  return rest === '' || '/?#'.includes(rest[0]) || '/?#'.includes(pre[pre.length - 1]);
}

function inScope(target, scope) {
  const host = hostOf(target);
  if (!host) return { ok: false, reason: 'unparseable target' };
  const hosts = scope.allowed_hosts || [];
  const prefixes = scope.allowed_url_prefixes || [];
  const ips = scope.allowed_ips || [];
  if (hosts.length === 0 && prefixes.length === 0 && ips.length === 0)
    return { ok: false, reason: 'scope.json empty - nothing is authorized yet' };
  if (hostAllowed(host, hosts)) return { ok: true, reason: 'host allowlisted' };
  if (ips.length && ipAllowed(host, ips)) return { ok: true, reason: 'ip/cidr allowlisted' };
  if (prefixes.some((pre) => prefixAllowed(target, pre)))
    return { ok: true, reason: 'url-prefix allowlisted' };
  return { ok: false, reason: `host ${host} not in allowed_hosts/allowed_ips` };
}

module.exports = { loadScope, inScope, hostOf, hostAllowed, prefixAllowed, ipAllowed, cidrInScope, cidrParse, ipv4ToInt };

if (require.main === module) {
  const [cmd, target] = process.argv.slice(2);
  if (cmd !== 'check' || !target) {
    console.error('usage: node scope-guard.js check <url|host>');
    process.exit(2);
  }
  const res = inScope(target, loadScope());
  console.log(JSON.stringify(res));
  process.exit(res.ok ? 0 : 1);
}
