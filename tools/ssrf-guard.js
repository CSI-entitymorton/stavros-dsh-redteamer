#!/usr/bin/env node
// B9 (Ondata 3) — SSRF default-deny anti-metadata, SECOND layer inside repeater.js / oob.js.
//
// The FIRST layer remains the existing scope-guard (scope.json allow/deny + net.js
// resolveAndGuard DNS-pin). This module NEVER replaces it: it re-judges the PINNED address
// (or the literal host when no local pin exists, e.g. proxy-chained mode) against its own
// deny-lists, so a target that the first layer let through (broad allowed_ips, operator
// error, tampered state) still cannot aim our HTTP fetcher at cloud metadata or loopback.
//
// Two tiers (defense in depth, documented in reports/migliorie/ondata3-report.md):
//   HARD tier — ALWAYS denied unless an explicit opt-in flag/env is present:
//     127.0.0.0/8 + ::1 (loopback), 169.254.0.0/16 (link-local incl. 169.254.169.254
//     cloud metadata), fe80::/10 (v6 link-local), 0.0.0.0/:: (unspecified),
//     224.0.0.0/4 + v6 multicast, 240.0.0.0/4 reserved, ::ffff:-mapped equivalents,
//     plus well-known metadata HOSTNAMES (metadata.google.internal, instance-data,
//     localhost). Rationale: never legitimate targets for OUR fetcher.
//   PRIVATE tier — RFC1918 (10/8, 172.16/12, 192.168/16) and v6 ULA fc00::/7:
//     denied UNLESS the first layer positively authorized this exact pinned/host verdict
//     (opts.scopeAuthorized === true, i.e. inScope/pin already passed) OR the explicit
//     opt-in is present. This keeps internal-lab engagements (e.g. 192.168.0.94) fully
//     working with zero flags while still refusing private pivots that scope never
//     authorized (the case the first layer cannot see: proxy-chained DNS, raw literals
//     reached without a pin).
//
// Opt-in (explicit, visible): CLI flag --allow-metadata-target on repeater.js, env
// ALLOW_METADATA_TARGET=1 (equivalent; used by programmatic callers), oob.js flag of the
// same name for --public-url. The opt-in lifts BOTH tiers and is logged loudly.
//
// Every verdict is returned as data ({ok, tier, range, why}) so callers log it into their
// existing output flow (repeater results / oob stderr) — no silent decisions.
'use strict';
const net = require('net');
const { specialRange } = require('./net');

const METADATA_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'instance-data',
  'instance-data.ec2.internal',
  'metadata',
]);

function envOptIn() {
  const v = String(process.env.ALLOW_METADATA_TARGET || '').trim();
  return v === '1' || v.toLowerCase() === 'true' || v.toLowerCase() === 'yes';
}

/** Normalize an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its v4 form, else null. */
function v4Mapped(ip) {
  if (net.isIP(ip) !== 6) return null;
  const a = ip.toLowerCase();
  if (!a.startsWith('::ffff:')) return null;
  const tail = a.slice(7);
  return net.isIP(tail) === 4 ? tail : null;
}

/**
 * Judge one address/host. Returns:
 *   { ok: true,  tier: 'pass', range: null }                       — allowed
 *   { ok: false, tier: 'hard'|'private', range, why }              — denied
 * opts.allowMetadata    explicit operator opt-in (lifts both tiers)
 * opts.scopeAuthorized  first-layer verdict already passed for this same target
 * opts.callbackBase     URL is OUR OWN callback/listener base (oob.js): loopback and
 *                       RFC1918 bases are legitimate infrastructure (the oob default IS
 *                       http://127.0.0.1:<port>/), so only metadata/link-local/etc. stay denied.
 */
function checkAddress(ip, opts) {
  opts = opts || {};
  if (net.isIP(ip) === 0) {
    // Not an IP: only hostname-level hard rules apply here.
    const nameHit = METADATA_HOSTNAMES.has(String(ip).toLowerCase());
    if (nameHit && opts.callbackBase && String(ip).toLowerCase() === 'localhost') {
      return { ok: true, tier: 'pass-callback-base', range: 'metadata-hostname(loopback)' };
    }
    if (nameHit) {
      if (opts.allowMetadata) return { ok: true, tier: 'pass-optin', range: 'metadata-hostname' };
      return { ok: false, tier: 'hard', range: 'metadata-hostname', why: `${ip} is a well-known metadata/local hostname (B9 hard deny)` };
    }
    return { ok: true, tier: 'pass', range: null };
  }
  let ranges = [];
  const mapped = v4Mapped(ip);
  const effective = mapped || ip;
  if (mapped) ranges.push('ipv4-mapped');
  const sp = specialRange(effective);
  const HARD = new Set(['loopback', 'link-local', 'unspecified', 'multicast', 'reserved']);
  if (sp && HARD.has(sp)) ranges.push(sp);
  else if (sp === 'private') ranges.push('rfc1918-ula');
  else if (sp === 'cgnat') ranges.push('cgnat'); // treated as private-tier: shared space, not public internet
  if (!ranges.length) return { ok: true, tier: 'pass', range: null };
  const tier = ranges.includes('loopback') || ranges.includes('link-local')
    || ranges.includes('unspecified') || ranges.includes('multicast') || ranges.includes('reserved')
    ? 'hard' : 'private';
  // Callback-base mode: loopback-only bases are our own listener infrastructure.
  if (opts.callbackBase && tier === 'hard' && ranges.length === 1 && ranges[0] === 'loopback') {
    return { ok: true, tier: 'pass-callback-base', range: 'loopback' };
  }
  if (opts.callbackBase && tier === 'private') {
    return { ok: true, tier: 'pass-callback-base', range: ranges.join('+') };
  }
  if (opts.allowMetadata) return { ok: true, tier: 'pass-optin', range: ranges.join('+') };
  if (tier === 'private' && opts.scopeAuthorized) return { ok: true, tier: 'pass-private-scoped', range: ranges.join('+') };
  const why = tier === 'hard'
    ? `${effective} is in ${ranges.join('/')} — B9 hard default-deny (metadata/loopback); pass --allow-metadata-target to override explicitly`
    : `${effective} is ${ranges.join('/')} and the scope layer did not authorize it — B9 private-tier deny`;
  return { ok: false, tier, range: ranges.join('+'), why };
}

/** Convenience: judge a URL string (hostname rules + literal-IP rules). */
function checkTarget(urlOrHost, opts) {
  const s = String(urlOrHost || '').trim();
  let host = s;
  try { host = new URL(s).hostname.replace(/^\[|\]$/g, ''); } catch { /* bare host/IP */ }
  return checkAddress(host, opts);
}

module.exports = { checkAddress, checkTarget, METADATA_HOSTNAMES, envOptIn };
