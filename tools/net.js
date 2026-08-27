#!/usr/bin/env node
// Shared DNS/IP hardening for outbound requests. scope-guard.js matches HOSTNAMES (and
// allowed_ips for literal IP hosts). This closes the remaining gap: a host that IS in
// allowed_hosts could still resolve to 169.254.169.254 / 127.0.0.1 / an internal subnet
// (DNS rebinding, poisoned records, SSRF pivot). resolveAndGuard():
//   1. resolves the hostname to its addresses,
//   2. refuses any address in a private/link-local/loopback/other "special" range that is NOT
//      explicitly covered by scope.allowed_ips,
//   3. returns ONE pinned address to connect to, so a mid-run DNS change can't redirect the
//      request after we've validated it.
//
// Integration: call `const pin = await resolveAndGuard(url, scope)` before a request, then use
// the returned { address, family } as the socket's lookup() result (or connect to it directly)
// while keeping the original hostname for the Host header / SNI.
//
// Note: internal lab/VPN targets that resolve to private addresses must ALSO list their subnet
// in scope.json allowed_ips (e.g. 10.0.0.0/8), otherwise they are refused. This is intentional.
const dns = require('dns');
const net = require('net');
const { hostOf, ipAllowed } = require('./scope-guard');

// Returns a label if the IP is in a private/link-local/loopback/other special range, else null.
function specialRange(ip) {
  if (net.isIP(ip) === 4) {
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some((o) => o > 255 || o < 0)) return 'invalid';
    const n = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
    // >>> 0 on both sides: JS & yields a signed 32-bit int, so masks with the top bit set
    // (>= 0x80000000) must be compared as unsigned.
    if (((n & 0xff000000) >>> 0) === 0x0a000000) return 'private'; // 10.0.0.0/8
    if (((n & 0xfff00000) >>> 0) === 0xac100000) return 'private'; // 172.16.0.0/12
    if (((n & 0xffff0000) >>> 0) === 0xc0a80000) return 'private'; // 192.168.0.0/16
    if (((n & 0xff000000) >>> 0) === 0x7f000000) return 'loopback'; // 127.0.0.0/8
    if (((n & 0xffff0000) >>> 0) === 0xa9fe0000) return 'link-local'; // 169.254.0.0/16 (cloud metadata)
    if (((n & 0xffc00000) >>> 0) === 0x64400000) return 'cgnat'; // 100.64.0.0/10 (shared address space)
    if (((n & 0xf0000000) >>> 0) === 0xe0000000) return 'multicast'; // 224.0.0.0/4
    if (n === 0) return 'unspecified';
    if (((n & 0xf0000000) >>> 0) === 0xf0000000) return 'reserved'; // 240.0.0.0/4
    return null;
  }
  if (net.isIP(ip) === 6) {
    const a = ip.toLowerCase();
    if (a === '::') return 'unspecified';
    if (a === '::1') return 'loopback';
    if (a.startsWith('::ffff:')) return specialRange(a.slice(7)); // IPv4-mapped -> v4 rules
    if (a.startsWith('ff')) return 'multicast';
    if (/^fe[89ab]/.test(a)) return 'link-local'; // fe80::/10
    if (a.startsWith('fc') || a.startsWith('fd')) return 'private'; // ULA fc00::/7
    return null;
  }
  return null;
}

// Can a special-range address be allowed? allowed_ips is IPv4/CIDR only, so we map the few
// IPv6 specials that have a canonical IPv4 equivalent; other IPv6 specials can't be expressed
// and are therefore refused.
function specialAllowed(addr, special, allowedIps) {
  if (!special) return true;
  if (net.isIP(addr) === 4) return ipAllowed(addr, allowedIps);
  const a = addr.toLowerCase();
  if (a === '::1') return ipAllowed('127.0.0.1', allowedIps);
  if (a.startsWith('::ffff:')) return ipAllowed(a.slice(7), allowedIps);
  return false; // IPv6 special ranges cannot be expressed in allowed_ips -> fail closed
}

// Resolve target (a URL or bare host) against scope. Returns:
//   { address, family }          -> pinned address to use for the connection, or
//   { blocked: true, reason }    -> refused (unparseable, DNS failure, or special-range pivot).
async function resolveAndGuard(target, scope) {
  const host = hostOf(target);
  if (!host) return { blocked: true, reason: 'unparseable target' };
  // IP literal: scope-guard's inScope() already decided allow/deny; just hand it back.
  if (net.isIP(host)) return { address: host, family: net.isIP(host) };

  let records;
  try {
    records = await dns.promises.lookup(host, { all: true, verbatim: true });
  } catch (e) {
    return { blocked: true, reason: 'DNS resolution failed for ' + host + ': ' + (e.message || e) };
  }
  const addrs = (records || []).map((r) => r.address);
  if (!addrs.length) return { blocked: true, reason: 'no addresses resolved for ' + host };

  const allowedIps = scope.allowed_ips || [];
  for (const a of addrs) {
    const special = specialRange(a);
    if (special && !specialAllowed(a, special, allowedIps)) {
      return {
        blocked: true,
        reason: `host ${host} resolves to ${a} (${special}) which is not in allowed_ips — refusing (DNS-rebinding / internal-pivot guard). Add the subnet to scope.json allowed_ips if this is an authorized internal target.`,
      };
    }
  }
  // Pin the first IPv4 (predictable connection + deterministic scope checks).
  const chosen = records.find((r) => r.family === 4) || records[0];
  return { address: chosen.address, family: chosen.family };
}

module.exports = { resolveAndGuard, specialRange, specialAllowed };
