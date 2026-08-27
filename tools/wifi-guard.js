#!/usr/bin/env node
// Wireless scope guard — single source of truth for "am I allowed to touch this WiFi target".
// Separate model from scope-guard.js (which is IP/host): wireless targets are BSSIDs (AP MACs),
// ESSIDs (network names), client stations (MACs) and channels — NOT IPs. Used HARD (in code)
// by tools/wifi.js; used procedurally by agents via
//   node tools/wifi-guard.js check <bssid|essid|station|channel>
// Exit 0 = in scope, 1 = out of scope/blocked, 2 = usage error.
//
// wifi-scope.json:
//   bssids:   ["AA:BB:CC:DD:EE:FF"]  -> allowed access points (MACs, normalized)
//   essids:   ["MyLabWiFi"]          -> allowed network names (exact, case-sensitive)
//   stations: ["11:22:33:44:55:66"]  -> allowed client MACs (deauth/capture targets)
//   channels: [1, 6, 11]             -> allowed channels (numbers or strings)
//   monitor_iface: "wlan0"           -> NIC hint (optional)
//   wireless_ops: { auto:[...], confirm:[...] } -> action tiers (enforced by tools/wifi.js)
//
// Fail-closed: empty bssids+essids+stations means NOTHING is authorized. A MAC passes if it is
// in bssids OR stations (deauth targets a station, capture targets the AP).
const fs = require('fs');
const path = require('path');

function loadWifiScope(scopePath) {
  // WIFI_SCOPE_JSON env override: lets tests point at another file.
  const p = scopePath || process.env.WIFI_SCOPE_JSON || path.join(__dirname, '..', 'wifi-scope.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// Normalize a MAC/BSSID to lowercase colon form ("aa:bb:cc:dd:ee:ff"). Accepts colon, dash and
// bare 12-hex separators. Returns null if not a valid 48-bit MAC.
function normalizeMac(s) {
  const t = String(s == null ? '' : s).trim().toLowerCase();
  if (!t) return null;
  const hex = t.replace(/[:-]/g, '');
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return hex.match(/.{2}/g).join(':');
}

function isMac(s) {
  return normalizeMac(s) != null;
}

function isChannel(s) {
  const t = String(s == null ? '' : s).trim();
  if (!/^\d{1,3}$/.test(t)) return false;
  const n = Number(t);
  // 2.4 GHz 1-14, 5 GHz 32-177; accept 1-200 defensively.
  return n >= 1 && n <= 200;
}

function bssidInScope(bssid, scope) {
  const m = normalizeMac(bssid);
  if (!m) return { ok: false, reason: 'invalid BSSID: ' + bssid };
  const allowed = (scope && scope.bssids) || [];
  return allowed.some((a) => normalizeMac(a) === m)
    ? { ok: true, reason: 'BSSID allowlisted' }
    : { ok: false, reason: `BSSID ${m} not in wifi-scope.json bssids` };
}

function stationInScope(mac, scope) {
  const m = normalizeMac(mac);
  if (!m) return { ok: false, reason: 'invalid station MAC: ' + mac };
  const allowed = (scope && scope.stations) || [];
  return allowed.some((a) => normalizeMac(a) === m)
    ? { ok: true, reason: 'station allowlisted' }
    : { ok: false, reason: `station ${m} not in wifi-scope.json stations` };
}

function essidInScope(essid, scope) {
  const e = String(essid == null ? '' : essid);
  if (!e.trim()) return { ok: false, reason: 'empty ESSID' };
  const allowed = (scope && scope.essids) || [];
  return allowed.some((a) => a === e)
    ? { ok: true, reason: 'ESSID allowlisted' }
    : { ok: false, reason: `ESSID ${JSON.stringify(e)} not in wifi-scope.json essids` };
}

function channelInScope(ch, scope) {
  const t = String(ch == null ? '' : ch).trim();
  if (!isChannel(t)) return { ok: false, reason: 'invalid channel: ' + t };
  const n = Number(t);
  const allowed = (scope && scope.channels) || [];
  return allowed.some((a) => Number(a) === n)
    ? { ok: true, reason: 'channel allowlisted' }
    : { ok: false, reason: `channel ${n} not in wifi-scope.json channels` };
}

// Auto-detect the target type and check it. A MAC is in scope if it's an allowed BSSID OR an
// allowed station (deauth aims at a station, capture aims at the AP).
function inWifiScope(target, scope) {
  const t = String(target == null ? '' : target).trim();
  if (isMac(t)) {
    const asBssid = bssidInScope(t, scope);
    if (asBssid.ok) return Object.assign({ type: 'bssid' }, asBssid);
    const asStation = stationInScope(t, scope);
    if (asStation.ok) return Object.assign({ type: 'station' }, asStation);
    return { ok: false, type: 'mac', reason: `MAC ${normalizeMac(t)} not in wifi-scope.json bssids/stations` };
  }
  if (isChannel(t)) return Object.assign({ type: 'channel' }, channelInScope(t, scope));
  return Object.assign({ type: 'essid' }, essidInScope(t, scope));
}

function scopeEmpty(scope) {
  return !(scope && (
    (Array.isArray(scope.bssids) && scope.bssids.length) ||
    (Array.isArray(scope.essids) && scope.essids.length) ||
    (Array.isArray(scope.stations) && scope.stations.length)
  ));
}

module.exports = {
  loadWifiScope, normalizeMac, isMac, isChannel,
  bssidInScope, stationInScope, essidInScope, channelInScope, inWifiScope, scopeEmpty,
};

if (require.main === module) {
  const [cmd, target] = process.argv.slice(2);
  if (cmd !== 'check' || !target) {
    console.error('usage: node wifi-guard.js check <bssid|essid|station|channel>');
    process.exit(2);
  }
  let scope;
  try {
    scope = loadWifiScope();
  } catch {
    console.log(JSON.stringify({ ok: false, reason: 'wifi-scope.json missing - nothing is authorized yet' }));
    process.exit(1);
  }
  if (scopeEmpty(scope)) {
    console.log(JSON.stringify({ ok: false, reason: 'wifi-scope.json empty - nothing is authorized yet' }));
    process.exit(1);
  }
  const res = inWifiScope(target, scope);
  console.log(JSON.stringify(res));
  process.exit(res.ok ? 0 : 1);
}
