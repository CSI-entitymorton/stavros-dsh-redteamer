// Offline self-check for the wireless scope guard (wifi-guard.js). Pure unit test on the
// BSSID/ESSID/station/channel model — no network, no hardware, no subprocess.
// Run: node tools/test-wifi-guard.js
const assert = require('assert');
const wg = require('./wifi-guard');

// ---- MAC normalization ----
assert.strictEqual(wg.normalizeMac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff', 'colon lowercased');
assert.strictEqual(wg.normalizeMac('aa-bb-cc-dd-ee-ff'), 'aa:bb:cc:dd:ee:ff', 'dash separators');
assert.strictEqual(wg.normalizeMac('AABBCCDDEEFF'), 'aa:bb:cc:dd:ee:ff', 'bare 12-hex');
assert.strictEqual(wg.normalizeMac('zz:bb:cc:dd:ee:ff'), null, 'non-hex rejected');
assert.strictEqual(wg.normalizeMac('aa:bb:cc:dd:ee'), null, 'too short rejected');
assert.strictEqual(wg.normalizeMac(''), null, 'empty rejected');
assert.strictEqual(wg.normalizeMac(null), null, 'null rejected');

// ---- channel detection ----
assert.ok(wg.isChannel('6'), 'channel 6');
assert.ok(wg.isChannel(11), 'channel 11 as number');
assert.ok(!wg.isChannel('0'), 'channel 0 rejected');
assert.ok(!wg.isChannel('999'), 'channel 999 rejected');
assert.ok(!wg.isChannel('abc'), 'non-numeric rejected');

// ---- a representative scope ----
const scope = {
  bssids: ['AA:BB:CC:DD:EE:FF'],
  essids: ['MyLabWiFi'],
  stations: ['11:22:33:44:55:66'],
  channels: [1, 6, 11],
};

// ---- per-type checks ----
assert.deepStrictEqual(wg.bssidInScope('aa:bb:cc:dd:ee:ff', scope), { ok: true, reason: 'BSSID allowlisted' }, 'bssid in scope (normalized)');
assert.strictEqual(wg.bssidInScope('66:55:44:33:22:11', scope).ok, false, 'unknown bssid out of scope');
assert.strictEqual(wg.bssidInScope('not-a-mac', scope).ok, false, 'invalid bssid rejected');

assert.deepStrictEqual(wg.stationInScope('11-22-33-44-55-66', scope), { ok: true, reason: 'station allowlisted' }, 'station in scope');
assert.strictEqual(wg.stationInScope('aa:bb:cc:dd:ee:ff', scope).ok, false, 'bssid not a station');

assert.deepStrictEqual(wg.essidInScope('MyLabWiFi', scope), { ok: true, reason: 'ESSID allowlisted' }, 'essid in scope');
assert.strictEqual(wg.essidInScope('MyLabWiFi ', scope).ok, false, 'essid is exact (no trim fallback)');
assert.strictEqual(wg.essidInScope('mylabwifi', scope).ok, false, 'essid case-sensitive');
assert.strictEqual(wg.essidInScope('', scope).ok, false, 'empty essid rejected');

assert.deepStrictEqual(wg.channelInScope(6, scope), { ok: true, reason: 'channel allowlisted' }, 'channel in scope');
assert.strictEqual(wg.channelInScope(3, scope).ok, false, 'channel out of scope');

// ---- auto-detect ----
assert.strictEqual(wg.inWifiScope('aa:bb:cc:dd:ee:ff', scope).type, 'bssid', 'MAC detected as bssid');
assert.strictEqual(wg.inWifiScope('11:22:33:44:55:66', scope).type, 'station', 'MAC detected as station (station-only)');
assert.strictEqual(wg.inWifiScope('6', scope).type, 'channel', 'digit detected as channel');
assert.strictEqual(wg.inWifiScope('MyLabWiFi', scope).type, 'essid', 'name detected as essid');
assert.strictEqual(wg.inWifiScope('OtherWiFi', scope).ok, false, 'unknown essid out of scope');
assert.strictEqual(wg.inWifiScope('66:55:44:33:22:11', scope).ok, false, 'unknown MAC out of scope');

// ---- fail-closed empty scope ----
assert.ok(wg.scopeEmpty({}), 'empty object = empty scope');
assert.ok(wg.scopeEmpty({ bssids: [], essids: [], stations: [] }), 'empty arrays = empty scope');
assert.ok(!wg.scopeEmpty(scope), 'populated scope is not empty');

// ---- loadWifiScope honors env override ----
const fs = require('fs');
const os = require('os');
const path = require('path');
const tmpDir = path.join(os.tmpdir(), 'wifi-guard-test-' + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });
const scopeFile = path.join(tmpDir, 'wifi-scope.json');
fs.writeFileSync(scopeFile, JSON.stringify(scope));
process.env.WIFI_SCOPE_JSON = scopeFile;
const loaded = wg.loadWifiScope();
assert.deepStrictEqual(loaded.bssids, scope.bssids, 'env override loaded');
delete process.env.WIFI_SCOPE_JSON;
fs.rmSync(tmpDir, { recursive: true, force: true });

console.log('wifi-guard: all tests passed');
