// Offline self-check for the wireless runner (wifi.js). No network, no wireless NIC, no real
// binaries: a fake runWifi / runBinary returns canned output, and we assert scope + tier logic,
// command assembly and the airodump CSV parser. Run: node tools/test-wifi.js
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const wifi = require('./wifi');

const BSSID = 'AA:BB:CC:DD:EE:FF';
const BSSID_L = 'aa:bb:cc:dd:ee:ff';

// ---- target extraction ----
assert.deepStrictEqual(
  wifi.extractTargets(['-a', BSSID, 'wlan0mon']),
  { bssids: [BSSID_L], essids: [], channels: [] },
  'bssid extracted from -a flag'
);
assert.deepStrictEqual(
  wifi.extractTargets(['--bssid', 'aa-bb-cc-dd-ee-ff']),
  { bssids: [BSSID_L], essids: [], channels: [] },
  'bssid normalized from dash form'
);
assert.deepStrictEqual(
  wifi.extractTargets(['-e', 'MyLabWiFi', '--channel', '6']),
  { bssids: [], essids: ['MyLabWiFi'], channels: [6] },
  'essid + channel extracted'
);
assert.deepStrictEqual(
  wifi.extractTargets(['wlan0mon']),
  { bssids: [], essids: [], channels: [] },
  'iface-only yields no targets'
);

// ---- classification (bin + args -> action class / tier) ----
const scope = {
  bssids: [BSSID],
  essids: ['MyLabWiFi'],
  stations: ['11:22:33:44:55:66'],
  channels: [1, 6, 11],
  max_requests_per_second: 1000,
};
assert.deepStrictEqual(wifi.classify('airodump-ng', ['wlan0mon'], scope), { actionClass: 'scan', tier: 'auto' }, 'passive scan = auto');
assert.deepStrictEqual(wifi.classify('aircrack-ng', ['cap.cap', '-w', 'rockyou.txt'], scope), { actionClass: 'crack', tier: 'auto' }, 'offline crack = auto');
assert.deepStrictEqual(wifi.classify('aireplay-ng', ['-0', '3', '-a', BSSID, 'wlan0mon'], scope), { actionClass: 'deauth', tier: 'confirm' }, 'deauth = confirm');
assert.deepStrictEqual(wifi.classify('reaver', ['-i', 'wlan0mon', '-b', BSSID], scope), { actionClass: 'wps', tier: 'confirm' }, 'wps = confirm');
assert.deepStrictEqual(wifi.classify('wifite', [], scope), { actionClass: 'automated', tier: 'confirm' }, 'wifite = confirm');
assert.deepStrictEqual(wifi.classify('hcxdumptool', ['-i', 'wlan0mon'], scope), { actionClass: 'capture', tier: 'confirm' }, 'hcxdumptool = confirm');
assert.deepStrictEqual(wifi.classify('unknown-bin', [], scope), { actionClass: 'unknown', tier: 'confirm' }, 'unknown = confirm (fail closed)');

// ---- command assembly (pure) ----
const scanCmds = wifi.scanCommands('wlan0');
assert.deepStrictEqual(scanCmds[0].bin, 'airmon-ng');
assert.deepStrictEqual(scanCmds[1].bin, 'airodump-ng');
assert.ok(scanCmds[1].args.includes('wlan0mon'), 'monitor iface = <iface>mon');

const capDeauth = wifi.captureCommands(BSSID, { channel: 6 });
assert.strictEqual(capDeauth[0].bin, 'airodump-ng');
assert.strictEqual(capDeauth[1].bin, 'aireplay-ng', 'handshake capture adds deauth');
assert.ok(capDeauth[1].args.includes('-0'), 'deauth uses -0');

const capPmkid = wifi.captureCommands(BSSID, { channel: 6, pmkid: true });
assert.strictEqual(capPmkid.length, 1, 'pmkid capture is a single tool');
assert.strictEqual(capPmkid[0].bin, 'hcxdumptool');

const crackCmd = wifi.crackCommands('cap.cap', {});
assert.strictEqual(crackCmd[0].bin, 'aircrack-ng');
assert.ok(crackCmd[0].args.includes('cap.cap'));

const wpsCmd = wifi.wpsCommands(BSSID, { channel: 6 });
assert.strictEqual(wpsCmd[0].bin, 'reaver');

// ---- airodump CSV parser ----
const CSV = [
  'BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key',
  BSSID + ', 2026-08-18 10:00:00, 2026-08-18 10:05:00, 6, 130, WPA2, CCMP, PSK, -45, 100, 0, 0.0.0.0, 8, MyLabWiFi,',
  '11:22:33:44:55:66, 2026-08-18 10:00:00, 2026-08-18 10:05:00, 11, 54, OPN, , OPN, -70, 20, 0, 0.0.0.0, 7, OpenNet,',
  '',
  'Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs',
  '99:88:77:66:55:44, 2026-08-18 10:00:00, 2026-08-18 10:05:00, -50, 12, ' + BSSID + ', MyLabWiFi',
].join('\n');
const aps = wifi.parseAirodumpCsv(CSV);
assert.strictEqual(aps.length, 2, 'two APs parsed');
assert.deepStrictEqual(aps[0], { bssid: BSSID_L, channel: 6, privacy: 'WPA2', cipher: 'CCMP', auth: 'PSK', essid: 'MyLabWiFi' }, 'AP record normalized');
assert.deepStrictEqual(aps[1].bssid, '11:22:33:44:55:66', 'second AP bssid');
assert.strictEqual(aps[1].privacy, 'OPN', 'open network');
assert.deepStrictEqual(wifi.parseAirodumpCsv('garbage\nnope'), [], 'malformed -> []');
assert.deepStrictEqual(wifi.parseAirodumpCsv(null), [], 'null -> []');

// ---- AP store (appendAps dedups, env override) ----
const tmpDir = path.join(os.tmpdir(), 'wifi-test-' + process.pid);
fs.mkdirSync(tmpDir, { recursive: true });
process.env.WIFI_APS_JSONL = path.join(tmpDir, 'wifi-aps.jsonl');
assert.strictEqual(wifi.appendAps(aps), 2, 'two APs appended');
assert.strictEqual(wifi.appendAps([aps[0]]), 0, 'duplicate AP not appended');
assert.strictEqual(wifi.status().aps, 2, 'status reports two APs');
delete process.env.WIFI_APS_JSONL;

// ---- defaultRunWifi: fail-closed (scope + tier), injectable exec ----
const scopeFile = path.join(tmpDir, 'wifi-scope.json');
fs.writeFileSync(scopeFile, JSON.stringify(scope));
process.env.WIFI_SCOPE_JSON = scopeFile;
const fakeExec = () => ({ status: 0, stdout: '', stderr: '' });

(async () => {
  // confirm-tier without --confirm -> rejected
  await assert.rejects(
    wifi.defaultRunWifi('aireplay-ng', ['-0', '3', '-a', BSSID, 'wlan0mon'], { runBinary: fakeExec }),
    /confirm-tier/
  );
  // out-of-scope bssid -> rejected (even for an auto-tier scan bin)
  await assert.rejects(
    wifi.defaultRunWifi('airodump-ng', ['--bssid', '66:55:44:33:22:11', 'wlan0mon'], { runBinary: fakeExec }),
    /out-of-scope/
  );
  // offline crack (no live target, auto tier) is allowed — it works on a capture file
  const crackOk = await wifi.defaultRunWifi('aircrack-ng', ['cap.cap', '-w', 'rockyou.txt'], { runBinary: fakeExec });
  assert.strictEqual(crackOk.status, 0, 'offline crack runs without a live target');
  // confirm-tier bin with a confirm flag but no target -> fail closed
  await assert.rejects(
    wifi.defaultRunWifi('reaver', ['-i', 'wlan0mon'], { runBinary: fakeExec, confirm: 'lab' }),
    /no in-scope wireless target/
  );
  // confirm-tier bin without --confirm -> rejected at the tier gate (before any target check)
  await assert.rejects(
    wifi.defaultRunWifi('wifite', [], { runBinary: fakeExec }),
    /confirm-tier/
  );
  // passive scan (no target, auto tier) is allowed
  const scanOk = await wifi.defaultRunWifi('airodump-ng', ['wlan0mon'], { runBinary: fakeExec });
  assert.strictEqual(scanOk.status, 0, 'passive scan runs');
  // confirm-tier WITH --confirm + in-scope target runs
  const deauthOk = await wifi.defaultRunWifi('aireplay-ng', ['-0', '3', '-a', BSSID, 'wlan0mon'], { runBinary: fakeExec, confirm: 'authorized lab AP' });
  assert.strictEqual(deauthOk.status, 0, 'confirmed deauth runs');
  delete process.env.WIFI_SCOPE_JSON;

  // ---- subcommands with a fake runWifi (command assembly, no real exec) ----
  process.env.WIFI_APS_JSONL = path.join(tmpDir, 'wifi-aps.jsonl');
  const fakeRunWifi = async (bin, args, opts) => ({ status: 0, stdout: '', stderr: '' });
  const sc = await wifi.scan('wlan0', { runWifi: fakeRunWifi, csvText: CSV });
  assert.strictEqual(sc.results.length, 2, 'scan runs airmon-ng + airodump-ng');
  const cap = await wifi.capture(BSSID, { runWifi: fakeRunWifi, channel: 6, confirm: 'lab' });
  assert.strictEqual(cap.results.length, 2, 'capture runs dump + deauth');
  assert.strictEqual(cap.bssid, BSSID_L, 'capture normalizes bssid');
  const ck = await wifi.crack('cap.cap', { runWifi: fakeRunWifi });
  assert.strictEqual(ck.status, 0, 'crack runs');
  const wp = await wifi.wps(BSSID, { runWifi: fakeRunWifi, channel: 6, confirm: 'lab' });
  assert.strictEqual(wp.status, 0, 'wps runs');

  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log('wifi: all tests passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
