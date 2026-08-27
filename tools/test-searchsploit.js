// Self-check: searchsploit.js normalizes exploit-db --json output, survives malformed input,
// and only executes searchsploit via the injectable runner.
// Run: node tools/test-searchsploit.js
const assert = require('assert');
const { spawnSync } = require('child_process');
const S = require('./searchsploit');

const SAMPLE = JSON.stringify({
  SEARCH: 'CVE-2017-0144',
  DB_PATH_EXPLOIT: '/usr/share/exploitdb',
  RESULTS_EXPLOIT: [
    {
      Title: 'DOUBLEPULSAR - Payload Execution and Neutralization (Metasploit)',
      'EDB-ID': '47456', Date_Published: '2019-10-02', Author: 'Metasploit',
      Type: 'remote', Platform: 'windows', Port: '', Verified: '1',
      Codes: 'CVE-2017-0148;CVE-2017-0144;MS17-010', Tags: 'Remote',
      Path: '/usr/share/exploitdb/exploits/windows/remote/47456.rb',
      Source: 'https://example.com/47456.rb',
    },
  ],
  RESULTS_SHELLCODE: [],
});

// pure parser
const parsed = S.parseSearchsploit(SAMPLE);
assert.strictEqual(parsed.term, 'CVE-2017-0144');
assert.strictEqual(parsed.exploits.length, 1);
assert.strictEqual(parsed.exploits[0].edb_id, '47456');
assert.strictEqual(parsed.exploits[0].verified, true);
assert.deepStrictEqual(parsed.exploits[0].cves, ['CVE-2017-0148', 'CVE-2017-0144']);
assert.deepStrictEqual(parsed.exploits[0].codes, ['MS17-010']);

// malformed input -> empty, no throw
const bad = S.parseSearchsploit('not json at all');
assert.strictEqual(bad.exploits.length, 0);
assert.strictEqual(bad.shellcode.length, 0);
assert.strictEqual(S.parseSearchsploit('').term, null);

// normalizeEntry handles empty / missing Codes
const ne = S.normalizeEntry({ Title: 'x', 'EDB-ID': '1', Codes: '' });
assert.deepStrictEqual(ne.cves, []);
assert.deepStrictEqual(ne.codes, []);

// lookup via injectable exec (no real binary needed)
const fakeExec = (term) => ({ stdout: SAMPLE, status: 0 });
const res = S.lookup('CVE-2017-0144', { exec: fakeExec });
assert.strictEqual(res.ok, true);
assert.strictEqual(res.count, 1);
assert.strictEqual(S.lookup('CVE-2017-0144', { exec: () => ({ stdout: '', status: 1 }) }).ok, false);
assert.strictEqual(S.lookup('', { exec: fakeExec }).ok, false);

// e2e (guarded): only if the real searchsploit binary is installed (Kali).
// (--help/--version exit 2 on searchsploit, so probe with a real --json query instead.)
if (spawnSync('searchsploit', ['--json', 'zz-no-such-term'], { stdio: 'ignore', timeout: 30000 }).status === 0) {
  const real = S.lookup('CVE-2017-0144');
  assert.strictEqual(real.ok, true);
  assert.ok(real.exploits.length >= 1, 'CVE-2017-0144 should have exploit-db entries');
  assert.ok(real.exploits.some((e) => e.cves.includes('CVE-2017-0144')));
} else {
  console.log('searchsploit: binary not installed — e2e check skipped');
}

console.log('searchsploit: all tests passed');
