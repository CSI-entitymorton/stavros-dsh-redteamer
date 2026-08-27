// Self-check: report-html.js enriches findings (cvss/epss/cwe), escapes user text (no markup
// injection), and renders chains + recon from state.db. Pure builder is tested without I/O.
// Run: node tools/test-report-html.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const R = require('./report-html');
const state = require('./state');

// escaping
assert.strictEqual(R.htmlEscape('<script>"x"&</script>'), '&lt;script&gt;&quot;x&quot;&amp;&lt;/script&gt;');

// enrichment: cvss from vector, epss from cve, cwe title, normalized cves
const enr = R.enrichFinding({
  severity: 'High', title: 'SQLi', host: 'h', cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  cve: 'cve-2021-44228', cwe: 'cwe-79',
});
assert.strictEqual(enr.cvss, 9.8);
assert.deepStrictEqual(enr.cves, ['CVE-2021-44228']);
assert.ok(enr.epss > 0.9, 'Log4Shell EPSS should be high');
assert.strictEqual(enr.cwe_title, 'Cross-site Scripting');

// unknown CVE/CWE -> no epss, no crash
const enr2 = R.enrichFinding({ severity: 'Low', title: 'x', host: 'h', cwe: 'CWE-99999', cves: ['CVE-9999-0000'] });
assert.strictEqual(enr2.epss, null);
assert.strictEqual(enr2.cwe_title, null);

// summary counts
const s = R.summaryTable([
  { severity: 'Critical', cvss: 9.8, epss: 0.97 },
  { severity: 'High', cvss: 7.5, epss: null },
  { severity: 'Medium', cvss: null, epss: null },
]);
assert.strictEqual(s.total, 3);
assert.strictEqual(s.counts.Critical, 1);
assert.strictEqual(s.withCvss, 2);
assert.strictEqual(s.withEpss, 1);
assert.strictEqual(s.maxEpss, 0.97);

// buildHtml: title is escaped (XSS-safe), severity + cwe + epss + chains + recon all present
const html = R.buildHtml({
  generatedAt: '2026-08-18T00:00:00.000Z',
  findings: [
    { severity: 'Critical', title: '<img src=x onerror=alert(1)>', host: 'target.com', endpoint: '/a',
      cwe: 'CWE-79', cwe_title: 'Cross-site Scripting', cvss: 9.8, epss: 0.97, cves: ['CVE-2021-44228'], status: 'verified' },
  ],
  chains: [{ host: 'target.com', chain_count: 1, chains: [{ name: 'Leaked-secret authorization bypass', reasoning: 'why', findings: ['Leak [High]', 'IDOR [High]'] }] }],
  targets: [{ target: 'target.com', hosts: [{ address: '10.0.0.5', hostname: 'srv', os: 'Linux', ports: [{ port: 22, protocol: 'tcp', service: 'ssh', version: 'OpenSSH 8.2' }] }], endpoints: [] }],
  sploitByCve: { 'CVE-2021-44228': [{ edb_id: '1', title: 'x' }] },
});
assert.ok(!html.includes('<img src=x'), 'finding title must be escaped');
assert.ok(html.includes('&lt;img src=x'));
assert.ok(html.includes('Critical'));
assert.ok(html.includes('Cross-site Scripting'));
assert.ok(html.includes('97.0%'));
assert.ok(html.includes('1 sploit'));
assert.ok(html.includes('Leaked-secret authorization bypass'));
assert.ok(html.includes('OpenSSH 8.2'));
assert.ok(html.includes('verified'));

// collectFromState reads targets/hosts/ports from a temp STATE_DB
const tmpDb = path.join(os.tmpdir(), 'stavros-report-' + process.pid + '.db');
try { fs.unlinkSync(tmpDb); } catch {}
const db = state.open(tmpDb);
const tid = state.upsertTarget(db, 'target.com');
const hid = state.upsertHost(db, tid, '10.0.0.5', { hostname: 'srv', os: 'Linux' });
state.upsertPort(db, hid, 443, 'tcp', 'https', 'nginx', 'open');
state.upsertEndpoint(db, tid, 'GET', 'https://target.com/login', {});
const targets = R.collectFromState(db);
db.close();
assert.strictEqual(targets.length, 1);
assert.strictEqual(targets[0].hosts[0].ports[0].service, 'https');
assert.strictEqual(targets[0].endpoints.length, 1);
fs.unlinkSync(tmpDb);

console.log('report-html: all tests passed');
