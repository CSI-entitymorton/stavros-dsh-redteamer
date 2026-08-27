// Offline self-check for the pure output parsers (nuclei/httpx/nmap/ffuf/netexec).
// Run: node tools/test-parsers.js
// Covers happy paths AND malformed input: no parser may throw on garbage.
const assert = require('assert');
const p = require('./parsers');

// ---- nuclei -jsonl ----
const nuclei = p.parseNucleiJsonl(JSON.stringify({
  'template-id': 'http-cves/2021/CVE-2021-44228',
  'matched-at': 'https://app.example.com/login',
  host: 'https://app.example.com',
  info: {
    name: 'Apache Log4j RCE',
    severity: 'critical',
    tags: ['cve', 'rce', 'log4j'],
    classification: { 'cve-id': ['CVE-2021-44228'], 'cwe-id': ['CWE-502'] },
  },
  'matcher-name': 'log4shell-header',
}));
assert.strictEqual(nuclei.host, 'app.example.com');
assert.strictEqual(nuclei.url, 'https://app.example.com/login');
assert.strictEqual(nuclei.template_id, 'http-cves/2021/CVE-2021-44228');
assert.strictEqual(nuclei.severity, 'critical');
assert.strictEqual(nuclei.name, 'Apache Log4j RCE');
assert.deepStrictEqual(nuclei.tags, ['cve', 'rce', 'log4j']);
assert.deepStrictEqual(nuclei.cve, ['CVE-2021-44228']);
assert.strictEqual(nuclei.matcher, 'log4shell-header');

// nuclei: cve-id as a scalar (older nuclei) and missing fields still normalize
const nuclei2 = p.parseNucleiJsonl(JSON.stringify({
  'template-id': 'tpl', host: 'http://x.example.com',
  info: { classification: { 'cve-id': 'CVE-1' } },
}));
assert.deepStrictEqual(nuclei2.cve, ['CVE-1']);
assert.deepStrictEqual(nuclei2.tags, []);
assert.strictEqual(nuclei2.severity, 'info');

// ---- httpx -json ----
const httpx = p.parseHttpxJson(JSON.stringify({
  url: 'https://app.example.com/', input: 'app.example.com',
  status_code: 200, title: 'Dashboard', webserver: 'nginx/1.25',
  tech: ['nginx', 'express'], content_type: 'text/html', host: '10.0.0.5',
}));
assert.strictEqual(httpx.url, 'https://app.example.com/');
assert.strictEqual(httpx.status, 200);
assert.strictEqual(httpx.title, 'Dashboard');
assert.strictEqual(httpx.webserver, 'nginx/1.25');
assert.deepStrictEqual(httpx.tech, ['nginx', 'express']);
assert.strictEqual(httpx.content_type, 'text/html');
assert.strictEqual(httpx.host, '10.0.0.5');
assert.strictEqual(httpx.input, 'app.example.com');

// ---- ffuf -json ----
const ffuf = p.parseFfufJson(JSON.stringify({
  input: { FUZZ: 'admin' }, status: 301, length: 342, words: 20, lines: 12,
  url: 'https://app.example.com/admin',
}));
assert.strictEqual(ffuf.url, 'https://app.example.com/admin');
assert.strictEqual(ffuf.status, 301);
assert.strictEqual(ffuf.length, 342);
assert.strictEqual(ffuf.words, 20);
assert.strictEqual(ffuf.lines, 12);

// ---- nmap -oX - ----
const nmap = p.parseNmapXml(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sC -sV -oX -">
  <host><status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="app.example.com" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.15" accuracy="98"/></os>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port>
      <port protocol="tcp" portid="8080"><state state="filtered"/></port>
    </ports>
  </host>
  <host><status state="down"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>`);
assert.strictEqual(nmap.length, 2, 'both hosts parsed: ' + JSON.stringify(nmap));
const h0 = nmap[0];
assert.strictEqual(h0.address, '10.0.0.5');
assert.strictEqual(h0.hostname, 'app.example.com');
assert.strictEqual(h0.os, 'Linux 5.15');
assert.strictEqual(h0.ports.length, 3);
assert.deepStrictEqual(h0.ports[0], { port: 22, protocol: 'tcp', service: 'ssh', version: '8.9', state: 'open' });
assert.strictEqual(h0.ports[2].port, 8080);
assert.strictEqual(h0.ports[2].state, 'filtered');
assert.strictEqual(nmap[1].ports.length, 0, 'down host has no ports');

// ---- netexec (text, ponytail) ----
const nxc = p.parseNetexec(`
SMB         10.0.0.5     445    DC01              [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB         10.0.0.5     445    DC01              [+] corp.local\\admin:P@ssw0rd
SMB         10.0.0.5     445    DC01              Share           Permissions     Remark
SMB         10.0.0.5     445    DC01              -----           -----------     ------
SMB         10.0.0.5     445    DC01              ADMIN$          READ,WRITE
SMB         10.0.0.5     445    DC01              C$              NO ACCESS
SMB         10.0.0.5     445    DC01              IPC$            READ
`);
assert.strictEqual(nxc.length, 1);
const nx = nxc[0];
assert.strictEqual(nx.address, '10.0.0.5');
assert.strictEqual(nx.hostname, 'DC01');
assert.ok(nx.os.startsWith('Windows 10.0'), 'os banner: ' + nx.os);
assert.strictEqual(nx.sign, true);
assert.ok(nx.creds.includes('corp.local\\admin:P@ssw0rd'), 'creds: ' + JSON.stringify(nx.creds));
assert.ok(nx.shares.includes('ADMIN$') && nx.shares.includes('C$') && nx.shares.includes('IPC$'),
  'shares: ' + JSON.stringify(nx.shares));

// ---- h8mail -j (whole JSON document) ----
const h8 = p.parseH8mailJson(JSON.stringify({
  targets: [
    { target: 'admin@example.com', pwn_num: 2, data: [
      ['SOURCE:collection1', 'password:P@ss', 'username:admin'],
      ['SOURCE:snusbase', 'hash:5f4dcc3b5aa765d61d8327deb882cf99'],
    ] },
    { target: 'plain-username', pwn_num: 0, data: [] },
  ],
}));
assert.strictEqual(h8.length, 2);
assert.strictEqual(h8[0].target, 'admin@example.com');
assert.strictEqual(h8[0].domain, 'example.com');
assert.strictEqual(h8[0].pwn_num, 2);
assert.strictEqual(h8[0].sources.length, 2);
assert.strictEqual(h8[0].sources[0].source, 'collection1');
assert.strictEqual(h8[0].sources[0].fields.password, 'P@ss');
assert.strictEqual(h8[0].sources[0].fields.username, 'admin');
assert.strictEqual(h8[0].sources[1].fields.hash, '5f4dcc3b5aa765d61d8327deb882cf99');
assert.strictEqual(h8[1].domain, null, 'no email -> no domain');
assert.deepStrictEqual(p.parseH8mailJson(''), []);
assert.deepStrictEqual(p.parseH8mailJson('not json'), []);
assert.deepStrictEqual(p.parseH8mailJson('{"targets":[]}'), []);
assert.deepStrictEqual(p.parseH8mailJson('{"nope":1}'), []);
assert.deepStrictEqual(p.parseH8mailJson(null), []);

// ---- malformed input never throws, returns null/[] ----
assert.strictEqual(p.parseNucleiJsonl(''), null);
assert.strictEqual(p.parseNucleiJsonl('not json {'), null);
assert.strictEqual(p.parseNucleiJsonl('{"foo":1}'), null, 'no template/host -> null');
assert.strictEqual(p.parseHttpxJson('garbage'), null);
assert.strictEqual(p.parseHttpxJson('{"status_code":200}'), null, 'no url -> null');
assert.strictEqual(p.parseFfufJson('{'), null);
assert.strictEqual(p.parseFfufJson('{"status":200}'), null, 'no url -> null');
assert.deepStrictEqual(p.parseNmapXml(''), []);
assert.deepStrictEqual(p.parseNmapXml('not xml at all'), []);
assert.deepStrictEqual(p.parseNmapXml(null), []);
assert.deepStrictEqual(p.parseNetexec(''), []);
assert.deepStrictEqual(p.parseNetexec('random line with 1.2.3.4 445 hostname rest but no proto'), []);
assert.deepStrictEqual(p.parseNetexec(null), []);

console.log('parsers: all tests passed');
