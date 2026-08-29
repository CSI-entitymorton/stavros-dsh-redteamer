#!/usr/bin/env node
// Pure, zero-dependency parsers that normalize third-party tool output into records
// for the deterministic pipeline (tools/stavros.js). Each function takes a string
// (one line for the JSONL tools, a whole blob for nmap/netexec) and returns a plain
// record or array — NO network I/O, NO subprocesses, NO external XML parser.
//
// Contract: malformed / empty input must NEVER throw — single-record parsers return
// null, multi-record parsers return []. This lets the pipeline skip bad lines instead
// of dying on a stray log line.
//
// ponytail: text parsers (nmap -oX via regex, netexec) rely on each tool's stable
// output shape. A tool that changes its formatting silently degrades to [] rather than
// producing wrong records — acceptable for a harness, but re-verify on tool upgrades.

// ---- tiny shared helpers ----

// Wrap a scalar or array as an array (used for nuclei info.tags / classification cve-id,
// which differ between nuclei versions).
function arr(x) {
  return Array.isArray(x) ? x : (x == null ? [] : [x]);
}

// Extract a hostname from a URL-ish string (nuclei emits http(s)://… and bare host:port).
function hostnameOf(u) {
  if (!u) return null;
  try {
    return new URL(u.includes('://') ? u : 'http://' + u).hostname || null;
  } catch {
    return null;
  }
}

// One line of `nuclei -jsonl` -> normalized finding record (or null).
//   { host, url, template_id, severity, name, tags[], cve[], matcher }
function parseNucleiJsonl(line) {
  let o;
  try {
    o = JSON.parse(String(line == null ? '' : line).trim());
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object') return null;
  if (o['template-id'] == null && o['matched-at'] == null && o.host == null) return null;
  const info = o.info || {};
  const cls = info.classification || {};
  const url = o['matched-at'] || o.host || null;
  return {
    host: hostnameOf(url),
    url,
    template_id: o['template-id'] || null,
    severity: String(info.severity || 'info').toLowerCase(),
    name: info.name || o['template-id'] || null,
    tags: arr(info.tags).map((t) => String(t)),
    cve: arr(cls['cve-id']).map((c) => String(c)),
    matcher: o['matcher-name'] || o['matcher_name'] || null,
  };
}

// One line of `httpx -json` -> normalized host/URL record (or null).
//   { url, status, title, webserver, tech[], content_type, host, input }
// `host` (resolved IP) and `input` (the queried name) are extras the pipeline uses to
// populate state.db hosts; the documented core fields stay as in the plan.
function parseHttpxJson(line) {
  let o;
  try {
    o = JSON.parse(String(line == null ? '' : line).trim());
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object') return null;
  const url = o.url || o.final_url || o.input || null;
  if (!url) return null;
  return {
    url,
    status: o.status_code != null ? Number(o.status_code) : null,
    title: o.title || null,
    webserver: o.webserver || null,
    tech: arr(o.tech).map((t) => String(t)),
    content_type: o.content_type || null,
    host: o.host || null,
    input: o.input || null,
  };
}

// One line of `ffuf -json` -> normalized hit record (or null).
//   { url, status, length, words, lines }
function parseFfufJson(line) {
  let o;
  try {
    o = JSON.parse(String(line == null ? '' : line).trim());
  } catch {
    return null;
  }
  if (!o || typeof o !== 'object') return null;
  if (o.url == null) return null;
  return {
    url: o.url,
    status: o.status != null ? Number(o.status) : null,
    // feroxbuster --json emits content_length instead of ffuf's length; accept both.
    length: o.length != null ? Number(o.length) : (o.content_length != null ? Number(o.content_length) : null),
    words: o.words != null ? Number(o.words) : null,
    lines: o.lines != null ? Number(o.lines) : null,
  };
}

// `nmap -oX -` (full XML) -> hosts[] = { address, hostname, os, ports[] = { port,
// protocol, service, version, state } }. Regex-based (no external XML parser): nmap's
// -oX structure is fixed enough for this to be stable in practice.
function parseNmapXml(xml) {
  const hosts = [];
  if (xml == null || typeof xml !== 'string') return hosts;
  const hostRe = /<host\b[^>]*>([\s\S]*?)<\/host>/g;
  let m;
  while ((m = hostRe.exec(xml))) {
    const block = m[1];
    // Prefer the IPv4 address; fall back to the first <address> of any type.
    let address = null;
    const addrRe = /<address\b([^>]*)\/>/g;
    let am;
    while ((am = addrRe.exec(block))) {
      const attrs = am[1];
      const a = (attrs.match(/\baddr="([^"]+)"/) || [])[1];
      const type = (attrs.match(/\baddrtype="([^"]+)"/) || [])[1];
      if (a == null) continue;
      if (address == null || type === 'ipv4') address = a;
      if (type === 'ipv4') break;
    }
    if (!address) continue;

    const hostname = (block.match(/<hostname\b[^>]*\bname="([^"]+)"/) || [])[1] || null;
    const os = (block.match(/<osmatch\b[^>]*\bname="([^"]+)"/) || [])[1] || null;

    const ports = [];
    const portRe = /<port\b([^>]*)>([\s\S]*?)<\/port>/g;
    let pm;
    while ((pm = portRe.exec(block))) {
      const attrs = pm[1];
      const inner = pm[2];
      const port = (attrs.match(/\bportid="(\d+)"/) || [])[1];
      if (port == null) continue;
      const protocol = (attrs.match(/\bprotocol="([^"]+)"/) || [])[1] || 'tcp';
      const serviceAttrs = (inner.match(/<service\b([^>]*)\/>/) || [])[1] || '';
      const service = (serviceAttrs.match(/\bname="([^"]+)"/) || [])[1] || null;
      const version = (serviceAttrs.match(/\bversion="([^"]+)"/) || [])[1]
        || (serviceAttrs.match(/\bproduct="([^"]+)"/) || [])[1] || null;
      const state = (inner.match(/<state\b[^>]*\bstate="([^"]+)"/) || [])[1] || 'unknown';
      ports.push({ port: Number(port), protocol, service, version, state });
    }
    hosts.push({ address, hostname: hostname || null, os, ports });
  }
  return hosts;
}

// `netexec <proto> <target>` text output -> hosts[] = { address, hostname, os, sign,
// shares[], creds[] }.
//
// ponytail: netexec/crackmapexec output is human text, not a stable machine format; the
// share/cred columns vary by module and version. This is a best-effort parse of the SMB
// layout and will silently miss exotic lines. Prefer machine-readable flags if/when the
// binary grows them.
function parseNetexec(text) {
  const byIp = new Map();
  if (text == null || typeof text !== 'string') return [];
  const lineRe = /^([A-Z][A-Z0-9_-]{1,11})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s+(.*)$/;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    const m = line.match(lineRe);
    if (!m) continue;
    const [, proto, ip, port, hostname, rest] = m;
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) continue;
    let h = byIp.get(ip);
    if (!h) {
      h = { address: ip, hostname: null, os: null, sign: null, shares: [], creds: [] };
      byIp.set(ip, h);
    }
    // The 4th column is the NETBIOS/FQDN hostname; status markers ([*]/[+]/[-]) are not.
    if (hostname && !hostname.startsWith('[') && h.hostname == null) h.hostname = hostname;
    // OS from the "[*] Windows ... Build ..." banner (or a plain Linux/Unix token).
    const osM = rest.match(/Windows[\d. ]*(?:Build\s*\d+)?/i) || rest.match(/Linux/i) || rest.match(/Unix/i);
    if (osM && h.os == null) h.os = osM[0].trim();
    const signM = rest.match(/signing\s*:\s*(True|False)/i);
    if (signM && h.sign == null) h.sign = signM[1].toLowerCase() === 'true';
    // Credentials appear on [+] lines: "[+] DOMAIN\user:password".
    if (rest.trim().startsWith('[+]')) {
      const credM = rest.match(/(?:[A-Za-z0-9_.-]+\\)?[^\s:]+:[^\s]+/);
      if (credM && !h.creds.includes(credM[0])) h.creds.push(credM[0]);
    }
    // Share table rows: the 5th column is a bare share name (ADMIN$, C$, IPC$, Users…).
    const rt = rest.trim();
    if (rt && !rt.startsWith('[') && !/^(Share|----|=)/.test(rt)) {
      const tok = rt.split(/\s+/)[0];
      if (tok && !tok.includes(':') && /^[A-Za-z0-9_.$-]+$/.test(tok) && tok !== proto) {
        if (!h.shares.includes(tok)) h.shares.push(tok);
      }
    }
  }
  return [...byIp.values()];
}

// `h8mail -j <file>` (whole JSON document) -> records[] = { target, domain, pwn_num,
// sources[] = { source, fields } } (or []). h8mail's data is an array of groups, each
// starting with a "SOURCE:<name>" entry followed by "FIELD:value" pairs.
function parseH8mailJson(text) {
  let o;
  try {
    o = JSON.parse(String(text == null ? '' : text).trim());
  } catch {
    return [];
  }
  if (!o || !Array.isArray(o.targets)) return [];
  const out = [];
  for (const t of o.targets) {
    if (!t || typeof t !== 'object' || !t.target) continue;
    const sources = [];
    for (const group of Array.isArray(t.data) ? t.data : []) {
      if (!Array.isArray(group)) continue;
      let source = null;
      const fields = {};
      for (const item of group) {
        const s = String(item == null ? '' : item);
        if (s.toUpperCase().startsWith('SOURCE:')) {
          source = s.slice(7).trim();
          continue;
        }
        const idx = s.indexOf(':');
        if (idx > 0) fields[s.slice(0, idx).trim()] = s.slice(idx + 1).trim();
      }
      sources.push({ source: source || 'unknown', fields });
    }
    const domM = String(t.target).match(/@([A-Z0-9.-]+\.[A-Z]{2,})$/i);
    out.push({
      target: t.target,
      domain: domM ? domM[1].toLowerCase() : null,
      pwn_num: Number(t.pwn_num) || 0,
      sources,
    });
  }
  return out;
}

// ---- breadth parsers (Ondata 6): TLS, tech/WAF, crawl, dir-bust, SMB enum ----
// Same contract as above: malformed/empty input never throws; list parsers return [].

// Shared helper: several tools ship a whole JSON array, a whole object, or NDJSON depending
// on version/flags — accept all three shapes deterministically.
function jsonListOrNdjson(text) {
  const t = String(text == null ? '' : text).trim();
  if (!t) return [];
  try {
    const o = JSON.parse(t);
    if (Array.isArray(o)) return o.filter((x) => x && typeof x === 'object' && !Array.isArray(x));
    if (o && typeof o === 'object') return [o];
    return [];
  } catch { /* fall through to NDJSON */ }
  const out = [];
  for (const line of t.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const o = JSON.parse(line);
      if (o && typeof o === 'object' && !Array.isArray(o)) out.push(o);
    } catch { /* skip bad line */ }
  }
  return out;
}

// `testssl.sh --jsonfile out.json` (or --json stdout) → records[] =
//   { host, port, id, severity, finding, cve }. Severity map: CRITICAL/HIGH/MEDIUM/LOW kept,
//   everything else (OK/INFO/DEBUG/warn) → 'info' (upstream decides what is finding-worthy).
function parseTestsslJson(text) {
  const out = [];
  for (const o of jsonListOrNdjson(text)) {
    if (o.id == null) continue;
    const sev = String(o.severity || 'info').toUpperCase();
    const severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev) ? sev.toLowerCase() : 'info';
    const target = typeof o.target === 'string' && o.target.trim() ? o.target.trim() : null;
    out.push({
      host: hostnameOf(target) || (target ? String(target).split(':')[0] : null),
      port: o.port != null && /^\d+$/.test(String(o.port)) ? Number(o.port) : null,
      id: String(o.id),
      severity,
      finding: o.finding != null ? String(o.finding).slice(0, 300) : null,
      cve: o.cve != null && String(o.cve).trim() ? String(o.cve).trim() : null,
    });
  }
  return out;
}

// `whatweb --log-json=-` → records[] = { target, status, tech: [{ name, version }] }.
// plugins is a map name → { version: [...], string: [...], certainty: N }; WAF/tech vendors
// (CloudFlare, ModSecurity, …) land here and feed the planner's rate-reduction rule.
function parseWhatwebJson(text) {
  const out = [];
  for (const o of jsonListOrNdjson(text)) {
    if (typeof o.target !== 'string' || !o.target.trim()) continue;
    const plugins = o.plugins && typeof o.plugins === 'object' && !Array.isArray(o.plugins) ? o.plugins : {};
    const tech = [];
    for (const [name, p] of Object.entries(plugins)) {
      let version = null;
      if (p && typeof p === 'object') {
        const v = Array.isArray(p.version) ? p.version[0] : p.version;
        version = v != null && String(v).trim() !== '' ? String(v) : null;
      }
      tech.push({ name: String(name), version });
    }
    out.push({ target: o.target, status: o.http_status != null ? Number(o.http_status) : null, tech });
  }
  return out;
}

// `katana -jsonl` (projectdiscovery crawler) → records[] = { method, url, status }.
function parseKatanaJsonl(text) {
  const out = [];
  for (const o of jsonListOrNdjson(text)) {
    const req = o.request && typeof o.request === 'object' ? o.request : {};
    const resp = o.response && typeof o.response === 'object' ? o.response : {};
    const url = typeof req.endpoint === 'string' && req.endpoint.trim() ? req.endpoint.trim() : null;
    if (!url) continue;
    out.push({
      method: typeof req.method === 'string' && req.method ? req.method.toUpperCase() : 'GET',
      url,
      status: resp.status_code != null ? Number(resp.status_code) : null,
    });
  }
  return out;
}

// `dirsearch -o report.json --format json` → records[] = { url, status, length }.
function parseDirsearchJson(text) {
  const out = [];
  for (const o of jsonListOrNdjson(text)) {
    const results = Array.isArray(o.results) ? o.results : [o];
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      const url = typeof r.url === 'string' && r.url.trim()
        ? r.url.trim()
        : (typeof r.target === 'string' && typeof r.path === 'string'
          ? r.target.replace(/\/+$/, '') + (r.path.startsWith('/') ? r.path : '/' + r.path)
          : null);
      if (!url) continue;
      out.push({
        url,
        status: r.status != null ? Number(r.status) : null,
        length: r['content-length'] != null ? Number(r['content-length']) : null,
      });
    }
  }
  return out;
}

// `enum4linux-ng -oJ out.json` → [ { host, os, workgroup, users[], shares[] } ] (single record
// or []). users → {username}; shares → {name, type, comment, access}. Feeds the asset graph's
// accounts/shares tables so the authenticated pass starts from what is actually enumerated.
function parseEnum4linuxNgJson(text) {
  const objs = jsonListOrNdjson(text);
  const o = objs.length === 1 ? objs[0] : null;
  if (!o || typeof o.target !== 'string' || !o.target.trim()) return [];
  const users = (Array.isArray(o.users) ? o.users : [])
    .map((u) => (u && typeof u.username === 'string' && u.username.trim() ? { username: u.username.trim() } : null))
    .filter(Boolean);
  const shares = (Array.isArray(o.shares) ? o.shares : [])
    .map((s) => (s && typeof s.name === 'string' && s.name.trim() ? {
      name: s.name.trim(),
      type: s.type != null ? String(s.type) : null,
      comment: s.comment != null ? String(s.comment).slice(0, 200) : null,
      access: s.ops4_status != null ? String(s.ops4_status) : null,
    } : null))
    .filter(Boolean);
  const os = o.smb && typeof o.smb === 'object' && o.smb.native_os ? String(o.smb.native_os) : null;
  const workgroup = typeof o.workgroup === 'string' && o.workgroup.trim() ? o.workgroup.trim() : null;
  return [{ host: o.target.trim(), os, workgroup, users, shares }];
}

module.exports = {
  parseNucleiJsonl,
  parseHttpxJson,
  parseNmapXml,
  parseFfufJson,
  parseNetexec,
  parseH8mailJson,
  parseTestsslJson,
  parseWhatwebJson,
  parseKatanaJsonl,
  parseDirsearchJson,
  parseEnum4linuxNgJson,
};
