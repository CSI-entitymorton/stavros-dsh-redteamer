#!/usr/bin/env node
// Offline enrichment lookups for the reporter: EPSS (Exploit Prediction Scoring System)
// scores for high-value CVEs and human-readable CWE titles. Zero-dependency, deterministic.
//   node tools/epss.js CVE-2021-44228     -> { cve, epss, percentile, source: 'embedded' }
//   node tools/epss.js --cwe CWE-79       -> { cwe, title, description }
//
// ponytail: EPSS_MAP is a TINY embedded snapshot of well-known CVEs with APPROXIMATE scores,
// for offline enrichment only — it is not the authoritative daily EPSS feed (which changes
// daily and is far too large to embed). Live upgrade (implemented): tools/threatintel.js
// refreshes NVD API v2 + CISA KEV + the official FIRST EPSS API into reports/cache/ and
// lookupBestEpss()/lookupMaxBestEpss() prefer those cached-live scores over this map.
// Treat a missing lookup as "unknown", never as "0.0".

// EPSS scores (0..1) + percentile (0..1) — approximate snapshot, guidance only.
const EPSS_MAP = {
  'CVE-2017-0144': { epss: 0.9754, percentile: 0.9999 }, // MS17-010 / EternalBlue
  'CVE-2017-0143': { epss: 0.9754, percentile: 0.9999 },
  'CVE-2017-5638': { epss: 0.9748, percentile: 0.9999 }, // Apache Struts2
  'CVE-2019-0708': { epss: 0.9738, percentile: 0.9998 }, // BlueKeep
  'CVE-2019-11510': { epss: 0.9724, percentile: 0.9998 }, // Pulse Secure
  'CVE-2019-19781': { epss: 0.9720, percentile: 0.9998 }, // Citrix ADC
  'CVE-2020-0796': { epss: 0.9604, percentile: 0.9995 }, // SMBGhost
  'CVE-2020-1472': { epss: 0.9689, percentile: 0.9997 }, // ZeroLogon
  'CVE-2020-5902': { epss: 0.9700, percentile: 0.9997 }, // F5 BIG-IP
  'CVE-2021-21972': { epss: 0.9671, percentile: 0.9997 }, // vCenter
  'CVE-2021-26084': { epss: 0.9677, percentile: 0.9997 }, // Confluence OGNL
  'CVE-2021-26855': { epss: 0.9705, percentile: 0.9997 }, // ProxyLogon
  'CVE-2021-26857': { epss: 0.9705, percentile: 0.9997 },
  'CVE-2021-26858': { epss: 0.9705, percentile: 0.9997 },
  'CVE-2021-34527': { epss: 0.9660, percentile: 0.9996 }, // PrintNightmare
  'CVE-2021-22204': { epss: 0.9553, percentile: 0.9993 }, // ExifTool
  'CVE-2021-41773': { epss: 0.9728, percentile: 0.9998 }, // Apache 2.4.49 path traversal
  'CVE-2021-44228': { epss: 0.9757, percentile: 0.9999 }, // Log4Shell
  'CVE-2022-22965': { epss: 0.9717, percentile: 0.9998 }, // Spring4Shell
  'CVE-2022-26134': { epss: 0.9722, percentile: 0.9998 }, // Confluence OGNL (2)
  'CVE-2022-30190': { epss: 0.9600, percentile: 0.9995 }, // Follina
  'CVE-2022-47966': { epss: 0.9690, percentile: 0.9997 }, // ManageEngine
  'CVE-2023-23397': { epss: 0.9694, percentile: 0.9997 }, // Outlook NTLM leak
  'CVE-2023-34362': { epss: 0.9718, percentile: 0.9998 }, // MOVEit SQLi
  'CVE-2023-44487': { epss: 0.1304, percentile: 0.6200 }, // HTTP/2 Rapid Reset (DoS)
  'CVE-2023-4966': { epss: 0.9701, percentile: 0.9997 }, // Citrix Bleed
  'CVE-2024-21762': { epss: 0.9589, percentile: 0.9994 }, // FortiOS SSL VPN
  'CVE-2024-3400': { epss: 0.9687, percentile: 0.9997 }, // PAN-OS
  'CVE-2014-0160': { epss: 0.9744, percentile: 0.9999 }, // Heartbleed
  'CVE-2014-6271': { epss: 0.9677, percentile: 0.9997 }, // Shellshock
  'CVE-2015-1635': { epss: 0.9633, percentile: 0.9996 }, // MS15-034
  'CVE-2018-13379': { epss: 0.9694, percentile: 0.9997 }, // Fortinet SSL VPN path
};

// CWE id -> { title, description }. Common classes used by this harness's findings.
const CWE_MAP = {
  'CWE-16': { title: 'Configuration', description: 'Weak or missing security-relevant configuration.' },
  'CWE-22': { title: 'Path Traversal', description: "Improper limitation of a pathname to a restricted directory ('Path Traversal')." },
  'CWE-77': { title: 'Command Injection', description: 'Improper neutralization of special elements used in a command.' },
  'CWE-79': { title: 'Cross-site Scripting', description: 'Improper neutralization of input during web page generation (reflected/stored/DOM).' },
  'CWE-89': { title: 'SQL Injection', description: 'Improper neutralization of special elements used in an SQL command.' },
  'CWE-94': { title: 'Code Injection', description: 'Improper control of generation of code (code injection).' },
  'CWE-95': { title: 'Eval Injection', description: "Improper neutralization of directives in dynamically evaluated code ('Eval Injection')." },
  'CWE-200': { title: 'Information Exposure', description: 'Exposure of sensitive information to an unauthorized actor.' },
  'CWE-250': { title: 'Excess Privileges', description: 'Execution with unnecessary privileges.' },
  'CWE-269': { title: 'Improper Privilege Management', description: 'Improper privilege management.' },
  'CWE-284': { title: 'Improper Access Control', description: 'Improper access control (authorization).' },
  'CWE-287': { title: 'Improper Authentication', description: 'Improper authentication.' },
  'CWE-306': { title: 'Missing Authentication', description: 'Missing authentication for critical function.' },
  'CWE-312': { title: 'Cleartext Storage', description: 'Cleartext storage of sensitive information.' },
  'CWE-319': { title: 'Cleartext Transmission', description: 'Cleartext transmission of sensitive information.' },
  'CWE-321': { title: 'Hard-coded Key', description: 'Use of hard-coded cryptographic key.' },
  'CWE-330': { title: 'Insufficient Randomness', description: 'Use of insufficiently random values.' },
  'CWE-347': { title: 'Improper Signature Verification', description: 'Improper verification of cryptographic signature.' },
  'CWE-352': { title: 'CSRF', description: 'Cross-Site Request Forgery.' },
  'CWE-362': { title: 'Race Condition', description: 'Concurrent execution using shared resource with improper synchronization.' },
  'CWE-400': { title: 'Resource Exhaustion', description: 'Uncontrolled resource consumption.' },
  'CWE-434': { title: 'Unrestricted Upload', description: 'Unrestricted upload of file with dangerous type.' },
  'CWE-441': { title: 'Unintended Proxy', description: 'Unintended proxy or intermediary (confused deputy).' },
  'CWE-502': { title: 'Deserialization', description: 'Deserialization of untrusted data.' },
  'CWE-521': { title: 'Weak Password', description: 'Weak password requirements.' },
  'CWE-601': { title: 'Open Redirect', description: 'URL redirection to untrusted site (open redirect).' },
  'CWE-611': { title: 'XXE', description: 'Improper restriction of XML external entity reference.' },
  'CWE-639': { title: 'Authorization Bypass (IDOR)', description: 'Authorization bypass through user-controlled key (IDOR/BOLA).' },
  'CWE-640': { title: 'Weak Password Recovery', description: 'Weak password recovery mechanism for forgotten password.' },
  'CWE-770': { title: 'Allocation Without Limits', description: 'Allocation of resources without limits or throttling.' },
  'CWE-798': { title: 'Hard-coded Credentials', description: 'Use of hard-coded credentials.' },
  'CWE-862': { title: 'Missing Authorization', description: 'Missing authorization.' },
  'CWE-863': { title: 'Incorrect Authorization', description: 'Incorrect authorization.' },
  'CWE-915': { title: 'Mass Assignment', description: 'Improperly controlled modification of dynamically-determined object attributes.' },
  'CWE-918': { title: 'SSRF', description: 'Server-Side Request Forgery.' },
  'CWE-1321': { title: 'Prototype Pollution', description: 'Improperly controlled modification of object prototype attributes.' },
  'CWE-1333': { title: 'Inefficient Regex', description: "Inefficient regular expression complexity (ReDoS)." },
  'CWE-1336': { title: 'Template Injection', description: 'Improper neutralization of special elements used in a template engine.' },
};

function normCve(id) {
  let s = String(id || '').trim().toUpperCase().replace(/_/g, '-');
  if (!s) return '';
  s = s.replace(/^CVE-?/, '');
  return /^\d{4}-\d{4,}$/.test(s) ? 'CVE-' + s : '';
}

function normCwe(id) {
  let s = String(id || '').trim().toUpperCase().replace(/_/g, '-');
  if (!s) return '';
  s = s.replace(/^CWE-?/, '');
  return /^\d+$/.test(s) ? 'CWE-' + s : '';
}

// Look up an embedded EPSS score for a CVE. Returns null when unknown (never fabricate).
function lookupEpss(cve) {
  const id = normCve(cve);
  const hit = EPSS_MAP[id];
  if (!hit) return null;
  return { cve: id, epss: hit.epss, percentile: hit.percentile, source: 'embedded' };
}

// Best (highest) EPSS across a list of CVEs, so a finding tagged with several CVEs picks
// the most-likely-to-be-exploited one. Returns null if none are in the map.
function lookupMaxEpss(cves) {
  let best = null;
  for (const c of Array.isArray(cves) ? cves : [cves]) {
    const r = lookupEpss(c);
    if (r && (!best || r.epss > best.epss)) best = r;
  }
  return best;
}

// CWE title/description for the reporter. Returns null when unknown.
function lookupCwe(cwe) {
  const id = normCwe(cwe);
  const hit = CWE_MAP[id];
  if (!hit) return null;
  return { cwe: id, title: hit.title, description: hit.description };
}

// Best-known EPSS for a CVE: live-refreshed FIRST-EPSS-API score from the threatintel disk
// cache when present, else the embedded snapshot. Lazy require avoids the epss<->threatintel
// require cycle. Returns null when unknown in both (never fabricate).
function lookupBestEpss(cve) {
  const id = normCve(cve);
  try {
    const ti = require('./threatintel');
    const intel = ti.lookupCached(id);
    if (intel && typeof intel.epss === 'number') {
      return { cve: id, epss: intel.epss, percentile: intel.percentile != null ? intel.percentile : null, source: 'first-epss-api' };
    }
  } catch {}
  return lookupEpss(cve);
}

// Best across a list (same "highest wins" rule as lookupMaxEpss) over cached-live scores.
function lookupMaxBestEpss(cves) {
  let best = null;
  for (const c of Array.isArray(cves) ? cves : [cves]) {
    const r = lookupBestEpss(c);
    if (r && (!best || r.epss > best.epss)) best = r;
  }
  return best;
}

if (require.main === module) {
  const [arg, val] = process.argv.slice(2);
  if (!arg) { console.error('usage: node tools/epss.js CVE-2021-44228 | --cwe CWE-79'); process.exit(2); }
  if (arg === '--cwe') {
    if (!val) { console.error('usage: node tools/epss.js --cwe CWE-79'); process.exit(2); }
    console.log(JSON.stringify(lookupCwe(val) || { cwe: normCwe(val), unknown: true }, null, 2));
    process.exit(0);
  }
  const cve = arg === '--cve' ? val : arg;
  if (!cve) { console.error('usage: node tools/epss.js CVE-2021-44228'); process.exit(2); }
  console.log(JSON.stringify(lookupEpss(cve) || { cve: normCve(cve), unknown: true }, null, 2));
  process.exit(0);
}

module.exports = { lookupEpss, lookupMaxEpss, lookupCwe, lookupBestEpss, lookupMaxBestEpss, normCve, normCwe, EPSS_MAP, CWE_MAP };
