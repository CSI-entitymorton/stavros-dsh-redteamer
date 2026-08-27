#!/usr/bin/env node
// Standalone HTML report generator (Fase 3). Consolidates reports/findings.jsonl +
// reports/state.db (SQLite) + attack chains (chain.js) into a single self-contained HTML
// file (severity + CVSS + CWE + EPSS + exploit-db matches). The Markdown report stays.
//   node tools/report-html.js [--findings <file>] [--state <db>] [--sploit <jsonl>] [--out <file>] [--host <h>]
// Env overrides: FINDINGS_JSONL, STATE_DB (same convention as the rest of the harness).
// All free-text fields are HTML-escaped, so a finding title can never inject markup.
const fs = require('fs');
const path = require('path');
const state = require('./state');
const { buildChains } = require('./chain');
const { calculate } = require('./cvss');
const { lookupCwe, lookupMaxEpss, normCve } = require('./epss');

const SEV_ORDER = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
const SEV_CLASS = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low', Info: 'info' };

function htmlEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sevRank(f) { return SEV_ORDER[f.severity] || 0; }

function fmtEpss(epss) {
  return epss == null ? '&mdash;' : (epss * 100).toFixed(1) + '%';
}
function fmtCvss(cvss) {
  return cvss == null ? '&mdash;' : cvss.toFixed(1);
}

// Read a JSONL file into objects; missing/malformed lines are dropped.
function loadJsonl(file) {
  try {
    return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch {
    return [];
  }
}

function loadFindings(file) {
  return loadJsonl(file || process.env.FINDINGS_JSONL || path.join(__dirname, '..', 'reports', 'findings.jsonl'));
}

// searchsploit.jsonl records -> { CVE: [record, ...] }
function loadSploit(file) {
  const byCve = {};
  for (const r of loadJsonl(file)) {
    for (const c of (Array.isArray(r.cves) ? r.cves : [])) {
      (byCve[c] = byCve[c] || []).push(r);
    }
  }
  return byCve;
}

// Attach computed cvss / normalized cves / epss / cwe title for display. Pure (no I/O).
function enrichFinding(f) {
  const out = Object.assign({}, f);
  let cvss = f.cvss;
  if (cvss == null && f.cvss_vector) {
    try { cvss = calculate(f.cvss_vector).base_score; } catch { /* leave null */ }
  }
  out.cvss = typeof cvss === 'number' ? cvss : null;

  let cves = Array.isArray(f.cves) ? f.cves.slice()
    : (typeof f.cve === 'string' && f.cve.trim() ? [f.cve] : []);
  cves = cves.map(normCve).filter((c) => c && c !== 'CVE-');
  out.cves = cves;

  let epss = f.epss;
  if (epss == null && cves.length) {
    const best = lookupMaxEpss(cves);
    if (best) epss = best.epss;
  }
  out.epss = typeof epss === 'number' ? epss : null;
  out.cwe_title = f.cwe ? ((lookupCwe(f.cwe) || {}).title || null) : null;
  return out;
}

// targets from state.db (mirrors stavros.js report()).
function collectFromState(db) {
  return state.listTargets(db).map((t) => ({
    target: t.host,
    hosts: state.listHosts(db, t.id).map((h) => ({
      address: h.address, hostname: h.hostname, os: h.os,
      ports: state.listPorts(db, h.id),
    })),
    endpoints: state.listEndpoints(db, t.id),
  }));
}

function summaryTable(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) if (counts[f.severity] != null) counts[f.severity]++;
  const withCvss = findings.filter((f) => f.cvss != null).length;
  const withEpss = findings.filter((f) => f.epss != null).length;
  const maxEpss = findings.reduce((m, f) => (f.epss != null && f.epss > m ? f.epss : m), 0);
  return { counts, total: findings.length, withCvss, withEpss, maxEpss };
}

function findingsRows(findings, sploitByCve) {
  const sorted = findings.slice().sort((a, b) => sevRank(b) - sevRank(a) || String(a.title).localeCompare(String(b.title)));
  return sorted.map((f) => {
    const cves = f.cves.map((c) => {
      const n = (sploitByCve[c] || []).length;
      return `<code>${htmlEscape(c)}</code>${n ? ` <span class="tag">${n} sploit</span>` : ''}`;
    }).join(' ');
    return `<tr class="${SEV_CLASS[f.severity] || ''}">
      <td class="sev">${htmlEscape(f.severity)}</td>
      <td class="title">${htmlEscape(f.title)}${f.status === 'verified' ? ' <span class="tag verified">verified</span>' : ''}</td>
      <td>${htmlEscape(f.host)}</td>
      <td class="mono">${htmlEscape(f.endpoint || '')}</td>
      <td>${f.cwe ? `<code>${htmlEscape(f.cwe)}</code>${f.cwe_title ? '<br><small>' + htmlEscape(f.cwe_title) + '</small>' : ''}` : '&mdash;'}</td>
      <td class="num">${fmtCvss(f.cvss)}</td>
      <td class="num">${fmtEpss(f.epss)}</td>
      <td>${f.cves.length ? cves : '&mdash;'}</td>
    </tr>`;
  }).join('\n');
}

function chainsSection(chains) {
  if (!chains || !chains.length) return '<p class="muted">No attack chains detected.</p>';
  return chains.map((c) => `<section class="chain">
    <h3>${htmlEscape(c.host)} <span class="muted">(${c.chain_count} chain${c.chain_count === 1 ? '' : 's'})</span></h3>
    ${c.chains.map((ch) => `<div class="chain-item"><strong>${htmlEscape(ch.name)}</strong><p class="muted">${htmlEscape(ch.reasoning)}</p><ul>${ch.findings.map((t) => '<li>' + htmlEscape(t) + '</li>').join('')}</ul></div>`).join('')}
  </section>`).join('\n');
}

function reconSection(targets) {
  if (!targets || !targets.length) return '<p class="muted">No recon data in state.db yet (run stavros.js recon/scan/enumerate).</p>';
  return targets.map((t) => `<section class="target">
    <h3>${htmlEscape(t.target)}</h3>
    ${t.hosts.map((h) => `<div class="host">
      <strong>${htmlEscape(h.address)}</strong>${h.hostname ? ' <span class="muted">' + htmlEscape(h.hostname) + '</span>' : ''}${h.os ? ' <span class="tag">' + htmlEscape(h.os) + '</span>' : ''}
      ${h.ports && h.ports.length ? '<ul class="ports">' + h.ports.map((p) => `<li>${htmlEscape(p.port)}/${htmlEscape(p.protocol)} <span class="muted">${htmlEscape(p.service || '')}${p.version ? ' ' + htmlEscape(p.version) : ''}</span></li>`).join('') + '</ul>' : ''}
    </div>`).join('')}
    ${t.endpoints && t.endpoints.length ? `<details><summary>${t.endpoints.length} endpoint(s)</summary><ul class="mono">${t.endpoints.map((e) => '<li>' + htmlEscape(e.method + ' ' + e.url) + '</li>').join('')}</ul></details>` : ''}
  </section>`).join('\n');
}

// Pure HTML builder (no I/O): { findings (enriched), targets, chains, sploitByCve, generatedAt }.
function buildHtml(data) {
  const d = data || {};
  const findings = d.findings || [];
  const s = summaryTable(findings);
  const generatedAt = d.generatedAt || new Date().toISOString();
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stavros Red Team Report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0f1216; color: #dbe2ea; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 80px; }
  h1 { font-size: 1.6rem; } h2 { border-bottom: 1px solid #2a313c; padding-bottom: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 12px 0; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #242b34; vertical-align: top; }
  th { color: #9aa7b4; font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: .04em; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .sev { font-weight: 700; }
  tr.crit .sev, .crit { color: #ff5b68; } tr.high .sev, .high { color: #ff9a3c; }
  tr.med .sev, .med { color: #ffd166; } tr.low .sev, .low { color: #6cc7ff; } tr.info .sev, .info { color: #9aa7b4; }
  .tag { background: #232b35; border-radius: 4px; padding: 1px 6px; font-size: 0.7rem; color: #9aa7b4; }
  .tag.verified { background: #14321f; color: #5fd78a; }
  .muted { color: #8b97a5; } .mono, code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.8rem; }
  .chain, .target, .host { background: #161b22; border: 1px solid #242b34; border-radius: 8px; padding: 12px 16px; margin: 12px 0; }
  .chain-item { margin: 10px 0; padding-top: 8px; border-top: 1px dashed #2a313c; }
  ul { margin: 6px 0 6px 20px; padding: 0; } li { margin: 2px 0; }
  .kpis { display: flex; gap: 14px; flex-wrap: wrap; margin: 16px 0; }
  .kpi { background: #161b22; border: 1px solid #242b34; border-radius: 8px; padding: 10px 16px; }
  .kpi b { display: block; font-size: 1.4rem; } .kpi span { color: #8b97a5; font-size: 0.75rem; }
  details summary { cursor: pointer; color: #6cc7ff; }
  footer { margin-top: 40px; color: #6b7684; font-size: 0.75rem; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Stavros Red Team Report</h1>
  <p class="muted">Generated ${htmlEscape(generatedAt)} &middot; authorized targets only (scope.json)</p>

  <div class="kpis">
    <div class="kpi"><b>${s.total}</b><span>findings</span></div>
    <div class="kpi crit"><b>${s.counts.Critical}</b><span>critical</span></div>
    <div class="kpi high"><b>${s.counts.High}</b><span>high</span></div>
    <div class="kpi med"><b>${s.counts.Medium}</b><span>medium</span></div>
    <div class="kpi low"><b>${s.counts.Low}</b><span>low</span></div>
    <div class="kpi"><b>${fmtEpss(s.maxEpss)}</b><span>max EPSS</span></div>
  </div>

  <h2>Findings (${s.total})</h2>
  ${findings.length ? `<table>
    <thead><tr><th>Sev</th><th>Finding</th><th>Host</th><th>Endpoint</th><th>CWE</th><th>CVSS</th><th>EPSS</th><th>CVEs</th></tr></thead>
    <tbody>${findingsRows(findings, d.sploitByCve || {})}</tbody>
  </table>` : '<p class="muted">No findings recorded yet.</p>'}

  <h2>Attack chains</h2>
  ${chainsSection(d.chains)}

  <h2>Reconnaissance (state.db)</h2>
  ${reconSection(d.targets)}

  <footer>Auto-generated by tools/report-html.js. Markdown report remains the source of truth; this is a consolidated view. Contains ${s.withCvss}/${s.total} findings with CVSS and ${s.withEpss}/${s.total} with EPSS.</footer>
</div>
</body>
</html>
`;
}

function main() {
  const argv = process.argv.slice(2);
  const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  const findingsFile = opt('--findings');
  const stateFile = opt('--state');
  const sploitFile = opt('--sploit');
  const outFile = opt('--out') || path.join(__dirname, '..', 'reports', 'report.html');
  const hostFilter = opt('--host');

  // Gate check: report generation requires the report gate to have PASSed in gate-log.md.
  // This is the deterministic enforcement boundary (same as dsh-sec-enforce reportGate).
  const gateLog = path.join(__dirname, '..', 'reports', 'gate-log.md');
  const skipGate = argv.includes('--skip-gate');
  if (!skipGate) {
    try {
      const log = fs.readFileSync(gateLog, 'utf8');
      const hasPass = log.split('\n').some((l) => l.includes('stavros/report') && l.includes('pass'));
      if (!hasPass) {
        console.error(`[report-html] BLOCKED: report gate "stavros/report" not PASSed in ${gateLog}.`);
        console.error('[report-html] Run: node tools/gate.js pass report  (after validating all criteria)');
        console.error('[report-html] Or use --skip-gate to bypass (not recommended for final reports).');
        process.exit(1);
      }
    } catch (e) {
      console.error(`[report-html] BLOCKED: cannot read ${gateLog} — gate-log.md missing. Run the gate first.`);
      console.error('[report-html] Run: node tools/gate.js pass report  (after validating all criteria)');
      process.exit(1);
    }
  }

  const findings = loadFindings(findingsFile).map(enrichFinding);
  const filtered = hostFilter ? findings.filter((f) => f.host === hostFilter || f.host === hostFilter.replace(/^https?:\/\//, '')) : findings;

  let db = null;
  let targets = [];
  try {
    db = state.open(stateFile || undefined);
    targets = collectFromState(db);
  } catch {
    targets = [];
  } finally {
    if (db) db.close();
  }

  const chains = buildChains(filtered);
  const sploitByCve = sploitFile ? loadSploit(sploitFile) : {};
  const html = buildHtml({
    findings: filtered, targets, chains, sploitByCve, generatedAt: new Date().toISOString(),
  });

  const tmp = outFile + '.' + process.pid;
  fs.writeFileSync(tmp, html);
  fs.renameSync(tmp, outFile);
  console.log(JSON.stringify({ ok: true, out: outFile, findings: filtered.length, chains: chains.length }));
}

if (require.main === module) main();

module.exports = { buildHtml, enrichFinding, loadFindings, loadSploit, collectFromState, htmlEscape, summaryTable };
