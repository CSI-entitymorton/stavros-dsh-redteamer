#!/usr/bin/env node
// Tool-plane detection for the Stavros harness: batch `command -v` on expected binaries,
// writes reports/tmp/tool-plane.json + a readable table. Agents MUST read this before choosing
// a tool — never invent output for a tool that is not installed (same discipline as knowledge.md,
// now deterministic). Install-failed tools are registered here so the harness does not retry them.
//   node tools/tool-plane.js                 # detect + write reports/tmp/tool-plane.json
//   node tools/tool-plane.js --json          # print JSON to stdout
//   node tools/tool-plane.js --table         # print readable table (default)
// Pattern adapted from SeaOf0/dsh-redteam-model (MIT) — shared/scripts/tool-plane.

'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const OUT = path.join(__dirname, '..', 'reports', 'tmp', 'tool-plane.json');
const IS_WIN = process.platform === 'win32';

// Expected toolchain per capability class. `required` tools gate the corresponding capability:
// if missing, the agent must degrade (script / MCP / ask_user) instead of faking output.
const TOOL_PLANE = {
  recon: {
    subfinder: { required: false },
    amass: { required: false },
    dnsx: { required: false },
    gau: { required: false },
    waybackurls: { required: false },
    katana: { required: false },
  },
  scan: {
    nmap: { required: true },
    masscan: { required: false },
    nuclei: { required: false },
    httpx: { required: false },
    ffuf: { required: false },
    gobuster: { required: false },
    dirsearch: { required: false },
  },
  web: {
    sqlmap: { required: false },
    dalfox: { required: false },
    nikto: { required: false },
    whatweb: { required: false },
  },
  creds: {
    hydra: { required: false },
    john: { required: false },
    hashcat: { required: false },
    h8mail: { required: false },
    netexec: { required: false },
    'impacket-secretsdump': { required: false },
  },
  ad: {
    enum4linux: { required: false },
    enum4linux_ng: { required: false },
    ldapsearch: { required: false },
    bloodhound_python: { required: false },
  },
  host: {
    msfconsole: { required: false },
    msfvenom: { required: false },
    sliver: { required: false },
  },
  wireless: {
    aircrack_ng: { required: false },
    airmon_ng: { required: false },
    airodump_ng: { required: false },
    reaver: { required: false },
  },
  cloud: {
    aws: { required: false },
    az: { required: false },
    gcloud: { required: false },
  },
};

function hasBin(bin) {
  const r = IS_WIN
    ? spawnSync('where', [bin], { stdio: 'ignore' })
    : spawnSync('/usr/bin/which', [bin], { stdio: 'ignore' });
  return r.status === 0;
}

function detect() {
  const out = { ts: new Date().toISOString(), tools: {} };
  for (const [category, tools] of Object.entries(TOOL_PLANE)) {
    for (const [bin, meta] of Object.entries(tools)) {
      out.tools[bin] = {
        category,
        required: !!meta.required,
        installed: hasBin(bin),
        // install-failed registry: the harness marks attempts here and must not retry
        install_state: meta.install_state || null,
      };
    }
  }
  return out;
}

function table(out) {
  const lines = ['Tool-plane detection', '', '| Tool | Category | Required | Installed | Install state |', '|---|---|---|---|---|'];
  for (const [bin, meta] of Object.entries(out.tools)) {
    lines.push(`| ${bin} | ${meta.category} | ${meta.required ? 'yes' : 'no'} | ${meta.installed ? 'yes' : 'NO'} | ${meta.install_state || '-'} |`);
  }
  const missing = Object.entries(out.tools).filter(([, m]) => m.required && !m.installed);
  if (missing.length) {
    lines.push('', `⚠ required tools missing: ${missing.map(([b]) => b).join(', ')}`);
    lines.push('  → degrade: local script (python3 first) / MCP / ask_user before proceeding');
  } else {
    lines.push('', 'All required tools present.');
  }
  return lines.join('\n');
}

/** Mark a tool install attempt as failed (so future runs do not retry it). */
function markInstallFailed(bin, note) {
  let data = { ts: new Date().toISOString(), tools: {} };
  try { data = JSON.parse(fs.readFileSync(OUT, 'utf8')); } catch {}
  if (!data.tools[bin]) data.tools[bin] = { category: 'other', required: false, installed: false };
  data.tools[bin].install_state = 'install-failed';
  data.tools[bin].install_note = note || '';
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(data, null, 2) + '\n');
}

function main() {
  const args = process.argv.slice(2);
  const data = detect();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(data, null, 2) + '\n');
  if (args.includes('--json')) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(table(data));
  }
  const missing = Object.entries(data.tools).filter(([, m]) => m.required && !m.installed);
  process.exit(missing.length ? 1 : 0);
}

if (require.main === module) main();

module.exports = { TOOL_PLANE, detect, hasBin, table, markInstallFailed, OUT };