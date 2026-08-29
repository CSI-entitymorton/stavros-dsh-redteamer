#!/usr/bin/env node
// Tool-plane detection for the Stavros harness: batch `command -v` on expected binaries,
// writes reports/tmp/tool-plane.json + a readable table. Agents MUST read this before choosing
// a tool — never invent output for a tool that is not installed (same discipline as knowledge.md,
// now deterministic). Install-failed tools are registered here so the harness does not retry them.
//   node tools/tool-plane.js                 # detect + write reports/tmp/tool-plane.json
//   node tools/tool-plane.js --json          # print JSON to stdout
//   node tools/tool-plane.js --table         # print readable table (default)
// Ondata 2 — E5 preflight extension (additive):
//   node tools/tool-plane.js --require recon,scan [--require-bin nmap,curl]
//     → capability preflight: exit ≠ 0 listing the missing binaries when a REQUIRED tool of
//       a requested category is absent, or an explicitly required bin is absent; optional
//       missing tools of those categories are listed as `optional_missing` (warnings only,
//       so requiring a plane stays meaningful on minimal boxes).
// Env overrides (used by tests / multi-project setups): TOOL_PLANE_OUT (output file),
// TOOL_PLANE_CONFIG (JSON file merged over the built-in map: {cat: {bin: {required}}}).
// Pattern adapted from SeaOf0/dsh-redteam-model (MIT) — shared/scripts/tool-plane.

'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const OUT = process.env.TOOL_PLANE_OUT || path.join(__dirname, '..', 'reports', 'tmp', 'tool-plane.json');
const IS_WIN = process.platform === 'win32';

// Ondata 3 — E12 TOOL_REQUIRES_KEY (additive, mai fallback silenziosi):
//   node tools/tool-plane.js --require-key b1[=ENV],b2    preflight env-key (exit≠0 elencando mancanti)
//   node tools/tool-plane.js --check-keys                 report JSON presente/mancante per ogni bin con requisito
// Requisiti = union(registry[bin].requires_key, env TOOL_REQUIRES_KEY "bin=ENV[,ENV...]"); una env
// MALFORMATA è FATALE (exit 2), mai ignorata. Registry letto da TOOL_REGISTRY o tool-registry.json.
const REGISTRY_DEFAULT = path.join(__dirname, 'tool-registry.json');
function loadRegistry() {
  const f = process.env.TOOL_REGISTRY || REGISTRY_DEFAULT;
  try {
    return { loaded: true, file: f, map: JSON.parse(fs.readFileSync(f, 'utf8')), error: null };
  } catch (e) {
    return { loaded: false, file: f, map: null, error: e.message };
  }
}
function parseToolRequiresKeyEnv(text) {
  if (text == null || String(text).trim() === '') return { ok: true, pairs: {} };
  const pairs = {};
  for (const part of String(text).split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq <= 0) return { ok: false, error: `TOOL_REQUIRES_KEY: coppia malformata "${part}" (atteso bin=ENV[,ENV...])` };
    const bin = part.slice(0, eq).trim();
    const keys = part.slice(eq + 1).split(',').map((s) => s.trim()).filter(Boolean);
    if (!bin) return { ok: false, error: `TOOL_REQUIRES_KEY: nome bin vuoto in "${part}"` };
    if (keys.length === 0) return { ok: false, error: `TOOL_REQUIRES_KEY: nessuna env per "${bin}" in "${part}"` };
    pairs[bin] = [...new Set([...(pairs[bin] || []), ...keys])];
  }
  return { ok: true, pairs };
}
// Requisiti noti per bin: union(registry.requires_key su TUTTI i bin, env pairs).
function knownKeyRequirements(reg) {
  const parsed = parseToolRequiresKeyEnv(process.env.TOOL_REQUIRES_KEY);
  if (!parsed.ok) return parsed;
  const out = {};
  if (reg && reg.loaded && reg.map) {
    for (const [bin, spec] of Object.entries(reg.map)) {
      if (bin.startsWith('_')) continue;
      if (spec && Array.isArray(spec.requires_key) && spec.requires_key.length) {
        out[bin] = [...new Set(spec.requires_key.map((k) => String(k)))];
      }
    }
  }
  for (const [bin, keys] of Object.entries(parsed.pairs)) {
    out[bin] = [...new Set([...(out[bin] || []), ...keys])];
  }
  return { ok: true, requirements: out };
}
// "b1=ENV,b2,b3=ENV2" -> [{bin, env?}]; una env per bin per entry (i multi-env passano da
// registry/TOOL_REQUIRES_KEY); malformata -> throw TypeError.
function parseRequireKeyList(list) {
  const out = [];
  if (!list) return out;
  for (const part of String(list).split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq === -1) { out.push({ bin: part }); continue; }
    const bin = part.slice(0, eq).trim();
    const env = part.slice(eq + 1).trim();
    if (!bin) throw new TypeError(`--require-key: bin vuoto in "${part}"`);
    if (!env) throw new TypeError(`--require-key: env vuota per "${bin}" (atteso ${bin}=ENV)`);
    out.push({ bin, env });
  }
  return out;
}
function presentInEnv(key) { return Object.prototype.hasOwnProperty.call(process.env, key); }

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
  let plane = TOOL_PLANE;
  // E5/test hook: merge an external config over the built-in map (additive per key).
  if (process.env.TOOL_PLANE_CONFIG) {
    try {
      const extra = JSON.parse(fs.readFileSync(process.env.TOOL_PLANE_CONFIG, 'utf8'));
      plane = {};
      const cats = new Set([...Object.keys(TOOL_PLANE), ...Object.keys(extra)]);
      for (const c of cats) {
        plane[c] = Object.assign({}, TOOL_PLANE[c] || {}, extra[c] || {});
      }
    } catch { /* malformed config: keep built-in plane */ }
  }
  for (const [category, tools] of Object.entries(plane)) {
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

/** E5: capability preflight over detected data. Returns {ok, missing[], optional_missing[]}. */
function requireCheck(data, categories, bins) {
  const missing = [];
  const optionalMissing = [];
  const seenBins = new Set();
  const wantCats = new Set(String(categories || '').split(',').map((s) => s.trim()).filter(Boolean));
  const wantBins = new Set(String(bins || '').split(',').map((s) => s.trim()).filter(Boolean));
  for (const [bin, meta] of Object.entries(data.tools)) {
    const inCat = wantCats.has(meta.category);
    const explicit = wantBins.has(bin);
    if (!inCat && !explicit) continue;
    if (!meta.installed) {
      const rec = { bin, category: meta.category, required: explicit ? true : !!meta.required, via: explicit && !inCat ? 'require-bin' : meta.category };
      if (rec.required) missing.push(rec);
      else optionalMissing.push(rec);
    }
    seenBins.add(bin);
  }
  // Explicitly required bins unknown to the plane are checked LIVE (never silently ignored).
  for (const b of wantBins) {
    if (!seenBins.has(b) && !hasBin(b)) missing.push({ bin: b, category: '(not in tool-plane map)', required: true, via: 'require-bin' });
  }
  return { ok: missing.length === 0, missing, optional_missing: optionalMissing };
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
  const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
  const data = detect();
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(data, null, 2) + '\n');

  // E5 preflight mode (additive): --require cat1,cat2 [--require-bin b1,b2]
  if (args.includes('--require') || args.includes('--require-bin')) {
    const req = requireCheck(data, opt('--require'), opt('--require-bin'));
    const payload = Object.assign({ ts: data.ts, require: { categories: opt('--require'), bins: opt('--require-bin') }, ok: req.ok, missing: req.missing, optional_missing: req.optional_missing }, {});
    if (args.includes('--json')) console.log(JSON.stringify(payload, null, 2));
    else {
      for (const m of req.missing) console.error(`MISSING (required): ${m.bin} [${m.category}]`);
      for (const m of req.optional_missing) console.error(`missing (optional): ${m.bin} [${m.category}]`);
      console.error(req.ok
        ? `preflight OK: requested capability present${req.optional_missing.length ? ` (${req.optional_missing.length} optional missing)` : ''}`
        : `PREFLIGHT FAILED: ${req.missing.length} required tool(s) missing — degrade (script/MCP/ask_user), do NOT fake output`);
    }
    process.exit(req.ok ? 0 : 1);
  }

  // E12 modes (additive): --require-key b1[=ENV],b2 and --check-keys.
  if (args.includes('--require-key') || args.includes('--check-keys')) {
    const reg = loadRegistry();
    const known = knownKeyRequirements(reg);
    if (!known.ok) {
      console.error('ERRORE FATALE: ' + known.error);
      process.exit(2);
    }
    const reqs = known.requirements;
    if (args.includes('--check-keys')) {
      const report = { ts: new Date().toISOString(), registry: reg.file, requirements: {} };
      let anyMissing = false;
      for (const bin of Object.keys(reqs).sort()) {
        const present = reqs[bin].filter(presentInEnv);
        const missing = reqs[bin].filter((k) => !presentInEnv(k));
        if (missing.length) anyMissing = true;
        report.requirements[bin] = { keys: reqs[bin], present, missing };
      }
      if (args.includes('--json')) console.log(JSON.stringify(report, null, 2));
      else {
        for (const [bin, r] of Object.entries(report.requirements)) {
          if (r.missing.length) console.error(`MISSING (key): ${bin} -> ${r.missing.join(', ')}`);
        }
        console.error(anyMissing
          ? `CHECK-KEYS FAILED: ${Object.values(report.requirements).reduce((n, r) => n + r.missing.length, 0)} env key(s) missing — configure_api_key, never silent fallback`
          : `check-keys OK: ${Object.keys(report.requirements).length} bin(s) with requirements, all keys present`);
      }
      process.exit(anyMissing ? 1 : 0);
    }
    // --require-key: preflight esplicito su bin scelti (env per-bin opzionale via =ENV).
    let specs;
    try {
      specs = parseRequireKeyList(opt('--require-key'));
    } catch (e) {
      console.error('uso errato: ' + e.message);
      process.exit(2);
    }
    if (specs.length === 0) {
      console.error('uso errato: --require-key richiede almeno un bin (es. --require-key sqlmap=SQLMAP_API_KEY,curl)');
      process.exit(2);
    }
    const missing = [];
    const unknown = [];
    for (const { bin, env } of specs) {
      const keys = env ? [env] : (reqs[bin] || []);
      if (keys.length === 0) { unknown.push(bin); continue; }
      for (const k of keys) if (!presentInEnv(k)) missing.push({ bin, key: k });
    }
    if (args.includes('--json')) {
      console.log(JSON.stringify({ ts: new Date().toISOString(), require_key: specs.map((s) => s.bin + (s.env ? '=' + s.env : '')), ok: missing.length === 0, missing, unknown_requirement: unknown }, null, 2));
    } else {
      for (const m of missing) console.error(`MISSING (key): ${m.bin} -> env ${m.key} non impostata`);
      for (const b of unknown) console.error(`warning: nessun requisito chiave noto per "${b}" (specifica =ENV o aggiungi requires_key nel registry)`);
      console.error(missing.length
        ? `PREFLIGHT KEY FAILED: ${missing.length} env key(s) mancanti — configure_api_key, mai fallback silenzioso`
        : `preflight key OK${unknown.length ? ` (${unknown.length} bin senza requisito noto)` : ''}`);
    }
    process.exit(missing.length ? 1 : 0);
  }

  if (args.includes('--json')) {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(table(data));
  }
  const missing = Object.entries(data.tools).filter(([, m]) => m.required && !m.installed);
  process.exit(missing.length ? 1 : 0);
}

if (require.main === module) main();

module.exports = { TOOL_PLANE, detect, hasBin, table, markInstallFailed, OUT, requireCheck,
  // ondata-3 (E12) additions
  loadRegistry, parseToolRequiresKeyEnv, knownKeyRequirements, parseRequireKeyList };