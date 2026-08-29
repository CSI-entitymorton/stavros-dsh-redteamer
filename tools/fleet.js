#!/usr/bin/env node
// E4 (rimandati) — fleet DICHIARATIVA: composizione squadre red/blue ripetibile.
//   docs/agents-fleet.yaml  = fonte di verità (preset/orchestratore, mai memoria dell'agente).
//
// Shape (validata fail-closed):
//   version: 1
//   name: <string>
//   teams:
//     - name: red|blue   color: red|blue   order: <int>
//       agents:
//         - id: <unique>   role: <string>   preset: <string>   requires_keys?: [ENV...]
//       artifacts?: [{path, surface}]      # template dichiarativi, risolti dall'orchestratore
//
// CLI (pattern di model-routing.js, zero dipendenze, zero rete):
//   node tools/fleet.js plan               # dry-run a ZERO scritture
//   node tools/fleet.js render --out <dir> # deterministico, confinato all'outdir
//   node tools/fleet.js apply --yes --out <dir>   # render + backup preventivo + marker applied
// Env: FLEET_FILE (default docs/agents-fleet.yaml).
'use strict';
const fs = require('fs');
const path = require('path');

const WS = path.join(__dirname, '..');
const FLEET_FILE = () => process.env.FLEET_FILE || path.join(WS, 'docs', 'agents-fleet.yaml');

// ---- mini YAML per il sottoinsieme fleet (stesso spirito di workflow.js parseSubset) ----
function parseYaml(text) {
  const lines = text.split(/\r?\n/).map((raw, i) => {
    if (raw.includes('\t')) throw new Error(`fleet yaml: tab non ammessi (line ${i + 1})`);
    const indent = raw.match(/^\s*/)[0].length;
    return { indent, body: raw.trim(), ln: i + 1 };
  }).filter((l) => l.body && !l.body.startsWith('#'));
  let pos = 0;
  const fail = (ln, msg) => { throw new Error(`fleet yaml: line ${ln}: ${msg}`); };
  const peek = () => lines[pos];
  const next = () => lines[pos++];
  function scalar(s, ln) {
    s = String(s == null ? '' : s).trim();
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1);
    if (s === '') return null;
    if (/^-?\d+$/.test(s)) return parseInt(s, 10);
    if (/^(true|false)$/.test(s)) return s === 'true';
    if (/^null$/.test(s)) return null;
    // liste flow del sottoinsieme fleet: [] o [a, b] (solo scalari)
    if (/^\[.*\]$/.test(s)) {
      const inner = s.slice(1, -1).trim();
      if (inner === '') return [];
      return inner.split(',').map((x) => x.trim()).filter(Boolean);
    }
    return s;
  }
  function parseBlock(indent) {
    const list = [];
    const map = {};
    let form = null;
    while (peek() && peek().indent === indent) {
      const { body, ln } = next();
      if (body.startsWith('- ')) {
        if (form === 'map') fail(ln, 'item di lista dentro un mapping');
        form = 'list';
        const item = body.slice(2).trim();
        // item mapping inline? (es. `- name: red` → mapping a una riga)
        const m = item.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
        if (m) {
          const obj = { [m[1]]: m[2].trim() !== '' ? scalar(m[2].trim(), ln) : null };
          // attributi annidati del mapping (indent maggiore)
          if (peek() && peek().indent > indent) {
            const inner = parseBlock(peek().indent);
            for (const [k, v] of Object.entries(inner)) obj[k] = v;
          }
          list.push(obj);
        } else {
          list.push(scalar(item, ln));
        }
        continue;
      }
      const m = body.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
      if (!m) fail(ln, `token inatteso: ${JSON.stringify(body.slice(0, 60))}`);
      if (form === 'list') fail(ln, 'chiave dentro una lista');
      form = 'map';
      const key = m[1];
      const rest = m[2].trim();
      if (rest !== '') map[key] = scalar(rest, ln);
      else if (peek() && peek().indent > indent) map[key] = parseBlock(peek().indent);
      else map[key] = null;
    }
    return form === 'list' ? list : map;
  }
  const root = {};
  while (peek()) {
    const { body, ln } = peek();
    const m = body.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
    if (!m) fail(ln, `token inatteso: ${JSON.stringify(body.slice(0, 60))}`);
    const key = m[1];
    const rest = m[2].trim();
    if (rest !== '') { next(); root[key] = scalar(rest, ln); continue; }
    next();
    if (!peek() || peek().indent <= 0) fail(ln, `il blocco "${key}" non ha contenuto`);
    root[key] = parseBlock(peek().indent);
  }
  return root;
}

function loadFleet(file) {
  file = file || FLEET_FILE();
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { throw new Error('cannot read fleet ' + file + ': ' + e.message); }
  const doc = parseYaml(raw);
  const errs = validateFleet(doc);
  if (errs.length) throw new Error('invalid fleet: ' + errs.join('; '));
  return { file, doc };
}

function validateFleet(doc) {
  const errs = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return ['fleet must be a mapping'];
  if (doc.version !== 1) errs.push('version must be 1');
  if (!doc.name || typeof doc.name !== 'string') errs.push('name (string) required');
  if (!Array.isArray(doc.teams) || !doc.teams.length) errs.push('teams must be a non-empty list');
  else {
    const teamNames = new Set();
    const agentIds = new Set();
    doc.teams.forEach((t, i) => {
      const at = `teams[${i}]`;
      if (!t || typeof t !== 'object' || Array.isArray(t)) { errs.push(`${at}: team must be a mapping`); return; }
      if (typeof t.name !== 'string' || !t.name.trim()) errs.push(`${at}: name required`);
      else if (teamNames.has(t.name)) errs.push(`${at}: duplicate team name "${t.name}"`);
      else teamNames.add(t.name);
      if (!['red', 'blue'].includes(t.color)) errs.push(`${at}: color must be red|blue (got ${JSON.stringify(t.color)})`);
      if (t.order != null && !Number.isInteger(t.order)) errs.push(`${at}: order must be an int`);
      if (!Array.isArray(t.agents) || !t.agents.length) errs.push(`${at}: agents must be a non-empty list`);
      else t.agents.forEach((a, j) => {
        const aat = `${at}.agents[${j}]`;
        if (!a || typeof a !== 'object' || Array.isArray(a)) { errs.push(`${aat}: agent must be a mapping`); return; }
        if (typeof a.id !== 'string' || !a.id.trim()) errs.push(`${aat}: id required`);
        else if (agentIds.has(a.id)) errs.push(`${aat}: duplicate agent id "${a.id}"`);
        else agentIds.add(a.id);
        if (typeof a.role !== 'string' || !a.role.trim()) errs.push(`${aat}: role required`);
        if (typeof a.preset !== 'string' || !a.preset.trim()) errs.push(`${aat}: preset required`);
        if (a.requires_keys != null && (!Array.isArray(a.requires_keys) || a.requires_keys.some((k) => typeof k !== 'string' || !k.trim())))
          errs.push(`${aat}: requires_keys must be a list of env-var names`);
      });
      if (t.artifacts != null) {
        if (!Array.isArray(t.artifacts)) errs.push(`${at}: artifacts must be a list`);
        else t.artifacts.forEach((a, j) => {
          if (!a || typeof a.path !== 'string' || !a.path.trim()) errs.push(`${at}.artifacts[${j}]: path required`);
        });
      }
    });
  }
  return errs;
}

function fleetSummary(doc) {
  return {
    name: doc.name,
    version: doc.version,
    teams: doc.teams.map((t) => ({
      name: t.name, color: t.color, order: t.order || 0,
      agents: t.agents.map((a) => ({ id: a.id, role: a.role, preset: a.preset, requires_keys: a.requires_keys || [] })),
      artifacts: (t.artifacts || []).map((a) => ({ path: a.path, surface: a.surface || null })),
    })),
    totals: {
      teams: doc.teams.length,
      agents: doc.teams.reduce((n, t) => n + t.agents.length, 0),
      red: doc.teams.filter((t) => t.color === 'red').reduce((n, t) => n + t.agents.length, 0),
      blue: doc.teams.filter((t) => t.color === 'blue').reduce((n, t) => n + t.agents.length, 0),
    },
  };
}

// RENDER: deterministico (nessun timestamp nel contenuto) e confinato all'outdir (stesse
// guardie di model-routing: niente HOME / ~/.dsh / radice / dir dell'agente).
function render(doc, outDir) {
  const bad = [path.join(WS, 'docs'), process.env.AGENT_PRESETS_DIR, process.env.HOME, path.parse(process.cwd()).root]
    .filter(Boolean).map((p) => path.resolve(p));
  const out = path.resolve(outDir);
  if (bad.some((b) => out === b || out.startsWith(b + path.sep))) {
    throw new Error('render refused: outdir must not be HOME, ~/.dsh/AGENT_PRESETS_DIR, docs/ or the filesystem root (confined rendering)');
  }
  const s = fleetSummary(doc);
  const files = {};
  files['fleet.json'] = JSON.stringify({ generated_by: 'tools/fleet.js', fleet: s }, null, 2) + '\n';
  for (const t of doc.teams) {
    const md = ['# Fleet team — ' + t.name, '', `Color: ${t.color} · Order: ${t.order || 0}`, '',
      '| Agent | Role | Preset | Keys |', '|---|---|---|---|'];
    for (const a of t.agents) md.push(`| ${a.id} | ${a.role} | ${a.preset} | ${(a.requires_keys || []).join(', ') || '—'} |`);
    if (t.artifacts && t.artifacts.length) {
      md.push('', 'Artifacts (template dichiarativi):', '');
      for (const a of t.artifacts) md.push(`- \`${a.path}\`${a.surface ? ' (surface: ' + a.surface + ')' : ''}`);
    }
    files[`agents-${t.name}.md`] = md.join('\n') + '\n';
  }
  return { files, summary: s };
}

function writeRender(outDir, files, backup) {
  fs.mkdirSync(outDir, { recursive: true });
  if (backup) {
    const bk = path.join(outDir, '.backup-fleet', new Date().toISOString().replace(/[:.]/g, '-'));
    const prev = Object.keys(files).filter((f) => fs.existsSync(path.join(outDir, f)));
    if (prev.length) {
      fs.mkdirSync(bk, { recursive: true });
      for (const f of prev) fs.copyFileSync(path.join(outDir, f), path.join(bk, f));
      const sums = prev.map((f) => require('crypto').createHash('sha256').update(fs.readFileSync(path.join(outDir, f))).digest('hex') + '  ' + f);
      fs.writeFileSync(path.join(bk, 'SHA256SUMS'), sums.join('\n') + '\n');
    }
  }
  for (const [f, content] of Object.entries(files)) {
    const tmp = path.join(outDir, f + '.' + process.pid);
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, path.join(outDir, f));
  }
}

function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  try {
    const { doc } = loadFleet(opt('--file'));
    if (cmd === 'plan') {
      console.log(JSON.stringify({ execution_plan: true, fleet: fleetSummary(doc) }, null, 2));
      return 0;
    }
    if (cmd === 'render') {
      const out = opt('--out');
      if (!out) { console.error('render richiede --out <dir>'); return 2; }
      const { files, summary } = render(doc, out);
      writeRender(out, files, false);
      console.log(JSON.stringify({ ok: true, out, files: Object.keys(files), agents: summary.totals.agents }));
      return 0;
    }
    if (cmd === 'apply') {
      const out = opt('--out');
      if (!out) { console.error('apply richiede --out <dir>'); return 2; }
      if (!argv.includes('--yes')) { console.error('apply rifiutato: serve --yes esplicito (backup preventivo incluso)'); return 1; }
      const { files, summary } = render(doc, out);
      writeRender(out, files, true);
      const marker = path.join(out, '.fleet-applied.json');
      fs.writeFileSync(marker, JSON.stringify({ applied_at: new Date().toISOString(), name: summary.name, agents: summary.totals.agents }) + '\n');
      console.log(JSON.stringify({ ok: true, applied: true, out, files: Object.keys(files), marker, agents: summary.totals.agents }));
      return 0;
    }
    console.error('usage: node tools/fleet.js plan | render --out <dir> | apply --yes --out <dir>');
    return 2;
  } catch (e) {
    console.error(String(e.message || e));
    return 1;
  }
}

if (require.main === module) process.exit(main());

module.exports = { loadFleet, validateFleet, fleetSummary, render, parseYaml };
