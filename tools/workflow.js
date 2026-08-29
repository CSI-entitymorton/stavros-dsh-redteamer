#!/usr/bin/env node
// Declarative workflow runner (Ondata 2 — C1w + E7). Executes a YAML "dialetto workflow"
// file where EVERY step is a scope-enforcing wrapper call: cmd must always start with
//   node tools/run.js <binary> ...
// so scope-guard/enforce/audit coverage is inherited by construction (never bypassed).
//
// Dialect (validated fail-closed):
//   name: <required>            description: <optional>
//   vars: {k: default-scalar}   --var k=v overrides; {target}/{var} placeholders everywhere
//   requires: [binaries]        preflight presence (via tools/tool-plane hasBin) BEFORE anything
//   steps[]:
//     id: unique required
//     cmd: required, MUST start with 'node tools/run.js '
//     when: {exit_code: N|[..], file_exists: path}   (AND-ed; exit_code = last EXECUTED step)
//     parallel_group: <label>  consecutive steps sharing a label run concurrently (Promise.all)
//     on_error: stop (default) | continue   ('continue' is explicit opt-in in the YAML)
//     artifacts: [{path, surface}]  verified after the step, appended to evidence-index.md and
//                                   folded into reports/tmp/coverage-workflow.json
//   decisions: [{id, when: {file_contains: {path,text} | env: {name, equals?}}, then: {set_var: {name, value}}}]
//     (E6, Ondata 4/rimandati, OPZIONALE) DECISIONI deterministiche codificate in YAML, mai
//     affidate alla memoria dell'agente. Esempio d'uso: un probe scrive reports/tmp/waf.txt
//     con "WAF" → decisione set_var rate=slow → i cmd successivi usano {rate}.
//     Valutate in ordine, PRIMA della risoluzione dei placeholder (possono vedersi a vicenda);
//     le variabili impostate finiscono nel vars map usato da {placeholder} ovunque.
//   reports: {<fase>: [{path, type, surface}]}   (E3, Ondata 4, OPZIONALE) dichiarazione
//     DICHIARATIVA dei report attesi per fase stage-gate: gate.js la consuma con
//     --workflow <file> (o GATE_WORKFLOW_FILE) sostituendo i check 'file' hardcoded della fase
//     (fail-closed: report dichiarato ma mancante → gate FAIL). Fasi senza reports: →
//     comportamento legacy (elenco hardcoded). Mai toccati i check chain/oracle/evidenceQuote.
//
// CLI:
//   node tools/workflow.js run <file.yaml> -t <target> [--dry-run] [--only-step id] [--var k=v]...
//   node tools/workflow.js validate <file.yaml>
// E7: --dry-run prints the execution-plan (waves, resolved cmds, requires status, target scope
// verdict) and executes NOTHING: no spawn, no log file, no evidence/coverage writes.
//
// YAML parsing: python3+PyYAML subprocess when importable, otherwise a documented mini-parser
// for the strict subset above (indentation-based; unsupported syntax fails loudly instead of
// guessing). WORKFLOW_NO_PYYAML=1 forces the mini-parser (used by tests for parity).
//
// Logs: reports/tmp/workflow/<name>-<ts>.jsonl — one JSON line per step
// {ts,name,step,bin,args,cmd,exit,ms,artifacts} (+ run_start/run_summary lines). The per-step
// shape also carries bin/args so loop-watch can consume the same stream.
// Target safety: at run/dry-run time the -t target is scope-checked (CIDR -> cidrInScope,
// else canonTarget+inScope) against the SAME scope.json as run.js; a target out of scope
// blocks everything (fail-closed), including dry-run (plan reports it).

'use strict';
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { execFileSync } = require('child_process');
const { loadScope, inScope, cidrInScope, canonTarget } = require('./scope-guard');
const { hasBin } = require('./tool-plane');

// F5 (ondata 3, additivo): le artifacts REALI prodotti dai workflow vengono registrate nel
// ledger Action→Artifact (producer=workflow, action_id=workflow:<name>:<step>). Il ledger
// NON blocca mai il workflow: un errore di registrazione è visibile nel summary, non fatale.
const ARTIFACT_LEDGER_FILE = process.env.ARTIFACT_LEDGER_FILE || null; // default del modulo ledger
function ledgerRecordWorkflowArtifacts(planName, results) {
  const out = { recorded: 0, error: null };
  try {
    const ledger = require('./artifact-ledger');
    const file = ARTIFACT_LEDGER_FILE || ledger.resolveLedgerFile({});
    for (const r of results) {
      for (const a of (r.artifacts || [])) {
        if (!a.exists) continue;
        const entry = ledger.buildEntry(file, {
          action: `workflow:${planName}:${r.id}`,
          producer: 'workflow',
          kind: a.surface || 'artifact',
          exit: r.exit,
        }, path.resolve(opts_cwd_safe(), a.path));
        ledger.recordEntry(file, entry);
        out.recorded++;
      }
    }
  } catch (e) { out.error = String(e.message || e); }
  return out;
}
function opts_cwd_safe() {
  // executePlan passa cwd via opts; qui usiamo process.cwd() (stessa base del run).
  return process.cwd();
}

const WS_ROOT = path.join(__dirname, '..');
const LOG_DIR = process.env.WORKFLOW_LOG_DIR || path.join(WS_ROOT, 'reports', 'tmp', 'workflow');
const COVERAGE_FILE = process.env.COVERAGE_WORKFLOW_FILE || path.join(WS_ROOT, 'reports', 'tmp', 'coverage-workflow.json');
const EVIDENCE_FILE = process.env.EVIDENCE_INDEX_FILE || path.join(WS_ROOT, 'evidence-index.md');
const CMD_PREFIX = 'node tools/run.js ';

// ---------------------------------------------------------------- YAML loading

function pyYamlAvailable() {
  if (process.env.WORKFLOW_NO_PYYAML === '1') return false;
  try {
    execFileSync('python3', ['-c', 'import yaml'], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

function parseWithPyYaml(text) {
  const out = execFileSync('python3', ['-c',
    'import sys,yaml,json;json.dump(yaml.safe_load(sys.stdin.read()),sys.stdout)'],
  { input: text });
  return JSON.parse(out.toString('utf8'));
}

// Mini-parser for the documented subset. Indentation-driven, strictly typed: any construct
// outside the dialect is a hard error naming the line (never a silent guess).
function parseSubset(text) {
  const root = {};
  const stack = [{ indent: -1, obj: root }];
  let curStep = null;
  let curMapKey = null; // 'vars' | 'when'
  let curWhen = null;
  let curArt = null;
  let curRep = null; // E3: item di reports:<fase> (stesso shape di artifacts: path/type/surface)
  let lines = text.split(/\r?\n/);
  lines.forEach((rawLine, idx) => {
    const ln = idx + 1;
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) return;
    if (!/^(\s*)([A-Za-z_][\w-]*|-\s?)/.test(rawLine)) fail(ln, rawLine);
    const indent = rawLine.match(/^\s*/)[0].length;
    if (rawLine.includes('\t')) fail(ln, rawLine, 'tab indentation not allowed in mini-parser');
    while (stack.length && indent <= stack[stack.length - 1].indent && stack.length > 1) {
      stack.pop();
      const top = stack[stack.length - 1];
      if (top.key === 'steps') curStep = null;
      if (top.key === 'vars') curMapKey = null;
      if (top.key === 'when') { curWhen = null; curMapKey = curMapKey === 'when' ? null : curMapKey; }
      if (top.key === 'artifacts') curArt = null;
      if (top.key === 'reports-phase') curRep = null; // E3
    }
    const ctx = stack[stack.length - 1];
    const body = rawLine.trim();
    if (body.startsWith('- ')) {
      const item = body.slice(2).trim();
      if (ctx.key === 'requires') { ctx.obj.push(scalar(item, ln)); return; }
      if (ctx.key === 'artifacts') {
        if (!item.startsWith('path:')) fail(ln, rawLine, 'artifact items need "path:" inline or an indented block');
        curArt = { path: scalar(item.slice(5).trim(), ln) };
        ctx.obj.push(curArt);
        stack.push({ indent, key: 'artifacts-item', obj: curArt });
        return;
      }
      if (ctx.key === 'reports-phase') {
        // E3: item di reports:<fase> — stesso shape di artifacts (path obbligatorio, type/surface opzionali)
        if (!item.startsWith('path:')) fail(ln, rawLine, 'reports items need "path:" inline or an indented block');
        curRep = { path: scalar(item.slice(5).trim(), ln) };
        ctx.obj.push(curRep);
        stack.push({ indent, key: 'reports-item', obj: curRep });
        return;
      }
      if (ctx.key === 'steps') {
        if (!item.startsWith('id:')) fail(ln, rawLine, 'every step must start with "- id:" in the mini-parser');
        curStep = { id: scalar(item.slice(3).trim(), ln) };
        ctx.obj.push(curStep);
        stack.push({ indent, key: 'steps', obj: curStep });
        return;
      }
      fail(ln, rawLine, 'list items are only supported under requires/steps/artifacts/reports');
    }
    const m = body.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
    if (!m) fail(ln, rawLine);
    const [, k, vRaw] = m;
    const v = vRaw.trim();
    if (ctx.key === 'steps' && curStep) {
      if (k === 'when') {
        curStep.when = {}; curWhen = curStep.when; stack.push({ indent, key: 'when', obj: curWhen }); return;
      }
      if (k === 'artifacts') {
        curStep.artifacts = []; stack.push({ indent, key: 'artifacts', obj: curStep.artifacts }); return;
      }
      if (k === 'cmd' && v.startsWith('|')) fail(ln, rawLine, 'block scalars not supported by mini-parser');
      curStep[k] = k === 'on_error' || k === 'parallel_group' ? scalar(v, ln) : scalar(v, ln);
      return;
    }
    if (ctx.key === 'when' && curWhen) { curWhen[k] = scalar(v, ln); return; }
    if (ctx.key === 'artifacts-item' && curArt) { curArt[k] = scalar(v, ln); return; }
    if (ctx.key === 'reports-item' && curRep) { curRep[k] = scalar(v, ln); return; } // E3
    if (ctx.key === 'reports') {
      // E3: <fase>: → lista di item {path,type,surface}
      if (v !== '') fail(ln, rawLine, `reports.${k} must be a block list, not inline`);
      const list = [];
      ctx.obj[k] = list;
      stack.push({ indent, key: 'reports-phase', obj: list });
      return;
    }
    // mapping content of a structural block (vars: k: v)
    if (ctx.key === 'vars') { ctx.obj[k] = scalar(v, ln); return; }
    // top-level-ish keys
    // structural keys: block-style ONLY in the mini-parser — an inline value here would be
    // silently discarded otherwise (silent guess = forbidden).
    if (k === 'vars' || k === 'requires' || k === 'steps' || k === 'reports') {
      if (v !== '') throw new Error(`mini-parser: "${k}: ${v}" uses inline/flow syntax (line ${ln}) — use block lists (or install python3-PyYAML)`);
      if (k === 'vars') { root.vars = {}; stack.push({ indent, key: 'vars', obj: root.vars }); curMapKey = 'vars'; return; }
      if (k === 'requires') { root.requires = []; stack.push({ indent, key: 'requires', obj: root.requires }); return; }
      if (k === 'reports') { root.reports = {}; stack.push({ indent, key: 'reports', obj: root.reports }); return; } // E3
      root.steps = []; stack.push({ indent, key: 'steps', obj: root.steps }); return;
    }
    if (root[k] !== undefined) fail(ln, rawLine, `duplicate key ${k}`);
    root[k] = scalar(v, ln);
  });
  return root;

  function fail(ln, rawLine, why) {
    throw new Error(`mini-parser: unsupported syntax at line ${ln}: ${JSON.stringify(rawLine.slice(0, 80))}${why ? ' — ' + why : ''} (install python3-PyYAML for full YAML)`);
  }
}

function scalar(s, ln) {
  s = String(s == null ? '' : s).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1);
  if (s === '') return null;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^(true|false)$/.test(s)) return s === 'true';
  if (/^null$/.test(s)) return null;
  // NOTE: {placeholder} braces are LEGAL in scalars; only flow-sequence brackets are refused.
  if (/[\[\]]/.test(s)) throw new Error(`mini-parser: flow syntax "${s}" unsupported (line ${ln}) — use block lists`);
  return s;
}

function loadWorkflow(file) {
  const text = fs.readFileSync(file, 'utf8');
  const data = pyYamlAvailable() ? parseWithPyYaml(text) : parseSubset(text);
  return { doc: data, parser: pyYamlAvailable() ? 'pyyaml' : 'mini' };
}

// ---------------------------------------------------------------- validation

function validateDoc(doc) {
  const errs = [];
  const push = (m) => errs.push(m);
  if (!doc || typeof doc !== 'object') push('document is not a mapping');
  else {
    if (!doc.name || typeof doc.name !== 'string') push('"name" (string) is required');
    else if (!/^[a-z0-9][a-z0-9._-]*$/i.test(doc.name)) push(`bad workflow name: ${doc.name}`);
    if (doc.vars != null && (typeof doc.vars !== 'object' || Array.isArray(doc.vars))) push('"vars" must be a mapping of scalars');
    if (!Array.isArray(doc.steps) || !doc.steps.length) push('"steps" must be a non-empty list');
    else {
      const seen = new Set();
      doc.steps.forEach((s, i) => {
        const at = `step[${i}]`;
        if (!s || typeof s !== 'object') { push(`${at}: not a mapping`); return; }
        if (!s.id || typeof s.id !== 'string') push(`${at}: "id" required`);
        else if (seen.has(s.id)) push(`${at}: duplicate step id "${s.id}"`);
        else seen.add(s.id);
        if (typeof s.cmd !== 'string' || !s.cmd.trim().startsWith(CMD_PREFIX)) {
          push(`${at}: cmd MUST start with "${CMD_PREFIX}" (got ${JSON.stringify(String(s.cmd || '').slice(0, 60))})`);
        }
        if (s.when != null) {
          if (typeof s.when !== 'object' || Array.isArray(s.when)) push(`${at}: "when" must be a mapping`);
          else {
            if (s.when.exit_code != null && !Number.isInteger(s.when.exit_code) && !(Array.isArray(s.when.exit_code) && s.when.exit_code.every(Number.isInteger))) {
              push(`${at}: when.exit_code must be an int or int[]`);
            }
            if (s.when.file_exists != null && typeof s.when.file_exists !== 'string') push(`${at}: when.file_exists must be a path string`);
          }
        }
        if (s.on_error != null && !['stop', 'continue'].includes(s.on_error)) push(`${at}: on_error must be stop|continue`);
        if (s.artifacts != null) {
          if (!Array.isArray(s.artifacts)) push(`${at}: artifacts must be a list`);
          else s.artifacts.forEach((a, j) => {
            if (!a || typeof a.path !== 'string' || !a.path.trim()) push(`${at}.artifacts[${j}]: "path" required`);
          });
        }
      });
    }
    if (doc.requires != null && !Array.isArray(doc.requires)) push('"requires" must be a list of binary names');
    // E6 (rimandati): decisions: — decisioni deterministiche codificate in YAML.
    if (doc.decisions != null) {
      if (!Array.isArray(doc.decisions)) push('"decisions" must be a list');
      else doc.decisions.forEach((d, i) => {
        const at = `decisions[${i}]`;
        if (!d || typeof d !== 'object' || Array.isArray(d)) { push(`${at}: item must be a mapping`); return; }
        if (typeof d.id !== 'string' || !d.id.trim()) { push(`${at}: "id" required`); return; }
        if (!d.when || typeof d.when !== 'object' || Array.isArray(d.when)) { push(`${at}: "when" required (file_contains | env)`); return; }
        const hasFile = d.when.file_contains && typeof d.when.file_contains === 'object' &&
          typeof d.when.file_contains.path === 'string' && d.when.file_contains.path.trim() &&
          typeof d.when.file_contains.text === 'string' && d.when.file_contains.text.trim() !== '';
        const hasEnv = d.when.env && typeof d.when.env === 'object' && typeof d.when.env.name === 'string' && d.when.env.name.trim();
        if (!hasFile && !hasEnv) push(`${at}: when must be {file_contains:{path,text}} or {env:{name,equals?}}`);
        if (d.when.env && d.when.env.equals !== undefined && typeof d.when.env.equals !== 'string' && typeof d.when.env.equals !== 'number' && typeof d.when.env.equals !== 'boolean')
          push(`${at}: when.env.equals must be a scalar`);
        if (!d.then || typeof d.then !== 'object' || !d.then.set_var || typeof d.then.set_var.name !== 'string' || !d.then.set_var.name.trim())
          push(`${at}: then.set_var {name,value} required`);
      });
    }
    // E3 (Ondata 4): reports:<fase> — dichiarazione DICHIARATIVA dei report attesi per il
    // stage-gate. Shape: {path obbligatorio, type? string, surface? string}. Consumata da
    // gate.js --workflow; qui solo validazione della forma.
    if (doc.reports != null) {
      if (typeof doc.reports !== 'object' || Array.isArray(doc.reports)) push('"reports" must be a mapping <phase> -> list of {path,type,surface}');
      else for (const [phase, list] of Object.entries(doc.reports)) {
        if (!Array.isArray(list) || !list.length) push(`reports.${phase}: must be a non-empty list`);
        else list.forEach((r, j) => {
          const at = `reports.${phase}[${j}]`;
          if (!r || typeof r !== 'object' || Array.isArray(r)) { push(`${at}: item must be a mapping`); return; }
          if (typeof r.path !== 'string' || !r.path.trim()) push(`${at}: "path" required`);
          if (r.type != null && typeof r.type !== 'string') push(`${at}: type must be a string`);
          if (r.surface != null && typeof r.surface !== 'string') push(`${at}: surface must be a string`);
        });
      }
    }
  }
  return errs;
}

// ---------------------------------------------------------------- substitution & plan

function subst(template, vars, what) {
  return String(template).replace(/\{([A-Za-z_][\w-]*)\}/g, (_, k) => {
    if (!(k in vars) || vars[k] == null) throw new Error(`unresolved placeholder {${k}} in ${what} (pass --var ${k}=... )`);
    return String(vars[k]);
  });
}

// F9 (rimandati): PATCH DEL PIANO A CALDO — overlay di step applicato PRIMA della risoluzione
// dei placeholder (le patch possono usare {var}); i campi non toccati restano; step inesistente
// → errore fail-closed. Il goal non viene riavviato: si modificano obiettivo/criteri del singolo
// subtask a run-in-corso (workflow.js run --patch <overlay.yaml>).
function validatePatch(overlay) {
  const errs = [];
  if (!overlay || typeof overlay !== 'object' || Array.isArray(overlay) || !Array.isArray(overlay.steps) || !overlay.steps.length)
    return ['patch must be a mapping with a non-empty steps list'];
  overlay.steps.forEach((p, i) => {
    const at = `patch.steps[${i}]`;
    if (!p || typeof p !== 'object' || Array.isArray(p)) { errs.push(`${at}: must be a mapping`); return; }
    if (typeof p.id !== 'string' || !p.id.trim()) { errs.push(`${at}: id required`); return; }
    const hasField = ['cmd', 'when', 'on_error', 'artifacts'].some((k) => p[k] !== undefined);
    if (!hasField) errs.push(`${at}: at least one of cmd/when/on_error/artifacts`);
    if (p.cmd !== undefined && (typeof p.cmd !== 'string' || !p.cmd.trim().startsWith(CMD_PREFIX)))
      errs.push(`${at}: cmd MUST start with "${CMD_PREFIX}"`);
    if (p.on_error !== undefined && !['stop', 'continue'].includes(p.on_error)) errs.push(`${at}: on_error must be stop|continue`);
    if (p.when !== undefined && (typeof p.when !== 'object' || Array.isArray(p.when))) errs.push(`${at}: when must be a mapping`);
    if (p.artifacts !== undefined && (!Array.isArray(p.artifacts) || p.artifacts.some((a) => !a || typeof a.path !== 'string' || !a.path.trim())))
      errs.push(`${at}: artifacts must be a list of {path}`);
  });
  return errs;
}

function applyPatch(doc, overlay) {
  const out = { ...doc, steps: doc.steps.map((s) => ({ ...s })) };
  const byId = new Map(out.steps.map((s) => [s.id, s]));
  for (const p of overlay.steps) {
    const target = byId.get(p.id);
    if (!target) throw new Error(`patch: no step with id "${p.id}" in the plan (fail-closed)`);
    for (const k of ['cmd', 'when', 'on_error', 'artifacts']) {
      if (p[k] !== undefined) target[k] = JSON.parse(JSON.stringify(p[k]));
    }
  }
  return out;
}

// E6: valuta le decisioni dichiarative in ORDINE, partendo dal vars map corrente; ogni
// decisione vera applica then.set_var (visibile alle successive e ai {placeholder}).
// Condizioni supportate (deterministiche, offline): file_contains (path relativo a opts.cwd,
// contiene il testo) e env (variabile == equals, o presente se equals omesso).
// Ritorna { vars, applied:[{id, reason}] }.
function evaluateDecisions(doc, baseVars, opts) {
  opts = opts || {};
  const vars = Object.assign({}, baseVars || {});
  const applied = [];
  for (const d of (doc && Array.isArray(doc.decisions) ? doc.decisions : [])) {
    const w = d.when || {};
    let hit = null;
    if (w.file_contains) {
      const full = path.isAbsolute(w.file_contains.path)
        ? w.file_contains.path
        : path.resolve(opts.cwd || process.cwd(), w.file_contains.path);
      let text = '';
      try { text = fs.readFileSync(full, 'utf8'); } catch {}
      if (text.includes(w.file_contains.text)) hit = `file_contains ${w.file_contains.path}`;
    } else if (w.env) {
      const val = process.env[w.env.name];
      if (w.env.equals === undefined ? val !== undefined && val !== '' : String(val) === String(w.env.equals))
        hit = `env ${w.env.name}${w.env.equals !== undefined ? '=' + w.env.equals : ''}`;
    }
    if (hit) {
      vars[d.then.set_var.name] = d.then.set_var.value;
      applied.push({ id: d.id, reason: hit, set_var: d.then.set_var.name, value: d.then.set_var.value });
    }
  }
  return { vars, applied };
}

function buildPlan(doc, opts) {
  const vars = Object.assign({}, doc.vars || {}, opts.extraVars, { target: opts.target });
  // E6: decisioni dichiarative PRIMA della risoluzione dei placeholder (il loro set_var
  // alimenta {rate} ecc.); le decisioni applicate sono esposte nel plan (dry-run compreso).
  const decided = evaluateDecisions(doc, vars, opts);
  Object.assign(vars, decided.vars);
  // Fail-closed placeholder resolution FIRST (unknown {x} never reaches a command line).
  for (const s of doc.steps) {
    subst(s.cmd, vars, `step ${s.id} cmd`);
    if (s.when && s.when.file_exists) subst(s.when.file_exists, vars, `step ${s.id} when.file_exists`);
    (s.artifacts || []).forEach((a) => subst(a.path, vars, `step ${s.id} artifact`));
  }
  const requires = (doc.requires || []).map((b) => ({ bin: b, present: !!hasBin(b) }));
  const steps = [];
  let wave = [];
  let waveGroup = null;
  const flush = () => { if (wave.length) steps.push({ parallel: wave.length > 1, group: waveGroup, steps: wave }); wave = []; waveGroup = null; };
  for (const s of doc.steps) {
    const g = s.parallel_group || null;
    if (g && waveGroup === g) wave.push(resolve(s));
    else { flush(); waveGroup = g; wave = [resolve(s)]; if (!g) flush(); }
  }
  flush();
  function resolve(s) {
    return {
      id: s.id,
      cmd: subst(s.cmd, vars, `step ${s.id} cmd`),
      // NB: exit_code 0 is a VALID gate value — never use truthiness here.
      when_exit_code: (s.when && s.when.exit_code != null) ? s.when.exit_code : null,
      when_file_exists: (s.when && s.when.file_exists) ? subst(s.when.file_exists, vars, `step ${s.id} when`) : null,
      on_error: s.on_error || 'stop',
      artifacts: (s.artifacts || []).map((a) => ({ path: subst(a.path, vars, `step ${s.id} artifact`), surface: a.surface || null })),
    };
  }
  return { name: doc.name, description: doc.description || '', target: opts.target, vars, requires, waves: steps, decisions: decided.applied };
}

function checkTargetScope(target, scope) {
  if (cidrParseSafe(target)) {
    const v = cidrInScope(target, scope);
    return { ok: !!v.ok, reason: v.reason || (v.ok ? 'ip/cidr allowlisted' : 'cidr out of scope') };
  }
  const c = canonTarget(/^https?:\/\//i.test(target) ? target : 'http://' + target);
  if (!c.ok) return { ok: false, reason: 'canon: ' + c.reason };
  const v = inScope(c.canonical, scope);
  return { ok: !!v.ok, reason: v.reason || '' , canonical: c.canonical };
}
function cidrParseSafe(t) { return /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(t); }

// ---------------------------------------------------------------- execution

function tokenize(cmd) {
  const out = []; const re = /[^\s"']+|"([^"]*)"|'([^']*)'/g; let m;
  while ((m = re.exec(cmd))) out.push(m[1] != null ? m[1] : (m[2] != null ? m[2] : m[0]));
  return out;
}

function spawnCapture(bin, args) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => resolve({ code: 127, ms: Date.now() - t0, stdout: '', stderr: String(e.message), spawnError: true }));
    child.on('close', (code) => resolve({ code: code == null ? 1 : code, ms: Date.now() - t0, stdout: out, stderr: err }));
  });
}

function nextEvidenceNumber() {
  try {
    const txt = fs.readFileSync(EVIDENCE_FILE, 'utf8');
    let max = 0;
    for (const m of txt.matchAll(/^\|\s*E-(\d+)\s*\|/gm)) max = Math.max(max, parseInt(m[1], 10));
    return max + 1;
  } catch { return 1; }
}

function appendEvidence(rows) {
  if (!rows.length) return null;
  fs.mkdirSync(path.dirname(EVIDENCE_FILE), { recursive: true });
  let n = nextEvidenceNumber();
  const date = new Date().toISOString().slice(0, 10);
  const lines = rows.map((r) => `| E-${String(n++).padStart(3, '0')} | ${date} | \`${r.artifact}\` | workflow \`${r.workflow}\` step \`${r.step}\` artefatto prodotto (surface: ${r.surface || 'n/a'}; exit ${r.exit}) | workflow.js |`);
  fs.appendFileSync(EVIDENCE_FILE, lines.join('\n') + '\n');
  return n - 1;
}

function updateCoverage(planName, executedSteps, target) {
  let data = {};
  try { data = JSON.parse(fs.readFileSync(COVERAGE_FILE, 'utf8')); } catch {}
  data.workflows = data.workflows || {};
  data.workflows[planName] = {
    last_ts: new Date().toISOString(),
    targets: Array.from(new Set([...((data.workflows[planName] || {}).targets || []), target])),
    steps: executedSteps.map((s) => ({ id: s.id, exit: s.exit == null ? null : s.exit, skipped: s.skipped || null, artifacts: (s.artifacts || []).map((a) => a.path) })),
  };
  fs.mkdirSync(path.dirname(COVERAGE_FILE), { recursive: true });
  const tmp = COVERAGE_FILE + '.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(tmp, COVERAGE_FILE);
}

async function executePlan(plan, opts) {
  fs.mkdirSync(opts.logDir, { recursive: true });
  const logFile = path.join(opts.logDir, `${plan.name}-${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`);
  const logLine = (obj) => fs.appendFileSync(logFile, JSON.stringify(obj) + '\n');
  logLine({ ts: new Date().toISOString(), event: 'run_start', name: plan.name, target: plan.target, dry_run: false });

  const results = [];
  let lastExit = null;
  let aborted = false;
  let firstFail = null;
  for (const w of plan.waves) {
    if (aborted) {
      for (const s of w.steps) results.push({ ...s, skipped: 'aborted', exit: null, ms: null, artifacts: [] });
      continue;
    }
    const waveOut = await Promise.all(w.steps.map(async (s) => {
      // `when` gating (evaluated against state from BEFORE this wave → deterministic).
      if (s.when_file_exists && !fs.existsSync(path.resolve(opts.cwd, s.when_file_exists))) {
        logLine({ ts: new Date().toISOString(), event: 'step_skipped', name: plan.name, step: s.id, reason: 'when.file_exists absent: ' + s.when_file_exists });
        return { ...s, skipped: 'when.file_exists', exit: null, ms: null, artifacts: [] };
      }
      if (s.when_exit_code != null) {
        const want = Array.isArray(s.when_exit_code) ? s.when_exit_code : [s.when_exit_code];
        if (lastExit == null || !want.includes(lastExit)) {
          logLine({ ts: new Date().toISOString(), event: 'step_skipped', name: plan.name, step: s.id, reason: `when.exit_code wanted ${want}, last executed exit ${lastExit}` });
          return { ...s, skipped: 'when.exit_code', exit: null, ms: null, artifacts: [] };
        }
      }
      const toks = tokenize(s.cmd);
      const bin = toks[0]; const args = toks.slice(1);
      const r = await spawnCapture(bin, args);
      const rec = { ...s, exit: r.code, ms: r.ms, stdout_tail: r.stdout.split('\n').filter(Boolean).slice(-3).join(' | ').slice(0, 300) || undefined, stderr_tail: r.stderr.split('\n').filter(Boolean).slice(-2).join(' | ').slice(0, 300) || undefined };
      rec.bin = bin; rec.args = args; // loop-watch compatible fields
      rec.artifacts = s.artifacts.map((a) => ({ ...a, exists: fs.existsSync(path.resolve(opts.cwd, a.path)) }));
      delete rec.when_exit_code; delete rec.when_file_exists;
      logLine({ ts: new Date().toISOString(), event: 'step', name: plan.name, step: rec.id, bin: rec.bin, args: rec.args, cmd: rec.cmd, exit: rec.exit, ms: rec.ms, artifacts: rec.artifacts });
      return rec;
    }));
    for (const rec of waveOut) results.push(rec);
    const executed = waveOut.filter((r) => r.skipped == null);
    if (executed.length) lastExit = executed[executed.length - 1].exit;
    for (const rec of executed) {
      if (rec.exit !== 0 && rec.on_error === 'stop') { aborted = true; firstFail = firstFail || rec; }
    }
  }
  const summary = {
    ts: new Date().toISOString(), event: 'run_summary', name: plan.name, target: plan.target,
    ok: !firstFail, failed_step: firstFail ? firstFail.id : null, steps_total: results.length,
    executed: results.filter((r) => r.skipped == null).length, skipped: results.filter((r) => r.skipped != null).length,
    log: logFile,
  };
  logLine(summary);
  updateCoverage(plan.name, results, plan.target);
  const evRows = [];
  // Only EXISTING artifacts are registered as evidence (an artifact declared but never
  // produced is visible in the log/coverage, never in evidence-index.md).
  for (const r of results) for (const a of (r.artifacts || [])) if (a.exists) evRows.push({ artifact: a.path, workflow: plan.name, step: r.id, surface: a.surface, exit: r.exit });
  const evidenceUpTo = appendEvidence(evRows);
  summary.evidence_rows = evRows.length;
  // F5 hook (additive, non-blocking): mirror existing artifacts into the action→artifact ledger.
  const ledgered = ledgerRecordWorkflowArtifacts(plan.name, results);
  summary.artifacts_ledgered = ledgered.recorded;
  if (ledgered.error) summary.artifacts_ledger_error = ledgered.error;
  return { results, summary, logFile, evidenceUpTo, firstFail };
}

// ---------------------------------------------------------------- CLI

function printPlan(plan, scopeVerdict, missingRequires) {
  console.log(JSON.stringify({
    execution_plan: true, name: plan.name, description: plan.description, target: plan.target,
    target_scope: scopeVerdict,
    decisions_applied: plan.decisions || [],
    requires: plan.requires.map((r) => ({ bin: r.bin, present: r.present })),
    waves: plan.waves.map((w, i) => ({
      wave: i + 1, parallel: w.parallel, group: w.group,
      steps: w.steps.map((s) => ({
        id: s.id, cmd: s.cmd, on_error: s.on_error,
        when: { exit_code: s.when_exit_code, file_exists: s.when_file_exists },
        artifacts: s.artifacts,
      })),
    })),
    missing_requires: missingRequires,
  }, null, 2));
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (cmd === 'validate' || cmd === 'run') {
    const file = argv[1];
    if (!file || file.startsWith('-')) { usage(); process.exit(2); }
    let loaded;
    try { loaded = loadWorkflow(file); } catch (e) {
      console.error(JSON.stringify({ ok: false, error: 'yaml-parse-failed: ' + e.message, parser_hint: 'install python3-PyYAML or fix the mini-parser subset violation' }));
      process.exit(1);
    }
    const errs = validateDoc(loaded.doc);
    if (errs.length) {
      console.error(JSON.stringify({ ok: false, error: 'dialect-validation-failed', errors: errs, parser: loaded.parser }));
      process.exit(1);
    }
    if (cmd === 'validate') { console.log(JSON.stringify({ ok: true, name: loaded.doc.name, steps: loaded.doc.steps.length, parser: loaded.parser })); return; }

    const rest = argv.slice(2);
    let target = null; let onlyStep = null; let patchFile = null; const extraVars = {};
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '-t' || rest[i] === '--target') target = rest[++i];
      else if (rest[i] === '--only-step') onlyStep = rest[++i];
      else if (rest[i] === '--patch') patchFile = rest[++i]; // F9: overlay a caldo
      else if (rest[i] === '--var' || rest[i] === '-v') { const kv = String(rest[++i] || '').split('='); extraVars[kv[0]] = kv.slice(1).join('='); }
    }
    if (!target) { console.error(JSON.stringify({ ok: false, error: 'missing -t <target>' })); process.exit(2); }

    // F9: patch del piano a caldo — overlay validato (fail-closed) applicato PRIMA del buildPlan.
    let docToPlan = loaded.doc;
    if (patchFile) {
      let overlay;
      try { overlay = loadWorkflow(patchFile).doc; } catch (e) {
        console.error(JSON.stringify({ ok: false, error: 'patch load failed: ' + e.message })); process.exit(1);
      }
      const perrs = validatePatch(overlay);
      if (perrs.length) {
        console.error(JSON.stringify({ ok: false, error: 'patch invalid', errors: perrs })); process.exit(1);
      }
      try { docToPlan = applyPatch(loaded.doc, overlay); } catch (e) {
        console.error(JSON.stringify({ ok: false, error: e.message })); process.exit(1);
      }
    }

    let plan;
    try { plan = buildPlan(docToPlan, { target, extraVars }); } catch (e) {
      console.error(JSON.stringify({ ok: false, error: e.message })); process.exit(1);
    }
    if (onlyStep) {
      const found = plan.waves.some((w) => w.steps.some((s) => s.id === onlyStep));
      if (!found) { console.error(JSON.stringify({ ok: false, error: `--only-step: no step "${onlyStep}" in ${plan.name}` })); process.exit(2); }
      plan.waves = plan.waves.map((w) => ({ ...w, steps: w.steps.filter((s) => s.id === onlyStep) })).filter((w) => w.steps.length);
    }
    const missingRequires = plan.requires.filter((r) => !r.present).map((r) => r.bin);
    const scope = loadScope();
    const scopeVerdict = checkTargetScope(target, scope);
    if (missingRequires.length || !scopeVerdict.ok) {
      console.error(JSON.stringify({ ok: false, error: 'preflight-failed', missing_requires: missingRequires, target_scope: scopeVerdict }));
      process.exit(1);
    }
    if (argv.includes('--dry-run')) { printPlan(plan, scopeVerdict, missingRequires); return; } // E7: nothing executed, nothing written

    const out = await executePlan(plan, { logDir: LOG_DIR, cwd: process.cwd() });
    console.log(JSON.stringify({ ok: out.summary.ok, name: plan.name, target: plan.target, summary: out.summary, steps: out.results.map((r) => ({ id: r.id, exit: r.exit, skipped: r.skipped || undefined, ms: r.ms, artifacts: (r.artifacts || []).map((a) => ({ path: a.path, exists: a.exists })) })) }, null, 2));
    process.exit(out.summary.ok ? 0 : (out.firstFail ? Math.max(out.firstFail.exit, 1) : 1));
  } else usage();

  function usage() {
    console.error('usage: node tools/workflow.js validate <file.yaml>\n' +
      '       node tools/workflow.js run <file.yaml> -t <target> [--dry-run] [--only-step id] [--var k=v]...');
    process.exit(2);
  }
}

if (require.main === module) main();
module.exports = { loadWorkflow, validateDoc, buildPlan, checkTargetScope, tokenize, parseSubset, printPlan, evaluateDecisions, validatePatch, applyPatch };
