#!/usr/bin/env node
// B1 — Budget-cap hard di engagement (richieste / wall-clock / token) con graceful stop.
// F2 — Budget hard tool-call PER CLASSE agente (general/limited/recon).
//
// Comandi:
//   node tools/budget.js check  [--agent-class <classe>]
//   node tools/budget.js tick   --agent-class <classe>
//   node tools/budget.js reset  --reason "<perche' l'operatore sblocca>"
//
// Contratto exit-code (agganciabile da orchestratore/skill):
//   0 = ok, sotto soglia
//   2 = uso errato (comando mancante, classe sconosciuta, nome classe non sicuro)
//   3 = budget ENGAGEMENT superato o halted in attesa dell'operatore
//   4 = budget CLASSE superato o halted per-classe
//
// Fail-closed: QUALUNQUE cap superato -> snapshot dello stato + halt persistente in
// operation-state.json (.budget) + banner "OPERATOR REQUEST REQUIRED". Mentre halted,
// check/tick continuano a rispondere 3/4 finche' un OPERATORE non esegue `reset --reason`.
// Misconfig del file config (assente/corrotto) NON blocca mai: `check` risponde
// {enabled:false} exit 0 segnalando la condizione (spec B1: mai bloccare per misconfig).
//
// Contatori deterministici (niente magia):
//   requests    = numero righe non vuote di reports/tmp/run-audit.jsonl (1 riga = 1 exec run.js)
//   wall_minutes= now - budget.started_at (seedato alla prima `check` se assente)
//   tokens      = somma delle righe {tokens:N} del jsonl puntato da DSH_TOKEN_USAGE_FILE
//                 (se env assente/file mancante: tokens=null, cap max_tokens NON valutabile
//                  -> non e' un superamento; viene segnalato token_source_absent)
//   tool_calls  = numero righe di reports/tmp/tool-calls-<class>.jsonl (1 tick = 1 tool-call)
//
// Percorsi configurabili per test/engagement (CLI flag > env > default standard):
//   --config <file>      | BUDGET_CONFIG_FILE   | tools/budget.json
//   --state <file>       | BUDGET_STATE_FILE    | <ws>/operation-state.json
//   --audit <file>       | RUN_AUDIT_FILE       | reports/tmp/run-audit.jsonl
//   --counters-dir <dir> | BUDGET_COUNTERS_DIR  | dirname(audit) (default reports/tmp/)
//   --classes <file>     | BUDGET_CLASSES_FILE  | tools/budgets.json
//
// Semantica del reset (documentata in docs/orchestration-policy.md): il reset apre un NUOVO
// periodo di budget — aggiorna started_at e fissa baseline {requests,tokens}; i cap vengono
// valutati sul DELTA dal reset (contatori assoluti restano nel JSON per trasparenza). Senza
// questa semantica un reset lascerebbe i contatori oltre soglia e ri-halterebbe subito.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function resolvePaths(cli) {
  return {
    config: cli.config || process.env.BUDGET_CONFIG_FILE || path.join(ROOT, 'tools', 'budget.json'),
    state: cli.state || process.env.BUDGET_STATE_FILE || path.join(ROOT, 'operation-state.json'),
    audit: cli.audit || process.env.RUN_AUDIT_FILE || path.join(ROOT, 'reports', 'tmp', 'run-audit.jsonl'),
    countersDir: cli.countersDir || process.env.BUDGET_COUNTERS_DIR || null, // default: dirname(audit), risolto dopo
    classes: cli.classes || process.env.BUDGET_CLASSES_FILE || path.join(ROOT, 'tools', 'budgets.json'),
    tokens: process.env.DSH_TOKEN_USAGE_FILE || null,
  };
}

// ---- IO helpers -------------------------------------------------------------
function atomicWriteJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp-' + process.pid + '-' + Math.random().toString(36).slice(2, 8);
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

function readJsonObject(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

// Conta le righe non vuote di un jsonl (1 riga = 1 evento contabilizzato). File assente = 0.
function countLines(file) {
  try {
    const text = fs.readFileSync(file, 'utf8');
    let n = 0;
    for (const line of text.split(/\r?\n/)) if (line.trim()) n++;
    return n;
  } catch {
    return 0;
  }
}

// Somma {tokens:N} su jsonl. Ritorna {value:number|null, source:'env-set'|'env-unset'}.
function sumTokens(file) {
  if (!file) return { value: null, source: 'env-unset' };
  try {
    const text = fs.readFileSync(file, 'utf8');
    let sum = 0;
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        const j = JSON.parse(line);
        if (j && typeof j.tokens === 'number' && isFinite(j.tokens)) sum += j.tokens;
      } catch {}
    }
    return { value: sum, source: 'env-set' };
  } catch {
    return { value: null, source: 'env-set-missing-file' };
  }
}

function nowIso() {
  return new Date().toISOString();
}

// Timestamp per nomi file: ISO senza ':' (sicuro su ogni filesystem).
function stampForFile() {
  return new Date().toISOString().replace(/:/g, '-');
}

function loadStateOrCreate(file) {
  const st = readJsonObject(file);
  if (st) return st;
  // operation-state.json assente/non leggibile: creazione MINIMA preservando la forma
  // {version, ..., created_at, updated_at} usata dall'harness.
  const ts = nowIso();
  return { version: 1, created_at: ts, updated_at: ts, pending: [], budget: {} };
}

// Seed di started_at alla prima `check` (write atomico che preserva tutti gli altri campi).
function ensureStartedAt(state, stateFile) {
  if (!state.budget || typeof state.budget !== 'object') state.budget = {};
  if (!state.budget.started_at) {
    state.budget.started_at = nowIso();
    state.updated_at = nowIso();
    atomicWriteJson(stateFile, state);
  }
  return state;
}

function saveState(state, stateFile) {
  state.updated_at = nowIso();
  atomicWriteJson(stateFile, state);
}

// Snapshot di graceful stop B1: copia fedele dello stato corrente affianco al file di stato.
function writeSnapshot(stateFile) {
  try {
    const dir = path.dirname(stateFile);
    fs.mkdirSync(dir, { recursive: true });
    const snap = path.join(dir, 'operation-state.snapshot-' + stampForFile() + '.json');
    let payload;
    try {
      payload = fs.readFileSync(stateFile, 'utf8');
    } catch {
      payload = JSON.stringify({ version: 1, note: 'snapshot su stato assente' }, null, 2);
    }
    fs.writeFileSync(snap, payload);
    return snap;
  } catch {
    return null;
  }
}

// ---- CLI parsing ------------------------------------------------------------
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--agent-class') out.agentClass = argv[++i];
    else if (a === '--reason') out.reason = argv[++i];
    else if (a === '--config') out.config = argv[++i];
    else if (a === '--state') out.state = argv[++i];
    else if (a === '--audit') out.audit = argv[++i];
    else if (a === '--counters-dir') out.countersDir = argv[++i];
    else if (a === '--classes') out.classes = argv[++i];
    else if (a === '-h' || a === '--help') out.help = true;
    else out._.push(a);
  }
  return out;
}

function usage() {
  console.error('usage: node tools/budget.js check [--agent-class <classe>]');
  console.error('       node tools/budget.js tick --agent-class <classe>');
  console.error('       node tools/budget.js reset --reason "<motivo operatore>"');
  process.exit(2);
}

const CLASS_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/; // niente traversal/strani caratteri nel nome contatore

// ---- core -------------------------------------------------------------------
// Carica il config engagement. Ritorna {cfg, error}: cfg=null se assente, error=true se corrotto.
function loadConfig(file) {
  if (!fs.existsSync(file)) return { cfg: null, error: false };
  const cfg = readJsonObject(file);
  if (!cfg) return { cfg: null, error: true };
  return { cfg, error: false };
}

function loadClasses(file) {
  if (!fs.existsSync(file)) return { classes: null, error: false };
  const j = readJsonObject(file);
  if (!j || !j.classes || typeof j.classes !== 'object') return { classes: null, error: true };
  return { classes: j.classes, error: false };
}

// Valutazione cap engagement sui valori EFFETTIVI (delta dalla baseline se presente).
function evaluateEngagement(cfg, counters, baseline) {
  const caps = {};
  const exceeded = [];
  const effReq = Math.max(0, counters.requests - (baseline ? baseline.requests : 0));
  const effTok = counters.tokens == null || !baseline || baseline.tokens == null
    ? counters.tokens
    : Math.max(0, counters.tokens - baseline.tokens);
  if (typeof cfg.max_requests === 'number') {
    caps.max_requests = cfg.max_requests;
    if (effReq > cfg.max_requests) exceeded.push({ cap: 'max_requests', observed: effRequestsReport(effReq), limit: cfg.max_requests });
  }
  if (typeof cfg.max_wall_minutes === 'number') {
    caps.max_wall_minutes = cfg.max_wall_minutes;
    if (counters.wall_minutes_raw > cfg.max_wall_minutes) {
      exceeded.push({ cap: 'max_wall_minutes', observed: counters.wall_minutes, limit: cfg.max_wall_minutes });
    }
  }
  if (typeof cfg.max_tokens === 'number') {
    caps.max_tokens = cfg.max_tokens;
    if (effTok == null) {
      caps.max_tokens_note = 'token_source_absent: cap dichiarato ma DSH_TOKEN_USAGE_FILE non misurabile — cap NON valutato';
    } else if (effTok > cfg.max_tokens) {
      exceeded.push({ cap: 'max_tokens', observed: effTok, limit: cfg.max_tokens });
    }
  }
  return { caps, exceeded, effective: { requests: effReq, tokens: effTok } };
}

function effRequestsReport(n) {
  return n;
}

// Halt persistente engagement: snapshot + .budget={halted:true,...} atomico.
function haltEngagement(state, stateFile, reason, counters) {
  const snap = writeSnapshot(stateFile);
  state.budget = state.budget && typeof state.budget === 'object' ? state.budget : {};
  state.budget.halted = true;
  state.budget.reason = reason;
  state.budget.counters = counters;
  state.budget.ts = nowIso();
  state.budget.history = Array.isArray(state.budget.history) ? state.budget.history : [];
  state.budget.history.push({ ts: nowIso(), action: 'halt', reason, counters });
  saveState(state, stateFile);
  return snap;
}

function counterFile(countersDir, cls) {
  return path.join(countersDir, 'tool-calls-' + cls + '.jsonl');
}

function classCounterPath(paths, cli, cls) {
  const dir = paths.countersDir || path.dirname(paths.audit);
  return counterFile(dir, cls);
}

// ---- comandi ----------------------------------------------------------------
function cmdCheck(cli) {
  const paths = resolvePaths({ ...cli, agentClass: undefined });
  const { cfg, error } = loadConfig(paths.config);

  // Misconfig -> MAI bloccare: enabled=false exit 0 con segnalazione esplicita.
  if (!cfg || error) {
    const note = error
      ? 'budget config UNREADABLE/CORRUPT at ' + paths.config + ' — budgets DISABLED (segnalare all\'operatore)'
      : 'budget config absent at ' + paths.config + ' — budgets DISABLED';
    console.log(JSON.stringify({
      enabled: false,
      note,
      halted: false,
      exceeded: [],
      operator_action: null,
    }, null, 2));
    return 0;
  }

  let state = loadStateOrCreate(paths.state);
  state = ensureStartedAt(state, paths.state); // write atomico solo se seed necessario

  // --- contatori engagement ---
  const requests = countLines(paths.audit);
  const startedMs = Date.parse(state.budget.started_at);
  const wallRaw = isFinite(startedMs) ? Math.max(0, (Date.now() - startedMs) / 60000) : 0;
  const tok = sumTokens(paths.tokens);
  const counters = {
    requests,
    wall_minutes: Math.round(wallRaw * 100) / 100,
    wall_minutes_raw: wallRaw,
    tokens: tok.value,
  };

  const baseline = state.budget.baseline && typeof state.budget.baseline === 'object' ? state.budget.baseline : null;
  const { caps, exceeded, effective } = evaluateEngagement(cfg, counters, baseline);

  const result = {
    enabled: true,
    counters: { requests, wall_minutes: counters.wall_minutes, tokens: counters.tokens },
    effective,
    caps,
    halted: state.budget.halted === true,
    exceeded,
    baseline,
    notes: [],
  };
  if (tok.source !== 'env-set' || tok.value == null) {
    result.notes.push(tok.source === 'env-unset'
      ? 'DSH_TOKEN_USAGE_FILE non impostato: contatore token non disponibile'
      : 'DSH_TOKEN_USAGE_FILE punta a un file non leggibile: contatore token non disponibile');
  }

  let code = 0;

  // --- classe agente (F2) ---
  if (cli.agentClass != null) {
    const cls = String(cli.agentClass);
    const { classes, error: classesError } = loadClasses(paths.classes);
    if (!classes || classesError) {
      result.notes.push('budgets.json assente/corrotto: budget per-classe DISABILITATO (segnalare all\'operatore)');
      result.class_budgets_enabled = false;
    } else if (!CLASS_NAME_RE.test(cls)) {
      console.error('uso errato: agent-class deve matchare ' + CLASS_NAME_RE + ' (ricevuto: ' + cls + ')');
      return 2;
    } else if (!classes[cls]) {
      console.error('uso errato: agent-class sconosciuta "' + cls + '" — note: ' + Object.keys(classes).join(', '));
      return 2;
    } else {
      const cFile = classCounterPath(paths, cli, cls);
      const toolCalls = countLines(cFile);
      // Delta dal baseline fissato dall'ultimo reset (nuovo periodo): senza questo, un reset
      // lascerebbe il contatore assoluto oltre cap e ri-halterebbe subito senza nuove chiamate.
      const prevEntry = state.budget.classes && state.budget.classes[cls];
      const clsBaseline = prevEntry && typeof prevEntry.baseline === 'number' ? prevEntry.baseline : 0;
      const effToolCalls = Math.max(0, toolCalls - clsBaseline);
      const maxToolCalls = typeof classes[cls].max_tool_calls === 'number' ? classes[cls].max_tool_calls : null;
      const classHalted = !!(state.budget.classes && state.budget.classes[cls] && state.budget.classes[cls].halted);
      const classExceeded = maxToolCalls != null && effToolCalls > maxToolCalls && !classHalted;
      result.class_budgets_enabled = true;
      result.class = cls;
      result.tool_calls = toolCalls;
      result.effective_tool_calls = effToolCalls;
      result.max_tool_calls = maxToolCalls;
      result.class_exceeded = classHalted || classExceeded;
      result.class_halted = classHalted;
      if (classExceeded) {
        state.budget.classes = state.budget.classes && typeof state.budget.classes === 'object' ? state.budget.classes : {};
        state.budget.classes[cls] = {
          halted: true,
          tool_calls: toolCalls,
          effective_tool_calls: effToolCalls,
          baseline: clsBaseline,
          max_tool_calls: maxToolCalls,
          ts: nowIso(),
        };
        state.budget.history = Array.isArray(state.budget.history) ? state.budget.history : [];
        state.budget.history.push({ ts: nowIso(), action: 'halt-class', class: cls, tool_calls: toolCalls, max_tool_calls: maxToolCalls });
        saveState(state, paths.state);
        result.class_halted = true;
      }
    }
  }

  // --- decisione exit + azioni graceful stop ---
  if (result.halted || exceeded.length > 0) {
    code = 3;
    if (!result.halted) {
      // primo superamento: snapshot + halt persistente
      const reason = 'engagement budget exceeded: ' + exceeded.map((e) => e.cap + '=' + e.observed + '>' + e.limit).join('; ');
      const snap = haltEngagement(state, paths.state, reason, {
        requests, wall_minutes: counters.wall_minutes, tokens: counters.tokens,
      });
      result.halted = true;
      result.snapshot = snap || null;
      result.notes.push('graceful stop: snapshot stato + halt persistente in operation-state.json (.budget)');
    } else {
      result.notes.push('halt pregresso ancora attivo: serve `node tools/budget.js reset --reason "..."` dell\'operatore');
    }
    result.operator_request = 'OPERATOR REQUEST REQUIRED';
    console.error('=== OPERATOR REQUEST REQUIRED ===');
    console.error(result.exceeded.length
      ? 'Budget engagement superato: ' + JSON.stringify(result.exceeded)
      : 'Engagement in HALT da budget precedente (reset operatore richiesto).');
    console.error('Nessuna ulteriore attivita\' fino a: node tools/budget.js reset --reason "..."');
  } else if (result.class_exceeded) {
    code = 4;
    result.operator_request = 'OPERATOR REQUEST REQUIRED (class ' + result.class + ')';
    console.error('=== OPERATOR REQUEST REQUIRED (class ' + result.class + ') ===');
    console.error('Budget tool-call classe "' + result.class + '" superato: ' + result.tool_calls + '>' + result.max_tool_calls);
  }

  delete counters.wall_minutes_raw;
  console.log(JSON.stringify(result, null, 2));
  return code;
}

function cmdTick(cli) {
  if (!cli.agentClass) usage();
  const paths = resolvePaths(cli);
  const cls = String(cli.agentClass);
  const { classes, error } = loadClasses(paths.classes);
  if (!classes || error) {
    console.log(JSON.stringify({
      class_budgets_enabled: false,
      note: 'budgets.json assente/corrotto: tick non conteggiato (segnalare all\'operatore)',
      class: cls, tool_calls: null, max_tool_calls: null, exceeded: false, halted: false,
    }, null, 2));
    return 0; // mai bloccare per misconfig, ma segnala
  }
  if (!CLASS_NAME_RE.test(cls)) {
    console.error('uso errato: agent-class deve matchare ' + CLASS_NAME_RE + ' (ricevuto: ' + cls + ')');
    return 2;
  }
  if (!classes[cls]) {
    console.error('uso errato: agent-class sconosciuta "' + cls + '" — note: ' + Object.keys(classes).join(', '));
    return 2;
  }
  const maxToolCalls = typeof classes[cls].max_tool_calls === 'number' ? classes[cls].max_tool_calls : null;
  const cFile = classCounterPath(paths, cli, cls);

  let state = loadStateOrCreate(paths.state);
  state.budget = state.budget && typeof state.budget === 'object' ? state.budget : {};
  state.budget.classes = state.budget.classes && typeof state.budget.classes === 'object' ? state.budget.classes : {};
  const prev = state.budget.classes[cls];

  // Fail-closed: mentre halted NESSUN incremento — l'agente deve aver gia' smesso.
  if (prev && prev.halted) {
    console.log(JSON.stringify({
      class_budgets_enabled: true, class: cls, tool_calls: prev.tool_calls,
      max_tool_calls: prev.max_tool_calls, exceeded: true, halted: true,
      note: 'classe in halt: tick NON registrato, fermarsi e scalare all\'operatore',
    }, null, 2));
    console.error('=== OPERATOR REQUEST REQUIRED (class ' + cls + ') ===');
    return 4;
  }

  // append deterministico {ts}
  try {
    fs.mkdirSync(path.dirname(cFile), { recursive: true });
    fs.appendFileSync(cFile, JSON.stringify({ ts: nowIso() }) + '\n');
  } catch (e) {
    console.error('impossibile appendere al contatore classe: ' + e.message);
    return 2;
  }
  const toolCalls = countLines(cFile);
  // Cap valutato sul DELTA dal baseline dell'ultimo reset (nuovo periodo di budget).
  const clsBaseline = prev && typeof prev.baseline === 'number' ? prev.baseline : 0;
  const effToolCalls = Math.max(0, toolCalls - clsBaseline);

  const over = maxToolCalls != null && effToolCalls > maxToolCalls;
  const result = {
    class_budgets_enabled: true,
    class: cls,
    tool_calls: toolCalls,
    effective_tool_calls: effToolCalls,
    max_tool_calls: maxToolCalls,
    exceeded: over,
    halted: false,
  };
  if (over) {
    state.budget.classes[cls] = { halted: true, tool_calls: toolCalls, effective_tool_calls: effToolCalls, baseline: clsBaseline, max_tool_calls: maxToolCalls, ts: nowIso() };
    state.budget.history = Array.isArray(state.budget.history) ? state.budget.history : [];
    state.budget.history.push({ ts: nowIso(), action: 'halt-class', class: cls, tool_calls: toolCalls, max_tool_calls: maxToolCalls });
    saveState(state, paths.state);
    result.halted = true;
    result.operator_request = 'OPERATOR REQUEST REQUIRED (class ' + cls + ')';
    console.error('=== OPERATOR REQUEST REQUIRED (class ' + cls + ') ===');
    console.error('Budget tool-call classe "' + cls + '" superato (' + toolCalls + '>' + maxToolCalls + '): STOP immediato dell\'agente.');
  }
  console.log(JSON.stringify(result, null, 2));
  return over ? 4 : 0;
}

function cmdReset(cli) {
  if (cli.reason == null || !String(cli.reason).trim()) {
    console.error('uso errato: reset richiede --reason "<motivo>" (disciplina operatore)');
    return 2;
  }
  const paths = resolvePaths(cli);
  const state = loadStateOrCreate(paths.state);
  state.budget = state.budget && typeof state.budget === 'object' ? state.budget : {};

  const requests = countLines(paths.audit);
  const tok = sumTokens(paths.tokens);
  const ts = nowIso();

  // Nuovo periodo di budget: started_at aggiornato + baseline dei contatori cumulativi.
  state.budget.started_at = ts;
  state.budget.halted = false;
  delete state.budget.reason;
  delete state.budget.counters;
  state.budget.baseline = { requests, tokens: tok.value, ts };
  if (state.budget.classes && typeof state.budget.classes === 'object') {
    for (const cls of Object.keys(state.budget.classes)) {
      if (state.budget.classes[cls] && state.budget.classes[cls].halted) {
        // Il contatore jsonl resta (tracciabilita'), ma viene fissato un baseline per-classe:
        // nel nuovo periodo i cap valutano il delta, non il totale assoluto. Baseline = ultimo
        // raw osservato registrato allo halt (tool_calls); fallback: riconto dal file contatore.
        const prevCls = state.budget.classes[cls];
        const clsCount = typeof prevCls.tool_calls === 'number'
          ? prevCls.tool_calls
          : countLines(counterFile(paths.countersDir || path.dirname(paths.audit), cls));
        state.budget.classes[cls] = { halted: false, cleared_at: ts, baseline: clsCount };
      }
    }
  }
  state.budget.history = Array.isArray(state.budget.history) ? state.budget.history : [];
  state.budget.history.push({ ts, action: 'reset', reason: String(cli.reason), baseline: state.budget.baseline });
  saveState(state, paths.state);

  console.log(JSON.stringify({
    reset: true,
    ts,
    reason: String(cli.reason),
    baseline: state.budget.baseline,
    classes_cleared: true,
    note: 'nuovo periodo: cap valutati sul delta dal reset; wall-clock riparte da ora',
  }, null, 2));
  return 0;
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.help) usage();
  const [cmd] = cli._;
  if (cmd === 'check') return cmdCheck(cli);
  if (cmd === 'tick') return cmdTick(cli);
  if (cmd === 'reset') return cmdReset(cli);
  usage();
}

if (require.main === module) process.exit(main());

// Libreria: riusabile da skill/policy senza spawn.
module.exports = {
  resolvePaths, parseArgs, loadConfig, loadClasses, evaluateEngagement,
  countLines, sumTokens, loadStateOrCreate, atomicWriteJson, CLASS_NAME_RE,
};
