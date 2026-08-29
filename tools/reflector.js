#!/usr/bin/env node
// F3 — Reflector auto-recovery su tool-call malformate.
//
// Input: righe jsonl {tool, args, error, ts} via --log <file.jsonl> oppure stdin.
// Regola deterministica: >= 3 fallimenti CONSECUTIVI dello stesso tool (stesso nome,
// campo `error` presente) -> genera un recovery prompt STRUTTURATO:
//   {intervention, tool, failures, threshold, usage_hint, last_errors:[ultimi 2], instruction}
//
// Semantica di "consecutivo" (documentata): una sequenza di righe adiacenti con error=true
// e stesso tool; QUALSIASI riga in mezzo che sia un successo o l'errore di UN ALTRO tool
// interrompe la serie. Le righe malformate/senza `tool` vengono saltate senza rompere la serie.
//
// usage_hint viene dal dizionario interno USAGE_HINTS (firme d'uso reali dei comandi dell'
// harness), con fallback generico per tool sconosciuti. Comando standalone:
//   node tools/reflector.js advise --tool <nome>   # stampa {tool, usage_hint}, exit 0
//
// Exit-code: 0 = nessun intervento · 6 = intervento consigliato · 2 = uso errato/input illeggibile.
'use strict';
const fs = require('fs');
const path = require('path');

const DEFAULT_THRESHOLD = 3;
const DEFAULT_LAST_ERRORS = 2;

// Firme d'uso essenziali e CORRETTE dei comandi dell'harness (verificate sui sorgenti tools/).
const USAGE_HINTS = {
  'run.js': 'node tools/run.js [--dry-run] [--run-timeout <ms>] <binary> [args...] — wrapper OBBLIGATORIO per i binari terzi: passa il binario come primo argomento (mai stringhe di shell composte), serve almeno un host in scope tra gli argomenti o nello stdin piped.',
  'record-finding.js': 'node tools/record-finding.js \'<json>\' — JSON singolo con required: severity (Critical|High|Medium|Low|Info), title, host, poc; status verification-level: suspected|triggered|exploited|proven_impact (severity mai sopra il ceiling del livello); dedup su (host|endpoint|title).',
  'verify-finding.js': 'node tools/verify-finding.js one \'<finding-json>\' | batch [--file findings.jsonl] — oracolo re-fire N/N via repeater.',
  'repeater.js': 'node tools/repeater.js --url <u> [--method M] [--header "K: V"]... [--data D] [--vary "param=v1,v2"] [--show-body] — motore richieste HTTP con scope+DNS-pin+identity.',
  'coverage.js': 'node tools/coverage.js <host> [--json|--write] — matrice copertura classi×host per un host.',
  'gate.js': 'node tools/gate.js status <host> | pass <phase> | check <phase> — stage-gate strutturali recon→report.',
  'workflow.js': '(FUTURO, non ancora installato) node tools/workflow.js run workflows/<flow>.yaml — NON invocarlo finche\' non esiste in tools/: usa run.js direttamente.',
};
const FALLBACK_HINT = 'rileggi l\'--help dello strumento, riduci gli argomenti al minimo valido, valida il JSON prima di richiamare; se dopo un tentativo corretto fallisce di nuovo, fermati e scala all\'operatore (fail-closed).';

// Risolve l'hint: match esatto, poi con '.js', poi basename, poi fallback generico.
function hintFor(toolName) {
  const t = String(toolName == null ? '' : toolName).trim();
  if (!t) return { hint: FALLBACK_HINT, matched: false };
  if (USAGE_HINTS[t]) return { hint: USAGE_HINTS[t], matched: true };
  const withJs = t.endsWith('.js') ? t : t + '.js';
  if (USAGE_HINTS[withJs]) return { hint: USAGE_HINTS[withJs], matched: true };
  for (const key of Object.keys(USAGE_HINTS)) {
    if (path.basename(t) === key || path.basename(t) === key.replace(/\.js$/, '')) {
      return { hint: USAGE_HINTS[key], matched: true };
    }
  }
  return { hint: FALLBACK_HINT, matched: false };
}

function isFailure(entry) {
  return entry != null && typeof entry === 'object' && Boolean(entry.error);
}

// Scansione deterministica: ritorna {intervention, tool, failures, last_errors, maxRun}.
function scan(entries, threshold, lastK) {
  let runTool = null;
  let runCount = 0;
  let runErrors = [];
  let maxRun = 0;
  for (const e of entries) {
    if (e == null || typeof e !== 'object' || e.tool == null) continue; // riga malformata: salta
    if (isFailure(e)) {
      if (e.tool === runTool) {
        runCount++;
        runErrors.push(String(e.error));
      } else {
        runTool = e.tool;
        runCount = 1;
        runErrors = [String(e.error)];
      }
      if (runCount > maxRun) maxRun = runCount;
      if (runCount >= threshold) {
        return {
          intervention: true,
          tool: runTool,
          failures: runCount,
          last_errors: runErrors.slice(-lastK),
          maxRun,
        };
      }
    } else {
      runTool = null;
      runCount = 0;
      runErrors = [];
    }
  }
  return { intervention: false, tool: null, failures: 0, last_errors: [], maxRun };
}

function parseEntries(text) {
  const entries = [];
  let skipped = 0;
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch {
      skipped++;
    }
  }
  return { entries, skipped };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--log') out.log = argv[++i];
    else if (a === '--tool') out.tool = argv[++i];
    else if (a === '--threshold') out.threshold = parseInt(argv[++i], 10);
    else if (a === '--last-errors') out.lastErrors = parseInt(argv[++i], 10);
    else if (a === 'advise') out.advise = true;
    else if (a === '-h' || a === '--help') out.help = true;
  }
  return out;
}

function usage() {
  console.error('usage: node tools/reflector.js --log <file.jsonl> [--threshold N] [--last-errors K]');
  console.error('       cat log.jsonl | node tools/reflector.js');
  console.error('       node tools/reflector.js advise --tool <nome>');
  process.exit(2);
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.help) usage();

  // --- advise standalone ---
  if (cli.advise) {
    if (!cli.tool) usage();
    const { hint, matched } = hintFor(cli.tool);
    console.log(JSON.stringify({ tool: cli.tool, usage_hint: hint, matched }, null, 2));
    return 0;
  }

  const threshold = cli.threshold != null ? cli.threshold : DEFAULT_THRESHOLD;
  const lastK = cli.lastErrors != null ? cli.lastErrors : DEFAULT_LAST_ERRORS;
  if (!isFinite(threshold) || threshold < 1 || !isFinite(lastK) || lastK < 1) usage();

  // --- sorgente input: --log file oppure stdin piped ---
  let text = null;
  if (cli.log) {
    try {
      text = fs.readFileSync(cli.log, 'utf8');
    } catch {
      console.error('log illeggibile: ' + cli.log);
      return 2;
    }
  } else if (!process.stdin.isTTY) {
    try {
      text = fs.readFileSync(0, 'utf8');
    } catch {
      text = null;
    }
  }
  if (text == null) usage();

  const { entries, skipped } = parseEntries(text);
  // Fail-closed: ZERO righe valide (input vuoto o solo righe malformate) non puo' produrre
  // un verdetto "nessun intervento" — l'orchestratore proseguirebbe su input inutilizzabile.
  if (entries.length === 0) {
    console.error('reflector: nessuna riga valida nell\'input (' + skipped + ' scartate) — nulla da analizzare');
    return 2;
  }
  const r = scan(entries, threshold, lastK);
  const { hint } = hintFor(r.tool);

  const result = {
    intervention: r.intervention,
    tool: r.tool,
    failures: r.failures,
    threshold,
    usage_hint: r.intervention ? hint : null,
    last_errors: r.last_errors,
    instruction: r.intervention
      ? 'INTERVENTO CONSIGLIATO: ' + r.failures + ' fallimenti consecutivi di "' + r.tool +
        '". 1) leggi usage_hint; 2) correggi gli argomenti alla firma minima valida; ' +
        '3) ritenta UNA sola volta; 4) se fallisce ancora, FERMATI e scala all\'operatore (fail-closed).'
      : null,
    scanned: entries.length,
    skipped_lines: skipped,
    longest_failure_run: r.maxRun,
  };
  console.log(JSON.stringify(result, null, 2));
  if (r.intervention) {
    console.error('=== REFLECTOR: recovery prompt generato per "' + r.tool + '" (exit 6) ===');
    return 6;
  }
  return 0;
}

if (require.main === module) process.exit(main());

module.exports = { USAGE_HINTS, FALLBACK_HINT, hintFor, scan, parseEntries, isFailure };
