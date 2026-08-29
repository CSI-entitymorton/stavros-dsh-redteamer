#!/usr/bin/env node
// SC3/B6 — Retrieval a BUDGET FISSO: selezione deterministica delle osservazioni/diagnostiche
// da iniettare nei prompt (pattern PentestGPT P5: 6 osservazioni + 4 diagnostiche invece della
// storia crescente dell'engagement).
//
// Problema: in engagement lunghi la storia cresce senza limiti e il contesto si erosiona; la
// tentazione è riassumere, ma i riassunti violano la disciplina A2 «evidenza = citazione esatta»
// (tools/evidence-quote.js). Soluzione: i prompt consumano una SELEZIONE a budget fisso calcolata
// da una funzione PURA — nessuna chiamata LLM/rete, nessun accesso fs in libreria, niente
// Date.now/Math.random né stato globale: stesso input -> stesso output BYTE-IDENTICO.
//
// Algoritmo (deterministico, questo e' il contratto, non un dettaglio implementativo):
//   1. ordinamento globale degli item: score DESC -> tie-break ts ASC (valore Date.parse) ->
//      tie-break id ASC (comparatore code-unit ESPLICITO; MAI localeCompare, che dipende dal locale);
//   2. cap per kind in quell'ordine: prime obsLimit 'observation' + prime diagLimit 'diagnostic';
//      gli eccedenti finiscono in dropped come {id, reason:'kind_limit'};
//   3. passata char-budget sui superstiti NELL'ORDINE GLOBALE (interleaved tra i due kind):
//      ogni superstite e' esaminato UNA volta, in sequenza: se entra nel residuo viene preso,
//      altrimenti dropped {id, reason:'char_budget'} e si prosegue col successivo — first-fit
//      nell'ordine, NESSUN salto avanti e nessun riordino "ottimizzato";
//   4. selected = superstiti nello stesso ordine globale, COPIE degli item (mai riferimenti
//      mutabili all'input; copia superficiale con campo chars normalizzato aggiunto);
//   5. counts = {selected:{observation,diagnostic,total}, dropped:{kind_limit,char_budget}};
//      chars = totale accumulato dai selezionati.
//
// Nota unita' di misura (onestà): il campo si chiama `chars` per continuita' col dominio, ma la
// metrica e' BYTE UTF-8. Default quando `chars` manca: Buffer.byteLength(text); item senza testo: 0.
//
// Fail-closed: QUALUNQUE violazione -> throw TypeError con messaggio che cita indice e/o id
// dell'item offendente. Nessun fallback silenzioso: id vuoto/duplicato, kind non in
// {'observation','diagnostic'} (strict, nessun alias), score non finito, ts non parseabile
// secondo Date.parse, chars non intero positivo, text non-stringa, limiti non interi > 0,
// input non-array o vuoto. (Il check di ts e' Date.parse valido, come da specifica: su Node
// fisso v24 il risultato e' stabile e quindi deterministico.)
//
// CLI (MAI scritture su disco, MAI rete):
//   node tools/retrieval-budget.js select [--file items.json] [--stdin]
//        [--obs-limit N] [--diag-limit N] [--char-budget N]
//     input: array JSON diretto OPPURE wrapper {"items":[...]}; serve almeno una sorgente
//     (--file ha precedenza su --stdin se entrambe presenti; --stdin va piped).
//   node tools/retrieval-budget.js help        (oppure nessun argomento)
//
// Contratto exit-code:
//   0 = selezione prodotta (JSON pretty, 2 spazi, su stdout)
//   1 = CONTENUTO input invalido (JSON malformato, forma non riconosciuta, schema item/limiti violato)
//   2 = USO errato (comando sconosciuto, nessuna sorgente input, file illeggibile, flag numeriche malformate)
//       — stessa convenzione "uso errato/input illeggibile" di budget.js / loop-watch.js / reflector.js
'use strict';
const fs = require('fs');

// Limiti fissi default (pattern PentestGPT P5). Congelati: nessuno li muta a runtime.
const DEFAULTS = Object.freeze({ obsLimit: 6, diagLimit: 4, charBudget: 12000 });

// ---- validazione -------------------------------------------------------------

// Intero > 0 per le opts numeriche. Rifiuto chiaro, mai coercizioni implicite.
function positiveIntOpt(name, v) {
  if (!Number.isInteger(v) || v <= 0) {
    throw new TypeError('opt ' + name + ' deve essere un intero > 0 (ricevuto: ' + String(v) + ')');
  }
  return v;
}

// Valida UN item e ritorna il record annotato usato dall'algoritmo. Throw TypeError citante.
function annotateItem(raw, index, seenIds) {
  const at = 'items[' + index + ']';
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError(at + ': item non valido — atteso oggetto {id,kind,score,ts}, ricevuto: ' +
      (raw === null ? 'null' : typeof raw));
  }
  if (typeof raw.id !== 'string' || raw.id === '') {
    throw new TypeError(at + ': campo "id" mancante o non valido (attesa stringa non vuota, ricevuto: ' +
      String(raw.id) + ')');
  }
  if (seenIds.has(raw.id)) {
    throw new TypeError(at + ' (id="' + raw.id + '"): id DUPLICATO — prima occorrenza in items[' +
      seenIds.get(raw.id) + ']');
  }
  seenIds.set(raw.id, index);
  if (raw.kind !== 'observation' && raw.kind !== 'diagnostic') {
    throw new TypeError(at + ' (id="' + raw.id + '"): kind "' + String(raw.kind) +
      '" non valido — solo \'observation\' | \'diagnostic\' (strict, nessun alias)');
  }
  if (!Number.isFinite(raw.score)) {
    throw new TypeError(at + ' (id="' + raw.id + '"): score deve essere numero finito (Number.isFinite), ricevuto: ' +
      String(raw.score));
  }
  const tsMs = typeof raw.ts === 'string' && raw.ts.trim() !== '' ? Date.parse(raw.ts) : NaN;
  if (!Number.isFinite(tsMs)) {
    throw new TypeError(at + ' (id="' + raw.id + '"): ts non parseabile come data (ISO-8601, Date.parse valido), ricevuto: ' +
      String(raw.ts));
  }
  let chars;
  if (raw.chars != null) {
    if (!Number.isInteger(raw.chars) || raw.chars <= 0) {
      throw new TypeError(at + ' (id="' + raw.id + '"): chars deve essere intero positivo (opzionale), ricevuto: ' +
        String(raw.chars));
    }
    chars = raw.chars;
  } else if (raw.text == null) {
    chars = 0;
  } else {
    if (typeof raw.text !== 'string') {
      throw new TypeError(at + ' (id="' + raw.id + '"): text deve essere stringa o assente, ricevuto: ' +
        typeof raw.text);
    }
    chars = Buffer.byteLength(raw.text, 'utf8');
  }
  return { raw, id: raw.id, kind: raw.kind, score: raw.score, tsMs, chars };
}

// ---- core --------------------------------------------------------------------

// Comparatore code-unit esplicito per stringhe: MAI localeCompare (dipende dal locale/ICU).
function cmpId(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

// Ordinamento globale: score DESC -> ts ASC -> id ASC. Gli id sono unici (validati prima),
// quindi l'ordine e' TOTALE: il risultato non dipende dalla stabilita' interna del sort di V8.
function cmpGlobal(a, b) {
  if (a.score !== b.score) return b.score - a.score; // score DESC
  if (a.tsMs !== b.tsMs) return a.tsMs - b.tsMs;     // tie-break ts ASC
  return cmpId(a.id, b.id);                          // tie-break id ASC (code-unit)
}

/**
 * select(items, opts) — selezione a budget fisso, funzione pura e deterministica.
 *
 * items: array NON vuoto di { id, kind:'observation'|'diagnostic', score:number, ts:string,
 *                            text?:string, chars?:intero positivo }
 * opts:  { obsLimit?=6, diagLimit?=4, charBudget?=12000 } — interi > 0 quando presenti.
 *
 * Ritorna { selected, dropped, counts, chars }. Non legge/scrive fs, non usa Date.now/Math.random.
 * L'input non viene mai mutato (l'ordinamento avviene su una copia annotata).
 */
function select(items, opts) {
  if (!Array.isArray(items)) {
    throw new TypeError('select: input deve essere un ARRAY di item (ricevuto: ' +
      (items === null ? 'null' : typeof items) + ')');
  }
  if (items.length === 0) {
    throw new TypeError('select: input vuoto — serve almeno 1 item (fail-closed, nessun fallback silenzioso)');
  }
  const o = opts == null ? {} : opts;
  if (typeof o !== 'object' || Array.isArray(o)) {
    throw new TypeError('select: opts deve essere un oggetto o assente (ricevuto: ' + typeof o + ')');
  }
  const obsLimit = o.obsLimit == null ? DEFAULTS.obsLimit : positiveIntOpt('obsLimit', o.obsLimit);
  const diagLimit = o.diagLimit == null ? DEFAULTS.diagLimit : positiveIntOpt('diagLimit', o.diagLimit);
  const charBudget = o.charBudget == null ? DEFAULTS.charBudget : positiveIntOpt('charBudget', o.charBudget);

  // Validazione completa PRIMA di qualunque decisione: o tutto e' ben formato o nulla esce.
  const seenIds = new Map();
  const ann = items.map((raw, i) => annotateItem(raw, i, seenIds));
  ann.sort(cmpGlobal);

  // (2) cap per kind nell'ordine globale.
  const survivors = [];
  const dropped = [];
  let nObs = 0;
  let nDiag = 0;
  for (const it of ann) {
    if (it.kind === 'observation') {
      if (nObs < obsLimit) { survivors.push(it); nObs++; }
      else dropped.push({ id: it.id, reason: 'kind_limit' });
    } else {
      if (nDiag < diagLimit) { survivors.push(it); nDiag++; }
      else dropped.push({ id: it.id, reason: 'kind_limit' });
    }
  }

  // (3)+(4) passata char-budget first-fit nell'ordine globale; i presi diventano COPIE.
  const selected = [];
  let acc = 0;
  let selObs = 0;
  let selDiag = 0;
  for (const it of survivors) {
    if (acc + it.chars > charBudget) {
      dropped.push({ id: it.id, reason: 'char_budget' });
      continue;
    }
    acc += it.chars;
    if (it.kind === 'observation') selObs++;
    else selDiag++;
    // Copia superficiale dell'item di input + chars normalizzato; nessun riferimento condiviso
    // con l'oggetto di input a livello di item (mutare la copia non tocca l'originale).
    selected.push(Object.assign({}, it.raw, { chars: it.chars }));
  }

  return {
    selected,
    dropped,
    counts: {
      selected: { observation: selObs, diagnostic: selDiag, total: selected.length },
      dropped: {
        kind_limit: dropped.filter((d) => d.reason === 'kind_limit').length,
        char_budget: dropped.filter((d) => d.reason === 'char_budget').length,
      },
    },
    chars: acc,
  };
}

// ---- CLI ---------------------------------------------------------------------
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--file') out.file = argv[++i];
    else if (a === '--stdin') out.stdin = true;
    else if (a === '--obs-limit') out.obsLimit = argv[++i];
    else if (a === '--diag-limit') out.diagLimit = argv[++i];
    else if (a === '--char-budget') out.charBudget = argv[++i];
    else if (a === '-h' || a === '--help') out.help = true;
    else out._.push(a);
  }
  return out;
}

function printUsage(to) {
  to('usage: node tools/retrieval-budget.js select [--file items.json] [--stdin]');
  to('                                            [--obs-limit N] [--diag-limit N] [--char-budget N]');
  to('       node tools/retrieval-budget.js help');
  to('');
  to('  input : array JSON diretto oppure wrapper {"items":[...]}; serve --file oppure --stdin');
  to('          (--file ha precedenza se entrambe; --stdin va piped). MAI scritture su disco.');
  to('  output: risultato JSON pretty (2 spazi) su stdout, exit 0.');
  to('  default: obsLimit=' + DEFAULTS.obsLimit + ' diagLimit=' + DEFAULTS.diagLimit + ' charBudget=' + DEFAULTS.charBudget);
  to('  exit  : 0 ok | 1 input contenuto invalido (JSON/schema) | 2 uso errato (sorgente assente,');
  to('          file illeggibile, flag numeriche non intere > 0)');
}

// Converte il valore stringa di una flag numerica in intero > 0; rifiuto chiaro (uso errato).
function intFlag(cliValue, flagName) {
  if (cliValue == null) return undefined;
  const n = Number(cliValue);
  if (!Number.isInteger(n) || n <= 0) {
    throw new TypeError('flag ' + flagName + ' deve essere un intero > 0 (ricevuto: "' + String(cliValue) + '")');
  }
  return n;
}

function cmdSelect(cli) {
  if (!cli.file && !cli.stdin) {
    console.error('uso errato: select richiede una sorgente input — --file <items.json> oppure --stdin (piped)');
    printUsage(console.error);
    return 2;
  }
  let text;
  if (cli.file) {
    try {
      text = fs.readFileSync(cli.file, 'utf8');
    } catch (e) {
      console.error('impossibile leggere --file ' + cli.file + ': ' + e.message);
      return 2;
    }
  } else {
    try {
      text = fs.readFileSync(0, 'utf8'); // stdin piped
    } catch (e) {
      console.error('impossibile leggere stdin: ' + e.message);
      return 2;
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    console.error('JSON malformato: ' + e.message);
    return 1;
  }
  const arr = Array.isArray(parsed)
    ? parsed
    : (parsed != null && typeof parsed === 'object' && !Array.isArray(parsed) && Array.isArray(parsed.items))
      ? parsed.items
      : null;
  if (!arr) {
    console.error('forma input non riconosciuta: atteso array JSON diretto oppure oggetto {"items":[...]}');
    return 1;
  }

  // Le flag numeriche sono USO del CLI: validate prima e a parte -> exit 2 se malformate.
  let limits;
  try {
    limits = {
      obsLimit: intFlag(cli.obsLimit, '--obs-limit'),
      diagLimit: intFlag(cli.diagLimit, '--diag-limit'),
      charBudget: intFlag(cli.charBudget, '--char-budget'),
    };
  } catch (e) {
    console.error('uso errato: ' + (e && e.message ? e.message : String(e)));
    return 2;
  }

  let result;
  try {
    result = select(arr, limits);
  } catch (e) {
    console.error('input respinto: ' + (e && e.message ? e.message : String(e)));
    return 1;
  }
  console.log(JSON.stringify(result, null, 2));
  return 0;
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.help || cli._.length === 0 || cli._[0] === 'help') {
    printUsage(console.log);
    return 0;
  }
  const cmd = cli._[0];
  if (cmd === 'select') return cmdSelect(cli);
  console.error('uso errato: comando sconosciuto "' + cmd + '"');
  printUsage(console.error);
  return 2;
}

if (require.main === module) process.exit(main());

// Libreria: riusabile da orchestratore/skill senza spawn (funzione pura, zero side-effect).
module.exports = { select, DEFAULTS, parseArgs };
