#!/usr/bin/env node
// F1 — Loop-detection mentor sui log di esecuzione (default: reports/tmp/run-audit.jsonl).
//
// Firma comando = bin + args NORMALIZZATI: i numeri diventano 'N' e gli hash-es/uuid 'H'
// (robustezza: nmap -p 80 / -p 443 / --rate 1000 condividono la firma).
//   Regole di loop (configurabili):
//     - >= 5 esecuzioni IDENTICHE CONSECUTIVE            -> mode:'consecutive'
//     - >= 10 esecuzioni IDENTICHE totali nella finestra -> mode:'total'
//
// Output JSON su stdout:
//   {loop, signature, count, mode:'consecutive'|'total', advice:[], scanned,
//    events_analyzed, files, thresholds:{consecutive,total}}
//
// Exit-code: 0 = nessun loop · 5 = loop rilevato (agganciabile) · 2 = uso errato/input illeggibile.
//
// Uso:
//   node tools/loop-watch.js [--min-repeat N] [--window-last M] [--total-repeat N] [file.jsonl ...]
//   env RUN_AUDIT_FILE sovrascrive il default quando non passano file espliciti.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DEFAULT_AUDIT = () => process.env.RUN_AUDIT_FILE || path.join(ROOT, 'reports', 'tmp', 'run-audit.jsonl');

const DEFAULT_CONSECUTIVE = 5;
const DEFAULT_TOTAL = 10;

// Maschera token volatili dentro un singolo argomento.
function normalizeArg(arg) {
  let s = String(arg == null ? '' : arg);
  // uuid v4-ish
  s = s.replace(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/gi, 'H');
  // hash-es lunghi (md5/sha1/sha256/...) come token intero
  if (/^[0-9a-f]{8,}$/i.test(s)) return 'H';
  // numeri rimasti (porte, thread, dimensioni, ID) -> N
  return s.replace(/\d+/g, 'N');
}

function signatureOf(entry) {
  const bin = String(entry.bin || '');
  const args = Array.isArray(entry.args) ? entry.args.map(normalizeArg) : [];
  return (bin + ' ' + args.join(' ')).trim();
}

// Advice table per-bin (fonte: migliorie-da-progetti-oss.md §3.1 F1) + fallback generico.
const BIN_ADVICE = {
  nmap: [
    'nmap: prova -sV per la versione servizio se hai solo fatto discovery',
    'nmap: passa a full-port-range (-p-) se hai scansionato solo le top-ports',
    'nmap: passa a scansione servizio-specifico o script NSE mirato (--script <svc>*)',
  ],
  ffuf: [
    'ffuf: riduci la wordlist o usa una lista piu\' mirata per la tecnologia rilevata',
    'ffuf: prova altre estensioni (-e php,txt,bak,...) e filtra i falsi positivi ricorrenti (-fs/-fc)',
  ],
  nuclei: [
    'nuclei: aggiorna i templates prima di ritentare',
    'nuclei: cambia -severity/-tags per ridurre il rumore e concentrarti su superfici diverse',
  ],
  gobuster: [
    'gobuster: cambia estensioni (-x) o wordlist',
    'gobuster: verifica i filtri status/size: forse stai setacciando rumore',
  ],
  feroxbuster: [
    'feroxbuster: cambia estensioni (-x) o wordlist',
    'feroxbuster: verifica i filtri status/size: forse stai setacciando rumore',
  ],
};
const GENERIC_ADVICE = [
  'generico: cambia approccio — passa a una fase diversa del playbook (recon->enum->test->verify)',
  'generico: consulta il playbook (pentest-playbook) per la fase corrente prima di ripetere il comando',
  'generico: chiedi al mentor/orchestratore: un loop ripetuto brucia budget senza nuovo informazione',
];

function adviceFor(bin) {
  const out = [];
  const key = String(bin || '').toLowerCase();
  if (BIN_ADVICE[key]) out.push(...BIN_ADVICE[key]);
  out.push(...GENERIC_ADVICE);
  return out;
}

function parseArgs(argv) {
  const out = { files: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--min-repeat') out.minRepeat = parseInt(argv[++i], 10);
    else if (a === '--total-repeat') out.totalRepeat = parseInt(argv[++i], 10);
    else if (a === '--window-last') out.windowLast = parseInt(argv[++i], 10);
    else if (a === '-h' || a === '--help') out.help = true;
    else out.files.push(a);
  }
  return out;
}

function usage() {
  console.error('usage: node tools/loop-watch.js [--min-repeat N] [--total-repeat N] [--window-last M] [file.jsonl ...]');
  process.exit(2);
}

// Legge tutti i file in ordine; righe non-JSON o senza `bin` vengono saltate (contate).
function readEvents(files) {
  const events = [];
  let scanned = 0;
  let skipped = 0;
  for (const f of files) {
    let text;
    try {
      text = fs.readFileSync(f, 'utf8');
    } catch {
      return { error: 'file illeggibile: ' + f };
    }
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      scanned++;
      try {
        const j = JSON.parse(line);
        if (j && typeof j === 'object' && j.bin != null) events.push(j);
        else skipped++;
      } catch {
        skipped++;
      }
    }
  }
  return { events, scanned, skipped };
}

function analyze(events, opts) {
  // Accetta SOLO la forma {minRepeat,totalRepeat} (contratto export); default difensivi se
  // assenti/non finiti, cosi' un chiamante con chiavi sbagliate non disattiva silenziosamente
  // il confronto con undefined (bug fix ondata 1: main() passava {consecutive,total}).
  const minConsecutive = Number.isFinite(opts.minRepeat) ? opts.minRepeat : DEFAULT_CONSECUTIVE;
  const minTotal = Number.isFinite(opts.totalRepeat) ? opts.totalRepeat : DEFAULT_TOTAL;
  // --- consecutive: run piu' lungo di firma identica ---
  let bestSig = null;
  let bestCount = 0;
  let curSig = null;
  let curCount = 0;
  const totals = new Map();
  for (const e of events) {
    const sig = signatureOf(e);
    totals.set(sig, (totals.get(sig) || 0) + 1);
    if (sig === curSig) {
      curCount++;
    } else {
      curSig = sig;
      curCount = 1;
    }
    if (curCount > bestCount) {
      bestCount = curCount;
      bestSig = curSig;
    }
  }
  if (bestCount >= minConsecutive) {
    return { loop: true, signature: bestSig, count: bestCount, mode: 'consecutive' };
  }
  // --- total nella finestra ---
  let totSig = null;
  let totCount = 0;
  for (const [sig, n] of totals) {
    if (n > totCount) {
      totCount = n;
      totSig = sig;
    }
  }
  if (totCount >= minTotal) {
    return { loop: true, signature: totSig, count: totCount, mode: 'total' };
  }
  return { loop: false, signature: null, count: 0, mode: null };
}

function main() {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.help) usage();
  if (cli.minRepeat != null && (!isFinite(cli.minRepeat) || cli.minRepeat < 2)) usage();
  if (cli.totalRepeat != null && (!isFinite(cli.totalRepeat) || cli.totalRepeat < 2)) usage();
  if (cli.windowLast != null && (!isFinite(cli.windowLast) || cli.windowLast < 1)) usage();

  const files = cli.files.length ? cli.files.slice() : [DEFAULT_AUDIT()];
  const data = readEvents(files);
  if (data.error) {
    console.error(data.error);
    return 2;
  }
  let events = data.events;
  const thresholds = {
    consecutive: cli.minRepeat != null ? cli.minRepeat : DEFAULT_CONSECUTIVE,
    total: cli.totalRepeat != null ? cli.totalRepeat : DEFAULT_TOTAL,
  };
  if (cli.windowLast != null && events.length > cli.windowLast) {
    events = events.slice(-cli.windowLast);
  }

  const r = analyze(events, { minRepeat: thresholds.consecutive, totalRepeat: thresholds.total });

  const result = {
    loop: r.loop,
    signature: r.signature,
    count: r.count,
    mode: r.mode,
    advice: r.loop ? adviceFor((r.signature || '').split(' ')[0]) : [],
    scanned: data.scanned,
    skipped_lines: data.skipped,
    events_analyzed: events.length,
    files,
    thresholds,
  };
  console.log(JSON.stringify(result, null, 2));
  if (r.loop) {
    console.error('=== LOOP DETECTED (' + r.mode + ', x' + r.count + ') ===');
    console.error('Firma ripetuta: ' + r.signature);
    console.error('Applica gli advice nell\'output o cambia fase: NON ripetere il comando.');
    return 5;
  }
  return 0;
}

if (require.main === module) process.exit(main());

module.exports = { normalizeArg, signatureOf, analyze, adviceFor, BIN_ADVICE, GENERIC_ADVICE };
