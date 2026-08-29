#!/usr/bin/env node
// SC3/F6 — Routing modelli per RUOLO (dichiarativo, default READ-ONLY).
//
// Scopo: dare all'harness una politica DICHIARATIVA ruolo->modello + fase->ruolo, con override
// opzionali per-mode, e un CLI che la PROPAGA come sidecar `model-route.json` dentro ogni
// directory-di-modalita' trovata sotto la root dei preset (~/.dsh/.agent-presets/<mode>/).
// Il sidecar rende la politica osservabile/auditable punto-per-modo senza toccare NESSUN file
// esistente del preset (preset.yml / agent.cordis.yml / skills/ / refs/ NON vengono mai
// letti-modificati: l'unica unita' di aggiornamento e' il sidecar NUOVO model-route.json).
//
// Design (contratti, non dettagli):
//   1. DEFAULT / `plan` = DRY-RUN a ZERO side-effect su fs (nemmeno mkdir): carica+valida la
//      mappa, scopre le mode-dir, stampa tabelle e l'AZIONE per modo: `create` (sidecar
//      assente) / `update` (presente ma contenuto diverso) / `unchanged`. Root assente ->
//      messaggio «root assente — nessuna azione», exit 0.
//   2. `render --out <dir>` scrive le PROPOSTE (<dir>/<mode>.model-route.json) SOLO dentro
//      outdir, con contenuto DETERMINISTICO (niente timestamp -> due run sono byte-identici).
//      Fail-closed (exit 1, zero scritture) se outdir risolto e': uguale a homedir, dentro
//      homedir/.dsh, dentro AGENT_PRESETS_DIR, o la radice `/`. Check DOPPIO: lessicale con
//      path.resolve + anti-symlink via realpathSync dell'antenato esistente piu' vicino.
//      outdir viene creato (mkdir recursive) SOLO dopo i check di rifiuto.
//   3. `apply [--yes]`: SENZA --yes rifiuto chiaro exit!=0 e ZERO scritture (mai sovrascrittura
//      automatica). CON --yes: pre-valida TUTTO prima di scrivere (all-or-nothing: mappa,
//      root esistente, permuta/scrittura di ogni mode-dir verificati in preflight); se un
//      sidecar esiste gia', PRIMA backup copy in <root>/.backup-model-routing/<ts-sicuro>/
//      con SHA256SUMS accanto (formato compatibile `sha256sum -c`); poi scrittura ATOMICA
//      tmp+rename del nuovo model-route.json. Limite dichiarato onestamente: l'atomicita'
//      multi-file non esiste su fs POSIX — il preflight riduce la finestra, e in caso di
//      errore a meta' scrittura i backup gia' scritti permettono il ripristino manuale.
//
// Confronto `unchanged` vs `update`: SEMANTICO sui campi deterministici della proposta
// (generated_by, version, roles, phases_resolved, mode_overrides_applied, map_sha256), NON
// byte-a-byte: `applied_at` e' metadato di QUANDO apply ha scritto e non conta come divergenza
// (altrimenti plan direbbe `update` per sempre dopo ogni apply). Sidecar non-parsabile ->
// `update` (contenuto diverso, verra' fatto backup prima della sostituzione).
//
// Env override (fondamentali per i test in fixture):
//   MODEL_ROUTING_FILE : path della mappa (default: tools/model-routing.json accanto a questo script);
//   AGENT_PRESETS_DIR  : root dei preset (default: os.homedir()/.dsh/.agent-presets — si usa
//                        os.homedir(), cosi' nei test basta ridefinire $HOME).
//
// Validazione mappa fail-closed (per TUTTE le modalità, plan incluso): collezione TUTTI gli
// errori prima di rifiutare (mai solo il primo): JSON malformato; top-level non-oggetto;
// version != 1; roles vuoto/assente/non-oggetto; role.model mancante/vuoto/non-stringa;
// phases che riferisce ruolo INESISTENTE; modes override con fase o ruolo INESISTENTI.
//
// Contratto exit-code: 0 ok | 1 rifiuto/validazione (guardie outdir, --yes mancante, root
// assente per apply, mappa invalida) | 2 USO errato (comando sconosciuto, flag sconosciuta,
// --out mancante/senza valore, mappa illeggibile — stessa convenzione "input illeggibile" di
// retrieval-budget.js/budget.js).
//
// MAI rete, MAI chiamate LLM, MAI segreti: solo stdlib Node.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// ---- costanti ------------------------------------------------------------------
const GENERATOR = 'tools/model-routing.js';           // firma dentro il sidecar
const SIDECAR_NAME = 'model-route.json';              // UNICO file che questo tool puo' scrivere
const BACKUP_DIRNAME = '.backup-model-routing';       // backup dentro la root (nome puntato: mai scambiato per mode-dir)
const SUPPORTED_MAP_VERSION = 1;
const MAX_WALK_ENTRIES = 50000;                       // guardia anti-walk-patologico in discovery

function mapFilePath() {
  return process.env.MODEL_ROUTING_FILE || path.join(__dirname, 'model-routing.json');
}
function presetsRootDir() {
  return process.env.AGENT_PRESETS_DIR || path.join(os.homedir(), '.dsh', '.agent-presets');
}

// ---- util ----------------------------------------------------------------------
// Comparatore code-unit ESPLICITO: MAI localeCompare (dipende dal locale -> non deterministico).
function cmpCodeUnit(a, b) { if (a < b) return -1; if (a > b) return 1; return 0; }
function isPlainObject(v) { return v != null && typeof v === 'object' && !Array.isArray(v); }
function deepCopy(v) { return JSON.parse(JSON.stringify(v)); }
function nonEmptyString(v) { return typeof v === 'string' && v.trim() !== ''; }
function sha256Hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function serializeJson(obj) { return JSON.stringify(obj, null, 2) + '\n'; }
function hasOwn(obj, k) { return Object.prototype.hasOwnProperty.call(obj, k); }
function pad(s, n) { return s.length >= n ? s : s + ' '.repeat(n - s.length); }

// Uguaglianza strutturale profonda tra valori JSON (chiavi in numero identico incluse).
function jsonEqual(a, b) {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => jsonEqual(v, b[i]));
  }
  if (isPlainObject(a) || isPlainObject(b)) {
    if (!isPlainObject(a) || !isPlainObject(b)) return false;
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => hasOwn(b, k) && jsonEqual(a[k], b[k]));
  }
  return a === b;
}

// Scrittura ATOMICA tmp+rename nella STESSA directory (rename POSIX atomico); il temp e'
// rimosso a qualunque errore: nessun residuo .tmp sul fs.
let tmpSeq = 0;
function atomicWriteFile(filePath, data) {
  const dir = path.dirname(filePath);
  const tmp = path.join(dir, '.' + path.basename(filePath) + '.tmp-' + process.pid + '-' + (++tmpSeq));
  try {
    fs.writeFileSync(tmp, data);
    fs.renameSync(tmp, filePath);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* il temp magari non esiste ancora: nulla da pulire */ }
    throw new Error('scrittura atomica fallita per "' + filePath + '": ' + e.message);
  }
}

// ---- validazione mappa (colleziona TUTTI gli errori, poi rifiuta) ----------------
function validateMap(m) {
  const errs = [];
  if (!isPlainObject(m)) {
    errs.push('"top-level": la mappa deve essere un oggetto JSON (ricevuto: ' +
      (m === null ? 'null' : Array.isArray(m) ? 'array' : typeof m) + ')');
    return errs;
  }
  if ('_comment' in m && typeof m._comment !== 'string') {
    errs.push('"_comment": presente ma non-stringa (ricevuto: ' + typeof m._comment + ')');
  }
  if (typeof m.version !== 'number' || m.version !== SUPPORTED_MAP_VERSION) {
    errs.push('"version": atteso ' + SUPPORTED_MAP_VERSION + ' (unica schema nota, fail-closed), ricevuto: ' +
      JSON.stringify(m.version));
  }

  // roles: obbligatori, non vuoti, ciascuno con model non-vuoto.
  const roleNames = new Set();
  if (!isPlainObject(m.roles)) {
    errs.push('"roles": assente/non-oggetto — attesa mappa ruolo->{model,note}');
  } else if (Object.keys(m.roles).length === 0) {
    errs.push('"roles": VUOTO — serve almeno un ruolo (fail-closed)');
  } else {
    for (const role of Object.keys(m.roles)) {
      if (role.trim() === '') { errs.push('"roles": nome ruolo vuoto'); continue; }
      roleNames.add(role);
      const rv = m.roles[role];
      if (!isPlainObject(rv)) {
        errs.push('"roles.' + role + '": atteso oggetto {model,note}, ricevuto: ' + (rv === null ? 'null' : typeof rv));
        continue;
      }
      if (!nonEmptyString(rv.model)) {
        errs.push('"roles.' + role + '.model": mancante/vuoto/non-stringa (ricevuto: ' + JSON.stringify(rv.model) + ')');
      }
      if ('note' in rv && typeof rv.note !== 'string') {
        errs.push('"roles.' + role + '.note": presente ma non-stringa');
      }
    }
  }

  // phases: ogni valore deve riferire un ruolo ESISTENTE.
  const phaseNames = new Set();
  if (!isPlainObject(m.phases)) {
    errs.push('"phases": assente/non-oggetto — attesa mappa fase->ruolo');
  } else {
    for (const phase of Object.keys(m.phases)) {
      if (phase.trim() === '') { errs.push('"phases": nome fase vuoto'); continue; }
      phaseNames.add(phase);
      const role = m.phases[phase];
      if (!nonEmptyString(role)) {
        errs.push('"phases.' + phase + '": valore atteso stringa ruolo non vuota (ricevuto: ' + JSON.stringify(role) + ')');
      } else if (!roleNames.has(role)) {
        errs.push('"phases.' + phase + '": riferisce ruolo INESISTENTE "' + role + '"');
      }
    }
  }

  // modes: override opzionali; strict — fase e ruolo di ogni override devono esistere.
  if (m.modes != null) {
    if (!isPlainObject(m.modes)) {
      errs.push('"modes": presente ma non-oggetto');
    } else {
      for (const mode of Object.keys(m.modes)) {
        const ov = m.modes[mode];
        if (!isPlainObject(ov)) {
          errs.push('"modes.' + mode + '": atteso oggetto {"<fase>":"<ruolo>"}, ricevuto: ' +
            (ov === null ? 'null' : Array.isArray(ov) ? 'array' : typeof ov));
          continue;
        }
        for (const phase of Object.keys(ov)) {
          const role = ov[phase];
          if (!nonEmptyString(role)) {
            errs.push('"modes.' + mode + '.' + phase + '": valore atteso stringa ruolo non vuota');
          } else if (!roleNames.has(role)) {
            errs.push('"modes.' + mode + '.' + phase + '": riferisce ruolo INESISTENTE "' + role + '"');
          }
          if (!phaseNames.has(phase)) {
            errs.push('"modes.' + mode + '": override per fase INESISTENTE in "phases": "' + phase + '"');
          }
        }
      }
    }
  }
  return errs;
}

// Caricamento mappa con classificazione errore: io->2, parse->1, validazione->1.
function loadMap() {
  const p = mapFilePath();
  let text;
  try {
    text = fs.readFileSync(p, 'utf8');
  } catch (e) {
    return { ok: false, kind: 'io', message: 'impossibile leggere la mappa "' + p + '": ' + e.message };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, kind: 'parse', errors: ['"mappa ' + p + '": JSON malformato — ' + e.message] };
  }
  const errors = validateMap(parsed);
  if (errors.length > 0) {
    return { ok: false, kind: 'validation', errors: errors.map((x) => 'mappa ' + p + ': ' + x) };
  }
  // map_sha256 = SHA256 dei BYTE raw della mappa: identifica univocamente la versione della
  // politica che ha generato il sidecar (stessa mappa -> stesso hash -> confronti stabili).
  return { ok: true, map: parsed, path: p, sha256: sha256Hex(Buffer.from(text, 'utf8')) };
}

// ---- discovery delle mode-dir -----------------------------------------------------
// Mode-dir = sottodirectory IMMEDIAATA della root, nome senza punto iniziale (i nomi puntati
// come .backup-model-routing sono riservati al tool), NON symlink, contenente ALMENO UN file
// (ricorsivo; i symlink non vengono seguiti ne' contati).
function dirHasAnyFile(dir, state) {
  const stack = [dir];
  while (stack.length > 0) {
    if (++state.visited > MAX_WALK_ENTRIES) {
      throw new Error('discovery: superato il limite di ' + MAX_WALK_ENTRIES + ' voci esplorate sotto "' + dir + '"');
    }
    const cur = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(cur, { withFileTypes: true });
    } catch (e) {
      throw new Error('discovery: impossibile esplorare la directory "' + cur + '": ' + e.message);
    }
    for (const ent of ents) {
      if (ent.isSymbolicLink()) continue;           // fail-closed: non si segue fuori dall'albero
      if (ent.isFile()) return true;
      if (ent.isDirectory()) stack.push(path.join(cur, ent.name));
    }
  }
  return false;
}

function listModeDirs(root) {
  let ents;
  try {
    ents = fs.readdirSync(root, { withFileTypes: true });
  } catch (e) {
    throw new Error('impossibile leggere la root dei preset "' + root + '": ' + e.message);
  }
  const state = { visited: 0 };
  const modes = [];
  for (const ent of ents) {
    if (ent.isSymbolicLink()) continue;
    if (!ent.isDirectory()) continue;
    if (ent.name.startsWith('.')) continue;         // riservati al tool (es. .backup-model-routing)
    const full = path.join(root, ent.name);
    if (dirHasAnyFile(full, state)) modes.push({ name: ent.name, dir: full });
  }
  modes.sort((a, b) => cmpCodeUnit(a.name, b.name)); // ordine deterministico code-unit
  return modes;
}

// ---- risoluzione politica per modo -------------------------------------------------
// Righe {phase,role,model} ordinate per fase; gli override del modo (se presenti in mappa)
// sostituiscono il ruolo globale fase-per-fase. La validazione garantisce che ogni override
// riferisca fase e ruolo esistenti -> qui non servono ulteriori check.
function resolvePhasesForMode(map, modeName) {
  const overrides = (modeName != null && isPlainObject(map.modes) && isPlainObject(map.modes[modeName]))
    ? map.modes[modeName] : {};
  const rows = [];
  for (const phase of Object.keys(map.phases)) {
    const overridden = hasOwn(overrides, phase);
    const role = overridden ? overrides[phase] : map.phases[phase];
    rows.push({ phase, role, model: map.roles[role].model, overridden });
  }
  rows.sort((a, b) => cmpCodeUnit(a.phase, b.phase));
  return rows;
}

function overridesAppliedForMode(map, modeName) {
  const ov = (modeName != null && isPlainObject(map.modes) && isPlainObject(map.modes[modeName]))
    ? map.modes[modeName] : {};
  return Object.keys(ov).sort(cmpCodeUnit);
}

// Proposta sidecar per modo: campi DETERMINISTICI, nessun timestamp (render/plan).
function buildProposal(map, mapSha256, modeName) {
  const proposal = {
    generated_by: GENERATOR,
    version: SUPPORTED_MAP_VERSION,
    roles: deepCopy(map.roles),
    phases_resolved: {},
    mode_overrides_applied: overridesAppliedForMode(map, modeName),
    map_sha256: mapSha256,
  };
  for (const row of resolvePhasesForMode(map, modeName)) {
    proposal.phases_resolved[row.phase] = { role: row.role, model: row.model };
  }
  return proposal;
}

// Stato del sidecar esistente in una mode-dir. Errori "strani" (permessi, non-file) -> throw
// fail-closed; solo ENOENT e' uno stato normale (sidecar assente -> create). JSON non
// parsabile NON e' fatale: e' contenuto diverso -> update (con backup in apply).
function readSidecarState(modeDir) {
  const p = path.join(modeDir, SIDECAR_NAME);
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    if (e.code === 'ENOENT') return { exists: false, path: p };
    throw new Error('impossibile stat del sidecar "' + p + '": ' + e.message);
  }
  if (!st.isFile()) throw new Error('il sidecar "' + p + '" non è un file regolare: rifiuto (fail-closed)');
  let obj;
  try {
    obj = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    return { exists: true, path: p, parseError: e.message };
  }
  return { exists: true, path: p, obj: isPlainObject(obj) ? obj : null };
}

// Confronto semantico: uguali se TUTTI i campi della proposta coincidono; chiavi extra nel
// sidecar esistente (es. applied_at scritto da apply) NON contano come divergenza.
function divergingKeys(existingObj, proposal) {
  if (!isPlainObject(existingObj)) return Object.keys(proposal);
  const out = [];
  for (const k of Object.keys(proposal)) {
    if (!hasOwn(existingObj, k) || !jsonEqual(existingObj[k], proposal[k])) out.push(k);
  }
  return out;
}

// ---- guardie anti-traversal per render ---------------------------------------------
// realpathSync "best effort": risolve il REAL path dell'antenato esistente piu' vicino e
// riattacca i segmenti mancanti -> i symlink sugli antenati non possono mascherare il target.
function realPathBestEffort(p) {
  let cur = path.resolve(p);
  const tail = [];
  for (;;) {
    try {
      return path.resolve.apply(null, [fs.realpathSync(cur)].concat(tail));
    } catch (_) {
      const parent = path.dirname(cur);
      if (parent === cur) return path.resolve.apply(null, [cur].concat(tail));
      tail.unshift(path.basename(cur));
      cur = parent;
    }
  }
}
function isSameOrInside(child, ancestor) {
  return child === ancestor || child.startsWith(ancestor + path.sep);
}
function outdirRejections(outArg) {
  const resolved = path.resolve(outArg);
  const home = os.homedir();
  const dshDir = path.join(home, '.dsh');
  const presetsRoot = presetsRootDir();
  const reasons = [];
  const rootOfFs = path.parse(resolved).root;
  if (resolved === rootOfFs) {
    reasons.push('--out "' + outArg + '" risolve nella RADICE del filesystem ("' + resolved + '"): rifiutato');
  }
  // HOME: rifiuto solo per UGUAGLIANZA (spec) — una sottodirectory qualsiasi della home è
  // outdir legittimo; il contenimento vietato riguarda ~/.dsh e AGENT_PRESETS_DIR.
  const lexicalTargets = [
    { label: 'la HOME dell\'utente', target: home, inside: false },
    { label: 'la directory riservata ~/.dsh', target: dshDir, inside: true },
    { label: 'la root dei preset (AGENT_PRESETS_DIR)', target: presetsRoot, inside: true },
  ];
  for (const t of lexicalTargets) {
    const hit = t.inside ? isSameOrInside(resolved, t.target) : resolved === t.target;
    if (hit) {
      reasons.push('--out "' + outArg + '" risolve in "' + resolved + '" =/' + (t.inside ? 'dentro ' : '') + t.label +
        ' ("' + t.target + '"): rifiutato');
    }
  }
  // Secondo livello: stessi check sui real-path (anti-symlink sull'antenato esistente piu' vicino).
  const realResolved = realPathBestEffort(resolved);
  const realTargets = [
    { label: 'la HOME dell\'utente (realpath)', target: realPathBestEffort(home), inside: false },
    { label: 'la directory riservata ~/.dsh (realpath)', target: realPathBestEffort(dshDir), inside: true },
    { label: 'la root dei preset AGENT_PRESETS_DIR (realpath)', target: realPathBestEffort(presetsRoot), inside: true },
  ];
  for (const t of realTargets) {
    const hit = t.inside ? isSameOrInside(realResolved, t.target) : realResolved === t.target;
    if (hit) {
      reasons.push('--out "' + outArg + '" ha realpath "' + realResolved + '" =/' + (t.inside ? 'dentro ' : '') + t.label +
        ' ("' + t.target + '"): rifiutato');
    }
  }
  return reasons;
}

// Stato della root preset per plan/render/apply.
function rootStatus(root) {
  if (!fs.existsSync(root)) return { exists: false };
  let st;
  try {
    st = fs.statSync(root);
  } catch (e) {
    throw new Error('impossibile stat della root dei preset "' + root + '": ' + e.message);
  }
  return { exists: true, isDirectory: st.isDirectory() };
}

// ---- comando: plan (dry-run, ZERO scritture) ----------------------------------------
function cmdPlan(res) {
  const root = presetsRootDir();
  console.log('model-routing: plan — DRY-RUN, ZERO scritture su fs (nemmeno mkdir)');
  console.log('mappa        : ' + res.path);
  console.log('map sha256   : ' + res.sha256);
  console.log('preset root  : ' + root);

  const rs = rootStatus(root); // può throware fail-closed su errori fs diversi da ENOENT
  if (!rs.exists) {
    console.log('\nroot assente (' + root + ') — nessuna azione.');
    return 0;
  }
  if (!rs.isDirectory) {
    console.error('ERRORE: la root dei preset "' + root + '" esiste ma NON è una directory: rifiuto (fail-closed)');
    return 1;
  }

  const modes = listModeDirs(root);

  // Tabella ruoli -> modello.
  console.log('\nRuoli -> modello:');
  for (const role of Object.keys(res.map.roles)) {
    const note = res.map.roles[role].note ? '   # ' + res.map.roles[role].note : '';
    console.log('  ' + pad(role, 12) + '-> ' + res.map.roles[role].model + note);
  }

  // Tabella globale fase -> ruolo -> modello.
  console.log('\nFasi -> ruolo -> modello (globale):');
  for (const row of resolvePhasesForMode(res.map, null)) {
    console.log('  ' + pad(row.phase, 16) + '-> ' + pad(row.role, 12) + '-> ' + row.model);
  }

  // Override per-mode configurati nella mappa (anche per mode senza dir su disco).
  console.log('\nOverride per-mode configurati nella mappa:');
  const overrideModes = res.map.modes && isPlainObject(res.map.modes) ? Object.keys(res.map.modes).sort(cmpCodeUnit) : [];
  if (overrideModes.length === 0) {
    console.log('  (nessuno)');
  } else {
    for (const mode of overrideModes) {
      for (const row of resolvePhasesForMode(res.map, mode)) {
        if (row.overridden) {
          console.log('  ' + pad('(' + mode + ')', 20) + pad(row.phase, 16) + '-> ' + pad(row.role, 12) + '-> ' + row.model);
        }
      }
    }
  }

  // Azione per modo: create / update / unchanged (unita' di aggiornamento = sidecar).
  console.log('\nAzioni per modo (unità di aggiornamento: <modo>/' + SIDECAR_NAME + '):');
  if (modes.length === 0) {
    console.log('  (nessuna mode-dir trovata sotto ' + root + ')');
    return 0;
  }
  for (const m of modes) {
    const proposal = buildProposal(res.map, res.sha256, m.name);
    const st = readSidecarState(m.dir);
    let action, note;
    if (!st.exists) {
      action = 'create';
      note = 'sidecar assente';
    } else if (st.parseError) {
      action = 'update';
      note = 'sidecar presente ma NON parsabile (' + st.parseError + ') → verrà fatto backup';
    } else {
      const dk = divergingKeys(st.obj, proposal);
      if (dk.length === 0) { action = 'unchanged'; note = 'contenuto proposto identico (applied_at escluso dal confronto)'; }
      else { action = 'update'; note = 'diverge su: ' + dk.join(', '); }
    }
    console.log('  ' + pad(m.name, 18) + pad(action, 11) + note);
  }
  console.log('\n(dry-run completato: nessuna scrittura eseguita; usa render/apply per agire)');
  return 0;
}

// ---- comando: render --out <dir> ------------------------------------------------------
function cmdRender(res, cli) {
  // Guardie PRIMA di qualunque effetto (nemmeno mkdir): doppio check lessicale + realpath.
  const reasons = outdirRejections(cli.out);
  if (reasons.length > 0) {
    console.error('render RIFIUTATO (fail-closed) — zero scritture eseguite. Motivi:');
    for (const r of reasons) console.error('  - ' + r);
    return 1;
  }
  const root = presetsRootDir();
  const rs = rootStatus(root);
  if (!rs.exists) {
    console.log('root assente (' + root + ') — nessuna proposta da renderizzare (zero scritture).');
    return 0;
  }
  if (!rs.isDirectory) {
    console.error('ERRORE: la root dei preset "' + root + '" esiste ma NON è una directory: rifiuto (fail-closed)');
    return 1;
  }
  const modes = listModeDirs(root);
  const outAbs = path.resolve(cli.out);
  fs.mkdirSync(outAbs, { recursive: true }); // solo DOPO i check di rifiuto
  if (modes.length === 0) {
    console.log('nessuna mode-dir trovata sotto ' + root + ' — outdir creato ma vuoto: ' + outAbs);
    return 0;
  }
  let n = 0;
  for (const m of modes) {
    const proposal = buildProposal(res.map, res.sha256, m.name); // deterministico: niente timestamp
    const dest = path.join(outAbs, m.name + '.' + SIDECAR_NAME);
    atomicWriteFile(dest, Buffer.from(serializeJson(proposal), 'utf8'));
    console.log('proposta scritta: ' + dest);
    n++;
  }
  console.log('render completato: ' + n + ' proposte (deterministiche, senza applied_at) in ' + outAbs);
  return 0;
}

// ---- comando: apply [--yes] ------------------------------------------------------------
function cmdApply(res, cli) {
  // Gate 1: mai sovrascrittura automatica — senza --yes ZERO scritture, anche se tutto il resto è valido.
  if (!cli.yes) {
    console.error('apply RIFIUTATO: manca --yes — nessuna sovrascrittura automatica, ZERO scritture eseguite.');
    console.error('riprova consapevolmente con: node ' + GENERATOR + ' apply --yes');
    return 1;
  }
  // Gate 2: root esistente (richiesta da spec per apply).
  const root = presetsRootDir();
  const rs = rootStatus(root);
  if (!rs.exists || !rs.isDirectory) {
    console.error('apply RIFIUTATO: root dei preset assente o non-directory (' + root + ') — zero scritture.');
    return 1;
  }
  let modes;
  try {
    modes = listModeDirs(root);
  } catch (e) {
    console.error('ERRORE discovery: ' + e.message);
    return 1;
  }
  if (modes.length === 0) {
    console.log('nessuna mode-dir trovata sotto ' + root + ' — nulla da fare (zero scritture).');
    return 0;
  }

  // PREFLIGHT all-or-nothing: TUTTO viene verificato prima della prima scrittura.
  const nowIso = new Date().toISOString(); // unico timestamp del batch (coerenza tra i modi)
  const stamp = nowIso.replace(/[:.]/g, '-'); // sicuro come nome-file: 2026-08-26T15-30-45-123Z
  const jobs = [];
  let backupsNeeded = 0;
  try {
    for (const m of modes) {
      fs.accessSync(m.dir, fs.constants.W_OK); // throw -> catturato sotto
      const st = readSidecarState(m.dir);      // throw su stati anomali -> fail-closed
      const job = { m, st, proposal: buildProposal(res.map, res.sha256, m.name) };
      if (st.exists) {
        job.original = fs.readFileSync(st.path); // byte originali da copiare in backup
        backupsNeeded++;
      }
      jobs.push(job);
    }
    if (backupsNeeded > 0) fs.accessSync(root, fs.constants.W_OK);
  } catch (e) {
    console.error('preflight FALLITO (zero scritture eseguite): ' + e.message);
    return 1;
  }
  const backupDir = path.join(root, BACKUP_DIRNAME, stamp);
  if (backupsNeeded > 0 && fs.existsSync(backupDir)) {
    console.error('preflight FALLITO: collisione timestamp backup, esiste già "' + backupDir + '" — zero scritture, riprovare.');
    return 1;
  }

  // Fase di scrittura: backup (con SHA256SUMS formato `sha256sum -c`) POI sidecar atomici.
  try {
    if (backupsNeeded > 0) {
      fs.mkdirSync(backupDir, { recursive: true });
      const sums = [];
      for (const job of jobs) {
        if (!job.original) continue;
        const backupFile = job.m.name + '.' + SIDECAR_NAME;
        fs.writeFileSync(path.join(backupDir, backupFile), job.original);
        sums.push(sha256Hex(job.original) + '  ' + backupFile + '\n'); // "<sha>  <nome>: compatibile sha256sum -c
      }
      atomicWriteFile(path.join(backupDir, 'SHA256SUMS'), Buffer.from(sums.join(''), 'utf8'));
      console.log('backup: ' + backupDir + ' (' + backupsNeeded + ' sidecar precedenti + SHA256SUMS)');
    }
    for (const job of jobs) {
      const sidecar = deepCopy(job.proposal);
      sidecar.applied_at = nowIso; // solo apply aggiunge applied_at (dopo gli altri campi)
      const wasUpdate = !!job.original;
      atomicWriteFile(path.join(job.m.dir, SIDECAR_NAME), Buffer.from(serializeJson(sidecar), 'utf8'));
      console.log('[' + job.m.name + '] ' + SIDECAR_NAME + ' ' + (wasUpdate ? 'aggiornato (precedente in backup)' : 'creato') +
        ' — applied_at=' + nowIso + ', map_sha256=' + res.sha256);
    }
  } catch (e) {
    // Atomicità multi-file non esiste su POSIX: qui l'errore è a metà batch. I backup già
    // scritti permettono il ripristino manuale; falliamo LOUD, mai silenziosamente.
    console.error('ERRORE durante la scrittura (batch parziale!): ' + e.message);
    console.error('i backup già presenti sotto ' + path.join(root, BACKUP_DIRNAME) + ' permettono il ripristino manuale.');
    return 1;
  }
  console.log('apply completato: ' + jobs.length + ' modi, ' + backupsNeeded + ' backup, applied_at=' + nowIso);
  return 0;
}

// ---- CLI ---------------------------------------------------------------------------------
function printUsage(to) {
  to('usage: node ' + GENERATOR + ' [plan]                      dry-run: tabelle + azioni per modo, ZERO scritture');
  to('       node ' + GENERATOR + ' render --out <dir>          proposte deterministiche <dir>/<mode>.model-route.json');
  to('       node ' + GENERATOR + ' apply [--yes]               scrive i sidecar (senza --yes: solo rifiuto, zero scritture)');
  to('       node ' + GENERATOR + ' help');
  to('');
  to('env: MODEL_ROUTING_FILE (default: tools/model-routing.json) · AGENT_PRESETS_DIR');
  to('     (default: ~/.dsh/.agent-presets, via os.homedir()). Unità di aggiornamento: SOLO il');
  to('     sidecar model-route.json dentro ogni mode-dir; MAI preset.yml/agent.cordis.yml/skills/refs.');
  to('exit: 0 ok | 1 rifiuto/validazione | 2 uso errato');
}

// Parsing permissive ma severo sulle flag: valore mancante o flag ignota -> uso errato (2).
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--yes') out.yes = true;
    else if (a === '--out') {
      const v = argv[++i];
      if (v == null) throw new TypeError('flag --out richiede un valore <dir>');
      out.out = v;
    } else if (a === '-h' || a === '--help') out.help = true;
    else if (/^--/.test(a) || /^-[^-]/.test(a)) throw new TypeError('flag sconosciuta "' + a + '"');
    else out._.push(a);
  }
  return out;
}

function main() {
  let cli;
  try {
    cli = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error('uso errato: ' + (e && e.message ? e.message : String(e)));
    printUsage(console.error);
    return 2;
  }
  if (cli.help || cli._.length === 0 || cli._[0] === 'help') {
    printUsage(console.log);
    return 0;
  }
  const cmd = cli._[0];
  const extra = cli._.slice(1);

  // Flag non applicabili al comando = uso errato (evita --yes "spente" su comandi read-only).
  if (cmd !== 'apply' && cli.yes) {
    console.error('uso errato: --yes è applicabile solo ad "apply"');
    return 2;
  }
  if (cmd !== 'render' && cli.out != null) {
    console.error('uso errato: --out è applicabile solo a "render"');
    return 2;
  }

  // La mappa va caricata+validata per OGNI modalità (plan incluso): fail-closed con elenco completo.
  const res = loadMap();
  if (!res.ok) {
    if (res.kind === 'io') {
      console.error('uso errato/input illeggibile: ' + res.message);
      return 2;
    }
    console.error('mappa RESPINTA (fail-closed) — ' + res.errors.length + ' errori:');
    for (const e of res.errors) console.error('ERRORE: ' + e);
    return 1;
  }

  if (cmd === 'plan') {
    if (extra.length > 0) { console.error('uso errato: "plan" non accetta argomenti extra (' + extra.join(' ') + ')'); return 2; }
    return cmdPlan(res);
  }
  if (cmd === 'render') {
    if (cli.out == null) { console.error('uso errato: render richiede --out <dir>'); return 2; }
    if (extra.length > 0) { console.error('uso errato: "render" non accetta argomenti extra (' + extra.join(' ') + ')'); return 2; }
    return cmdRender(res, cli);
  }
  if (cmd === 'apply') {
    if (extra.length > 0) { console.error('uso errato: "apply" non accetta argomenti extra (' + extra.join(' ') + ')'); return 2; }
    return cmdApply(res, cli);
  }
  console.error('uso errato: comando sconosciuto "' + cmd + '"');
  printUsage(console.error);
  return 2;
}

if (require.main === module) process.exit(main());

// Libreria: pezzi puri riutilizzabili da test/orchestratore senza spawn (zero side-effect).
module.exports = {
  validateMap, loadMap, listModeDirs, resolvePhasesForMode,
  overridesAppliedForMode, buildProposal, readSidecarState, divergingKeys,
  jsonEqual, cmpCodeUnit, outdirRejections, realPathBestEffort, parseArgs,
  constants: { GENERATOR, SIDECAR_NAME, BACKUP_DIRNAME, SUPPORTED_MAP_VERSION },
};
