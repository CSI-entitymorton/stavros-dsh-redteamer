#!/usr/bin/env node
// F4 (Ondata 4) — Entity taxonomy: typed language for the memory graph + coverage.
//   docs/entity-taxonomy.yaml  = SINGLE source of truth (versioned).
//   Entità: Target/Port/Service/Vuln/Finding/Evidence (campi obbligatori + relazioni
//   consentite). Validatore DETERMINISTICO (stdlib-only, zero rete): entità → tipi;
//   rifiuto FAIL-CLOSED su campi mancanti/tipi errati/entità spurie.
//
// Adattatore READ-ONLY verso il grafo memoria (NDJSON lab-memory.json, server MCP memory):
//   le righe evidence/finding diventano entità tipizzate SENZA scrivere mai il grafo reale
//   (nei test: env MEMORY_GRAPH_FILE su fixture in mkdtemp). Righe legacy con entityType
//   non-tassonomico vengono contate come "skipped" (il server MCP esistente non si rompe),
//   MAI prodotte dai nostri adattatori.
//
// Integrazione coverage.js: le superfici coperte derivano da entità tipizzate via
//   coveredClassesFromEntities(); coverage.buildMatrix accetta opts.entities (ADDITIVO).
//
// CLI:
//   node tools/entity-taxonomy.js taxonomy                    # riepilogo tassonomia
//   node tools/entity-taxonomy.js validate '<entity-json>'   # valida UNA entità (exit 0/1)
//   node tools/entity-taxonomy.js validate-file <jsonl>      # valida N entità
//   node tools/entity-taxonomy.js map-findings <findings.jsonl>   # finding rows → entità tipizzate
//   node tools/entity-taxonomy.js graph <memory.ndjson>      # legge il grafo (read-only), valida
//
// Env: TAXONOMY_FILE (default docs/entity-taxonomy.yaml), MEMORY_GRAPH_FILE (default
// <ws>/lab-memory.json, usato SOLO in modalità esplicite, mai scritto).
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const coverage = require('./coverage');

const WS = path.join(__dirname, '..');
const TAXONOMY_FILE = () => process.env.TAXONOMY_FILE || path.join(WS, 'docs', 'entity-taxonomy.yaml');
const MEMORY_GRAPH_FILE = () => process.env.MEMORY_GRAPH_FILE || path.join(WS, 'lab-memory.json');

// I sei tipi della tassonomia (spec §3.1 F4). Nulla al di fuori è ammesso.
const ENTITY_TYPES = ['Target', 'Port', 'Service', 'Vuln', 'Finding', 'Evidence'];
// Tipi di campo ammessi per i campi opzionali/obbligatori dichiarati nella YAML.
const FIELD_TYPES = ['string', 'number', 'boolean', 'array', 'object'];
// Campi nativi del grafo MCP memory: sempre accettati su ogni istanza.
const GRAPH_NATIVE_FIELDS = ['type', 'observations'];

// ---------------------------------------------------------------- YAML subset parser
// Parser dedicato per il sottoinsieme usato da docs/entity-taxonomy.yaml (indentation-driven,
// fail-closed: qualsiasi costrutto fuori dal sottoinsieme nomina la riga). Blocchi con soli
// item "- " → lista; blocchi con sole chiavi "k: v" → mapping; niente sintassi flow.
function scalar(s, ln) {
  s = String(s == null ? '' : s).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1);
  if (s === '') return null;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^(true|false)$/.test(s)) return s === 'true';
  if (/^null$/.test(s)) return null;
  if (/[\[\]]/.test(s)) throw new Error(`entity-taxonomy yaml: flow syntax "${s}" non supportata (line ${ln}) — usare liste a blocchi`);
  return s;
}

function parseYaml(text) {
  const lines = text.split(/\r?\n/).map((raw, i) => {
    if (raw.includes('\t')) throw new Error(`entity-taxonomy yaml: tab non ammessi (line ${i + 1})`);
    const indent = raw.match(/^\s*/)[0].length;
    const body = raw.trim();
    return { indent, body, ln: i + 1 };
  }).filter((l) => l.body && !l.body.startsWith('#'));
  let pos = 0;
  const fail = (ln, msg) => { throw new Error(`entity-taxonomy yaml: line ${ln}: ${msg}`); };
  const peek = () => lines[pos];
  const next = () => lines[pos++];

  // Parsa un blocco di righe con lo STESSO indent `indent`: item "- x" (→ lista) oppure
  // chiavi "k: v" / "k:" + blocco annidato (→ mapping). Il primo item determina la forma;
  // mischiare è un errore (mai una congettura silenziosa).
  function parseBlock(indent) {
    const list = [];
    const map = {};
    let form = null;
    while (peek() && peek().indent === indent) {
      const { body, ln } = next();
      if (body.startsWith('- ')) {
        if (form === 'map') fail(ln, 'item di lista dentro un mapping');
        form = 'list';
        list.push(scalar(body.slice(2).trim(), ln));
        continue;
      }
      const m = body.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
      if (!m) fail(ln, `token inatteso: ${JSON.stringify(body.slice(0, 60))}`);
      if (form === 'list') fail(ln, 'chiave dentro una lista');
      form = 'map';
      const key = m[1];
      const rest = m[2].trim();
      if (rest !== '') {
        map[key] = scalar(rest, ln);
      } else if (peek() && peek().indent > indent) {
        map[key] = parseBlock(peek().indent);
      } else {
        map[key] = null;
      }
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
    if (rest !== '') { // valore scalare inline a livello top (es. version: 1)
      next();
      root[key] = scalar(rest, ln);
      continue;
    }
    next();
    if (!peek() || peek().indent <= 0) fail(ln, `il blocco "${key}" non ha contenuto`);
    root[key] = parseBlock(peek().indent);
  }
  return root;
}

// ---------------------------------------------------------------- taxonomy loading

function loadTaxonomy(file) {
  file = file || TAXONOMY_FILE();
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    throw new Error(`cannot read taxonomy ${file}: ${e.message}`);
  }
  const doc = parseYaml(raw);
  const errs = validateTaxonomyShape(doc);
  if (errs.length) throw new Error('invalid taxonomy: ' + errs.join('; '));
  return { file, version: doc.version, entities: doc.entities, relations: doc.relations || {} };
}

// Fail-closed sulla YAML stessa: nessun tipo sconosciuto, nessuna forma malformata.
function validateTaxonomyShape(doc) {
  const errs = [];
  if (!Number.isInteger(doc.version) || doc.version < 1) errs.push('version must be a positive int');
  if (!doc.entities || typeof doc.entities !== 'object' || Array.isArray(doc.entities)) {
    errs.push('entities block missing/malformed');
    return errs;
  }
  for (const name of Object.keys(doc.entities)) {
    if (!ENTITY_TYPES.includes(name)) errs.push(`unknown entity type "${name}" in taxonomy (allowed: ${ENTITY_TYPES.join('/')})`);
    const def = doc.entities[name];
    if (!def || typeof def !== 'object' || Array.isArray(def)) { errs.push(`${name}: definition must be a mapping`); continue; }
    if (typeof def.description !== 'string') errs.push(`${name}: description (string) required`);
    if (!Array.isArray(def.required) || !def.required.length || def.required.some((r) => typeof r !== 'string' || !r.trim()))
      errs.push(`${name}: required must be a non-empty list of field names`);
    if (def.optional != null) {
      if (typeof def.optional !== 'object' || Array.isArray(def.optional)) errs.push(`${name}: optional must be a mapping`);
      else for (const [k, t] of Object.entries(def.optional)) {
        if (!FIELD_TYPES.includes(t)) errs.push(`${name}.optional.${k}: unknown type "${t}" (allowed: ${FIELD_TYPES.join('|')})`);
      }
    }
    if (def.relations != null && (!Array.isArray(def.relations) || def.relations.some((r) => typeof r !== 'string')))
      errs.push(`${name}: relations must be a list of relation names`);
  }
  if (doc.relations != null) {
    if (typeof doc.relations !== 'object' || Array.isArray(doc.relations)) errs.push('relations must be a mapping');
    else for (const [rel, spec] of Object.entries(doc.relations)) {
      if (!spec || typeof spec !== 'object' || Array.isArray(spec)) { errs.push(`relations.${rel}: must be {from:[],to:[]}`); continue; }
      for (const side of ['from', 'to']) {
        if (!Array.isArray(spec[side]) || spec[side].some((e) => !ENTITY_TYPES.includes(e)))
          errs.push(`relations.${rel}.${side}: must be a list of entity types`);
      }
    }
  }
  return errs;
}

// ---------------------------------------------------------------- type checks

function typeOf(value) {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'string') return 'string';
  if (typeof value === 'number') return 'number';
  if (typeof value === 'boolean') return 'boolean';
  if (typeof value === 'object') return 'object';
  return typeof value;
}

function typeCheck(value, want) {
  const got = typeOf(value);
  if (want === 'array') {
    if (got !== 'array') return `expected array, got ${got}`;
    return null;
  }
  if (want === 'object') {
    if (got !== 'object') return `expected object, got ${got}`;
    return null;
  }
  if (want === 'string') {
    if (got !== 'string' || !String(value).trim()) return 'expected non-empty string';
    return null;
  }
  if (want === 'number') {
    if (got !== 'number' || !Number.isFinite(value)) return 'expected finite number';
    return null;
  }
  if (want === 'boolean') {
    if (got !== 'boolean') return 'expected boolean';
    return null;
  }
  return `unknown field type "${want}"`;
}

// ---------------------------------------------------------------- entity validation

/**
 * Validate ONE entity instance against the taxonomy. Strict (fail-closed): unknown
 * entityType, missing required fields, wrong optional types, unknown fields and unknown
 * relation types are all rejected. Returns null (valid) or an error string.
 * opts.allowNonTaxonomy=true → an entityType outside the taxonomy returns {skipped:true}
 * (used ONLY by the read-only graph adapter; never by our producers).
 */
function validateEntity(e, tax, opts) {
  tax = tax || loadTaxonomy();
  opts = opts || {};
  if (!e || typeof e !== 'object' || Array.isArray(e)) return 'entity must be an object';
  if (typeof e.entityType !== 'string' || !e.entityType.trim()) return 'entityType (string) is required';
  const def = tax.entities[e.entityType];
  if (!def) {
    if (opts.allowNonTaxonomy) return { skipped: true, entityType: e.entityType };
    return `spurious entity: unknown entityType "${e.entityType}" (allowed: ${ENTITY_TYPES.join('/')})`;
  }
  const known = new Set([...def.required, ...Object.keys(def.optional || {}), ...GRAPH_NATIVE_FIELDS, 'entityType', 'name', 'relations']);
  for (const k of Object.keys(e)) {
    if (!known.has(k)) return `spurious field "${k}" on ${e.entityType} (allowed: ${[...known].join(', ')})`;
  }
  for (const req of def.required) {
    if (e[req] === undefined || e[req] === null || e[req] === '' || (typeof e[req] === 'number' && !Number.isFinite(e[req])))
      return `${e.entityType}: missing required field "${req}"`;
  }
  for (const [k, want] of Object.entries(def.optional || {})) {
    if (e[k] !== undefined && e[k] !== null) {
      const err = typeCheck(e[k], want);
      if (err) return `${e.entityType}.${k}: ${err}`;
    }
  }
  // campi nativi del grafo
  if (e.type !== undefined && e.type !== 'entity') return `${e.entityType}: type must be "entity"`;
  if (e.observations !== undefined) {
    const oerr = typeCheck(e.observations, 'array');
    if (oerr) return `${e.entityType}.observations: ${oerr}`;
  }
  if (e.name !== undefined) {
    const nerr = typeCheck(e.name, 'string');
    if (nerr) return `${e.entityType}.name: ${nerr}`;
  }
  // relations: ogni link deve essere una relazione consentita per l'entità
  if (e.relations !== undefined) {
    const rerr = typeCheck(e.relations, 'array');
    if (rerr) return `${e.entityType}.relations: ${rerr}`;
    const allowed = def.relations || [];
    for (const r of e.relations) {
      const rel = typeof r === 'string' ? { type: r } : r;
      if (!rel || typeof rel !== 'object') return `${e.entityType}.relations: entry must be {type,to}`;
      if (typeof rel.type !== 'string' || !allowed.includes(rel.type))
        return `${e.entityType}.relations: "${String(rel.type)}" not allowed (allowed: ${allowed.join('/')})`;
      if (rel.to !== undefined && (typeof rel.to !== 'string' || !rel.to.trim()))
        return `${e.entityType}.relations.${rel.type}: "to" must be a non-empty id string`;
    }
  }
  return null;
}

function validateEntities(list, tax) {
  tax = tax || loadTaxonomy();
  const errors = [];
  if (!Array.isArray(list)) return { ok: false, errors: ['input must be an array of entities'] };
  list.forEach((e, i) => {
    const err = validateEntity(e, tax);
    if (err) errors.push(`[${i}] ${err}`);
  });
  return { ok: errors.length === 0, errors, valid: list.length - errors.length, total: list.length };
}

// ---------------------------------------------------------------- finding → entities
// Adattatore (puro, READ-ONLY): una riga findings.jsonl diventa entità tipizzate coerenti
// (Finding + Vuln + Evidence se evidence_quote + Target), ognuna validata. Niente scritture.

function stableId(prefix, s) {
  return `${prefix}-${crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 16)}`;
}

function findingToEntity(f) {
  const errors = [];
  if (!f || typeof f !== 'object' || Array.isArray(f)) return { entities: [], errors: ['finding must be an object'] };
  const id = stableId('F', `${f.host}|${f.endpoint || ''}|${f.title}`);
  const hostId = stableId('T', f.host || 'unknown');
  const cls = coverage.classOf(f); // stessa classificazione di coverage.js → superfici coerenti
  const vulnId = stableId('V', `${f.host || ''}|${f.endpoint || ''}|${cls}`);
  const entities = [];

  entities.push({
    type: 'entity', name: hostId, entityType: 'Target', id: hostId,
    observations: [`target from finding ${f.title || ''}`.trim()],
    relations: [{ type: 'references_target', to: hostId }],
  });

  entities.push({
    type: 'entity', name: vulnId, entityType: 'Vuln', id: vulnId,
    surface_ref: f.host || 'unknown', class: cls,
    ...(f.cwe ? { cwe: String(f.cwe) } : {}),
    observations: [`vuln class ${cls} on ${f.host || ''}`.trim()],
    relations: [{ type: 'materialized_as', to: id }],
  });

  const finding = {
    type: 'entity', name: id, entityType: 'Finding', id,
    vuln_ref: vulnId, severity: f.severity, status: f.status, host: f.host,
    title: String(f.title || ''),
    observations: [String(f.title || ''), ...(f.poc ? ['poc recorded'] : [])],
    relations: [{ type: 'references_target', to: hostId }],
  };
  if (f.endpoint) finding.endpoint = String(f.endpoint);
  if (f.cwe) finding.cwe = String(f.cwe);
  if (f.cvss != null) finding.cvss = f.cvss;
  if (f.epss != null) finding.epss = f.epss;
  if (Array.isArray(f.cves)) finding.cves = f.cves.slice();
  if (f.oracle) finding.oracle = f.oracle;
  if (f.verify_level) finding.verify_level = String(f.verify_level);
  if (f.usage) finding.usage = f.usage; // F8 (Ondata 4): usage additivo sui record nuovi
  if (f.evidence_quote && f.evidence_quote.file && f.evidence_quote.text) {
    const evId = stableId('E', `${id}|${f.evidence_quote.file}|${f.evidence_quote.text}`);
    entities.push({
      type: 'entity', name: evId, entityType: 'Evidence', id: evId,
      finding_ref: id, file: String(f.evidence_quote.file), text: String(f.evidence_quote.text),
      observations: ['evidence quote of finding'],
    });
    finding.relations.push({ type: 'has_evidence', to: evId });
  }
  entities.push(finding);

  // fail-closed: ogni entità mappata deve superare la validazione
  const tax = loadTaxonomy();
  for (const e of entities) {
    const err = validateEntity(e, tax);
    if (err) errors.push(`${e.entityType}: ${err}`);
  }
  if (errors.length) return { entities: [], errors };
  return { entities, errors: [] };
}

function findingsToEntities(findings, tax) {
  tax = tax || loadTaxonomy();
  const out = [];
  const errors = [];
  const seen = new Set();
  for (const f of findings) {
    const r = findingToEntity(f);
    if (r.errors.length) { errors.push(r.errors.join('; ')); continue; }
    for (const e of r.entities) {
      const k = e.entityType + '|' + e.id;
      if (!seen.has(k)) { seen.add(k); out.push(e); }
    }
  }
  return { entities: out, errors, deduped: out.length };
}

// ---------------------------------------------------------------- memory graph (read-only)
// Legge il NDJSON del grafo memoria (server MCP memory, es. lab-memory.json) e restituisce
// le entità TIPIZZATE con esiti. MAI una scrittura: il grafo resta di proprietà del server.

function graphEntitiesFromFile(file, tax) {
  tax = tax || loadTaxonomy();
  file = file || MEMORY_GRAPH_FILE();
  const entities = [];
  let total = 0, skipped = 0, invalid = 0;
  const errors = [];
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) {
    return { ok: false, file, error: `cannot read graph ${file}: ${e.message}`, total, skipped, invalid, entities, errors };
  }
  raw.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    total++;
    let obj;
    try { obj = JSON.parse(line); } catch {
      invalid++; errors.push(`line ${i + 1}: invalid JSON`); return;
    }
    const r = validateEntity(obj, tax, { allowNonTaxonomy: true });
    if (r && r.skipped) { skipped++; return; }
    if (r) { invalid++; errors.push(`line ${i + 1}: ${r}`); return; }
    entities.push(obj);
  });
  return { ok: true, file, total, taxonomy: entities.length, skipped, invalid, entities, errors };
}

// ---------------------------------------------------------------- coverage integration
// Le superfici coperte derivano da entità tipizzate (Vuln/Finding). Stessa classificazione
// di coverage.js (coverage.classOf) → i due strati restano coerenti per costruzione.

function coveredClassesFromEntities(entities, tax) {
  tax = tax || loadTaxonomy();
  const covered = new Set();
  for (const e of entities) {
    if (e.entityType === 'Vuln' && typeof e.class === 'string') {
      if (coverage.CLASSES.includes(e.class)) covered.add(e.class);
      else {
        const c = coverage.classOf({ cwe: e.class, title: e.class, type: e.class });
        if (c !== 'other') covered.add(c);
      }
    } else if (e.entityType === 'Finding') {
      const c = coverage.classOf(e);
      if (c !== 'other') covered.add(c);
    }
  }
  return [...covered].sort();
}

// ---------------------------------------------------------------- CLI

function printTaxonomy(tax) {
  const lines = [`# Entity taxonomy — ${tax.file} (version ${tax.version})`, ''];
  for (const [name, def] of Object.entries(tax.entities)) {
    lines.push(`## ${name}`);
    lines.push(def.description || '');
    lines.push(`- required: ${def.required.join(', ')}`);
    const opt = Object.entries(def.optional || {});
    if (opt.length) lines.push(`- optional: ${opt.map(([k, t]) => `${k}:${t}`).join(', ')}`);
    if (def.relations && def.relations.length) lines.push(`- relations: ${def.relations.join(', ')}`);
    lines.push('');
  }
  return lines.join('\n');
}

function main() {
  const [cmd, arg] = process.argv.slice(2);
  try {
    if (cmd === 'taxonomy') {
      console.log(printTaxonomy(loadTaxonomy()));
      return 0;
    }
    if (cmd === 'validate') {
      let e;
      try { e = JSON.parse(arg || ''); } catch (err) {
        console.log(JSON.stringify({ ok: false, error: 'invalid entity JSON: ' + err.message }));
        return 1;
      }
      const tax = loadTaxonomy();
      const err = validateEntity(e, tax);
      if (err) { console.log(JSON.stringify({ ok: false, error: err })); return 1; }
      console.log(JSON.stringify({ ok: true, entityType: e.entityType, id: e.id || e.name }));
      return 0;
    }
    if (cmd === 'validate-file') {
      const list = fs.readFileSync(arg, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
      const r = validateEntities(list, loadTaxonomy());
      console.log(JSON.stringify(r));
      return r.ok ? 0 : 1;
    }
    if (cmd === 'map-findings') {
      const findings = fs.readFileSync(arg, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
      const r = findingsToEntities(findings, loadTaxonomy());
      console.log(JSON.stringify({ ok: r.errors.length === 0, entities: r.entities, errors: r.errors, count: r.deduped }));
      return r.errors.length ? 1 : 0;
    }
    if (cmd === 'graph') {
      const r = graphEntitiesFromFile(arg, loadTaxonomy());
      console.log(JSON.stringify(r));
      return r.ok && r.invalid === 0 ? 0 : 1;
    }
    console.error('usage: node tools/entity-taxonomy.js taxonomy | validate \'<entity-json>\' | validate-file <jsonl> | map-findings <findings.jsonl> | graph <memory.ndjson>');
    return 2;
  } catch (e) {
    console.error(String(e.message || e));
    return 1;
  }
}

if (require.main === module) process.exit(main());

module.exports = {
  ENTITY_TYPES, FIELD_TYPES, TAXONOMY_FILE, MEMORY_GRAPH_FILE,
  loadTaxonomy, validateTaxonomyShape, validateEntity, validateEntities,
  findingToEntity, findingsToEntities, graphEntitiesFromFile, coveredClassesFromEntities,
  parseYaml, scalar,
};
