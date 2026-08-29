#!/usr/bin/env node
// Zero-dependency OFFLINE test for tools/reflector.js (F3 auto-recovery).
// Stile tools/test-gate.js: PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
// Proprietà: nessuna rete, solo stdlib; fixture jsonl generate in directory TEMPORANEA;
// stdin testato via spawnSync input (nessuna TTY). I path reali del workspace non vengono toccati.
//
// Run: node tools/test-reflector.js

'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TOOL = path.join(__dirname, 'reflector.js');

let pass = 0, fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

function mkfixture(tag) { return fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-reflector-test-' + tag + '-')); }

function writeJsonl(file, entries) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}

function runReflector(args, opts) {
  const o = Object.assign({ encoding: 'utf8' }, opts || {});
  return spawnSync(process.execPath, [TOOL].concat(args), o);
}

const fail1 = (tool, err) => ({ tool, args: [], error: err, ts: '2026-08-26T00:00:00Z' });
const okEntry = (tool) => ({ tool, args: [], error: null, ts: '2026-08-26T00:00:01Z' });

console.log('# tools/reflector.js — F3');

// --- gruppo 1: unit su scan/hintFor (exports, senza spawn) --------------------
{
  const rf = require('./reflector.js');
  ok('USAGE_HINTS contiene i comandi harness richiesti dalla specifica', () => {
    for (const k of ['run.js', 'record-finding.js', 'verify-finding.js', 'repeater.js', 'coverage.js', 'gate.js']) {
      assert.ok(rf.USAGE_HINTS[k] && rf.USAGE_HINTS[k].length > 20, 'hint mancante/debole: ' + k);
    }
  });
  ok('hintFor: match esatto, con .js, basename e fallback generico', () => {
    assert.strictEqual(rf.hintFor('run.js').matched, true);
    assert.strictEqual(rf.hintFor('run').matched, true);
    assert.strictEqual(rf.hintFor('/percorso/qualunque/repeater.js').matched, true);
    const fb = rf.hintFor('tool-inesistente-xyz');
    assert.strictEqual(fb.matched, false);
    assert.strictEqual(fb.hint, rf.FALLBACK_HINT);
  });
  ok('scan: 2 fallimenti consecutivi -> nessun intervento', () => {
    const r = rf.scan([fail1('run.js', 'e1'), fail1('run.js', 'e2')], 3, 2);
    assert.strictEqual(r.intervention, false);
    assert.strictEqual(r.maxRun, 2);
  });
  ok('scan: 3 fallimenti consecutivi stesso tool -> intervento + last_errors=[2]', () => {
    const r = rf.scan([fail1('run.js', 'e1'), fail1('run.js', 'e2'), fail1('run.js', 'e3')], 3, 2);
    assert.strictEqual(r.intervention, true);
    assert.strictEqual(r.tool, 'run.js');
    assert.strictEqual(r.failures, 3);
    assert.deepStrictEqual(r.last_errors, ['e2', 'e3']);
  });
  ok('scan: un successo in mezzo ROMPE la serie', () => {
    const r = rf.scan([fail1('run.js', 'e1'), fail1('run.js', 'e2'), okEntry('run.js'), fail1('run.js', 'e3')], 3, 2);
    assert.strictEqual(r.intervention, false);
  });
  ok('scan: errore di UN ALTRO tool rompe la serie (stesso-tool richiesto)', () => {
    const events = [fail1('run.js', 'e1'), fail1('run.js', 'e2'), fail1('gate.js', 'g1'), fail1('run.js', 'e3')];
    const r = rf.scan(events, 3, 2);
    assert.strictEqual(r.intervention, false);
    assert.strictEqual(r.maxRun, 2);
  });
  ok('scan: righe malformate/senza tool saltate SENZA rompere la serie', () => {
    const events = [fail1('run.js', 'e1'), { rotta: true }, null, fail1('run.js', 'e2'), fail1('run.js', 'e3')];
    const r = rf.scan(events.filter(Boolean), 3, 2); // null filtrato a monte come fa parseEntries sulle righe
    assert.strictEqual(r.intervention, true);
  });
}

// --- gruppo 2: CLI --log -------------------------------------------------------
{
  const fx = mkfixture('a');
  try {
    const fNo = path.join(fx, 'no-intervention.jsonl');
    const fYes = path.join(fx, 'intervention.jsonl');
    writeJsonl(fNo, [fail1('record-finding.js', 'missing severity'), fail1('record-finding.js', 'bad json')]);
    writeJsonl(fYes, [
      fail1('verify-finding.js', 'finding json malformato'),
      fail1('verify-finding.js', 'host fuori scope'),
      fail1('verify-finding.js', 'oracolo non disponibile'),
    ]);

    const r0 = runReflector(['--log', fNo]);
    ok('CLI 2 fallimenti -> exit 0, intervention:false, usage_hint:null', () => {
      assert.strictEqual(r0.status, 0);
      const o = JSON.parse(r0.stdout);
      assert.strictEqual(o.intervention, false);
      assert.strictEqual(o.usage_hint, null);
      assert.strictEqual(o.longest_failure_run, 2);
    });

    const r6 = runReflector(['--log', fYes]);
    ok('CLI 3 fallimenti -> exit 6 + recovery JSON completo', () => {
      assert.strictEqual(r6.status, 6);
      const o = JSON.parse(r6.stdout);
      assert.strictEqual(o.intervention, true);
      assert.strictEqual(o.tool, 'verify-finding.js');
      assert.strictEqual(o.failures, 3);
      assert.strictEqual(o.threshold, 3);
      assert.strictEqual(Array.isArray(o.last_errors) && o.last_errors.length, 2);
      assert.ok(/verify-finding\.js/.test(o.usage_hint));
      assert.ok(/FERMATI|operatore/.test(o.instruction));
      assert.ok(r6.stderr.includes('exit 6'));
    });

    const rT2 = runReflector(['--log', fNo, '--threshold', '2']);
    ok('--threshold 2 abbassa la soglia -> exit 6 sullo stesso log', () => {
      assert.strictEqual(rT2.status, 6);
      assert.strictEqual(JSON.parse(rT2.stdout).threshold, 2);
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 3: stdin + advise + errori d'uso -----------------------------------
{
  const fx = mkfixture('b');
  try {
    const stdinText = [
      JSON.stringify(fail1('repeater.js', 'dns pin mismatch')),
      JSON.stringify(fail1('repeater.js', 'conn refused')),
      JSON.stringify(fail1('repeater.js', 'timeout')),
    ].join('\n') + '\n';
    const rIn = runReflector([], { input: stdinText });
    ok('stdin piped accettato al posto di --log -> exit 6', () => {
      assert.strictEqual(rIn.status, 6);
      assert.strictEqual(JSON.parse(rIn.stdout).tool, 'repeater.js');
    });

    const rAdv1 = runReflector(['advise', '--tool', 'coverage']);
    ok('advise --tool coverage -> matched:true + hint firma reale, exit 0', () => {
      assert.strictEqual(rAdv1.status, 0);
      const o = JSON.parse(rAdv1.stdout);
      assert.strictEqual(o.matched, true);
      assert.ok(/^node tools\/coverage\.js/.test(o.usage_hint));
    });

    const rAdv2 = runReflector(['advise', '--tool', 'strumento-misterioso']);
    ok('advise tool sconosciuto -> fallback generico, matched:false, exit 0', () => {
      assert.strictEqual(rAdv2.status, 0);
      const o = JSON.parse(rAdv2.stdout);
      assert.strictEqual(o.matched, false);
      assert.ok(o.usage_hint.length > 20);
    });

    const rAdvNoTool = runReflector(['advise']);
    ok('advise senza --tool -> exit 2', () => assert.strictEqual(rAdvNoTool.status, 2));

    const rNoInput = runReflector([], { input: '' });
    // stdin vuoto: nessun dato utilizzabile -> uso errato (nessun crash)
    ok('nessun input -> exit 2 (usage), mai crash', () => {
      assert.strictEqual(rNoInput.status, 2);
    });

    const rMissLog = runReflector(['--log', path.join(fx, 'assente.jsonl')]);
    ok('--log file illeggibile -> exit 2', () => assert.strictEqual(rMissLog.status, 2));

    const messy = path.join(fx, 'messy.jsonl');
    fs.writeFileSync(messy, [
      '{non-json',
      JSON.stringify(fail1('gate.js', 'x')),
      JSON.stringify(fail1('gate.js', 'y')),
      '',
      JSON.stringify(fail1('gate.js', 'z')),
    ].join('\n'));
    const rMessy = runReflector(['--log', messy]);
    ok('righe malformate contate in skipped_lines senza rompere la serie -> exit 6', () => {
      assert.strictEqual(rMessy.status, 6);
      const o = JSON.parse(rMessy.stdout);
      assert.strictEqual(o.skipped_lines, 1);
      assert.strictEqual(o.failures, 3);
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

console.log(`\nreflector: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
