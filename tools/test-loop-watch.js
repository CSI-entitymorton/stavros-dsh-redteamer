#!/usr/bin/env node
// Zero-dependency OFFLINE test for tools/loop-watch.js (F1 loop detection).
// Stile tools/test-gate.js: PASS/FAIL per caso, exit 1 se almeno un FAIL.
//
// Proprietà: nessuna rete, solo stdlib; fixture jsonl generate in directory TEMPORANEA;
// i path reali del workspace non vengono MAI letti (ogni invocazione CLI passa file espliciti;
// l'env RUN_AUDIT_FILE ereditato viene ripulito).
//
// Run: node tools/test-loop-watch.js

'use strict';
const assert = require('assert');
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TOOL = path.join(__dirname, 'loop-watch.js');

let pass = 0, fail = 0;
function ok(name, fn) {
  try { fn(); pass++; console.log(`  PASS ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name} :: ${String(e.message).split('\n')[0]}`); }
}

function mkfixture(tag) { return fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-loopwatch-test-' + tag + '-')); }

function writeJsonl(file, entries) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}

function runLoopWatch(args, extraEnv) {
  const env = {};
  for (const k of Object.keys(process.env)) {
    if (!/^RUN_AUDIT_FILE$/.test(k)) env[k] = process.env[k];
  }
  Object.assign(env, extraEnv || {});
  return spawnSync(process.execPath, [TOOL].concat(args), { encoding: 'utf8', env });
}

const ev = (bin, args) => ({ bin, args, ts: '2026-08-26T00:00:00Z' });

console.log('# tools/loop-watch.js — F1');

// --- gruppo 1: unit su normalizzazione/firma (exports, senza spawn) ----------
{
  const lw = require('./loop-watch.js');
  ok('normalizeArg: numeri -> N', () => {
    assert.strictEqual(lw.normalizeArg('8080'), 'N');
    assert.strictEqual(lw.normalizeArg('-p'), '-p'); // i flag non numerici restano
  });
  ok('normalizeArg: porta dentro argomento composto -> N', () => assert.strictEqual(lw.normalizeArg('--rate=1000'), '--rate=N'));
  ok('normalizeArg: uuid -> H', () => assert.strictEqual(lw.normalizeArg('3f2504e0-4f89-41d3-9a0c-0305e82c3301'), 'H'));
  ok('normalizeArg: hash esadecimale >=8 char -> H', () => assert.strictEqual(lw.normalizeArg('deadbeefdeadbeef'), 'H'));
  ok('signatureOf: bin + args normalizzati joinati', () => {
    assert.strictEqual(lw.signatureOf({ bin: 'nmap', args: ['-p', '80'] }), 'nmap -p N');
    // firme stabili attraverso valori volatili: nmap -p 80 ≡ nmap -p 443
    assert.strictEqual(lw.signatureOf({ bin: 'nmap', args: ['-p', '80'] }), lw.signatureOf({ bin: 'nmap', args: ['-p', '443'] }));
  });
  ok('adviceFor(nmap) contiene advice per-bin; adviceFor(unknown) solo generico', () => {
    const aNmap = lw.adviceFor('nmap');
    assert.ok(aNmap.some((s) => s.startsWith('nmap:')));
    assert.ok(aNmap.length > lw.GENERIC_ADVICE.length);
    const aX = lw.adviceFor('tool-inventato');
    assert.deepStrictEqual(aX, lw.GENERIC_ADVICE);
  });
  ok('analyze: 4 identiche consecutive -> no loop; 5 -> loop consecutive', () => {
    const sig = [ev('ffuf', ['-u', 'http://target.example/FUZZ'])];
    const r4 = lw.analyze(sig.concat(sig, sig, sig), { minRepeat: 5, totalRepeat: 10 });
    assert.strictEqual(r4.loop, false);
    const r5 = lw.analyze(sig.concat(sig, sig, sig, sig), { minRepeat: 5, totalRepeat: 10 });
    assert.strictEqual(r5.loop, true);
    assert.strictEqual(r5.mode, 'consecutive');
    assert.strictEqual(r5.count, 5);
    assert.strictEqual(r5.signature, 'ffuf -u http://target.example/FUZZ');
  });
  ok('analyze: >=10 identiche NON-consecutivi -> loop mode total', () => {
    const A = ev('gobuster', ['dir', '-w', 'wl.txt']);
    const B = ev('nmap', ['-p-', 'target.example']);
    const events = [];
    for (let i = 0; i < 10; i++) events.push(A, B); // mai 5 A consecutivi, ma 10+10 nella finestra
    const r = lw.analyze(events, { minRepeat: 5, totalRepeat: 10 });
    assert.strictEqual(r.loop, true);
    assert.strictEqual(r.mode, 'total');
    assert.ok(r.count === 20 || r.count === 10);
  });
}

// --- gruppo 2: CLI su file fixture --------------------------------------------
{
  const fx = mkfixture('a');
  try {
    const f4 = path.join(fx, 'no-loop.jsonl');
    const f5 = path.join(fx, 'loop-consec.jsonl');
    const same = ev('nuclei', ['-l', 'urls.txt']);
    writeJsonl(f4, [same, same, same, same]);                       // 4 < 5
    writeJsonl(f5, [same, same, same, same, same]);                 // 5 >= 5

    const rOk = runLoopWatch([f4]);
    const oOk = JSON.parse(rOk.stdout);
    ok('CLI sotto soglia -> exit 0, output JSON con campi contratto', () => {
      assert.strictEqual(rOk.status, 0);
      assert.strictEqual(oOk.loop, false);
      assert.deepStrictEqual(oOk.advice, []);
      assert.strictEqual(oOk.thresholds.consecutive, 5);
      assert.strictEqual(oOk.events_analyzed, 4);
    });

    const rLoop = runLoopWatch([f5]);
    const oLoop = JSON.parse(rLoop.stdout);
    ok('CLI 5 identiche -> exit 5, mode consecutive, advice per-bin nuclei', () => {
      assert.strictEqual(rLoop.status, 5);
      assert.strictEqual(oLoop.loop, true);
      assert.strictEqual(oLoop.mode, 'consecutive');
      assert.ok(oLoop.advice.some((s) => s.startsWith('nuclei:')));
      assert.ok(rLoop.stderr.includes('LOOP DETECTED'));
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 3: --min-repeat / --total-repeat / --window-last ------------------
{
  const fx = mkfixture('b');
  try {
    const f = path.join(fx, 'mixed.jsonl');
    const A = ev('ffuf', ['-w', 'common.txt']);
    const B = ev('nikto', ['-h', 'http://target.example']);
    // 3 ffuf, 1 nikto, 3 ffuf, 1 nikto, 2 ffuf = ffuf totale 8, max run 3
    writeJsonl(f, [A, A, A, B, A, A, A, B, A, A]);

    const rDef = runLoopWatch([f]);
    ok('default: max-run 3 e totale 8 sotto soglia -> exit 0', () => {
      assert.strictEqual(rDef.status, 0);
      assert.strictEqual(JSON.parse(rDef.stdout).loop, false);
    });

    const rMin = runLoopWatch(['--min-repeat', '3', f]);
    ok('--min-repeat 3 -> exit 5 mode consecutive (count 3)', () => {
      assert.strictEqual(rMin.status, 5);
      const o = JSON.parse(rMin.stdout);
      assert.strictEqual(o.mode, 'consecutive');
      assert.strictEqual(o.count, 3);
    });

    const rTot = runLoopWatch(['--total-repeat', '8', f]);
    ok('--total-repeat 8 -> exit 5 mode total (count 8)', () => {
      assert.strictEqual(rTot.status, 5);
      const o = JSON.parse(rTot.stdout);
      assert.strictEqual(o.mode, 'total');
      assert.strictEqual(o.count, 8);
    });

    const rWin = runLoopWatch(['--window-last', '1', '--min-repeat', '3', f]);
    ok('--window-last 1 restringe la finestra -> exit 0 nonostante loop nel passato', () => {
      assert.strictEqual(rWin.status, 0);
      const o = JSON.parse(rWin.stdout);
      assert.strictEqual(o.events_analyzed, 1);
      assert.strictEqual(o.scanned, 10);
    });
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

// --- gruppo 4: robustezza input + uso errato ----------------------------------
{
  const fx = mkfixture('c');
  try {
    const messy = path.join(fx, 'messy.jsonl');
    fs.writeFileSync(messy, [
      JSON.stringify(ev('nmap', ['-p', '80'])),
      '{riga-non-json',
      JSON.stringify({ nota: 'senza campo bin' }),
      '',
      JSON.stringify(ev('nmap', ['-p', '80'])),
    ].join('\n'));
    const r = runLoopWatch([messy]);
    ok('righe malformate/senza bin saltate e contate, exit 0', () => {
      assert.strictEqual(r.status, 0);
      const o = JSON.parse(r.stdout);
      assert.strictEqual(o.skipped_lines, 2);
      assert.strictEqual(o.events_analyzed, 2);
      assert.strictEqual(o.scanned, 4);
    });

    const rMiss = runLoopWatch([path.join(fx, 'assente.jsonl')]);
    ok('file illeggibile -> exit 2', () => assert.strictEqual(rMiss.status, 2));

    const rBad = runLoopWatch(['--min-repeat', '1', messy]);
    ok('--min-repeat 1 -> exit 2 (uso errato)', () => assert.strictEqual(rBad.status, 2));
  } finally { fs.rmSync(fx, { recursive: true, force: true }); }
}

console.log(`\nloop-watch: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
