// Offline self-check for privacy tokenization (PII path -> must have a test).
// Run: node tools/test-privacy.js
const assert = require('assert');
const fs = require('fs'), os = require('os'), path = require('path');
const mapFile = path.join(os.tmpdir(), 'tokmap-' + process.pid + '.json');
process.env.TOKEN_MAP = mapFile;
process.env.STAVROS_PRIVACY = '1';
const { tokenize, rehydrate, seedFromScope, loadMap } = require('./privacy');

// seed from scope populates HOST/IP
seedFromScope({ allowed_hosts: ['target.example.com'], allowed_ips: ['10.1.2.3', '10.0.0.0/8'] });
const m = loadMap();
assert.ok(Object.values(m.forward).some((t) => t.startsWith('HOST_')), 'HOST seeded');
assert.ok(Object.values(m.forward).some((t) => t.startsWith('IP_')), 'IP seeded');

// tokenize replaces detected PII with typed deterministic placeholders
const raw = 'admin@corp.io hit 192.168.9.9 and target.example.com';
const tok = tokenize(raw);
assert.ok(/EMAIL_\d{3}/.test(tok), 'email tokenized: ' + tok);
assert.ok(/IP_\d{3}/.test(tok), 'ip tokenized');
assert.ok(/HOST_\d{3}/.test(tok), 'seeded host tokenized');
assert.ok(!tok.includes('admin@corp.io'), 'no raw email leaks');

// deterministic: same real -> same token
assert.strictEqual(tokenize('admin@corp.io'), tokenize('admin@corp.io'));

// rehydrate is the exact inverse (round-trip)
assert.strictEqual(rehydrate(tok), raw, 'round-trip rehydrate(tokenize(x))===x');

// regression: a seeded host that's a substring of an email's domain must not fragment the
// email (regex pass must run BEFORE the seeded known-value split/join pass)
const mapFile2 = path.join(os.tmpdir(), 'tokmap2-' + process.pid + '.json');
process.env.TOKEN_MAP = mapFile2;
seedFromScope({ allowed_hosts: ['corp.io'], allowed_ips: [] });
const overlapTok = tokenize('admin@corp.io');
assert.ok(/EMAIL_\d{3}/.test(overlapTok), 'overlap: email tokenized: ' + overlapTok);
assert.ok(!overlapTok.includes('admin@'), 'overlap: username not leaked: ' + overlapTok);
assert.strictEqual(rehydrate(overlapTok), 'admin@corp.io', 'overlap: round-trip');
fs.rmSync(mapFile2, { force: true });
process.env.TOKEN_MAP = mapFile;

// disabled -> passthrough
process.env.STAVROS_PRIVACY = '0';
assert.strictEqual(tokenize('admin@corp.io'), 'admin@corp.io', 'disabled -> no tokenization');
process.env.STAVROS_PRIVACY = '1';

fs.rmSync(mapFile, { force: true });
console.log('privacy: all tests passed');
