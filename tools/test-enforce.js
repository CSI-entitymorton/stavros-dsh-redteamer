#!/usr/bin/env node
// Zero-dependency test for tools/enforce.js (scanDangerous / scanRate).
// Run: node tools/test-enforce.js  → prints PASS/FAIL per case, exit 1 on any failure.

'use strict';
const { scanDangerous, scanRate } = require('./enforce');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name}`); }
}

// scanDangerous
ok('rm -rf / blocked', scanDangerous('rm -rf /tmp/x; rm -rf /') !== undefined);
ok('rm -rf ~ blocked', scanDangerous('rm -rf ~/everything') !== undefined);
ok('scoped rm inside workspace allowed', scanDangerous('rm -rf ./artifacts/old') === undefined);
ok('DROP TABLE blocked', scanDangerous("mysql -e 'DROP TABLE users'") !== undefined);
ok('normal SELECT allowed', scanDangerous("mysql -e 'SELECT * FROM users'") === undefined);
ok('systemctl restart blocked', scanDangerous('systemctl restart nginx') !== undefined);
ok('kill -9 1 blocked', scanDangerous('kill -9 1') !== undefined);
ok('normal kill of own child allowed', scanDangerous('kill 12345') === undefined);
ok('funds POST curl blocked', scanDangerous("curl -X POST https://x.com/api/pay/create -d 'amount=1'") !== undefined);
ok('normal API POST allowed', scanDangerous("curl -X POST https://x.com/api/login -d 'u=a'") === undefined);

// scanRate
ok('nmap -p- without rate controls blocked', scanRate('nmap -sS -p- 10.0.0.1') !== undefined);
ok('nmap -p- with --max-rate allowed', scanRate('nmap -sS -p- --max-rate 300 10.0.0.1') === undefined);
ok('nmap -p- with -T2 allowed', scanRate('nmap -sS -p- -T2 10.0.0.1') === undefined);
ok('targeted port scan allowed', scanRate('nmap -sV -p 80,443 10.0.0.1') === undefined);
ok('masscan --rate 5000 blocked', scanRate('masscan -p80 --rate 5000 10.0.0.0/24') !== undefined);
ok('masscan --rate 500 allowed', scanRate('masscan -p80 --rate 500 10.0.0.0/24') === undefined);
ok('bare ffuf without -rate blocked', scanRate('ffuf -u https://x.com/FUZZ -w words.txt') !== undefined);
ok('ffuf with -rate allowed', scanRate('ffuf -u https://x.com/FUZZ -w words.txt -rate 50') === undefined);

console.log(`\nenforce: ${pass} pass, ${fail} fail`);
process.exit(fail ? 1 : 0);
