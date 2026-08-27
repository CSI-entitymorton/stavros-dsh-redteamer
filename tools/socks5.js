#!/usr/bin/env node
// Zero-dependency SOCKS5 client used by the anonymized egress chain.
//
//   const sock = await socks5Connect('127.0.0.1', 9050, 'api.target.com', 443);
//
// Key property: the target is sent to the proxy as a DOMAIN NAME (ATYP=0x03), so DNS
// resolution happens AT THE PROXY, never on the local machine. That is the DNS-leak
// guarantee of the chain: a local resolver must never see the destination hostname.
//
// Only the no-auth method (0x00) is implemented — that is what Tor (9050), dante,
// and the common commercial SOCKS5 providers expose. Fail-closed on anything else.
const net = require('net');

const SOCKS5 = 0x05;
const METHOD_NOAUTH = 0x00;
const CMD_CONNECT = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV4 = 0x01;
const ATYP_IPV6 = 0x04;

const REPLIES = {
  0x00: 'succeeded',
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

function buildTarget(targetHost, targetPort) {
  const host = String(targetHost);
  if (net.isIP(host) === 4) {
    const b = Buffer.alloc(7);
    b[0] = ATYP_IPV4;
    host.split('.').forEach((o, i) => (b[1 + i] = +o));
    b.writeUInt16BE(targetPort, 5);
    return b;
  }
  if (net.isIP(host) === 6) {
    const b = Buffer.alloc(19);
    b[0] = ATYP_IPV6;
    for (let i = 0; i < 8; i++) b.writeUInt16BE(parseInt(host.split(':')[i] || '0', 16) || 0, 1 + i * 2);
    b.writeUInt16BE(targetPort, 17);
    return b;
  }
  const name = Buffer.from(host, 'utf8');
  const b = Buffer.alloc(4 + name.length);
  b[0] = ATYP_DOMAIN;
  b[1] = name.length;
  name.copy(b, 2);
  b.writeUInt16BE(targetPort, 2 + name.length);
  return b;
}

// Returns a connected, handshake-complete net.Socket to (targetHost, targetPort) via the
// SOCKS5 proxy. Resolves the target name at the proxy (no local DNS).
function socks5Connect(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, proxyHost);
    let buf = Buffer.alloc(0);
    let stage = 'greet'; // greet -> connect
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('SOCKS5 handshake timeout')); }, timeoutMs || 10000);
    const fail = (e) => { clearTimeout(timer); sock.destroy(); reject(e); };

    sock.on('connect', () => {
      sock.write(Buffer.from([SOCKS5, 1, METHOD_NOAUTH]));
    });
    sock.on('error', (e) => fail(new Error('SOCKS5 connect error: ' + e.message)));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      try {
        if (stage === 'greet') {
          if (buf.length < 2) return;
          if (buf[0] !== SOCKS5) return fail(new Error('SOCKS5: bad version ' + buf[0]));
          if (buf[1] !== METHOD_NOAUTH) return fail(new Error('SOCKS5: server requires auth (method 0x' + buf[1].toString(16) + ')'));
          buf = buf.slice(2);
          stage = 'connect';
          sock.write(Buffer.concat([Buffer.from([SOCKS5, CMD_CONNECT, 0x00]), buildTarget(targetHost, targetPort)]));
        }
        if (stage === 'connect') {
          if (buf.length < 4) return;
          if (buf[0] !== SOCKS5) return fail(new Error('SOCKS5: bad reply version ' + buf[0]));
          if (buf[1] !== 0x00) return fail(new Error('SOCKS5 connect failed: ' + (REPLIES[buf[1]] || ('code 0x' + buf[1].toString(16)))));
          const atyp = buf[3];
          let addrLen = 0;
          if (atyp === ATYP_IPV4) addrLen = 4;
          else if (atyp === ATYP_IPV6) addrLen = 16;
          else if (atyp === ATYP_DOMAIN) { if (buf.length < 5) return; addrLen = buf[4]; }
          else return fail(new Error('SOCKS5: unsupported reply address type 0x' + atyp.toString(16)));
          if (buf.length < 4 + addrLen + 2) return;
          clearTimeout(timer);
          sock.removeAllListeners('data');
          // Do not write any buffered bytes into the pipe: anything past the handshake here
          // belongs to the tunneled stream — hand it back to the caller's own piping.
          if (buf.length > 4 + addrLen + 2) sock.unshift(buf.slice(4 + addrLen + 2));
          resolve(sock);
        }
      } catch (e) { fail(e); }
    });
  });
}

module.exports = { socks5Connect, buildTarget, REPLIES };
if (require.main === module) {
  const [ph, pp, th, tp] = process.argv.slice(2);
  if (!ph || !pp || !th || !tp) {
    console.error('usage: node socks5.js <proxyHost> <proxyPort> <targetHost> <targetPort>');
    process.exit(2);
  }
  socks5Connect(ph, +pp, th, +tp).then((s) => {
    console.log(JSON.stringify({ connected: true, via: ph + ':' + pp, to: th + ':' + tp }));
    s.destroy();
  }).catch((e) => { console.error(JSON.stringify({ connected: false, error: e.message })); process.exit(1); });
}
