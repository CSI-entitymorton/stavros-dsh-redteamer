# HTTP Request Smuggling / HTTP/2 desync (detection-only)

Targets: any app sitting **behind a front-end/proxy/load-balancer/CDN** (the backend does
the TLS termination or the front-end parses the request differently). Class `smuggling`,
CWE-444 (HTTP Response Splitting/Smuggling). Use the dedicated tool
`node tools/desync.js <url>` for the CL.TE / TE.CL / TE.TE probes; this file explains when
to run it and how to read the result.

> **Scope & safety.** `desync.js` is scope-gated and DNS-rebinding-safe (net.js pinning),
> just like every other network tool. It only measures whether YOUR OWN single connection
> desyncs — it never injects a second user's traffic and never delivers a malicious
> smuggled request to a victim. Detection-only: never use desync to strip a WAF for other
> clients.

## When to test it

- Any `HTTP/1.1 on 443` fronted by Nginx/Apache + upstream app server or cloud LB.
- If `Server:` differs between a direct hit and a proxied path (front-end vs back-end).
- High-security targets (banking, cloud-vulnerable) per OWASP Top 10 2025 A06
  (vulnerable components) + WSTG-INPV-15.

## Probes (via desync.js)

```bash
node tools/desync.js https://target.com            # all probes, full report
node tools/desync.js https://target.com --probe cl.te
node tools/desync.js https://target.com --probe te.cl
```

### What each probe means
- **CL.TE** — front-end trusts `Content-Length`, back-end trusts `Transfer-Encoding`.
  A `CL` body that contains a `0\r\n\r\n` chunk terminator can make the back-end treat the
  remainder as a NEW request (the smuggled bytes). On our own socket we observe a follow-up
  request either failing (400/abort) or — if the backend parses our smuggled bytes — the
  connection behaving differently than baseline.
- **TE.CL** — reverse. Obfuscated `Transfer-Encoding` variants (e.g. `Transfer-Encoding:
  chunked ` with trailing space, or a second TE header) can hide from the front-end while
  the back-end honors `Content-Length`.
- **TE.TE** — back-end parses a TE syntax the front-end rejects (e.g. `chunked;foo=bar`).

## Reading the result (honest assessment)

`desync.js` returns `likely: true|false` and a `confidence` per probe plus a follow-up
observable. Treat it as **`suspected` → `triggered`** only:

- `likely:true` + a reproducible follow-up error/reflection on a SECOND independent run
  (run it 3x; desync is flaky by nature) ⇒ verify_level `triggered`, severity up to **High**
  only with a real impact shown — a desync alone is Medium.
- A desync that you can chain to **bypass a WAF / poison a cache** is a critical finding,
  but PROVING impact on a live target is confirm-tier: do not attempt on a production
  target without explicit operator approval. Detection stays benign.
- If the probe is flaky or times out randomly on baseline too, mark it `suspected`/Low and
  note the ambiguity — do not force it.

## Reporting

```bash
node tools/record-finding.js '{"severity":"Medium","title":"HTTP Request Smuggling (TE.CL)","host":"HOST","endpoint":"/","class":"smuggling","cwe":"CWE-444","cvss":6.5,"cvss_vector":"AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N","verify_level":"triggered","poc":"<desync.js JSON + follow-up observable>","remediation":"Set all proxies/load-balancers and back-ends to the SAME request-parsing (drop TE-only requests or CL when TE present), reject obfuscated Transfer-Encoding, upgrade to HTTP/2-aware front-ends (fixes most CL.TE/TE.CL), and disable HTTP/1.1 downgrade where the LB is HTTP/2."}'
```

No `verify` block can re-fire a desync reliably (it needs the exact socket sequence), so
attach the tool's raw JSON output as evidence instead.