# Stavros payload references

Ready-to-use detection payloads for the injection classes that don't have a dedicated
tool. Agents read the relevant file before testing a class. Every payload uses a BENIGN
marker (unique string / arithmetic / time) — never a destructive action.

## Files

| File | Class |
|---|---|
| `ssti.md` | Server-Side Template Injection (Jinja2/Twig/Freemarker/Velocity/Go/Ruby) |
| `deserialization.md` | Java / .NET / PHP / Python-pickle deserialization (detection only) |
| `lfi.md` | Path traversal / LFI / RFI + PHP wrappers |
| `nosqli.md` | NoSQL injection (MongoDB operators, auth-bypass JSON) |
| `prototype-pollution.md` | Prototype pollution (server + client side) |
| `upload-bypass/gen-polyglot-jpeg.js` | Valid-JPEG/script polyglot for magic-byte/MIME upload filters (see `upload-bypass/README.md`) |

## Rules of use

1. **In scope only** — `node tools/scope-guard.js check <url>` first (exit 0 = allowed).
2. **Detect before exploit.** Confirm reflection / error / timing with the smallest marker first;
   only escalate to a real payload with explicit user confirmation.
3. **Substitute `MARKER`** with a unique token per run (e.g. `stavros-a1b2c3`) so you can attribute
   the response back to YOUR request and avoid tripping WAF dedupe.
4. **Time-based payloads** — cap the sleep (≤ 7s) and honor `max_requests_per_second`.
5. **Deserialization / RCE payloads** are for *detection* and *proof-of-concept* only. Actual
   RCE payloads require explicit per-action approval (knowledge.md rule 2).
