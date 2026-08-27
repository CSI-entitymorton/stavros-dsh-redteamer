# Stavros upload-bypass payloads

File-upload filter-bypass test artifacts (repo-vet churchofmalware plan — D4rc0d3 model).
The generator here builds **polyglot** files: bytes that are simultaneously a VALID image and a
syntactically valid script, to test filters that validate only magic bytes / MIME sniffing /
`getimagesize()`-style checks.

## Files

| File | Class |
|---|---|
| `gen-polyglot-jpeg.js` | Valid JPEG + embedded sh/pwsh/bat script body (after the EOI marker) |

## Usage

```bash
node tools/payloads/upload-bypass/gen-polyglot-jpeg.js --out /tmp/poly.jpg --mode sh
node tools/payloads/upload-bypass/gen-polyglot-jpeg.js --self-test
```

Then upload it through the in-scope target's upload feature and observe what the filter accepts,
where the file lands (response/URL), and whether anything executes. `repeater.js --upload`
handles the multipart; scope-guard stays hard on every hop.

## Rules of use

1. **In scope only** — `node tools/scope-guard.js check <url>` first.
2. **Detection before exploitation.** The default embedded command is a benign MARKER echo
   (`echo STAVROS-MARKER`) so you can attribute any execution to YOUR artifact. Replace the
   marker per run (`--marker stavros-a1b2c3`).
3. **Custom scripts are an operator decision** (`--script`) inside an AUTHORIZED engagement or
   lab — this tool never stages payloads by itself and never touches a target.
4. **Execution evidence** belongs in a finding with `verify_level` honest to what you actually
   proved: accepted-by-filter = `triggered`; executed marker = `exploited`.
5. The generated files are inert images unless something executes them — keep them out of PATH
   and delete them with the engagement residue (`residue.md`).
