# Changelog

All notable changes to this project are documented in this file. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-08-29

### Added

- Hardened enforcement core backported into the bundled toolset: fail-closed
  `scope-guard`, `oracle`, `opstate`, `audit-trail`, `ssrf-guard`, `workflow` and
  more — **78 zero-dependency, scope-guarded tools** total.
- `fleet`, `desync`, `header-check`, `planner` modules, plus the
  `entity-taxonomy` / `agents-fleet` data files.
- `stavros-hardware` and `stavros-privesc` subagents — **24 specialists** total.
- Release hygiene: `LICENSE` (MIT), `NOTICE`, `SECURITY.md`, and the
  "AUTHORIZED USE ONLY" banner.
- CI workflow (`ci.yml`): build + fail-closed smoke + hermetic tool suite on every
  push/PR.

### Changed

- Renamed the package/plugin from `dsh-stavros` to **`stavros-dsh-redteamer`**
  (package name, plugin id, docs, smoke-test profile).
- Rewrote the README as a public-facing page (badges, persona, quickstart,
  security model).

### Removed

- Benchmark-only tooling (`eval-juice-shop`, `gen-bench`, `test-benchgen`,
  `test-freebuff-variant`) and `planner-demo.js`/`examples/` from the bundled
  package (they stay in the upstream monorepo).

### Security

- `scope.json` is seeded fail-closed on first boot; an empty or missing scope
  blocks every guarded action (tested in CI).
- No exploit code, no av-evasion/darkweb content ships in the package.
