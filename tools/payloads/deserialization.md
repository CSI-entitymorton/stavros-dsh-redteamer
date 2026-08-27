# Deserialization — detection payloads (detection-only by default)

Serialized-object endpoints are usually spotted by their content type / body shape:
`application/x-java-serialized-object`, `application/octet-stream` with a Java stream
header, PHP `O:8:"Class":...`, .NET `AAEAAAD/////` (BinaryFormatter), Python pickle
`\x80\x04` (protocol 4) or `\x80\x03`.

## Fingerprint the format

| Stack | Magic / marker |
|---|---|
| Java native | `AC ED 00 05` hex header |
| .NET BinaryFormatter | base64 `AAEAAAD/////` |
| .NET JSON.NET | `{"$type":"System.Windows.Data.ObjectDataProvider, ..."}` |
| PHP `serialize()` | `O:<len>:"<class>":<n>:{...}` |
| Python pickle | `\x80\x04` / `\x80\x03` (bytes) |
| Ruby Marshal | `\x04\x08` |
| YAML (PyYAML/ruamel) | `!!python/object/apply:` tags |

## Detection (no gadget chain yet)

1. **Truncate / corrupt** the serialized blob and diff the response: a distinct
   stack trace / deserialization error (vs a generic 400) confirms the endpoint unserializes.
2. **Class not found:** replace the class name with `MARKER` — an error echoing the class
   name confirms the object is being resolved.
3. **Java `ysoserial` URLDNS gadget** is the classic *safe* detection: it makes the server
   resolve a DNS name (use `oob.js` DNS/HTTP marker) without executing code.

## Escalation (requires explicit approval)

- Java: `ysoserial` gadget chains (CommonsCollections4/6, Spring, etc.) — **only for PoC,
  never for persistence**.
- .NET: `ysoserial.net` (ObjectDataProvider / TypeConfuseDelegate).
- PHP: `phpggc` chains (Symfony/Laravel/Guzzle).
- Python: `pickle` `__reduce__` → `os.system` (sleep/`id` only with approval).

Rule: prove "the server unserializes untrusted input" with URLDNS/error evidence; do not
fire a command-execution gadget without the user's explicit go-ahead for that action.
