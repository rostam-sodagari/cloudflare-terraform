# YAML in five minutes

YAML is a text format made of `name: value` lines. Indentation (spaces at
the start of a line) shows what belongs to what. That is nearly all there
is to it.

## The building blocks

```yaml
# A line starting with # is a comment. It is ignored.

www:                       # a block named "www"
  name: www                # two spaces in: this belongs to "www"
  content: 203.0.113.10
  proxied: true            # true / false have no quotes

api:                       # the next block starts back at the left edge
  name: api
  content: 203.0.113.20
```

A **list** is lines starting with `- ` (dash, space). Each dash starts a
new item; the lines under it belong to that item:

```yaml
- ref: block_admin
  description: Admin only from the UK
  expression: (starts_with(http.request.uri.path, "/admin"))
  action: block

- ref: challenge_login
  description: Challenge the login page
  expression: (http.request.uri.path eq "/login")
  action: managed_challenge
```

Short lists can also be written on one line: `includes: [a.example, b.example]`.

## The rules that catch people out

| Rule | Wrong | Right |
|---|---|---|
| Use **spaces**, never tabs | (a tab before `name:`) | two spaces before `name:` |
| Always a **space after the colon** | `name:www` | `name: www` |
| Indent consistently (2 spaces) | `name` at 2 spaces, `content` at 3 | both at 2 |
| Quote **on/off** | `always_use_https: on` | `always_use_https: "on"` |
| Quote version numbers | `min_tls_version: 1.2` | `min_tls_version: "1.2"` |
| Quote IDs | `zone_id: 0123...` | `zone_id: "0123..."` |
| Quote **@** | `name: @` | `name: "@"` |
| Quote an expression of just `true` | `expression: true` | `expression: "true"` |
| Quote text containing `: ` or starting with `*`, `&`, `!`, `{`, `[`, `%` | `value: *.example` | `value: "*.example"` |
| Text that itself has double quotes goes in **single** quotes | `raw: "v=spf1 -all"` (YAML removes these quotes) | `raw: '"v=spf1 -all"'` |
| A key appears only once per file | two blocks called `www:` | rename one, e.g. `www2:` |
| Numbers of seconds have **no** quotes | `ttl: "300"` | `ttl: 300` |

Why the quotes? Without them YAML guesses the type: `on` becomes "yes",
`1.2` becomes a number, and Cloudflare then rejects the value. The check
spots all of these and tells you the fix.

## Uncommenting an example

Every file starts with commented examples. To use one, delete the `# `
(hash **and** the space after it) at the start of each line, keeping the
indentation that remains:

```yaml
# www:                     becomes      www:
#   name: www                             name: www
#   content: example.com                  content: example.com
```

## Checking your YAML

The repository checks every file for you and explains problems in plain
words, for example:

```
ERROR domains/example.com/dns/a.yaml:4: unknown field 'proxed' in www.
    fix: did you mean 'proxied'?
ERROR domains/example.com/settings/zone.yaml:2: always_use_https: true was read
  as yes/no, but Cloudflare expects the text "on".
    fix: write always_use_https: "on" with the quotes
```

The number after the file name is the line. You get these messages:

1. On your pull request, next to the line, automatically.
2. On your computer with `make validate D=example.com`
   (Windows: `.\cf.ps1 validate example.com`).

Many editors (VS Code with the YAML extension, for example) also underline
indentation mistakes as you type.
