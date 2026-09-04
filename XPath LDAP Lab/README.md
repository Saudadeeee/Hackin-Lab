# XPath & LDAP Injection Lab

Ten levels on the two query languages that still get assembled with string
concatenation long after everyone stopped doing it to SQL.

Levels 1-5 are XPath. Levels 6-10 are LDAP filters. Both halves run a real
engine: nothing in this lab matches on payloads, and no flag is awarded for an
input string.

| port | slug |
|------|------|
| 8100 | `xpathldap` |

## Running it

```bash
docker compose up --build -d
# http://localhost:8100
```

Self-test (runs the intended solution for all ten levels plus a set of
assertions against the LDAP filter engine):

```bash
docker compose exec -T web php /var/www/html/solve_check.php
```

On Git Bash for Windows the container path needs protecting from path
translation:

```bash
MSYS_NO_PATHCONV=1 docker compose exec -T web php //var/www/html/solve_check.php
```

## The two engines

**XPath** is PHP's own. `users.xml` is loaded into a `DOMDocument` and every
level builds an XPath 1.0 expression and hands it to `DOMXPath::evaluate()`.
When a level says an expression selected four nodes, libxml selected four
nodes. Malformed payloads produce the real parser error, which is printed in
the trace because a rejected payload teaches as much as a winning one.

**LDAP** has no server behind it, so `ldap.php` is a genuine RFC 4515 filter
parser and evaluator written out in full:

* recursive-descent parser for `&`, `|`, `!`, `=`, `>=`, `<=`, `~=`, presence
  (`attr=*`) and substring assertions (`a*b*c`)
* RFC 4515 section 3 escaping and unescaping, with structure decided **before**
  values are unescaped, which is what makes `\28` inert inside a value
* an evaluator over multi-valued attributes with case-insensitive matching and
  numeric-aware ordering comparisons
* a canonical re-serialiser and a parse-tree printer, both used in the level
  traces so you can see what the parser made of your bytes

Two deliberate deviations are documented in the source because levels depend on
them:

* `ldap_parse_first()` reads one complete filter off the front of the string and
  reports the rest as discarded. Plenty of client libraries behave this way, and
  it is why the textbook payloads end with an orphaned `(|(uid=*`.
* `ldap_unescape_whole_filter()` is a single unescape pass over an entire filter
  string. It is not RFC behaviour. It models the "normalise the filter, then
  parse it" shortcut, and it is the subject of level 10.

Everything else is the specification.

## Levels

| # | Title | Difficulty | Teaches |
|---|-------|-----------|---------|
| 1 | XPath Authentication Bypass | Easy | predicates, `and`/`or` precedence, tautologies |
| 2 | Reading Sibling Nodes | Easy | escaping a predicate, unions, changing the location path |
| 3 | Blind Boolean XPath | Medium | boolean oracles, `string-length()`/`substring()`, request cost |
| 4 | Quotes Are Filtered | Medium | injection with no string literals; filtering is not parsing |
| 5 | XPath Into an Attribute Predicate | Hard | numeric context, `\|` union, reaching another subtree |
| 6 | LDAP Authentication Bypass | Easy | RFC 4515 grammar, reading the parse tree you wrote |
| 7 | Wildcard Truncation | Medium | substring assertions, `*` as structure rather than data |
| 8 | Injecting Into an AND | Medium | closing your own group, keeping the remainder well formed |
| 9 | Blind Attribute Extraction | Hard | substring and ordering filters, extraction cost arithmetic |
| 10 | Escaping That Missed a Character | Expert | escape ordering, the backslash, unescape-before-parse |

Levels 3 and 9 are blind and ship an in-page probe console: one probe per click,
or a full linear or binary recovery loop, with a live request counter and a
server-side counter in the trace. The mental model on each page states the
expected request count for both strategies so the two numbers can be compared.
The flag on those levels is gated on submitting the recovered value.

## Data

`users.xml` holds eight staff records plus a `<vault>` subtree that no
application expression touches. `directory.php` holds eight LDAP entries in
provisioning order, with the system account first — which is what makes an
authentication bypass that matches everything land on an administrator.

Targets, if you want to check your own work:

| level | target |
|-------|--------|
| 2 | `svc_backup/recovery_token` |
| 3 | `svc_backup/apikey` |
| 4 | `mfrost/pin` |
| 5 | `vault/secret[@name='master']` |
| 8 | `uid=vault_agent` (`objectClass` has no `person`) |
| 9 | `recoveryKey` on `uid=svc_rotate` |

## Files

```
users.xml        XML directory for levels 1-5
ldap.php         RFC 4515 filter parser, evaluator, escaper, tree printer
directory.php    the seeded LDAP entries
helpers.php      lab metadata, flags, hints, shared level UI
index.php        level grid
submit.php       flag submission and progress
level1..10.php   the challenges
solve_check.php  self-test: 10 level solutions + engine assertions
```
