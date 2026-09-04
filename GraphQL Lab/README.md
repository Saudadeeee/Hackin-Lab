# GraphQL Lab

Intentionally-vulnerable teaching lab for **GraphQL API security**. Ten white-box levels covering discovery,
authorisation, request-shape bypasses and injection. Part of the Hackin Lab suite.

- **Port:** 8098
- **Progress cookie:** `graphql_lab_progress`
- **Data store:** SQLite at `data/graphql.sqlite`, built on first run (`pdo_sqlite`, which ships with
  `php:8.2-apache`).
- **Flags:** awarded for the data the endpoint actually returned, or for a state change the mutation actually
  made — never for matching the text of a query.

## Run

```bash
cd "GraphQL Lab"
docker compose up --build -d
# open http://localhost:8098
MSYS_NO_PATHCONV=1 docker compose exec -T web php //var/www/html/solve_check.php
```

## The engine

There is no Composer in this repo, so `graphql.php` is a hand-written GraphQL implementation, about 1000 lines
including comments. It is small but it is real, and every level depends on it behaving the way the specification
says:

| stage | what it does |
|---|---|
| lexer | names, ints, floats, `"strings"` and `"""block strings"""`, punctuation, `#` comments, commas as whitespace |
| parser | `query` / `mutation`, named and anonymous, variable definitions, selection sets, aliases, field arguments (int, float, string, boolean, null, enum, list, object, `$variable`), named fragments, inline fragments, directives (parsed and ignored) |
| schema | a PHP array of types, fields, argument definitions and resolver closures; type refs are source text, `[User!]!` |
| measure | `gql_depth()` counts nesting with or without fragment expansion; `gql_complexity()` counts field nodes. Both are optionally enforced per level |
| validate | every selected field must exist on the type it is selected on, with a `Did you mean …` suggestion list that a level can switch off |
| introspect | `__schema { queryType types { name fields { name args { name } } } }` and `__type(name:)`, with `NON_NULL` / `LIST` wrapper types carrying `ofType`. Gated per level |
| execute | resolvers, aliases as response keys, `__typename`, list and scalar completion, per-field errors with a `path`, and the standard `{"data":…,"errors":[…]}` envelope |

`GqlTrace` records what happened at each stage; every level page renders it as the pipeline trace, which is what
makes the difference between "the query was validated" and "the data was authorised" visible.

Left out on purpose: subscriptions, interfaces and unions, custom scalars, directive execution, input-object type
checking.

## Levels

| # | Title | Difficulty | Mechanic |
|---|-------|-----------|----------|
| 1 | Introspection Is On | Easy | `__schema` / `__type` reveal `internalMemo`, a root field no client calls |
| 2 | Suggestions Leak the Schema | Easy | introspection off, but `Did you mean "staffNotes"?` rebuilds it one guess at a time |
| 3 | Object-Level Authorisation | Medium | `user(id:)` never compares the argument with the session — GraphQL's IDOR |
| 4 | Field-Level Authorisation | Medium | the object decision is stamped on the row; `apiToken` re-fetches by id and ignores it |
| 5 | Aliases Defeat the Rate Limiter | Medium | 5 requests/minute, 256 aliased `redeem()` calls in one request |
| 6 | Mutation Without Authorisation | Hard | the guard authorises `$body["operationName"]`; an anonymous mutation has none |
| 7 | Batching Bypass | Hard | array body, all elements executed, guard reads `$body[0]` |
| 8 | Depth Limit and the Fragment Loop | Hard | counter treats a spread as a leaf: counted depth 3, executed depth 5 |
| 9 | Injection Through a Resolver | Expert | `filter: String!` concatenated into SQL; `UNION` returns a column the schema does not expose |
| 10 | Chain | Expert | introspect `grantRole` → anonymous mutation past the guard → `adminSettings.vaultKey` |

Levels 6, 7 and 10 reuse each other's lessons on purpose: 10 is 6's guard plus 1's discovery plus a real role
check that the escalation satisfies rather than dodges.

## State

Levels 5, 6 and 10 change persistent state (the rate-limit window, `users.role`). Each of those pages has a
**Reset lab state** button, and `solve_check.php` resets over HTTP before and after its run so the lab is left as
it was found.

If the database ends up in a bad state, delete `data/graphql.sqlite` and reload any page; it is rebuilt from the
seed data in `schema.php`.

## Files

```
graphql.php      lexer, parser, validator, introspection, executor, depth/complexity
schema.php       SQLite build + seed data, per-level schemas and resolvers, rate limiter
helpers.php      lab metadata, flags, level table, 5 hints per level, query-editor UI
level1..10.php   one endpoint + guard + teaching page per level
index.php        level grid
submit.php       flag submission and progress
solve_check.php  runs the intended solution for all ten levels
```
