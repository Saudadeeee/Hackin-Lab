# NoSQL Injection Lab

An intentionally-vulnerable, white-box teaching lab for **NoSQL (MongoDB) injection**, part of the
**Hackin Lab** web-security training suite. Ten progressive levels, each showing the real vulnerable
PHP source that builds and runs the query.

## The vulnerability

Every level builds a MongoDB-style **query object out of attacker-controlled input without sanitising
it**. The developer expects a field like `password` to be a plain string to compare, but MongoDB (and
its drivers) also accept **operator objects** — `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": "^F"}`,
`{"$where": "1==1"}`. Because the input shapes the query, an attacker can smuggle these operators in via
a JSON request body or a PHP array query-string (`password[$ne]=`).

There is **no real MongoDB**. `mongo.php` provides a faithful in-PHP document store and a
`mongo_find($collection, $query)` evaluator that implements `$eq $ne $gt $gte $lt $lte $in $nin $regex
$exists $where $or $and` exactly like MongoDB. The admin password is a long random secret, so the only
way to authenticate as admin is to abuse an operator — never by guessing. For the blind levels the admin
secret **is** the flag and lives only in the document store, so it must be extracted via injection.

## The 10 levels

| # | Level | Difficulty | Concept → how the flag is captured |
|---|-------|-----------|------------------------------------|
| 1 | Auth Bypass via `$ne` | Easy | JSON login; `{"password":{"$ne":null}}` matches admin → flag on admin match |
| 2 | Operator via Query String | Easy | `?username=admin&password[$ne]=x` — PHP array parsing builds the operator → flag on admin match |
| 3 | `$gt` Filter Bypass | Medium | A `$ne` blacklist is bypassed with `{"password":{"$gt":""}}` → flag on admin match |
| 4 | `$regex` Password Extraction | Medium | Match/no-match oracle; anchored `$regex` pins the hidden admin secret char-by-char → flag = extracted secret |
| 5 | `$in` / `$or` Operator Injection | Medium | Whole-body search filter; `$in`/`$or` widen results to include admin → flag on admin in results |
| 6 | `$where` JavaScript Injection | Medium | `{"$where":"1==1"}` (or `this.role=='admin'`) matches admin → flag on admin match |
| 7 | Blind Boolean Extraction | Hard | Boolean-only login, only `$regex` allowed; reconstruct the flag from the single success bit |
| 8 | Dollar-Keyword Filter Bypass | Hard | Raw `$` is blocked; `{"password":{"$ne":null}}` decodes back to `$ne` → flag on admin match |
| 9 | Type-Confusion `===` Bypass | Hard | `if ($username === 'admin') deny` is skipped by `username[$eq]=admin` (array ≠ string) → flag on admin match |
| 10 | Multi-Layer WAF Bypass | Expert | Stacked `$`/string-username/operator-blacklist filters; only `$gt` (as `$gt`) survives → flag on admin match |

Flags follow the form `FLAG{concept_snake_case}` and are also verified on the central **Submit Flag** page.

How the flag is awarded (never a raw string-match of the flag): each level runs the **real vulnerable
query** against the document store and only awards when the exploit **actually matches the `admin`
document** (or, for the blind levels 4 & 7, when the injection has **fully extracted the admin secret**
from the store).

## Running

```bash
docker compose up          # serves on http://localhost:8090
```

No database, no build step, no extra packages — plain `php:8.2-apache` with the lab directory mounted.
To stop: `docker compose down`.

> For teaching only. The code here is deliberately insecure — never deploy it or reuse its patterns.
