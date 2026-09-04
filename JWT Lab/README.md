# JWT & Token Forgery Lab

Port **8093** · 10 levels · slug `jwt`

A correct JWT verification does six things, in order:

1. split the compact serialisation into header / payload / signature
2. decide the algorithm from **server policy**, never from the token header
3. resolve the key for that algorithm from a trusted key store
4. verify the signature over `header.payload` with a constant-time compare
5. validate `exp`, `nbf`, `iss`, `aud`
6. only then read authorisation claims

Each level removes or corrupts exactly one of those steps, shows you the real
verifier, and traces your token through it.

## Running

```bash
docker compose up --build -d
# http://localhost:8093
```

The compose file maps `keys.hackinlab.internal` to the container itself, so
level 8 has a legitimate key host to compare against.

## Levels

| # | Title | Difficulty | Step broken |
|---|-------|-----------|-------------|
| 1 | Read the Token | Easy | none — the payload was never secret |
| 2 | alg: none | Easy | 2 — the token picks the algorithm |
| 3 | Decode Instead of Verify | Easy | 4 — no signature check at all |
| 4 | Weak HMAC Secret | Medium | 3 — the key is a dictionary word |
| 5 | RS256 to HS256 Confusion | Hard | 2+3 — one key, two primitives |
| 6 | kid Path Traversal | Hard | 3 — the key id is a file path |
| 7 | kid SQL Injection | Hard | 3 — the key id reaches a query |
| 8 | jku Header Hijack | Hard | 3 — the key set location is attacker-supplied |
| 9 | Claim Precedence Confusion | Expert | 6 — two components read different claims |
| 10 | Duplicate JSON Keys | Expert | 5 — a regex and a JSON parser disagree |

Levels 4, 9 and 10 share a signing key deliberately: what you crack in level 4
is still valid later, which is also how unrotated keys behave in production.

## Tooling

`tools.php` is a local JWT Workbench: decode, edit raw header/payload JSON
(duplicate keys and `\uXXXX` escapes survive), sign with HS256 / HS256 keyed on
the server public key / RS256 / `none` / keep-original-signature, run a
dictionary attack against a token, and generate an RSA keypair with its JWKS.

Other endpoints:

- `jwks.php` — the issuer's public key set; `jwks.php?pem=1` returns the raw PEM
- `paste.php` — host arbitrary JSON on this origin, for the `jku` level

## Files

```
jwt.php          base64url, JWT encode/verify, JWK to PEM, display helpers
helpers.php      lab metadata, flags, hints, shared level UI
tools.php        the JWT Workbench
jwks.php         published key set
paste.php        attacker-controlled JSON hosting
keys/            private.pem, public.pem, hs/*.key, keys.sqlite (level 7)
level1..10.php   the challenges
solve_check.php  runs the intended solution for all ten levels
```

## Self-test

```bash
docker compose exec web php /var/www/html/solve_check.php
# 10 passed, 0 failed
```
