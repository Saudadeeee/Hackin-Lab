# Crypto Oracle Lab

Port **8096** · 10 levels · slug `crypto`

AES is not broken here. Neither is SHA-1. Every level uses a sound primitive
inside a construction that hands the attacker exactly the leverage they need:
a repeated block, a reused nonce, a distinguishable error, an early-exit
comparison.

The question the lab trains you to ask is not "is the algorithm strong" but
**"what does this construction let me observe, and what can I change".**

## Running

```bash
docker compose up --build -d
# http://localhost:8096
```

Keys are derived deterministically from a lab constant, so tokens stay stable
across restarts and a half-finished attack is not lost to a `docker restart`.

## Levels

| # | Title | Difficulty | The leverage |
|---|-------|-----------|--------------|
| 1 | Encoding Is Not Encryption | Easy | there is no key |
| 2 | Repeating-Key XOR | Easy | known plaintext gives the keystream |
| 3 | ECB Cut and Paste | Medium | blocks are context-free |
| 4 | ECB Byte at a Time | Medium | determinism makes an encryptor a decryptor |
| 5 | CBC Bit Flipping | Medium | malleability without integrity |
| 6 | Padding Oracle | Hard | one bit of feedback per query |
| 7 | Hash Length Extension | Hard | a digest is a resumable state |
| 8 | The Comparison That Talks | Hard | early exit leaks the prefix length |
| 9 | Predictable Randomness | Expert | mt_rand seeded from the clock |
| 10 | Nonce Reuse | Expert | one keystream, two messages |

## Tooling

`tools.php` — the Crypto Workbench. Encoding, XOR, block splitting and ECB
detection, a CBC bit-flip calculator, and runners for the query-heavy attacks
(ECB byte-at-a-time, padding oracle, SHA-1 length extension, timing harness,
mt_rand seed cracker). Every runner prints its intermediate values, because the
intermediates are the lesson.

`oracle.php` — the endpoints the scripted levels attack, so you can write your
own client in any language instead of using the Workbench:

```
GET oracle.php?level=4&prefix=<hex>   -> hex of ECB(prefix || SECRET)
GET oracle.php?level=6&ct=<hex>       -> "padding-ok" | "padding-bad"
GET oracle.php?level=8&token=<ascii>  -> "ok" | "no"  (the timing is the signal)
GET oracle.php?level=9&issue=1        -> "<unix time>:<token>"
```

## Files

```
crypto.php       AES modes, PKCS#7, XOR, and a SHA-1 that can resume from a
                 captured state (needed for level 7)
secrets.php      the values the levels protect, kept out of the source panels
oracle.php       query endpoints for levels 4, 6, 8, 9
tools.php        the Crypto Workbench
helpers.php      lab metadata, flags, hints, shared level UI
level1..10.php   the challenges
solve_check.php  runs the intended solution for all ten levels
```

## Self-test

```bash
docker compose exec web php /var/www/html/solve_check.php
# 10 passed, 0 failed
```

Levels 4, 6 and 8 are exercised in miniature by the self-test — enough queries
to prove the oracle behaves as the level claims. Running them to completion is
the learner's job.
