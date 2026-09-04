# Auth & Password Reset Lab

Port **8099** · 10 levels · slug `authreset`

Account recovery is the part of authentication that most often undoes the rest
of it. Every level here is a working recovery flow — real tokens in a real
table, real password updates, real sessions — with one rule wrong.

Your account: `guest@hackinlab.internal` / `guest123`.
The target: `admin@hackinlab.internal`.

## Running

```bash
docker compose up --build -d
# http://localhost:8099
```

## Levels

| # | Title | Difficulty |
|---|-------|-----------|
| 1 | Username Enumeration | Easy |
| 2 | Predictable Reset Token | Easy |
| 3 | Host Header Poisoning | Medium |
| 4 | Token Not Bound to the Account | Medium |
| 5 | Token Survives Use | Medium |
| 6 | No Rate Limit on the OTP | Hard |
| 7 | Session Fixation | Hard |
| 8 | Second Factor Only Guards the Response | Hard |
| 9 | The Email Change Race | Expert |
| 10 | Chain | Expert |

Levels 1, 2 and 6 are the ones most easily reduced to brute force with no
understanding, so each of those states the arithmetic up front — search space,
observed rate, expected time — and the trace shows what distinguishes a hit
from a miss. The point is that you can predict the outcome before running the
attack.

## Supporting endpoints

- `mailbox.php` — the mail the application sent to accounts you are entitled
  to see. The administrator's mailbox is not readable; that is the whole point.
- `collector.php` — where mail lands when a level's exploit redirects it to a
  host you control (level 3).
- `visit.php` — simulates the victim clicking a link or signing in (level 7).
- `reset.php` — the reset-link landing page.

## Files

```
db.php           SQLite schema and seed data
mail.php         the fake mailer
helpers.php      lab metadata, flags, hints, shared level UI
level1..10.php   the challenges
solve_check.php  runs the intended attack for all ten levels
```

## Self-test

```bash
docker compose exec web php /var/www/html/solve_check.php
# 10 passed, 0 failed
```

Flags are awarded for the state actually reached — the administrator's password
hash genuinely changed to one you set, an authenticated administrator session
genuinely established — never for a matched input string.
