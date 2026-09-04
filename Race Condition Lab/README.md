# Race Condition & TOCTOU Lab

Port **8094** · 10 levels · slug `race`

Every endpoint in this lab is correct when one request runs at a time. The
defects only exist in the relationship *between* requests, which is why they
survive code review and unit tests.

## Running

```bash
docker compose up --build -d
# http://localhost:8094
```

## What makes this lab different

**A parallel-request launcher.** Each level ships a control that fires N
requests with `Promise.all`, optionally warming the connections first. Warming
sends one throwaway request per connection so TCP and PHP are already started —
the difference between hitting a 150 ms window and a 25 ms one.

**A server-side interleaving log.** Every level prints the actual sequence of
reads and writes with process ids and millisecond offsets. Two pids alternating
between a read and its matching write is the signature of a race. Pids running
one after another means something serialised your requests, which is a fact
about your test rather than about the code — level 6 exists entirely to teach
that.

**A deliberate split between check and effect.** In most levels the *check*
reads shared state with no lock (racy), while the *effect* is appended to a
ledger (atomic). That is how real code usually looks: `UPDATE t SET n = n + 1`
is safe on its own, but the decision to run it came from a `SELECT` taken a
moment earlier. Level 1 keeps the unsafe read-modify-write so the lost-update
failure is visible too.

**A reset button on every level.** Race levels get into stuck states; that is
expected, not a bug in your attack.

## Levels

| # | Title | Difficulty | Shape |
|---|-------|-----------|-------|
| 1 | The Lost Update | Easy | non-atomic read-modify-write |
| 2 | Single-Use Coupon | Easy | check-then-act on a boolean |
| 3 | Overdrawn | Easy | check-then-act on a number |
| 4 | Rate Limit Counted Too Late | Medium | the counter is behind the work |
| 5 | The Name Changed Underneath | Medium | TOCTOU across two endpoints |
| 6 | Why Your Race Does Not Reproduce | Hard | the session lock is serialising you |
| 7 | Shipped and Refunded | Hard | two endpoints, one state machine |
| 8 | Inside the Window | Hard | connection warming and delivery |
| 9 | Optimistic Locking, Pessimistically Wrong | Expert | non-atomic compare-and-swap |
| 10 | Compounding | Expert | two windows, chained |

## Files

```
race.php         per-learner state, ledgers, the interleaving log, the launcher
api.php          the endpoints being raced
level_defs.php   per-level teaching content (theory, model, fix, why)
helpers.php      lab metadata, flags, hints, the shared renderer
level1..10.php   challenge logic only
solve_check.php  performs the intended race for all ten levels with curl_multi
```

## Self-test

```bash
docker compose exec web php /var/www/html/solve_check.php
# 10 passed, 0 failed
```

Races are probabilistic, so the self-test retries each level a few times and
resets the state before every attempt.
