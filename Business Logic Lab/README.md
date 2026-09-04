# Business Logic Lab

An intentionally-flawed **business logic** teaching lab, part of the **Hackin Lab** web-security
training suite. Ten white-box levels, each a working e-commerce flow with real state: carts,
balances, coupons, orders, refunds and loyalty points that persist between requests.

This is the lab for the finding a scanner never reports. There is no injection anywhere in it,
no parser to confuse, and no payload syntax to discover. Every level ships code where each
individual statement is correct and the *rule* those statements add up to is wrong. You solve
them by reading the state machine and finding the transition the developer did not consider.

> The flag is never awarded by matching your input. It is awarded for the **state the shop
> actually reaches** — a balance above a threshold, an order marked `paid` with `amount_paid`
> of zero, a refund ledger that exceeds the order it belongs to, ownership of a gated SKU.
> Several different requests reach the same state on most levels, and all of them count.

## Levels

| # | Title | Difficulty | The wrong rule | Flag |
|---|-------|-----------|----------------|------|
| 1 | Negative Quantity | Easy | `if ($qty > 10)` bounds the range on one side only, so a line total can be negative | `FLAG{quantity_had_no_lower_bound}` |
| 2 | The Price Came From the Browser | Easy | The unit price round-trips through a hidden field and the checkout bills whatever comes back | `FLAG{the_client_does_not_know_the_price}` |
| 3 | Coupon Stacking | Medium | Coupons are validated in one loop and applied in another, so every code is still the first order | `FLAG{validated_all_then_applied_all}` |
| 4 | Rounding in the Wrong Direction | Medium | `sum(round(line))` instead of `round(sum(lines))`, with the customer choosing the number of lines | `FLAG{rounded_each_line_before_summing}` |
| 5 | Integer Overflow in the Cart | Medium | A quantity ceiling of five billion validated in PHP, stored in a signed 32-bit warehouse field | `FLAG{the_cap_was_wider_than_the_field}` |
| 6 | Skipping a Step | Hard | `confirm` checks that an order exists and nothing else; the flow is enforced by disabled buttons | `FLAG{confirm_never_checked_payment}` |
| 7 | Mass Assignment at Checkout | Hard | `array_merge($defaults, $_POST)` makes `discount_tier` and `internal_credit` writable | `FLAG{the_request_wrote_fields_the_form_never_showed}` |
| 8 | Refund More Than You Paid | Hard | Each refund is checked against the line total, never against the running refund total | `FLAG{each_refund_was_checked_alone}` |
| 9 | The Loyalty Loop | Expert | Points redeem at $0.02 and are earned at $0.01, so the round trip doubles them | `FLAG{the_round_trip_was_net_positive}` |
| 10 | Chain | Expert | Tier credit records the pre-discount subtotal, and the level-3 coupon engine still stacks | `FLAG{tier_credit_ignored_the_discount}` |

Difficulty ramp: L1–2 Easy, L3–5 Medium, L6–8 Hard, L9–10 Expert.

Level 10 chains level 3: the coupon engine is the same one, unfixed, and it is what lets you
write $12,000 into the membership ledger for nothing.

## How the levels teach

Each page follows the standard kit layout — real source on the left, the shop on the right,
five progressive hints and the flag form underneath — with two additions this lab needs:

- **The `pipeline` trace prints the arithmetic**, step by step, with your numbers substituted:
  quantity, unit price, line total, each discount, each rounding, the final total, and the
  balance update. When a total looks wrong, the trace shows the exact line where it went wrong.
- **The state panel shows where you are.** Cart contents, balances, order status, coupon wallet,
  refund ledger, membership tier. A business-logic exploit is a sequence, and you cannot plan a
  sequence you cannot see.

Every level has a **Reset this level** button. Stateful levels get into stuck states — a coupon
spent, a return quota exhausted, an order left in the wrong status — and resetting costs nothing.

## State

Each browser gets a random session id in the `bizlogic_sid` cookie. State is one JSON document
per session, namespaced by level, under `state/`:

```
state/<sid>.json   =>   { "1": {...}, "2": {...}, ... }
```

`shop.php` falls back to the system temp directory if `state/` is not writable, so a bind-mount
permissions problem never presents itself as a broken level. Level progress (which flags you have
submitted) is separate, and lives in the `bizlogic_lab_progress` cookie; reset it from the Submit
page.

## Running

```bash
cd "Business Logic Lab"
docker compose up --build -d
```

Then open <http://localhost:8097>.

## Self-test

`solve_check.php` drives the intended solution for all ten levels against the live app. Because
the levels are stateful it carries a cookie jar and resets each level before solving it, so the
run is idempotent.

```bash
docker compose exec -T web php /var/www/html/solve_check.php
# Git Bash on Windows:
# MSYS_NO_PATHCONV=1 docker compose exec -T web php //var/www/html/solve_check.php
```

Expected output ends with `10 passed, 0 failed`.

## Files

- `index.php` — level grid and progress bar
- `level1.php` … `level10.php` — the ten white-box challenges
- `shop.php` — the state machine, the catalogue, the coupon engine and the money maths
- `helpers.php` — flags, level metadata, 5 progressive hints per level, shared level UI
- `submit.php` — central flag checker and per-level checklist
- `solve_check.php` — regression test for all ten intended solutions
- `state/` — per-session JSON state (git-ignored, created at runtime)
- `css/styles.css` — shared Hackin Lab theme plus the kit layer
- `Dockerfile` / `docker-compose.yml` — port `8097`

## Security notice

This lab is **intentionally vulnerable**. Do not deploy it on a public network or any environment
you care about. Run it only locally or in an isolated sandbox.
