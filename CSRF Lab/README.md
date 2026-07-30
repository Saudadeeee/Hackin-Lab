# CSRF Lab

A white-box, intentionally-vulnerable **Cross-Site Request Forgery** teaching lab —
part of the **Hackin Lab** suite. Ten levels, one broken defense each.

## The vulnerability

CSRF abuses the fact that a browser automatically attaches a victim's session
cookie to any request to a site they are logged in to. If a state-changing action
is not protected by an unpredictable, session-bound anti-CSRF token (or an
equivalent control), an attacker page can forge that action on the victim's behalf.

Each level models a **logged-in victim admin**. You are the attacker. You craft a
PoC (a URL, an `<img>`/`<form>`, or a `fetch()` call) and click **Deliver to
victim** — the server-side bot `visit.php` performs your request **as the admin**
(the admin session is attached), exactly like a real victim opening your page. If
the protected action changes state **without a valid anti-CSRF token under that
level's protection**, the admin state actually changes and the level flag is
awarded. Flags are never granted by string-matching — only by a genuine bypass.

## The 10 levels

| # | Level | Difficulty | Bypass taught | How the flag is captured |
|---|-------|-----------|---------------|--------------------------|
| 1 | No-Token GET State Change | Easy | GET state-change, zero token | `<img src="change_email.php?email=...">` changes the admin email |
| 2 | No-Token POST Form | Easy | POST is not a defense | auto-submitting cross-site form changes the admin email |
| 3 | Unvalidated CSRF Token | Medium | token present but never checked | POST succeeds with any/no token (compare line commented out) |
| 4 | Static / Predictable Token | Medium | hardcoded constant token | replay the known static token `a1b2c3d4` to promote `mallory` |
| 5 | Token Not Bound to Session | Medium | format-only validation | any 32-hex `csrf_token` is accepted; email changes |
| 6 | SameSite=Lax Bypass | Medium | Lax leaks on top-level GET nav | `window.location` navigation carries the Lax cookie |
| 7 | JSON Endpoint via text/plain | Hard | simple request, no preflight | `fetch()` with `Content-Type: text/plain` and a JSON body |
| 8 | Referer Check Bypass | Hard | Referer check fails open | `<meta name="referrer" content="no-referrer">` + form |
| 9 | Double-Submit Cookie Flaw | Hard | attacker sets the token cookie | `document.cookie` token matches the body token; promote `mallory` |
| 10 | Multi-Layer Defense Bypass | Expert | chain the three gaps | top-level GET nav + no-referrer + any 32-hex token transfers ownership |

Each level captures its flag the same authentic way: the bot runs the level's
**real** state-changing handler with the admin session, and the flag is released
only when the state (admin email / user role / account owner) actually changes
without satisfying a sound anti-CSRF control.

## Flags

`FLAG{csrf_get_state_change}`, `FLAG{csrf_post_no_token}`,
`FLAG{csrf_token_not_checked}`, `FLAG{csrf_predictable_token}`,
`FLAG{csrf_token_not_bound}`, `FLAG{csrf_samesite_bypass}`,
`FLAG{csrf_json_content_type}`, `FLAG{csrf_referer_bypass}`,
`FLAG{csrf_double_submit_flaw}`, `FLAG{csrf_waf_bypass}`.

## Run it

```bash
docker compose up
```

Then open **http://localhost:8091**.

- Port: **8091** (host) → 80 (container)
- Base image: `php:8.2-apache`, current directory volume-mounted at `/var/www/html/`.
- No database or build step. Per-learner victim state lives in the PHP session; use
  **Reset victim** on any level to restore the admin account and re-attempt.

To stop and remove the container:

```bash
docker compose down
```

## Files

- `index.php` — level grid, progress bar, stats.
- `level1.php` … `level10.php` — white-box level pages (vulnerable source + PoC editor).
- `visit.php` — the victim-admin bot endpoint (`visit.php?level=N&poc=...`).
- `csrf_engine.php` — victim state, PoC parser, and the 10 real vulnerable handlers.
- `csrf_render.php` — shared two-column white-box level renderer.
- `helpers.php` — flags, progressive hints, inline flag submission, per-level boot.
- `submit.php` — central flag checker + progress checklist (cookie `csrf_lab_progress`).
- `css/styles.css` — shared Hackin Lab theme.
