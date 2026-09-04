# Hackin-Lab

Hackin-Lab is a Docker-powered suite of **local, hands-on web-security challenge labs**. Each lab targets one vulnerability class, ships 10–16 progressive white-box levels (Easy → Expert), and runs as its own self-contained container. Every level shows the **real vulnerable source code**, awards a `FLAG{...}` only when you actually exploit the flaw, tracks progress in a cookie, and offers 5 progressive hints.

> ⚠️ These labs are **intentionally vulnerable by design**, for education only. Run them locally / isolated — never expose them to the public internet.
>
> The repository contains weak keys, guessable secrets and a committed RSA keypair
> (`JWT Lab/keys/`) on purpose — they are the material the levels attack. Nothing
> here is a leaked credential, and none of it belongs anywhere but localhost.

## Labs

| Lab | Port | Levels | Vulnerability class |
|-----|------|--------|---------------------|
| [SQLi Lab](./SQLi%20Lab) | 8080 | 16 | SQL injection (union/blind/stacked/OUTFILE/second-order/INSERT/UPDATE/JSON/XPath/WAF) |
| [XSS Lab](./XSS%20Lab) | 8081 | 10 | Cross-Site Scripting (reflected/stored/DOM/filter & WAF bypass) |
| [Path Traversal Lab](./Path%20Traversal%20Lab) | 8082 | 10 | Path traversal / LFI (wrappers, encoding, filter bypass) |
| [IDOR Lab](./IDOR%20Lab) | 8083 | 10 | Broken access control / IDOR (JWT, mass-assignment, TOCTOU) |
| [OSCommand Injection](./OSCommand%20Injection) | 8084 | 10 | OS command injection (blind, time-based, OOB, WAF bypass) |
| [SSRF Lab](./SSRF%20Lab) | 8085 | 10 | Server-Side Request Forgery (metadata, scheme abuse, parser confusion) |
| [SSTI Lab](./SSTI%20Lab) | 8086 | 10 | Server-Side Template Injection → RCE |
| [XXE Lab](./XXE%20Lab) | 8087 | 10 | XML External Entity (OOB, error-based, XInclude, param-entity chain) |
| [File Upload Lab](./File%20Upload%20Lab) | 8088 | 10 | Unrestricted upload → web shell (extension/MIME/magic/.htaccess bypass) |
| [PHP Object Injection](./PHP%20Object%20Injection) | 8089 | 10 | Insecure deserialization (POP chains, phar, `__wakeup` bypass) |
| [NoSQL Injection Lab](./NoSQL%20Injection%20Lab) | 8090 | 10 | NoSQL injection (`$ne`/`$regex`/`$where`, blind, type confusion) |
| [CSRF Lab](./CSRF%20Lab) | 8091 | 10 | Cross-Site Request Forgery (token/SameSite/referer/double-submit) |
| [Open Redirect Lab](./Open%20Redirect%20Lab) | 8092 | 10 | Open redirect (allowlist, userinfo, encoding, CRLF) |
| [JWT Lab](./JWT%20Lab) | 8093 | 10 | JWT & token forgery (alg confusion, kid injection, jku, parser differentials) |
| [Race Condition Lab](./Race%20Condition%20Lab) | 8094 | 10 | Race conditions & TOCTOU (limit overrun, double-spend, single-packet timing) |
| [CORS CSP Lab](./CORS%20CSP%20Lab) | 8095 | 10 | Browser policy bypass (CORS allowlists, CSP nonces, gadgets, `strict-dynamic`) |
| [Crypto Oracle Lab](./Crypto%20Oracle%20Lab) | 8096 | 10 | Crypto misuse (ECB, CBC bit-flip, padding oracle, length extension, nonce reuse) |
| [Business Logic Lab](./Business%20Logic%20Lab) | 8097 | 10 | Business logic (negative quantity, coupon stacking, workflow skipping, refunds) |
| [GraphQL Lab](./GraphQL%20Lab) | 8098 | 10 | GraphQL (introspection, batching, alias abuse, depth limits, resolver injection) |
| [Auth Reset Lab](./Auth%20Reset%20Lab) | 8099 | 10 | Auth & recovery (enumeration, predictable tokens, host-header poisoning, 2FA) |
| [XPath LDAP Lab](./XPath%20LDAP%20Lab) | 8100 | 10 | XPath & LDAP filter injection (blind extraction, escaping failures) |

**21 labs · 216 levels**, plus a portal on **8079**. Ports are unique (8079–8100) so everything runs side by side.

## The main menu

```bash
./labs.sh up            # portal + every lab
```

Then open **<http://localhost:8079>**. The portal lists all 21 labs grouped by the
suggested order, shows which containers are actually running, and reads every
lab's progress cookie so the whole suite has one scoreboard — cookies are scoped
to the host rather than the port, so `localhost:8079` can see what you solved on
`localhost:8093`. It also carries a filter box (press `/`), direct links to each
lab's flag page and workbench, and a reset-everything button.

## Running a lab

`./labs.sh up` starts every lab, `./labs.sh status` health-checks the ports,
`./labs.sh down` stops them, `./labs.sh test` runs every self-test. Pass a filter
to scope it: `./labs.sh up jwt crypto`.


Each lab folder has its own `docker-compose.yml`. From inside a lab folder:

```bash
docker compose up -d            # bind-mounted PHP labs (XSS, etc.) — edit + refresh live
docker compose up --build -d    # labs with a Dockerfile (bakes secrets or hostnames)
```

**SQLi Lab** uses MySQL; after editing `init.sql` reset the DB volume:

```bash
cd "SQLi Lab" && docker compose down -v && docker compose up -d
```

Then open `http://localhost:<port>` for that lab.

## How each lab works

- **White-box:** every level page shows the actual vulnerable PHP/JS running the challenge, with the exploited line highlighted.
- **Authentic flag gate:** the server verifies a genuine exploit (a surviving payload, a secret file actually read, an internal endpoint actually reached, a state actually reached) before revealing the `FLAG{...}` — not a string match.
- **Progress:** stored per-lab in a `<slug>_lab_progress` cookie; a central `submit.php` per lab tracks completion and lets you reset.
- **Hints:** 5 progressive hints per level, from concept to full working payload.
- **Design system:** one shared black-and-white theme (Inter + JetBrains Mono) across every lab.

## Understand it, don't fuzz it

The newer labs (8093–8100) are built on `_kit/lab_kit.php`, and the
**SQLi**, **XSS** and **OSCommand Injection** labs have been retrofitted with the
same layer inside their existing two-panel layout. The goal is that a learner
who finishes a level can say *why* it worked without opening the hints:

- **A pipeline trace** shows the learner's own input travelling through every
  filter stage, with the blocking stage marked. A rejected payload explains
  itself instead of inviting another guess.
- **A sink view** prints the exact string handed to the dangerous operation —
  the assembled SQL, the shell command, the HTML, the verification key — with
  the attacker-controlled part highlighted.
- **A mental model box** explains how *that specific sink* parses input: where
  a value can break out, which bytes are structural, what has to stay valid.
- **Probes** are single questions with a payload attached ("does a single quote
  reach the parser?"), never finished exploits. They train hypothesis-testing
  in place of spraying.
- **A "why it worked" box** appears on success, and **the fix** shows the
  vulnerable line beside the correct one.

Several labs also ship a local workbench so a level is about the vulnerability
rather than about plumbing: a JWT decoder/signer/cracker, a crypto workbench
with oracle runners, and a parallel-request launcher with connection warming.

Retrofitting the older labs surfaced three levels that were no longer
exploitable as described, all now fixed and with their displayed source and
hints brought back into line:

- **XSS level 5** — PHP 8.1 changed the `htmlspecialchars()` default to
  `ENT_QUOTES|ENT_SUBSTITUTE`, which silently closed the single-quote attribute
  escape. `ENT_COMPAT` is now passed explicitly.
- **SQLi level 14** — the filter ran *after* the decoders, so the apostrophe was
  always blocked and no encoding could help. The order is now filter-then-decode,
  which is both the real-world bug and the lesson the level is named after.
- **SQLi level 16** — the WAF blocked the apostrophe, leaving no way out of the
  string literal and therefore no solution. Layer 3 no longer lists it; the
  level is solvable with `admin'||'1`, which teaches `||` as a synonym for `OR`
  and how operator precedence removes the need for a comment.

## Suggested order

The labs are independent, but the *concepts* are not. This order makes each lab
cheaper than the last, because later ones reuse a root cause you have already
met in a different grammar.

**Warm-up — learn the page, not the payload.** XSS levels 1-2 (:8081). Ignore the
hints. Read the source panel, run the three probes, predict what the trace will
say, then send your payload and check your prediction. That loop is the whole
method; the rest of the suite is practice at it.

**1 · Data becoming syntax.** One root cause, four grammars.
`XSS 1-10` (:8081) → `SQLi 1-8` (:8080) → `Path Traversal` (:8082) →
`OSCommand Injection` (:8084). By the fourth you should be asking "where does my
input end up, and what is structural there" before trying anything.

**2 · The same bug in less familiar grammars.**
`SQLi 9-16` (XPath, INSERT, UPDATE, JSON, stacked WAF layers) →
`XPath LDAP` (:8100) → `NoSQL Injection` (:8090) → `SSTI` (:8086) → `XXE` (:8087).

**3 · Trust and identity.** `JWT` (:8093) **in order** — the key you crack in
level 4 is still valid in 9 and 10, which is the point. Then
`Auth Reset` (:8099) and `IDOR` (:8083).

**4 · The browser as the boundary.** `CORS CSP` (:8095) → `CSRF` (:8091) →
`Open Redirect` (:8092) → `SSRF` (:8085), which walks the same allowlist
reasoning back to the server side.

**5 · Nothing to fuzz.** `Business Logic` (:8097) → `Race Condition` (:8094)
(do 2 and 3 first, then 6 — level 6 explains why your earlier races may not have
reproduced) → `File Upload` (:8088) → `PHP Object Injection` (:8089) →
`GraphQL` (:8098).

**6 · Correct primitives, wrong construction.** `Crypto Oracle` (:8096) **in
order** — each level assumes the one before it.

Rough pacing: a level takes 15-40 minutes if you read rather than guess. The
five hints are progressive and hint 5 is a working payload, so use hint 1 when
stuck and stop there.

## The look

The suite is themed as a **DOS IDE with the monitor turned down** — Turbo Vision
windows on a dark desktop. The direction is not decoration: the product already
is an IDE. Source on the left and challenge on the right is Norton Commander,
and the teaching trace is a debugger watch window, so the aesthetic is the
structure made visible.

- **Palette** — the EGA sixteen as *hues*, pulled well off full saturation.
  Windows at `#1a1e28` on a `#12141b` desktop, dark `#2b303c` chrome bars, and
  warm off-white `#c3c0b6` body text rather than pure white. Four accents, one
  job each: amber `#cfa65c` for titles and the default action, cyan `#6f9fb0`
  for labels and links, sage `#7fa06d` for pass, clay `#b5766e` for block.
- **Contrast is tuned, not maximised.** Body text sits at 9:1 and secondary text
  at 5.7:1 — comfortable for an hour of reading rather than the 15:1 a saturated
  palette produces. Colour arrives as a rule, a border or a single word; there
  are no solid slabs of it.
- **Type** — Silkscreen for chrome (titles, badges, buttons), IBM Plex Mono for
  everything that is data (code, traces, payloads, inputs), IBM Plex Sans for
  prose. Three faces, one job each.
- **Signature** — the trace is drawn as a watch window: a rail down the left, a
  numbered stage block per transformation, and the rail segment turning sage or
  clay where the input passed or was stopped.
- Zero border radius, soft offset shadows, `[OK]` / `[ERR]` / `[i]` line tags on
  status messages, `F1` on the hints button, and a single blinking block cursor
  on the two hero headings — disabled under `prefers-reduced-motion`.

### Changing the theme

Stylesheets are generated, so edit the parts and rebuild:

```
<lab>/css/base.css   the lab's own layout and components
_kit/kit.css         the teaching layer
_kit/retro.css       the theme: tokens plus the component reskin
```

```bash
./_kit/build-css.sh              # regenerate every lab
./_kit/build-css.sh "JWT Lab"    # or just one
```

The build hoists the font imports, points the original Inter/JetBrains families
at IBM Plex, and concatenates the three layers into `css/styles.css`. Do not
edit `styles.css` directly — it is overwritten.

## Self-tests

**Every lab** ships `solve_check.php`, which performs the *intended* solution for
each of its levels against the running container and gates on the effect — a row
actually read, a file actually executed, a state actually reached — never on a
payload matching a pattern.

```bash
./labs.sh test                  # all 21 labs
cd "<Lab Name>" && docker compose exec web php /var/www/html/solve_check.php
```

Current status: **216 levels verified solvable, 0 failing.**

These tests exist because an audit found levels that had quietly stopped working
and nothing was watching. Among them: four SQLi levels (one with a dead
`catch` block that never fired on PHP 8.0, three with filters that left no
reachable solution), an OS Command level whose WAF blocked every separator, a
File Upload flag gate that awarded the flag from a filename regex without the
server ever executing anything, and roughly twenty hints publishing payloads
their own level rejected. Run the suite after any change to a filter.

## Building a new lab

See [`_kit/BUILDING_A_LAB.md`](./_kit/BUILDING_A_LAB.md) for the teaching
contract, the kit API, the file layout and the port registry. Scaffold with:

```bash
./_kit/scaffold.sh "<Lab Name>" <slug> <port>
```

`JWT Lab` is the reference implementation.
