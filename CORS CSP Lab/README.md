# CORS & CSP Lab

Ten levels on the two browser policies that decide what one origin may do to another.
CORS decides who may **read** your responses; Content-Security-Policy decides what may
**run** on your pages. Both are enforced by the browser and configured by the server,
so every bug in them is a bug in a string somebody wrote.

Port **8095**, slug `browserpolicy`.

```bash
docker compose up --build -d
open http://localhost:8095/
```

## Levels

| # | Title | Difficulty | Teaches |
|---|-------|-----------|---------|
| 1 | Reflected Origin with Credentials | Easy | reflection is not an allowlist; why `*` and credentials cannot be combined |
| 2 | The null Origin | Easy | where `Origin: null` comes from, and that anybody can send it |
| 3 | Prefix Match | Medium | a regex anchored only with `^` approves any domain you can register |
| 4 | Suffix Match | Medium | `str_ends_with` on an origin has no idea where a hostname label begins |
| 5 | Wildcard Subdomain plus a Weak Link | Hard | a `*.domain` allowlist inherits the weakest host inside it |
| 6 | CSP with a JSONP Gadget | Medium | `'self'` allowlists an origin, which includes every endpoint on it |
| 7 | Predictable Nonce | Hard | a nonce is only safe if it is unpredictable **and** used once |
| 8 | Missing base-uri | Hard | the nonce rides on the element, so moving the document base moves the script |
| 9 | unsafe-eval Gadget | Expert | a string-to-code sink needs no script element, so CSP never sees it |
| 10 | strict-dynamic and the Script Gadget | Expert | propagated trust makes every loader you ship part of your policy |

## How the levels decide

No level awards a flag for a payload matching a pattern. Each one checks an effect.

**CORS levels (1–5).** The page takes the `Origin` you type, sends a genuine credentialed
request to `api.php?level=N`, and prints the response headers that came back. The flag
requires that the server really emitted `Access-Control-Allow-Origin` naming your origin
together with `Access-Control-Allow-Credentials: true`, and that the origin's parsed host
is outside the company domain. Level 5 additionally fetches `legacy.php` and parses the
returned HTML with `DOMDocument` to confirm your parameter became a script node.

**CSP levels (6–10).** `render.php` sends the real `Content-Security-Policy` header and
renders your payload without escaping, so the payload genuinely executes (or genuinely
does not) in your browser; `hlab.win()` reports back to the level page when it runs.
Independently, `csp.php` evaluates the *same policy string* against a real HTML parse of
your markup and prints the decision as trace stages, naming the directive responsible for
each one. The flag comes from that evaluation, so the lab is testable without a browser —
and when the browser and the evaluator disagree, the browser is right and the evaluator
has a bug.

`csp.php` models the parts of CSP Level 3 these levels depend on: the `default-src`
fallback, `'self'` and host/scheme sources, `'unsafe-inline'` and the rule that nonces or
hashes make it inert, nonce matching on the element, `sha256-` hashes against the exact
inline text, `'strict-dynamic'` (host sources ignored, parser-inserted scripts blocked,
script-inserted scripts allowed), `'unsafe-eval'`, and whether an injected `<base href>`
is honoured. It does not model report-only mode, Trusted Types, sandbox, or redirects.

Level 9 goes one step further: `jsexpr.php` is a miniature JavaScript expression
evaluator that runs your `${...}` over the same object graph `tmpl.js` exposes, so the
flag is awarded when the expression genuinely reaches the `Function` constructor and
invokes the result, not when it looks like it might.

## Files

```
helpers.php     lab metadata, flags, 5 hints per level, shared UI
cors.php        the five CORS policies and the browser-verdict analysis
csp.php         the CSP parser and evaluator
jsexpr.php      the miniature JS expression evaluator used by level 9
api.php         the account API the CORS levels attack
legacy.php      the weak host inside the level-5 wildcard (no CSP, reflects ?note)
jsonp.php       the JSONP endpoint level 6 uses
render.php      the frame that sends the real CSP header for levels 6-10
frame.js        defines hlab.win(), which reports execution back to the level page
loader.js       the data-main script gadget level 10 attacks
tmpl.js         the client-side template helper level 9 attacks
app/widget.js   the page's own widget, loaded by a relative path (level 8)
attacker/       the second origin: 127.0.0.1 answers here too
solve_check.php runs the intended solution for all ten levels
```

## Hostnames

`docker-compose.yml` maps `portal.`, `admin.`, `legacy.` and `cdn.hackinlab.internal`
to `127.0.0.1` so the container can reach itself under those names. Your browser does not
resolve them, and does not need to: the CORS levels make those requests server-side.

Levels 8 and 10 need a second origin your browser *can* reach. The lab uses the fact that
`localhost` and `127.0.0.1` are different origins to a browser even when one server
answers both, and each page prints the alternate origin to use.

## Verifying

```bash
for f in *.php; do php -l "$f"; done
docker compose up --build -d
docker compose exec -T web php /var/www/html/solve_check.php   # 10 passed, 0 failed
```
