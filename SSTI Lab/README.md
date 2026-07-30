# SSTI Lab — Server-Side Template Injection

Part of the **Hackin Lab** web-security training platform. A white-box lab of
ten progressively harder Server-Side Template Injection challenges built on a
deliberately-vulnerable, hand-rolled mini template engine.

## The vulnerability

`render_template($tpl)` scans user input for `{{ ... }}` expressions and
evaluates whatever is inside as raw PHP:

```php
eval('return (' . $expr . ');');   // the intentional SSTI sink
```

There is no sandbox. Each level layers a slightly tighter — and slightly
broken — filter on top of the same engine. A statement fallback
(`eval($expr . ';')`) lets multi-statement payloads (variable functions) run too.

Every level runs the **real** engine against your input and shows the true
rendered output. The flag is awarded only when the server-side verifier
(`verify_ssti_payload()`) confirms the intended technique actually executed —
never by string-matching the flag. File-read and RCE levels are gated on the
payload genuinely disclosing the baked secret `/var/secret/flag.txt` or
producing real command output (`uid=...`).

## The ten levels

| # | Level | Difficulty | Concept | How the flag is captured |
|---|-------|-----------|---------|--------------------------|
| 1 | Basic Template Injection | Easy | `{{7*7}}` → 49 | a `{{ }}` block evaluates as PHP |
| 2 | Variable & Superglobal Access | Easy | `{{ $_SERVER['HTTP_HOST'] }}` | a superglobal is read and rendered |
| 3 | Function Call Execution | Medium | `{{ phpversion() }}` / `{{ strrev(...) }}` | a PHP function is invoked in a block |
| 4 | Local File Disclosure | Medium | `{{ file_get_contents('/var/secret/flag.txt') }}` | output contains the real secret file contents |
| 5 | Remote Code Execution | Medium | `{{ system('id') }}` | output shows real command execution (`uid=`) |
| 6 | Keyword Blocklist Bypass | Medium | backticks / `call_user_func('sys'.'tem',...)` | RCE while `system\|exec\|shell_exec\|passthru` are blocked |
| 7 | Character Blocklist Bypass | Hard | `chr()` concat / `$_GET[0]` chaining | RCE with quotes and backticks banned |
| 8 | Variable-Function Indirection | Hard | `{{ $f='sys'.'tem';$f('id') }}` | RCE via a `$var(...)` call while names + `call_user_func` are blocked |
| 9 | Nested Delimiter Bypass | Hard | `{{{{...}}}}` | a tag survives the single-pass `{{ }}` stripper and runs |
| 10 | Multi-Layer WAF Bypass | Expert | nest + `chr()` + variable function | one vector beats the stacked keyword + character + stripper WAF |

## Run it

```bash
docker compose up --build
```

Then open <http://localhost:8086>.

The lab uses a **Dockerfile** (it bakes the secret at `/var/secret/flag.txt`),
so build with `--build` after changes. To tear it down completely:

```bash
docker compose down
```

Progress is tracked client-side in the `ssti_lab_progress` cookie (30-day
expiry) and can be reset from the **Submit Flag** page.

## Files

```
SSTI Lab/
├── css/styles.css     # shared Hackin Lab B&W theme
├── helpers.php        # the template engine, filters, verifier, hints, flags
├── index.php          # level grid + progress
├── submit.php         # central flag checker + progress checklist
├── level1.php … level10.php
├── Dockerfile         # bakes /var/secret/flag.txt
└── docker-compose.yml # php:8.2-apache, port 8086
```
