# Open Redirect Lab

A white-box, intentionally-vulnerable teaching lab for **Open Redirect** (a.k.a. Unvalidated
Redirects & Forwards, CWE-601). Part of the **Hackin Lab** web-security training suite.

Each level exposes a redirect endpoint that reads a `next` parameter and would hand it to
`header("Location: ...")` (or an `<a href>` / `location` assignment) behind a progressively
stronger — but always flawed — allowlist. The trusted host is **`example-bank.local`**; your goal
is to steer the redirect to the attacker host **`evil.attacker.example`**.

> **Safety by design:** the lab never issues a live cross-site redirect. `verify_redirect($level,
> $input)` re-applies the level's real validation, then *computes* the effective destination host a
> browser would navigate to (parsing exactly as the vulnerable code would). If that resolves to an
> off-allowlist / attacker host, it awards the flag and **shows where the victim would have been
> sent** — it renders the target as text instead of following it. Empty input never triggers a fatal.

## Levels

| # | Concept | Difficulty | How the flag is captured |
|---|---------|-----------|--------------------------|
| 1 | Basic open redirect — no validation | Easy | `next` goes straight to `Location`; effective host resolves off-allowlist. `?next=https://evil.attacker.example` |
| 2 | Protocol-relative bypass | Easy | Filter allows any value starting `/`; `//evil.attacker.example` is protocol-relative → attacker host. |
| 3 | Prefix allowlist bypass | Medium | `str_starts_with($host, "example-bank.local")`; `example-bank.local.evil.attacker.example` matches the prefix but resolves to the attacker domain. |
| 4 | Substring allowlist bypass | Medium | `str_contains($next, "example-bank.local")`; hide the substring in the path: `https://evil.attacker.example/example-bank.local`. |
| 5 | Backslash normalization | Medium | `//` and `http(s):` blocked; `/\evil.attacker.example` — the browser rewrites `\` to `/` → protocol-relative. |
| 6 | Userinfo (`@`) host spoof | Medium | Naive authority regex + prefix check; `https://example-bank.local@evil.attacker.example/` — text before `@` is userinfo, real host is the attacker. |
| 7 | Encoded slash bypass | Hard | Raw value checked, then `urldecode()`d; `%2f%2fevil.attacker.example` decodes to `//evil...`. |
| 8 | Dangerous scheme | Hard | Allowlist only checks the host; `javascript:`/`data:` have a `null` host, pass the check, and execute. |
| 9 | CRLF header injection | Hard | Decoded value concatenated into `Location`; `/dashboard%0d%0aLocation:%20https://evil.attacker.example` injects a second header. |
| 10 | Multi-layer filter bypass | Expert | Five stacked filters block every earlier trick; `https:/evil.attacker.example/login` (single slash) is hostless to `parse_url()` but a full URL to the browser. |

Flags follow the pattern `FLAG{redirect_...}` and are defined in `helpers.php`
(`get_flag_for_level()`).

## Running

```bash
cd "Open Redirect Lab"
docker compose up
```

Then open <http://localhost:8092/>. Stop with `Ctrl+C` (or `docker compose down`).

Base image is `php:8.2-apache`; no database or Dockerfile is required. Progress is stored client-side
in the `redirect_lab_progress` cookie (30-day expiry) and can be reset from the **Submit Flag** page.

## Layout

```
Open Redirect Lab/
├── css/styles.css      # shared Hackin Lab B&W theme
├── helpers.php         # flags, hints, the redirect engine + verify_redirect(), inline flag submit
├── index.php           # level grid / landing page
├── submit.php          # central flag checker + progress checklist
├── level1.php … level10.php
├── docker-compose.yml  # php:8.2-apache, port 8092:80
└── README.md
```
