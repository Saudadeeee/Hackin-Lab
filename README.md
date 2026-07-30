# Hackin-Lab

Hackin-Lab is a Docker-powered suite of **local, hands-on web-security challenge labs**. Each lab targets one vulnerability class, ships 10–16 progressive white-box levels (Easy → Expert), and runs as its own self-contained container. Every level shows the **real vulnerable source code**, awards a `FLAG{...}` only when you actually exploit the flaw, tracks progress in a cookie, and offers 5 progressive hints.

> ⚠️ These labs are **intentionally vulnerable by design**, for education only. Run them locally / isolated — never expose them to the public internet.

## Labs

| Lab | Port | Levels | Vulnerability class |
|-----|------|--------|---------------------|
| [SQLi Lab](./SQLi%20Lab) | 8080 | 16 | SQL injection (error/union/blind/OUTFILE/second-order/XPath/WAF…) |
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

**13 labs · 136 levels.** Ports are unique (8080–8092) so labs can run side by side.

## Running a lab

Each lab folder has its own `docker-compose.yml`. From inside a lab folder:

```bash
docker compose up -d            # bind-mounted PHP labs (XSS, etc.) — edit + refresh live
docker compose up --build -d    # labs with a Dockerfile (bakes secrets): IDOR, Path Traversal,
                                # OSCommand, SSRF, XXE, File Upload, PHP Object Injection
```

**SQLi Lab** uses MySQL; after editing `init.sql` reset the DB volume:

```bash
cd "SQLi Lab" && docker compose down -v && docker compose up -d
```

Then open `http://localhost:<port>` for that lab.

## How each lab works

- **White-box:** every level page shows the actual vulnerable PHP/JS running the challenge, with the exploited line highlighted.
- **Authentic flag gate:** the server verifies a genuine exploit (a surviving payload, a secret file actually read, an internal endpoint actually reached) before revealing the `FLAG{...}` — not a string match.
- **Progress:** stored per-lab in a `<slug>_lab_progress` cookie; a central `submit.php` per lab tracks completion and lets you reset.
- **Hints:** 5 progressive hints per level, from concept to full working payload.
- **Design system:** one shared black-and-white theme (Inter + JetBrains Mono) across every lab.
