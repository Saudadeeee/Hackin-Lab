# SSRF Lab

An intentionally-vulnerable **Server-Side Request Forgery** teaching lab, part of the
**Hackin Lab** web-security training suite. Ten white-box levels: each shows the real
vulnerable PHP source, fetches a user-supplied URL server-side, and awards the flag only
when your request actually reaches an internal resource whose response carries the flag.

> The flag is never awarded by matching your input. It is awarded when the **server's own
> fetch** brings back content containing the level's `FLAG{...}` — i.e. the SSRF genuinely
> reached the internal endpoint.

## The vulnerability

The app fetches a URL you control (`file_get_contents()` / PHP curl) with weak or missing
validation. Internal resources — a loopback-only `internal.php`, an internal `admin.php`
panel, a blind `beacon.php`, files under `/var/secret/`, and a mock cloud-metadata service
at `169.254.169.254` — are reachable only from inside the container, so a working SSRF is
the only way to read their flags.

## Levels

| # | Concept | New obstacle | Flag | How the flag is captured |
|---|---------|--------------|------|--------------------------|
| 1 | Basic SSRF | none | `FLAG{ssrf_basic}` | Server fetches `http://127.0.0.1/internal.php?level=1` (loopback-only page) |
| 2 | Internal service access | reach a loopback-only admin panel | `FLAG{ssrf_internal_service}` | Fetch `http://127.0.0.1/admin.php` (403 to you, 200 to the server) |
| 3 | Blind SSRF | response body hidden | `FLAG{ssrf_blind}` | Fetch `http://127.0.0.1/beacon.php`; hit confirmed server-side, body withheld |
| 4 | Host blocklist bypass | blocks `localhost` / `127.0.0.1` | `FLAG{ssrf_ip_encoding_bypass}` | Reach internal via `127.1`, `0`, decimal `2130706433`, or `[::1]` |
| 5 | Redirect-based SSRF | host allowlist, but follows 302 | `FLAG{ssrf_open_redirect_chain}` | `feed.local/redirector.php?url=http://127.0.0.1/internal.php?level=5` |
| 6 | Scheme abuse (`file://`) | scheme not validated | `FLAG{ssrf_file_scheme}` | `file:///var/secret/flag6.txt` read off disk |
| 7 | URL parser confusion | substring host allowlist | `FLAG{ssrf_url_parser_confusion}` | `http://example.com@127.0.0.1/internal.php?level=7` (userinfo trick) |
| 8 | Cloud metadata theft | scheme-only guard | `FLAG{ssrf_cloud_metadata}` | `http://169.254.169.254/latest/meta-data/iam/security-credentials/ssrf-lab-role` |
| 9 | Hostname allowlist bypass | trusts a hostname substring | `FLAG{ssrf_hostname_bypass}` | `http://corp-internal.attacker.local/internal.php?level=9` (loopback DNS) |
| 10 | Multi-layer WAF | scheme + host-literal + keyword filters | `FLAG{ssrf_waf_bypass}` | `http://2130706433/internal.php?level=10` (decimal IP survives all layers) |

Difficulty ramp: L1–2 Easy, L3–6 Medium, L7–9 Hard, L10 Expert.

## Running

```bash
cd "SSRF Lab"
docker compose up --build
```

Then open <http://localhost:8085>.

Notes:
- Uses a **Dockerfile** (bakes `/var/secret/flag6.txt`, installs the PHP `curl` extension,
  adds the `169.254.169.254` metadata address to loopback at startup).
- `cap_add: NET_ADMIN` is required for the metadata-IP alias; `extra_hosts` maps the
  trusted / attacker hostnames to loopback. All egress stays inside the container, so the
  lab works fully **offline** with no external network.
- Rebuild after changes with `docker compose up --build`. Progress is stored in the
  `ssrf_lab_progress` cookie; reset it from the Submit page.

## Files

- `index.php` — level grid, stats, progress bar
- `level1.php` … `level10.php` — the ten white-box challenges
- `submit.php` — central flag checker + per-level checklist + reset
- `helpers.php` — flags, 5 progressive hints per level, capture check, inline submit
- `internal.php` / `admin.php` / `beacon.php` — loopback-only internal endpoints
- `redirector.php` — open redirect on the trusted host (Level 5)
- `metadata.php` + `.htaccess` — mock cloud instance-metadata service (Level 8)
- `css/styles.css` — shared Hackin Lab theme
- `Dockerfile` / `docker-compose.yml` — port `8085`

## Security notice

This lab is **intentionally vulnerable**. Do not deploy it on a public network or any
environment you care about. Run it only locally / in an isolated sandbox.
