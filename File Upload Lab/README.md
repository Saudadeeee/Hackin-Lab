# File Upload Lab — Unrestricted File Upload (White-Box)

Part of the **Hackin Lab** web-security training suite. Ten intentionally-vulnerable
levels that teach how weak file-upload validation is bypassed to achieve **remote code
execution (RCE)**. Every level shows the *actual* server-side filter it runs.

> Intentionally insecure. Run it only locally / in an isolated environment.

## The vulnerability

An **Unrestricted File Upload** lets an attacker place an executable file (a PHP web
shell) into a web-served directory. Each level applies a progressively stronger — but
still flawed — validation filter. Defeat the filter, get an executable `.php` payload
stored under `uploads/levelN/`, and run it to read the secret at
`/var/secret/levelN_flag.txt`.

Two ways to capture each flag:
1. **Panel award** — when your crafted upload survives the level filter *and* is an
   executable PHP payload, `verify_upload()` re-applies the filter server-side and shows
   the `FLAG{...}` right on the page (no external tooling needed).
2. **Manual RCE** — the stored file is genuinely executable; click the stored-file link
   to run your shell against `/var/secret/`.

## Levels

| # | Concept | Bypass | Flag |
|---|---------|--------|------|
| 1 | No validation | Upload `shell.php` directly | `FLAG{upload_no_validation}` |
| 2 | Extension blocklist (blocks `.php`) | Use `.phtml` / `.php5` / `.pht` | `FLAG{upload_extension_blocklist_bypass}` |
| 3 | Content-Type (MIME) check | Forge `Content-Type: image/png` | `FLAG{upload_mime_bypass}` |
| 4 | Magic-byte / image check | Prepend `GIF89a;` polyglot | `FLAG{upload_magic_bytes_bypass}` |
| 5 | Double extension (last-ext allowlist) | `shell.php.jpg` | `FLAG{upload_double_extension}` |
| 6 | Case-sensitive blocklist | `shell.PhP` | `FLAG{upload_case_bypass}` |
| 7 | `.htaccess` upload | Upload `.htaccess` mapping `.jpg`→PHP, then `shell.jpg` | `FLAG{upload_htaccess}` |
| 8 | Trailing char / whitespace | `shell.php.` or `shell.php ` | `FLAG{upload_trailing_bypass}` |
| 9 | Content scan blocks `<?php` | Use the `<?=` short-echo tag | `FLAG{upload_content_filter_bypass}` |
| 10 | Multi-layer WAF (ext + MIME + magic + content) | `shell.php.jpg` + `image/png` + `GIF89a` + `<?=` | `FLAG{upload_waf_bypass}` |

Difficulty ramp: L1–2 Easy · L3–6 Medium · L7–9 Hard · L10 Expert.

## How each level page works

Every level offers three attacker-controlled fields — **Filename**, **Content-Type**, and
**File content** — so all bypasses are solvable from a plain browser. A real multipart
upload (`curl`/Burp with an `<input type="file">` named `file`) is also accepted for
tool-based solving.

Example (level 1):

```
Filename:      shell.php
Content-Type:  application/octet-stream
File content:  <?php readfile('/var/secret/level1_flag.txt'); ?>
```

Example (level 10, the finale):

```
Filename:      shell.php.jpg
Content-Type:  image/png
File content:  GIF89a;<?= readfile('/var/secret/level10_flag.txt'); ?>
```

## Run it

```bash
docker compose up --build          # http://localhost:8088
docker compose down                # stop
docker compose down --rmi local    # stop + remove the built image (rebakes secrets next up)
```

- Port: **8088**
- Progress cookie: `upload_lab_progress` (30-day expiry). Reset from the Submit page.
- Secrets are baked into the image at `/var/secret/` (not in the repo) via the `Dockerfile`,
  so a rebuild (`--build`) is required after cloning.

### Notes
- Uploads are written to `uploads/levelN/` inside the lab folder (bind-mounted). On some
  native-Linux setups you may need `chmod -R 777 uploads` for the web server to write
  there; the on-page flag award works regardless, since the verifier re-applies the filter
  in memory.
- The Apache config in the `Dockerfile` deliberately executes `.php/.phtml/.php5/.pht/...`
  (including double/trailing-character variants) and enables `AllowOverride All` under
  `uploads/` — that permissiveness is the point of the lab, not a mistake.
