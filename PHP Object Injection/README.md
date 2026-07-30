# PHP Object Injection Lab

Intentionally-vulnerable teaching lab for **PHP Object Injection / insecure deserialization**. Ten white-box levels: every page calls `unserialize()` on attacker-controlled input against defined "gadget" classes whose magic methods (`__destruct`, `__wakeup`, `__toString`) perform dangerous actions. Part of the Hackin Lab suite.

- **Port:** 8089
- **Progress cookie:** `poi_lab_progress`
- **Secret:** baked at `/var/secret/flag.txt` (contains a `POI_SECRET{...}` marker). A level awards its `FLAG{...}` only when a gadget effect actually reaches that secret — never by string-matching the flag.

## Run

```bash
cd "PHP Object Injection"
docker compose up --build -d      # rebuild bakes /var/secret/flag.txt
# open http://localhost:8089
```

A `phar.readonly=Off` INI is baked so Level 8 (phar deserialization) can build its archive.

## Levels

| # | Concept | Gadget / bypass |
|---|---------|-----------------|
| 1 | Property injection | control `$isAdmin`/property, bypass a check |
| 2 | `__destruct` file read | `TempFile::__destruct` → `file_get_contents($path)` |
| 3 | `__wakeup` gadget | `SessionStore::__wakeup` reads `$file` during unserialize |
| 4 | `__toString` gadget | `Template::__toString` fires on string cast |
| 5 | POP chain | `Logger`→`FileViewer` nested-object chain |
| 6 | Type juggling | loose `==` on a `0e…` magic-hash string |
| 7 | `__wakeup` bypass | property-count mismatch skips `__wakeup` (CVE-2016-7124) |
| 8 | Phar deserialization | `phar://` file op auto-unserializes metadata gadget |
| 9 | RCE POP chain | `Report`→`CommandRunner` → `shell_exec` |
| 10 | Signed-token WAF bypass | empty-signature HMAC skip + WAF-dodging file-read gadget |

Each level shows the real gadget source + `unserialize()` sink in the code panel, and ships a client-side serialize/base64 payload builder so the format is learnable without external tooling.
