# XXE Lab

Intentionally-vulnerable teaching lab for **XML External Entity (XXE)** injection. Ten white-box levels: each parses attacker-supplied XML with external entities **explicitly enabled** (`libxml_set_external_entity_loader` + `LIBXML_NOENT | LIBXML_DTDLOAD`) — the vulnerability modern libxml disables by default. Part of the Hackin Lab suite.

- **Port:** 8087
- **Progress cookie:** `xxe_lab_progress`
- **Secrets:** baked by the Dockerfile at `/var/secret/flag1..flag10` (outside the web root). A level awards its flag only when the entity actually resolves the secret (or reaches the internal service) — never by string-matching.

## Run

```bash
cd "XXE Lab"
docker compose up --build -d      # rebuild bakes /var/secret/flag*
# open http://localhost:8087
```

Hosted attack infrastructure served from the web root: `oob.dtd`, `error.dtd`, `chain.dtd`, plus `collector.php` (OOB sink) and `internal.php` (loopback-only service for the SSRF level).

## Levels

| # | Concept | Technique |
|---|---------|-----------|
| 1 | Classic file read | `<!ENTITY xxe SYSTEM "file:///var/secret/flag1.txt">` |
| 2 | php://filter source read | `php://filter/convert.base64-encode/resource=…flag2.php` |
| 3 | Blind XXE (OOB) | external `oob.dtd` exfils to `collector.php`, confirmed server-side |
| 4 | Error-based | `error.dtd` forces a failing load leaking the secret in the error |
| 5 | XInclude | DOCTYPE stripped → `<xi:include parse="text" href="file://…">` |
| 6 | SVG upload | DOCTYPE inside an uploaded SVG resolves on parse |
| 7 | DOCTYPE filter / encoding | WAF blocks ASCII `<!DOCTYPE`; send the doc as UTF-16 |
| 8 | Parameter-entity chaining | `chain.dtd` builds a general entity `&chained;` |
| 9 | SSRF via XXE | entity → `http://127.0.0.1/internal.php` (loopback-only) |
| 10 | Multi-layer WAF bypass | three ASCII filters (`<!DOCTYPE`, `SYSTEM`, `file://`) beaten by UTF-16 |

Each level shows the real parser sink in the code panel and provides starter XML to edit.
