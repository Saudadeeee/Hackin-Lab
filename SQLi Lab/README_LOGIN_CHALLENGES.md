# SQL Injection Login Challenge Labs

This project contains a self‑hosted set of sixteen SQL injection login challenges that progress from beginner to final boss. Every level is a different authentication scenario whose end goal is the same: **obtain the administrator account by exploiting SQL injection**. The lab is designed for hands‑on practice inside an isolated environment and ships with a hint system, flag validation, and a consistent look and feel across all levels.

---

## 1. Project Structure

```
SQLi Lab/
├── docker-compose.yml          # Web + database stack
├── init.sql                    # Database schema and seed data
├── index.php                   # Main challenge selector
├── challenge_index.php         # Intro page for the standalone admin challenge
├── includes/helpers.php        # Shared helpers (flags + hint renderer)
├── level1.php ... level16.php  # Sixteen login challenges
├── level7_set.php              # Setup step for the second-order challenge
├── sandbox.php                 # Free-form query runner
├── submit.php                  # Flag submission portal
└── README_LOGIN_CHALLENGES.md  # This file
```

---

## 2. Requirements

- Docker & Docker Compose
- Port **8080** available on the host

---

## 3. Getting Started

```bash
cd "SQLi Lab"
docker compose up --build -d
```

The application will be reachable at <http://localhost:8080>. If you change anything inside `init.sql` or want to reset the environment, bring the stack down (with volumes) and start it again:

```bash
docker compose down -v
docker compose up --build -d
```

---

## 4. Database & Credentials

The database is initialised by `init.sql` with a richer `users` table that contains the columns referenced by the challenges (email, phone, bio, etc.) and a `levels` table that stores the canonical flags.

Two MySQL users are provisioned:

| User         | Password   | Permissions                                      | Used by          |
|--------------|------------|--------------------------------------------------|------------------|
| `webapp`     | `webapp123`| CRUD on gameplay tables (`users`, `meta`, `logs`) | Level pages      |
| `flagchecker`| `flagchecker123` | Read‑only access to `levels` table            | `submit.php`     |

Environment variables in `docker-compose.yml` expose these credentials to the PHP container. If you need to change them, update both the compose file and `init.sql`, rebuild, and restart the services.

---

## 5. Level Overview

| Level | Theme                               | Key Skill/Concept                              |
|-------|--------------------------------------|------------------------------------------------|
| 1     | Basic login                          | Error-based SQLi fundamentals                  |
| 2     | Integer + UNION injection            | Column discovery & UNION exploitation          |
| 3     | Stacked queries                      | Multi-statement execution & privilege escalation |
| 4     | Boolean blind                        | True/false inference without errors            |
| 5     | Time-based blind                     | Leveraging `SLEEP()` to extract data           |
| 6     | File-based (OUTFILE)                 | Out-of-band exfiltration via filesystem        |
| 7     | Second-order (setup + trigger)       | Persisted payloads executed on later request   |
| 8     | Registration + stored payload        | Two-step injection through user data reuse     |
| 9     | XPath authentication                 | XML/XPath predicate manipulation               |
| 10    | INSERT injection                     | Tampering with `INSERT` to craft admin account |
| 11    | UPDATE injection                     | Modifying an existing account’s role           |
| 12    | JSON-based query                     | Injecting through JSON-parsed parameters       |
| 13    | Comment filter bypass                | Evading stripped comment characters            |
| 14    | Encoding filter bypass               | URL/HTML encoding combinations                 |
| 15    | Whitespace-free injection            | Alternative whitespace & tokenisation          |
| 16    | Advanced WAF (final boss)            | Combining multiple bypass strategies at once   |

Each level page renders hints through the shared helper. You start with no guidance, and every click on “Show next hint” reveals a single additional clue, allowing you to pace yourself.

---

## 6. Flags & Validation

- Every level displays the same canonical `FLAG{...}` string that is stored in the `levels` table and used by the submission portal.
- Once you capture a flag, navigate to `/submit.php` or use the “Submit Flags” button on the home page.
- Choosing the level and submitting the correct flag will mark it as complete via a browser cookie so you can track progress locally.

> **Note:** The gameplay user (`webapp`) cannot read the `levels` table, so you must retrieve each flag through the intended exploit path.

---

## 7. Hint System

Hints are declared in `includes/helpers.php`. They are:

- Centralised so every page displays the same consistent copy.
- Revealed incrementally to encourage exploration before giving the solution away.
- Easy to extend; simply add or edit the array entry for the desired level.

---

## 8. Customising the Lab

1. Duplicate an existing level file to use as a template.
2. Adjust the vulnerability, layout, and success condition.
3. Add the new level to `index.php` (and optionally `challenge_index.php` if relevant).
4. Insert a new entry in `includes/helpers.php` for the flag and hints.
5. Rebuild the containers so `init.sql` picks up the additional flag or seed data.

---

## 9. Troubleshooting

| Issue                                 | Fix                                                                 |
|---------------------------------------|----------------------------------------------------------------------|
| Containers running but site unreachable | Confirm port 8080 is free; restart Docker or the containers.        |
| DB connection errors                  | `docker compose down -v && docker compose up --build -d`             |
| Flags not updating after changing `init.sql` | Drop volumes (`docker compose down -v`) before bringing the stack up |
| Cookie state stale                    | Clear browser cookies for `localhost` or use a private window.      |
| Need a free-form SQL playground       | Visit `/sandbox.php`; credentials default to the `webapp` user.      |

---

## 10. Safety Reminder

These challenges are intentionally vulnerable and must only be used in this isolated environment. Do **not** reuse the sample credentials elsewhere and do not attempt these techniques against systems you do not explicitly own or have permission to test.

---

Happy hacking! Capture the flags, take notes as you go, and expand the lab with your own scenarios when you are ready.
