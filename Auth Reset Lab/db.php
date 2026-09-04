<?php
/**
 * Auth Reset Lab · storage layer
 * ---------------------------------------------------------------------------
 * Everything the lab does to accounts is real: real rows, real password hashes,
 * real token records, real sessions. No level awards a flag for a string that
 * looks like an exploit — it awards one when the database ends up in a state
 * that only the exploit can produce.
 *
 * Every table carries a `level` column. Levels never share rows, so solving
 * level 4 cannot half-solve level 9, and "Reset this level" on any page throws
 * away exactly that level's world and rebuilds it.
 *
 * SQLite is used because pdo_sqlite ships enabled in php:8.2-apache. The file
 * lives outside the document root (and outside the bind mount) so the lab keeps
 * working on hosts where the mounted filesystem does not support SQLite locks.
 */

const AR_ADMIN = 'admin@hackinlab.internal';
const AR_GUEST = 'guest@hackinlab.internal';
const AR_GUEST_PASSWORD = 'guest123';

/**
 * Level 8 hands the learner the administrator password on purpose: that level
 * is about the second factor, so the first factor is not the puzzle.
 */
const AR_L8_ADMIN_PASSWORD = 'Kestrel-Autumn-2019';

/* =========================================================================
 * Connection
 * ===================================================================== */

function ar_db_path(): string
{
    $env = getenv('AUTHRESET_DB');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    $dir = rtrim(sys_get_temp_dir(), "/\\") . '/authreset_lab';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    @chmod($dir, 0777);
    return $dir . '/lab.sqlite';
}

function ar_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    // The web server runs as www-data and solve_check.php may run as root.
    // A permissive umask keeps the -wal / -shm sidecar files writable by both.
    $oldMask = umask(0000);

    $path = ar_db_path();
    $pdo  = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA busy_timeout = 8000');
    ar_schema($pdo);

    foreach ([$path, $path . '-wal', $path . '-shm'] as $f) {
        if (file_exists($f)) {
            @chmod($f, 0666);
        }
    }
    umask($oldMask);

    return $pdo;
}

function ar_schema(PDO $db): void
{
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        level         INTEGER NOT NULL,
        email         TEXT    NOT NULL,
        password_hash TEXT    NOT NULL,
        display_name  TEXT    NOT NULL,
        is_admin      INTEGER NOT NULL DEFAULT 0
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS tokens (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        level      INTEGER NOT NULL,
        token      TEXT    NOT NULL,
        email      TEXT    NOT NULL,
        user_id    INTEGER,
        kind       TEXT    NOT NULL DEFAULT "reset",
        otp_code   TEXT,
        issued_at  INTEGER NOT NULL,
        expires_at INTEGER,
        used_at    INTEGER,
        attempts   INTEGER NOT NULL DEFAULT 0
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS mail (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        level      INTEGER NOT NULL,
        to_email   TEXT    NOT NULL,
        subject    TEXT    NOT NULL,
        body       TEXT    NOT NULL,
        link       TEXT,
        created_at INTEGER NOT NULL
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS sessions (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        level         INTEGER NOT NULL,
        sid           TEXT    NOT NULL,
        email         TEXT,
        authenticated INTEGER NOT NULL DEFAULT 0,
        otp_verified  INTEGER NOT NULL DEFAULT 0,
        note          TEXT,
        created_at    INTEGER NOT NULL
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS collected (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        level      INTEGER NOT NULL,
        host       TEXT,
        uri        TEXT,
        query      TEXT,
        token      TEXT,
        created_at INTEGER NOT NULL
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS probe_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        level      INTEGER NOT NULL,
        email      TEXT    NOT NULL,
        elapsed_ms REAL    NOT NULL,
        created_at INTEGER NOT NULL
    )');

    // A win row is written only after a state check passed (a password hash
    // that verifies against the learner's chosen string, an authenticated
    // session that exists in the sessions table). It is what makes the flag
    // survive a page reload; it is never written from a payload comparison.
    $db->exec('CREATE TABLE IF NOT EXISTS wins (
        level  INTEGER PRIMARY KEY,
        detail TEXT    NOT NULL,
        won_at INTEGER NOT NULL
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS level_state (
        level     INTEGER PRIMARY KEY,
        seeded_at INTEGER NOT NULL
    )');

    $db->exec('CREATE INDEX IF NOT EXISTS idx_users_level ON users(level, email)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_tokens_level ON tokens(level, token)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_mail_level ON mail(level, to_email)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_sessions_level ON sessions(level, sid)');
}

/* =========================================================================
 * Seeding and per-level isolation
 * ===================================================================== */

/** Addresses shown on level 1. Four are real accounts, four are not. */
function ar_l1_candidates(): array
{
    return [
        'guest@hackinlab.internal',
        'helpdesk@hackinlab.internal',
        'admin@hackinlab.internal',
        'm.torres@hackinlab.internal',
        'billing@hackinlab.internal',
        'webmaster@hackinlab.internal',
        'ops@hackinlab.internal',
        'sales@hackinlab.internal',
    ];
}

function ar_l1_existing(): array
{
    return [
        'guest@hackinlab.internal',
        'admin@hackinlab.internal',
        'billing@hackinlab.internal',
        'ops@hackinlab.internal',
    ];
}

/** Level 10: which of the usual administrator names is the real one? */
function ar_l10_candidates(): array
{
    return [
        'root@hackinlab.internal',
        'administrator@hackinlab.internal',
        'admin@hackinlab.internal',
        'sysadmin@hackinlab.internal',
        'it-support@hackinlab.internal',
    ];
}

function ar_purge_level(int $level): void
{
    $db = ar_db();
    foreach (['users', 'tokens', 'mail', 'sessions', 'probe_log', 'wins', 'level_state'] as $t) {
        $db->prepare("DELETE FROM $t WHERE level = ?")->execute([$level]);
    }
    // The collector is only used by level 3; it stores rows under level 3 or 0.
    if ($level === 3) {
        $db->exec('DELETE FROM collected');
    }
}

function ar_insert_user(int $level, string $email, string $plainPassword, string $name, int $isAdmin): int
{
    $db = ar_db();
    $db->prepare('INSERT INTO users(level, email, password_hash, display_name, is_admin) VALUES(?,?,?,?,?)')
       ->execute([$level, $email, password_hash($plainPassword, PASSWORD_DEFAULT), $name, $isAdmin]);
    return (int)$db->lastInsertId();
}

function ar_mail_insert(int $level, string $to, string $subject, string $body, ?string $link, ?int $when = null): int
{
    $db = ar_db();
    $db->prepare('INSERT INTO mail(level, to_email, subject, body, link, created_at) VALUES(?,?,?,?,?,?)')
       ->execute([$level, $to, $subject, $body, $link, $when ?? time()]);
    return (int)$db->lastInsertId();
}

/** Build one level's world from scratch. Called on first visit and on reset. */
function ar_seed_level(int $level): void
{
    $db  = ar_db();
    $now = time();

    $db->beginTransaction();
    try {
        ar_purge_level($level);

        // The administrator is always inserted first, so it holds the lowest
        // row id inside this level. Level 9 depends on that ordering.
        $adminPassword = $level === 8 ? AR_L8_ADMIN_PASSWORD : bin2hex(random_bytes(16));
        $adminId = ar_insert_user($level, AR_ADMIN, $adminPassword, 'Site Administrator', 1);
        ar_insert_user($level, AR_GUEST, AR_GUEST_PASSWORD, 'Guest User', 0);

        if ($level === 1) {
            ar_insert_user($level, 'billing@hackinlab.internal', bin2hex(random_bytes(8)), 'Billing', 0);
            ar_insert_user($level, 'ops@hackinlab.internal', bin2hex(random_bytes(8)), 'Operations', 0);
        }

        ar_mail_insert(
            $level,
            AR_GUEST,
            'Welcome to the Hackin-Lab intranet',
            "Your guest account is ready.\n\nSign in with guest@hackinlab.internal / guest123.\n"
            . "Password recovery is available from the sign-in page.",
            null,
            $now - 86400 * 30
        );

        if ($level === 5) {
            ar_seed_level5_history($level, $adminId, $now);
        }

        $db->prepare('INSERT OR REPLACE INTO level_state(level, seeded_at) VALUES(?,?)')->execute([$level, $now]);
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $e;
    }
}

/**
 * Level 5's history: fourteen months ago the administrator forwarded their own
 * account-setup link to the contractor account so someone could finish the
 * onboarding. The link was used the same afternoon. Nothing invalidated it.
 */
function ar_seed_level5_history(int $level, int $adminId, int $now): void
{
    $db     = ar_db();
    $issued = $now - 431 * 86400;
    $token  = bin2hex(random_bytes(16));   // 128 bits: the token itself is fine

    $db->prepare('INSERT INTO tokens(level, token, email, user_id, kind, issued_at, expires_at, used_at)
                  VALUES(?,?,?,?,"reset",?,NULL,?)')
       ->execute([$level, $token, AR_ADMIN, $adminId, $issued, $issued + 640]);

    ar_mail_insert(
        $level,
        AR_GUEST,
        'Fwd: Finish setting up the administrator account',
        "From: Site Administrator <admin@hackinlab.internal>\n"
        . "Date: " . gmdate('D, d M Y H:i:s', $issued) . " +0000\n\n"
        . "Can you finish the onboarding for me? Here is the link the system sent:\n\n"
        . "  http://localhost/reset.php?token=$token\n\n"
        . "(Already used it myself, so it is probably dead by now.)",
        "http://localhost/reset.php?token=$token",
        $issued
    );
}

/** Seed on first touch; every page calls this before doing anything else. */
function ar_ensure_level(int $level): void
{
    $db  = ar_db();
    $row = $db->prepare('SELECT level FROM level_state WHERE level = ?');
    $row->execute([$level]);
    if (!$row->fetch()) {
        ar_seed_level($level);
    }
}

function ar_reset_level(int $level): void
{
    ar_seed_level($level);
}

/* =========================================================================
 * Accounts
 * ===================================================================== */

/** Exact, case-sensitive lookup. */
function ar_user_by_email(int $level, string $email): ?array
{
    $st = ar_db()->prepare('SELECT * FROM users WHERE level = ? AND email = ? ORDER BY id ASC LIMIT 1');
    $st->execute([$level, $email]);
    $row = $st->fetch();
    return $row ?: null;
}

/**
 * Case-insensitive lookup, lowest row id wins. Level 9 turns on the fact that
 * this rule and the uniqueness rule used by the address-change endpoint are
 * not the same rule.
 */
function ar_user_by_email_ci(int $level, string $email): ?array
{
    $st = ar_db()->prepare('SELECT * FROM users WHERE level = ? AND lower(email) = lower(?) ORDER BY id ASC LIMIT 1');
    $st->execute([$level, $email]);
    $row = $st->fetch();
    return $row ?: null;
}

function ar_user_by_id(int $level, int $id): ?array
{
    $st = ar_db()->prepare('SELECT * FROM users WHERE level = ? AND id = ?');
    $st->execute([$level, $id]);
    $row = $st->fetch();
    return $row ?: null;
}

function ar_admin(int $level): array
{
    $u = ar_user_by_email($level, AR_ADMIN);
    if ($u === null) {
        // Only reachable if the level was never seeded; seed and retry once.
        ar_ensure_level($level);
        $u = ar_user_by_email($level, AR_ADMIN);
    }
    return (array)$u;
}

function ar_set_password(int $level, int $userId, string $plain): void
{
    ar_db()->prepare('UPDATE users SET password_hash = ? WHERE level = ? AND id = ?')
           ->execute([password_hash($plain, PASSWORD_DEFAULT), $level, $userId]);
}

function ar_set_email(int $level, int $userId, string $email): void
{
    ar_db()->prepare('UPDATE users SET email = ? WHERE level = ? AND id = ?')->execute([$email, $level, $userId]);
}

/** Short, stable label for a password hash so state changes are visible. */
function ar_fingerprint(string $hash): string
{
    return substr(sha1($hash), 0, 12);
}

/* =========================================================================
 * Tokens
 * ===================================================================== */

function ar_token_insert(
    int $level,
    string $token,
    string $email,
    ?int $userId,
    string $kind = 'reset',
    ?string $otp = null,
    ?int $issuedAt = null,
    ?int $ttl = 900
): int {
    $issuedAt = $issuedAt ?? time();
    $expires  = $ttl === null ? null : $issuedAt + $ttl;
    $db = ar_db();
    $db->prepare('INSERT INTO tokens(level, token, email, user_id, kind, otp_code, issued_at, expires_at)
                  VALUES(?,?,?,?,?,?,?,?)')
       ->execute([$level, $token, $email, $userId, $kind, $otp, $issuedAt, $expires]);
    return (int)$db->lastInsertId();
}

function ar_token_find(int $level, string $token): ?array
{
    $st = ar_db()->prepare('SELECT * FROM tokens WHERE level = ? AND token = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$level, $token]);
    $row = $st->fetch();
    return $row ?: null;
}

function ar_token_latest(int $level, string $email, string $kind = 'reset'): ?array
{
    $st = ar_db()->prepare('SELECT * FROM tokens WHERE level = ? AND email = ? AND kind = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$level, $email, $kind]);
    $row = $st->fetch();
    return $row ?: null;
}

function ar_token_mark_used(int $id): void
{
    ar_db()->prepare('UPDATE tokens SET used_at = ? WHERE id = ?')->execute([time(), $id]);
}

function ar_token_bump_attempts(int $id, int $by): void
{
    ar_db()->prepare('UPDATE tokens SET attempts = attempts + ? WHERE id = ?')->execute([$by, $id]);
}

/* =========================================================================
 * Sessions
 * ===================================================================== */

function ar_session_get(int $level, string $sid): ?array
{
    $st = ar_db()->prepare('SELECT * FROM sessions WHERE level = ? AND sid = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$level, $sid]);
    $row = $st->fetch();
    return $row ?: null;
}

function ar_session_create(int $level, string $sid, ?string $email = null, int $auth = 0, string $note = ''): array
{
    ar_db()->prepare('INSERT INTO sessions(level, sid, email, authenticated, otp_verified, note, created_at)
                      VALUES(?,?,?,?,0,?,?)')
           ->execute([$level, $sid, $email, $auth, $note, time()]);
    return (array)ar_session_get($level, $sid);
}

function ar_session_touch(int $level, string $sid): array
{
    $row = ar_session_get($level, $sid);
    return $row ?? ar_session_create($level, $sid, null, 0, 'anonymous');
}

function ar_session_authenticate(int $level, string $sid, string $email, int $otpVerified = 0, string $note = ''): void
{
    ar_session_touch($level, $sid);
    ar_db()->prepare('UPDATE sessions SET email = ?, authenticated = 1, otp_verified = ?, note = ? WHERE level = ? AND sid = ?')
           ->execute([$email, $otpVerified, $note, $level, $sid]);
}

function ar_session_mark_verified(int $level, string $sid): void
{
    ar_db()->prepare('UPDATE sessions SET otp_verified = 1 WHERE level = ? AND sid = ?')->execute([$level, $sid]);
}

/* =========================================================================
 * Collector (level 3)
 * ===================================================================== */

function ar_collect(int $level, string $host, string $uri, string $query, ?string $token): int
{
    $db = ar_db();
    $db->prepare('INSERT INTO collected(level, host, uri, query, token, created_at) VALUES(?,?,?,?,?,?)')
       ->execute([$level, $host, $uri, $query, $token, time()]);
    return (int)$db->lastInsertId();
}

function ar_collected(int $limit = 25): array
{
    $st = ar_db()->prepare('SELECT * FROM collected ORDER BY id DESC LIMIT ?');
    $st->bindValue(1, $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

/* =========================================================================
 * Probe log (level 1) and wins
 * ===================================================================== */

function ar_probe_log(int $level, string $email, float $ms): void
{
    ar_db()->prepare('INSERT INTO probe_log(level, email, elapsed_ms, created_at) VALUES(?,?,?,?)')
           ->execute([$level, $email, $ms, time()]);
}

function ar_probed_addresses(int $level): array
{
    $st = ar_db()->prepare('SELECT DISTINCT email FROM probe_log WHERE level = ?');
    $st->execute([$level]);
    return array_column($st->fetchAll(), 'email');
}

function ar_mark_win(int $level, string $detail): void
{
    ar_db()->prepare('INSERT OR REPLACE INTO wins(level, detail, won_at) VALUES(?,?,?)')
           ->execute([$level, $detail, time()]);
}

function ar_win(int $level): ?array
{
    $st = ar_db()->prepare('SELECT * FROM wins WHERE level = ?');
    $st->execute([$level]);
    $row = $st->fetch();
    return $row ?: null;
}
