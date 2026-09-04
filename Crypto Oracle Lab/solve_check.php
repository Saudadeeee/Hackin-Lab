<?php
/**
 * Self-test: runs the intended solution for every level against the live app.
 *
 *   docker compose exec web php /var/www/html/solve_check.php
 *
 * The long oracle-driven attacks (levels 4, 6, 8) are exercised in miniature -
 * enough queries to prove the oracle behaves as the level claims - and then the
 * recovered value is submitted. Running them to completion is the learner's job.
 */
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$base = 'http://localhost';
$pass = 0;
$fail = 0;

function post(string $url, array $fields): string
{
    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query($fields),
        'timeout' => 60,
        'ignore_errors' => true,
    ]]);
    return (string)@file_get_contents($url, false, $ctx);
}

function get(string $url): string
{
    $ctx = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => true]]);
    return trim((string)@file_get_contents($url, false, $ctx));
}

function check(int $level, string $body, string $extra = ''): void
{
    global $pass, $fail;
    $want = crypto_flag($level);
    if (strpos($body, $want) !== false) {
        $pass++;
        echo "  PASS  level $level  $want" . ($extra !== '' ? "  ($extra)" : '') . "\n";
    } else {
        $fail++;
        echo "  FAIL  level $level  (expected $want)" . ($extra !== '' ? "  ($extra)" : '') . "\n";
    }
}

echo "Crypto Oracle Lab self-test\n---------------------------\n";

/* 1 - hex is not encryption */
check(1, post("$base/level1.php", ['token' => cl_hex('user=guest;role=admin;id=41')]));

/* 2 - repeating-key XOR, key recovered from known plaintext */
$known  = 'user=guest;role=user;id=41';
$cipher = cl_xor_repeat($known, 'K3yStr3m');
$ks     = cl_xor($cipher, $known);                    // recovered keystream, 26 bytes
$want   = 'user=guest;role=admin;id=4';               // same length as the keystream we hold
$forged = '';
for ($i = 0; $i < strlen($want); $i++) {
    $forged .= chr(ord($want[$i]) ^ ord($ks[$i % 8]));
}
check(2, post("$base/level2.php", ['token' => cl_b64($forged)]), 'key recovered by XOR');

/* 3 - ECB cut and paste */
$k3 = cl_key(3);
$profile = static fn(string $e): string => 'email=' . str_replace(['&', '='], '', $e) . '&uid=41&role=user';
$adminBlock = substr(cl_aes_ecb_encrypt($profile(str_repeat('A', 10) . 'admin' . str_repeat("\x0b", 11)), $k3), 16, 16);
$victim     = cl_aes_ecb_encrypt($profile(str_repeat('B', 13)), $k3);
$crafted    = substr($victim, 0, 32) . $adminBlock;
check(3, post("$base/level3.php", ['token' => cl_hex($crafted)]), 'block spliced');

/* 4 - prove the ECB oracle, then submit the secret */
$pad   = str_repeat('A', 15);
$ref   = substr(cl_unhex(get("$base/oracle.php?level=4&prefix=" . bin2hex($pad))), 0, 16);
$byte0 = null;
foreach (range(32, 126) as $b) {
    if (substr(cl_unhex(get("$base/oracle.php?level=4&prefix=" . bin2hex($pad . chr($b)))), 0, 16) === $ref) {
        $byte0 = chr($b);
        break;
    }
}
$note = $byte0 === cl_secret_l4()[0] ? 'oracle recovers byte 0 correctly' : 'ORACLE MISMATCH';
check(4, post("$base/level4.php", ['answer' => cl_secret_l4()]), $note);

/* 5 - CBC bit flipping */
$k5   = cl_key(5);
$iv5  = cl_iv(5);
$blob = $iv5 . cl_aes_cbc_encrypt('comment=hello!!!' . ';role=guest;id=1', $k5, $iv5);
$cur  = ';role=guest;id=1';
$tgt  = ';role=admin;id=1';
for ($i = 0; $i < 16; $i++) {
    if ($cur[$i] !== $tgt[$i]) {
        $blob[16 + $i] = chr(ord($blob[16 + $i]) ^ ord($cur[$i]) ^ ord($tgt[$i]));
    }
}
check(5, post("$base/level5.php", ['token' => cl_hex($blob)]), 'C[0] edited');

/* 6 - prove the padding oracle distinguishes, then submit the plaintext */
$k6   = cl_key(6);
$iv6  = cl_iv(6);
$good = cl_hex($iv6 . cl_aes_cbc_encrypt(cl_secret_l6(), $k6, $iv6));
$bad  = $good;
// Corrupt a byte in the LAST ciphertext block, where the padding lives.
$bad[strlen($bad) - 6] = $bad[strlen($bad) - 6] === 'a' ? 'b' : 'a';
$r1 = get("$base/oracle.php?level=6&ct=$good");
$r2 = get("$base/oracle.php?level=6&ct=$bad");
$note = ($r1 === 'padding-ok') ? "oracle: intact=$r1 corrupted=$r2" : "ORACLE BROKEN ($r1/$r2)";
check(6, post("$base/level6.php", ['answer' => cl_secret_l6()]), $note);

/* 7 - SHA-1 length extension */
$data0 = 'user=guest&role=user&id=41';
$mac0  = sha1(cl_secret_l7() . $data0);
$slen  = strlen(cl_secret_l7());
$glue  = cl_sha1_padding($slen + strlen($data0));
$suf   = '&role=admin';
$newData = $data0 . $glue . $suf;
$newMac  = cl_sha1($suf, cl_sha1_state_from_digest($mac0), $slen + strlen($data0) + strlen($glue));
check(7, post("$base/level7.php", ['data' => $newData, 'mac' => $newMac]), "secret length $slen");

/* 8 - prove the timing channel, then submit the token */
$secret8 = cl_secret_l8();
$t0 = microtime(true);
get("$base/oracle.php?level=8&token=" . str_pad('', 16, '0'));
$msWrong = (microtime(true) - $t0) * 1000;
$t0 = microtime(true);
get("$base/oracle.php?level=8&token=" . substr($secret8, 0, 4) . '000000000000');
$msRight = (microtime(true) - $t0) * 1000;
$note = sprintf('0 bytes: %.0fms, 4 bytes: %.0fms', $msWrong, $msRight);
check(8, post("$base/level8.php", ['answer' => $secret8]), $note);

/* 9 - seed recovery */
$adminSeed  = cl_l9_admin_seed();
$adminToken = cl_l9_token_from_seed($adminSeed);
$prefix = substr($adminToken, 0, 6);
$found  = null;
for ($t = 1756900000; $t <= 1756900180; $t++) {
    if (str_starts_with(cl_l9_token_from_seed($t), $prefix)) {
        $found = $t;
        break;
    }
}
check(9, post("$base/level9.php", ['answer' => cl_l9_token_from_seed((int)$found)]), "seed $found found by search");

/* 10 - CTR nonce reuse */
$k10 = cl_key(10);
$n10 = cl_iv(10);
$myPlain  = 'user=guest;role=user;id=41;mfa=passed;theme=dark';
$myCipher = cl_aes_ctr($myPlain, $k10, $n10);
$ks10     = cl_xor($myCipher, $myPlain);
$newPlain = 'user=guest;role=admin;id=41';
check(10, post("$base/level10.php", ['token' => cl_hex(cl_xor($newPlain, $ks10))]), 'keystream reused');

echo "---------------------------\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
