<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 10;
$meta = crypto_levels()[$L];
$key  = cl_key(10);
$nonce = cl_iv(10);          // the same nonce for every session - the bug

$myPlain  = 'user=guest;role=user;id=41;mfa=passed;theme=dark';
$myCipher = cl_aes_ctr($myPlain, $key, $nonce);
$adminCipher = cl_aes_ctr(cl_secret_l10(), $key, $nonce);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $raw   = cl_unhex($token);
    $plain = cl_aes_ctr($raw, $key, $nonce);      // CTR: decrypt == encrypt
    $sess  = crypto_parse_kv($plain);
    $role  = $sess['role'] ?? '';

    $pipeline = [
        ['label' => 'submitted ciphertext', 'value' => cl_hex($raw)],
        ['label' => 'AES-128-CTR with the session nonce', 'value' => $plain,
         'note'  => 'CTR decryption is the same XOR as encryption. The server cannot tell a ciphertext it produced
                     from one you produced with the same keystream.'],
        ['label' => 'parsed session', 'value' => json_encode($sess)],
        ['label' => '$session["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if ($raw === '') {
        $result = crypto_decision(false, 'Token is not valid hex.');
    } elseif ($role === 'admin') {
        $flag   = crypto_flag($L);
        $result = crypto_decision(true, 'Admin session established.');
    } else {
        $result = crypto_decision(true, 'Session read with role <code>' . lk_esc($role) . '</code>.');
    }
}

$code = <<<'PHP'
// Session encryption. CTR mode, and the nonce is a per-deployment constant
// "so that sessions survive a restart".
define('SESSION_NONCE', '****************');     // 16 bytes, never changes

function seal(string $session): string {
    return bin2hex(openssl_encrypt(
        $session, 'aes-128-ctr', KEY, OPENSSL_RAW_DATA, SESSION_NONCE
    ));
}

function open(string $hex): array {
    return parse_kv(openssl_decrypt(
        hex2bin($hex), 'aes-128-ctr', KEY, OPENSSL_RAW_DATA, SESSION_NONCE
    ));
}
PHP;

$fixBad = <<<'PHP'
define('SESSION_NONCE', '****************');     // constant across sessions
return openssl_encrypt($session, 'aes-128-ctr', KEY, OPENSSL_RAW_DATA, SESSION_NONCE);
PHP;

$fixGood = <<<'PHP'
// A nonce is a NUMBER USED ONCE. Generate one per message and ship it
// alongside the ciphertext - it is not secret, only unique.
$nonce  = random_bytes(16);
$cipher = openssl_encrypt($session, 'aes-128-ctr', $key, OPENSSL_RAW_DATA, $nonce);
$token  = bin2hex($nonce . $cipher);

// And authenticate, so a forged ciphertext is rejected even if the keystream
// were somehow known:
$nonce  = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
$token  = base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
    $session, 'session-v1', $nonce, $key
));
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 6, 7],
    'annotation' => 'CTR turns AES into a stream cipher: the keystream is a function of the key and the nonce
        alone. A fixed nonce means every session is XORed against the <em>same</em> keystream, so one known
        plaintext exposes all of them.',

    'theory' => '<p>Stream ciphers encrypt as <code>C = P XOR KS(key, nonce)</code>. Two messages under the same
        nonce give <code>C1 XOR C2 = P1 XOR P2</code>: the key cancels, and what remains is a relationship between
        two plaintexts that classical cryptanalysis handles easily even when neither is known.</p>
        <p>When one plaintext <em>is</em> known, it is worse than a leak. <code>KS = C1 XOR P1</code> recovers the
        keystream itself, and from there you can decrypt every other message under that nonce and
        <strong>encrypt</strong> anything you like. Confidentiality and forgery resistance fail together.</p>
        <p>Recognising this in the wild: look for an IV or nonce that is a constant, derived from the user id, or
        reset when a process restarts. It has sunk WEP, it is the reason AES-GCM must never repeat a nonce (there
        it also leaks the authentication key), and it is a standard finding wherever "the IV is stored in the
        config".</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Nonces are public but must be unique. Generate randomly (96+ bits) or use a strict counter that
            can never repeat across restarts, and prepend it to the ciphertext.',
    ],

    'scenario' => '<strong>Scenario:</strong> sessions are encrypted with AES-128-CTR under a fixed nonce. You hold
        your own token and know its plaintext, and you have captured the administrator\'s token from a log.
        <br><strong>Goal:</strong> present a token that decrypts to <code>role=admin</code>.',

    'model' => [
        'title' => 'Two XORs, again',
        'html'  => '<pre class="lk-sinkline">KS  = C_you XOR P_you        (recover the keystream)
P_admin = C_admin XOR KS     (read the admin session, optional)
C_new   = P_new  XOR KS      (forge your own)</pre>
        <table class="lk-kv">
            <tr><td>your plaintext</td><td>' . lk_esc($myPlain) . '</td></tr>
            <tr><td>your ciphertext</td><td>' . cl_hex($myCipher) . '</td></tr>
            <tr><td>captured admin ciphertext</td><td>' . cl_hex($adminCipher) . '</td></tr>
        </table>
        <p>You can only forge as many bytes as you have keystream for - here
        <code>' . strlen($myPlain) . '</code> bytes, which is more than enough for a short session string. Use the
        Workbench <em>XOR two hex strings</em> tool twice, and submit the result as hex.</p>',
    ],

    'form'     => crypto_token_form(cl_hex($myCipher), $token, 'Forged token (hex)'),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'One reused nonce cost both confidentiality and integrity.',
    'why'      => '<p>The keystream depends on the key and the nonce, and both were identical for every session.
        Your own token, whose plaintext you knew, was therefore a complete disclosure of that keystream - and a
        keystream is exactly what you need to encrypt.</p>
        <p>Note that the server behaved correctly at every step. AES was not weakened, the key never leaked, and
        the decryption produced a perfectly valid session. The only mistake was reusing a value whose entire job is
        to be different every time.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
