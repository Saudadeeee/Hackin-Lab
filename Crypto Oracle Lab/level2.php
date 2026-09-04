<?php
require_once __DIR__ . '/helpers.php';

$L    = 2;
$meta = crypto_levels()[$L];

const L2_KEY = 'K3yStr3m';                       // 8 bytes, repeated over the message

$plain  = 'user=guest;role=user;id=41';
$issued = cl_b64(cl_xor_repeat($plain, L2_KEY));

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $raw     = cl_unb64($token);
    $decoded = cl_xor_repeat($raw, L2_KEY);
    $claims  = crypto_parse_kv($decoded);
    $role    = $claims['role'] ?? '';

    $pipeline = [
        ['label' => 'base64url_decode($token)', 'value' => cl_hex($raw),
         'note'  => 'Shown as hex, because the ciphertext bytes are not printable.'],
        ['label' => 'xor_repeat($cipher, $key)', 'value' => $decoded,
         'note'  => 'Encryption and decryption are the <em>same function</em>. That symmetry is what makes the
                     known-plaintext attack work in one step.'],
        ['label' => 'parse into key=value pairs', 'value' => json_encode($claims)],
        ['label' => '$claims["role"]', 'value' => (string)$role,
         'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if ($raw === '') {
        $result = crypto_decision(false, 'Token is not valid base64url.');
    } elseif ($role === 'admin') {
        $flag   = crypto_flag($L);
        $result = crypto_decision(true, 'Admin session established.');
    } else {
        $result = crypto_decision(true, 'Session read as role <code>' . lk_esc($role) . '</code>.');
    }
}

$code = <<<'PHP'
// "Proper encryption this time - the key never leaves the server."
define('SESSION_KEY', '********');       // 8 bytes

function xor_repeat(string $data, string $key): string {
    $out = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $out .= chr(ord($data[$i]) ^ ord($key[$i % strlen($key)]));
    }
    return $out;
}

function issue_session(string $user, string $role): string {
    return base64url(xor_repeat("user={$user};role={$role};id=41", SESSION_KEY));
}

function read_session(string $t): array {
    return parse_kv(xor_repeat(base64url_decode($t), SESSION_KEY));
}
PHP;

$fixBad = <<<'PHP'
$cipher = xor_repeat($plaintext, SESSION_KEY);     // key repeats every 8 bytes
PHP;

$fixGood = <<<'PHP'
// XOR is a valid cipher exactly once: with a key as long as the message,
// random, and never reused. That is a one-time pad, and key distribution
// makes it impractical for sessions.
//
// In practice, use an authenticated construction and let the library manage
// nonces:
$nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
$token  = base64_encode($nonce . $cipher);

// Modern stream ciphers (ChaCha20, AES-CTR) are XOR underneath. What makes
// them safe is that the keystream is generated fresh per nonce and never
// repeats - not that the XOR itself is doing any work.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4, 5, 6, 7, 8, 9],
    'annotation' => 'The keystream is eight bytes long and repeats. Any position where you know the plaintext hands
        you the key byte for that position - and here you know the plaintext of your own token completely.',

    'theory' => '<p>XOR has exactly one useful property and one fatal one. The useful one:
        <code>a ^ b ^ b == a</code>, so encryption and decryption are the same operation. The fatal one: if you know
        any two of <em>plaintext</em>, <em>ciphertext</em>, <em>key</em>, you get the third for free.</p>
        <p>With a repeating key, "knowing some plaintext" is enough to recover the whole key, because the key bytes
        you learn at positions 0..7 are the same bytes used at positions 8..15, 16..23, and so on. This is why
        repeating-key XOR falls to a known-plaintext attack instantly, and to statistical analysis even without
        known plaintext.</p>
        <p>Structured formats make this worse. Session strings, JSON, XML and protocol headers all start with bytes
        an attacker can predict, so "known plaintext" is usually free.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The lesson generalises past XOR: a keystream that repeats is a broken cipher, whatever generated
            it. Level 10 shows the same failure inside AES-CTR, which is otherwise a perfectly good construction.',
    ],

    'scenario' => '<strong>Scenario:</strong> the team replaced hex with "real encryption": a repeating-key XOR.
        The application shows you the plaintext of your own session, as a debugging convenience.
        <br><strong>Goal:</strong> forge a token that decrypts to <code>role=admin</code>.',

    'model' => [
        'title' => 'The arithmetic, once',
        'html'  => '<p>Your token is <code>C = P ^ K</code> where <code>P</code> is shown below and <code>K</code>
        repeats. Therefore:</p>
        <pre class="lk-sinkline">K = C ^ P            (recover the keystream)
C\' = P\' ^ K          (encrypt whatever you want)</pre>
        <p>Two XORs. No searching, no wordlist, no oracle queries.</p>
        <table class="lk-kv">
            <tr><td>your plaintext P</td><td>' . lk_esc($plain) . '</td></tr>
            <tr><td>your ciphertext C</td><td>' . cl_hex(cl_xor_repeat($plain, L2_KEY)) . '</td></tr>
        </table>
        <p>In the Workbench, <em>XOR two hex strings</em> gives you <code>K</code>; the repetition period tells you
        the key length. Then XOR your desired plaintext against the key and base64url the result.</p>',
    ],

    'form'     => crypto_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The key fell out of one subtraction.',
    'why'      => '<p>You never guessed the key - you computed it. Because XOR is its own inverse, one
        plaintext-ciphertext pair is not a hint about the key, it <em>is</em> the key for those positions.</p>
        <p>The repetition is what turned a partial leak into a total one. Eight known bytes covered the entire
        message, and would have covered a message of any length.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
