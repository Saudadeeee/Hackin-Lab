<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = crypto_levels()[$L];
$key  = cl_key(5);
$iv   = cl_iv(5);

//  block 0                block 1
// "comment=hello!!!" + ";role=guest;id=1"   -> 32 bytes exactly
$plain  = 'comment=hello!!!' . ';role=guest;id=1';
$issued = cl_hex($iv . cl_aes_cbc_encrypt($plain, $key, $iv));

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $blob = cl_unhex($token);
    if (strlen($blob) < 32 || (strlen($blob) - 16) % 16 !== 0) {
        $result   = crypto_decision(false, 'Expected IV followed by whole 16-byte blocks.');
        $pipeline = [['label' => 'length check', 'value' => strlen($blob) . ' bytes', 'verdict' => 'block']];
    } else {
        $useIv  = substr($blob, 0, 16);
        $cipher = substr($blob, 16);
        $dec    = cl_aes_cbc_decrypt_raw($cipher, $key, $useIv);
        $unpad  = cl_pkcs7_unpad($dec);
        $claims = $unpad === null ? [] : crypto_parse_kv($unpad);
        $role   = $claims['role'] ?? '';

        $blocks = cl_blocks($unpad ?? $dec);

        $pipeline = [
            ['label' => 'IV', 'value' => cl_hex($useIv)],
            ['label' => 'ciphertext blocks', 'value' => implode(' | ', array_map('bin2hex', cl_blocks($cipher)))],
            ['label' => 'P[0] = D(C[0]) XOR IV', 'value' => $blocks[0] ?? '',
             'note'  => 'If you modified C[0], this block is now noise. The application treats it as a free-text
                         comment and never validates it - that is what makes the corruption survivable.'],
            ['label' => 'P[1] = D(C[1]) XOR C[0]', 'value' => $blocks[1] ?? '',
             'note'  => 'Byte <em>n</em> here moved by exactly the amount you XORed into byte <em>n</em> of C[0].'],
            ['label' => 'parsed session', 'value' => json_encode($claims)],
            ['label' => '$session["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
        ];

        if ($unpad === null) {
            $result = crypto_decision(false, 'Padding invalid after decryption.');
        } elseif ($role === 'admin') {
            $flag   = crypto_flag($L);
            $result = crypto_decision(true, 'Admin session established.');
        } else {
            $result = crypto_decision(true, 'Session read with role <code>' . lk_esc($role) . '</code>.');
        }
    }
}

$code = <<<'PHP'
// Session cookie: AES-128-CBC, IV prepended. No MAC.
$plain  = "comment={$comment};role={$role};id={$id}";
$cookie = bin2hex($iv . aes_128_cbc_encrypt($plain, $key, $iv));

// ── on the way back in ──
$iv      = substr($blob, 0, 16);
$plain   = pkcs7_unpad(aes_128_cbc_decrypt(substr($blob, 16), $key, $iv));
$session = parse_kv($plain);

if (($session['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
$cookie = $iv . aes_128_cbc_encrypt($plain, $key, $iv);    // confidentiality only
PHP;

$fixGood = <<<'PHP'
// Encrypt-then-MAC, or an AEAD that does it for you. Either way the server
// must reject a ciphertext it did not produce, BEFORE decrypting it.
$ct  = $iv . aes_128_cbc_encrypt($plain, $encKey, $iv);
$tag = hash_hmac('sha256', $ct, $macKey, true);
$cookie = base64_encode($ct . $tag);

// verify:
if (!hash_equals($expectedTag, $givenTag)) {
    return deny('tampered');        // no decryption attempted
}
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [2, 3],
    'annotation' => 'CBC decryption XORs the previous ciphertext block into the current plaintext block. An
        attacker who can change the previous ciphertext block therefore has direct, byte-for-byte control over the
        next plaintext block. Nothing here authenticates the ciphertext, so that control is unopposed.',

    'theory' => '<p>CBC decryption is <code>P[i] = D(C[i]) XOR C[i-1]</code>. The <code>D(C[i])</code> term needs
        the key and is unpredictable to you. The <code>C[i-1]</code> term is a value you hold. XOR is linear, so any
        delta you introduce into <code>C[i-1]</code> appears unchanged in <code>P[i]</code>.</p>
        <p>The price is that <code>C[i-1]</code> itself decrypts to garbage, because <code>D</code> is not linear.
        So the attack is practical exactly when there is a block you are willing to destroy - a comment, a padding
        field, a display name - immediately before the block you want to edit.</p>
        <p>The general statement is bigger than CBC: <strong>encryption provides confidentiality, not
        integrity</strong>. Every unauthenticated mode is malleable in some way. CTR and other stream modes are
        worse, since a flipped ciphertext bit flips exactly the corresponding plaintext bit with no collateral
        damage at all.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Encrypt-then-MAC, and compare the tag with a constant-time function before touching the
            ciphertext. Verifying after decryption reintroduces the padding oracle you meet in the next level.',
    ],

    'scenario' => '<strong>Scenario:</strong> a session cookie of exactly two plaintext blocks, encrypted with
        CBC and no MAC. Block 0 is a comment the application never validates; block 1 carries the role.
        <br><strong>Goal:</strong> turn <code>;role=guest;id=1</code> into <code>;role=admin;id=1</code> without
        the key.',

    'model' => [
        'title' => 'The edit, byte by byte',
        'html'  => '<pre class="lk-sinkline">P[1] = D(C[1]) XOR C[0]
want:  P\'[1][n] = target[n]
have:  P[1][n]  = current[n]
so:    C\'[0][n] = C[0][n] XOR current[n] XOR target[n]</pre>
        <table class="lk-kv">
            <tr><td>block 1 now</td><td>;role=guest;id=1</td></tr>
            <tr><td>block 1 wanted</td><td>;role=admin;id=1</td></tr>
            <tr><td>positions differing</td><td>6, 7, 8, 9, 10 (0-indexed): <code>guest</code> &rarr; <code>admin</code></td></tr>
        </table>
        <p>The token is <code>IV || C[0] || C[1] || C[2]</code> in hex, so <code>C[0]</code> is hex characters
        32-63. Apply the XOR to those five byte positions and leave everything else untouched.</p>
        <p>The Workbench <em>CBC bit-flip calculator</em> takes the token, the block index, the current text and the
        target text, and returns the edited token. Do one by hand first - the arithmetic is three XORs and it is
        worth having done it once.</p>',
    ],

    'form'     => crypto_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You edited plaintext you could not read, in a ciphertext you could not decrypt.',
    'why'      => '<p>Trace step 3 shows block 0 as noise and step 4 shows block 1 saying exactly what you wanted.
        That asymmetry is the signature of a CBC bit-flip: one block destroyed, the next block edited with
        precision.</p>
        <p>The server had no way to notice. It decrypted a well-formed ciphertext, found valid padding, and parsed
        the result. Without a MAC there is no step at which "did I issue this?" is ever asked.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
