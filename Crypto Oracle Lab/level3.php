<?php
require_once __DIR__ . '/helpers.php';

$L    = 3;
$meta = crypto_levels()[$L];
$key  = cl_key(3);

/** The profile the service encrypts. Metacharacters are stripped from the email. */
function l3_profile_for(string $email): string
{
    $email = str_replace(['&', '='], '', $email);
    return 'email=' . $email . '&uid=41&role=user';
}

$email  = (string)($_POST['email'] ?? 'guest@hackinlab.internal');
$issued = cl_hex(cl_aes_ecb_encrypt(l3_profile_for($email), $key));

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];
$oracle   = '';

if (isset($_POST['email'])) {
    $p = l3_profile_for($email);
    $oracle = '<div class="lk-box"><h4><span class="lk-tag">ORACLE</span>ECB(profile_for(email))</h4><div class="lk-body">'
        . '<table class="lk-kv">'
        . '<tr><td>plaintext</td><td>' . lk_visible($p) . '</td></tr>'
        . '<tr><td>length</td><td>' . strlen($p) . ' bytes &rarr; ' . (int)ceil((strlen($p) + 1) / 16) . ' blocks after padding</td></tr>'
        . '</table>'
        . cl_block_table(cl_aes_ecb_encrypt($p, $key))
        . '<div class="form-group" style="margin-top:0.6rem"><label class="form-label">ciphertext (hex)</label>'
        . '<textarea class="form-control cl-mono" rows="3" onclick="this.select()">' . $issued . '</textarea></div>'
        . '</div></div>';
}

if ($token !== '') {
    $raw = cl_unhex($token);
    if ($raw === '' || strlen($raw) % 16 !== 0) {
        $result   = crypto_decision(false, 'Ciphertext must be a whole number of 16-byte blocks.');
        $pipeline = [['label' => 'length check', 'value' => strlen($raw) . ' bytes', 'verdict' => 'block']];
    } else {
        $dec    = cl_aes_ecb_decrypt_raw($raw, $key);
        $unpad  = cl_pkcs7_unpad($dec);
        $claims = $unpad === null ? [] : crypto_parse_kv($unpad);
        $role   = $claims['role'] ?? '';

        $pipeline = [
            ['label' => 'submitted ciphertext, block by block', 'value' => implode(' | ', array_map('bin2hex', cl_blocks($raw)))],
            ['label' => 'AES-128-ECB decrypt (no chaining)', 'value' => $dec,
             'note'  => 'Every block decrypted on its own. Their order and origin were never checked.'],
            ['label' => 'PKCS#7 unpad', 'value' => $unpad ?? '(invalid padding)',
             'verdict' => $unpad === null ? 'block' : null],
            ['label' => 'parsed profile', 'value' => json_encode($claims)],
            ['label' => '$profile["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
        ];

        if ($unpad === null) {
            $result = crypto_decision(false, 'Padding is invalid after decryption.');
        } elseif ($role === 'admin') {
            $flag   = crypto_flag($L);
            $result = crypto_decision(true, 'Profile accepted with role <code>admin</code>.');
        } else {
            $result = crypto_decision(true, 'Profile read with role <code>' . lk_esc($role) . '</code>.');
        }
    }
}

$code = <<<'PHP'
// Profile cookie. The email is attacker-controlled; & and = are stripped so
// the attacker "cannot inject extra fields".
function profile_for(string $email): string {
    $email = str_replace(['&', '='], '', $email);
    return "email={$email}&uid=41&role=user";
}

$cookie = bin2hex(aes_128_ecb_encrypt(profile_for($email), $key));

// ── on the way back in ──
$profile = parse_kv(pkcs7_unpad(aes_128_ecb_decrypt($cookie, $key)));
if (($profile['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
$cookie = aes_128_ecb_encrypt(profile_for($email), $key);      // ECB, no MAC
PHP;

$fixGood = <<<'PHP'
// Authenticated encryption. Any rearrangement of the ciphertext fails the
// tag check before a single byte of plaintext is parsed.
$nonce  = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
$cookie = $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
    profile_for($email), $aad = 'profile-v1', $nonce, $key
);

// Decryption throws if the tag does not match, so cut-and-paste, block
// reordering and bit flipping all fail closed.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 4, 5, 8],
    'annotation' => 'ECB encrypts each 16-byte block independently and with no positional binding, so ciphertext
        blocks are portable between messages. Stripping <code>&amp;</code> and <code>=</code> from the email stops
        <em>plaintext</em> injection and does nothing about <em>ciphertext</em> assembly.',

    'theory' => '<p>A block cipher mode decides how blocks relate to each other. ECB decides that they do not
        relate at all: <code>C[i] = E(P[i])</code>. Two consequences follow immediately.</p>
        <p>First, identical plaintext blocks produce identical ciphertext blocks, which leaks structure - the famous
        ECB penguin. Second, and more useful to an attacker, ciphertext blocks are <strong>context-free</strong>.
        A block you obtained from one encryption decrypts to the same plaintext wherever you paste it.</p>
        <p>So the attack is not cryptanalysis; it is alignment arithmetic. You choose input lengths that push the
        interesting text onto a block boundary, harvest the block you want, and reassemble a ciphertext the server
        will happily decrypt. The key is never involved.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The general rule this level teaches: encryption without authentication protects nothing you
            care about. If the server acts on the decrypted plaintext, it needs to know the ciphertext is the one
            it issued.',
    ],

    'scenario' => '<strong>Scenario:</strong> a profile cookie encrypted with AES-128-ECB. You can request a cookie
        for any email address, and the service will decrypt any cookie you hand back.
        <br><strong>Goal:</strong> produce a cookie that decrypts to a profile with <code>role=admin</code>.',

    'model' => [
        'title' => 'Block arithmetic, written out',
        'html'  => '<p>The plaintext is <code>email=</code> (6 bytes) + your email + <code>&amp;uid=41&amp;role=</code>
        (13 bytes) + <code>user</code>. Block boundaries fall every 16 bytes:</p>
        <pre class="lk-sinkline">0               1               2
email=AAAAAAAAAA|AAA&amp;uid=41&amp;role=|user............</pre>
        <p>Two questions to answer with arithmetic, not guesswork:</p>
        <ol>
            <li><strong>How long must the email be for a block to contain exactly <code>admin</code> plus its
                padding?</strong> The prefix is 6 bytes, so 10 filler bytes fill block 0; block 1 then starts at
                your byte 11. Put <code>admin</code> there, followed by 11 bytes of <code>0x0b</code> - the exact
                PKCS#7 padding for a 5-byte final block.</li>
            <li><strong>How long must the email be so that <code>role=</code> ends exactly on a boundary?</strong>
                <code>6 + len + 13</code> must be a multiple of 16. <code>len = 13</code> gives 32, so the third
                block is exactly <code>user</code> + padding.</li>
        </ol>
        <p>Take block 1 from the first cookie, replace block 2 of the second, and submit. Use the block table above
        to confirm your boundaries before you splice - it prints each block so you can see the alignment you
        predicted.</p>',
    ],

    'form' => '<form method="post" style="margin-bottom:1rem">
            <div class="form-group">
                <label class="form-label">Request a profile cookie for this email</label>
                <input type="text" name="email" class="form-control cl-mono" spellcheck="false" value="' . lk_esc($email) . '">
            </div>
            <button class="btn btn-outline" type="submit">Encrypt profile</button>
        </form>
        <form method="post">
            <div class="form-group">
                <label class="form-label">Submit a cookie (hex)</label>
                <textarea name="token" class="form-control cl-mono" rows="3" spellcheck="false">' . lk_esc($token) . '</textarea>
            </div>
            <div class="cl-actions">
                <button class="btn btn-primary" type="submit">Present cookie</button>
                <a class="btn btn-outline" href="tools.php">Open Crypto Workbench &rarr;</a>
            </div>
        </form>',

    'result'   => $oracle . $result,
    'flag'     => $flag,
    'flag_msg' => 'You assembled a valid ciphertext out of parts, without ever holding the key.',
    'why'      => '<p>Every block you submitted was genuinely produced by the server\'s key, so every block
        decrypted cleanly. ECB never records which message a block came from or what position it held, so the
        decryptor had no basis on which to object.</p>
        <p>The filter on <code>&amp;</code> and <code>=</code> was working exactly as designed and was irrelevant:
        you never needed those characters in your input, because the server had already encrypted them for you in
        another block.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
