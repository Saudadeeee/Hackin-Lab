<?php
require_once __DIR__ . '/helpers.php';

$L    = 1;
$meta = crypto_levels()[$L];

$plain  = 'user=guest;role=user;id=41';
$issued = cl_hex($plain);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $decoded = cl_unhex($token);
    $claims  = crypto_parse_kv($decoded);
    $role    = $claims['role'] ?? '';

    $pipeline = [
        ['label' => 'token as submitted', 'value' => $token],
        ['label' => 'hex2bin($token)', 'value' => $decoded,
         'note'  => 'One function call, no key parameter. That absence is the whole finding.'],
        ['label' => 'parse into key=value pairs', 'value' => json_encode($claims)],
        ['label' => '$claims["role"]', 'value' => (string)$role,
         'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if ($decoded === '') {
        $result = crypto_decision(false, 'Token is not valid hex.');
    } elseif ($role === 'admin') {
        $flag   = crypto_flag($L);
        $result = crypto_decision(true, 'Admin session established.');
    } else {
        $result = crypto_decision(true, 'Session read as role <code>' . lk_esc($role) . '</code>.');
    }
}

$code = <<<'PHP'
// "The session data is encrypted so the client cannot tamper with it."
function issue_session(string $user, string $role): string {
    $data = "user={$user};role={$role};id=41";
    return bin2hex($data);          // <- there is no key anywhere in this file
}

function read_session(string $token): array {
    return parse_kv(hex2bin($token));
}

$s = read_session($_POST['token']);
if (($s['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
return bin2hex("user={$user};role={$role};id=41");
PHP;

$fixGood = <<<'PHP'
// Two separate needs, two separate mechanisms.
//
// (a) The client must not be able to forge the session -> authenticate it.
$data = "user={$user};role={$role};id=41";
$mac  = hash_hmac('sha256', $data, $macKey, true);
$token = base64_encode($data . $mac);          // integrity, not confidentiality

// (b) The client must not be able to READ it -> use authenticated encryption.
$nonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$token  = base64_encode($nonce . sodium_crypto_secretbox($data, $nonce, $key));

// (c) Or, most often the right answer: keep the session server-side and give
//     the client nothing but an opaque, random identifier.
$id = bin2hex(random_bytes(16));
$store->put($id, ['user' => $user, 'role' => $role]);
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4],
    'annotation' => 'The token is hexadecimal, and hexadecimal is an <em>encoding</em>: a reversible mapping with
        no key and no secret. The session data is therefore fully readable and fully writable by whoever holds the
        token.',

    'theory' => '<p>Three things get confused constantly because they all produce unreadable-looking strings:</p>
        <table class="lk-kv">
            <tr><td>encoding</td><td>hex, base64, URL-encoding. Reversible by anyone. Purpose: safe transport.</td></tr>
            <tr><td>hashing</td><td>SHA-256, bcrypt. One-way. Purpose: fingerprinting, password storage.</td></tr>
            <tr><td>encryption</td><td>AES, ChaCha20. Reversible <em>with a key</em>. Purpose: confidentiality.</td></tr>
        </table>
        <p>You can usually classify a token in seconds. Even length that is a multiple of 16 with high entropy
        suggests a block cipher. A trailing <code>=</code> suggests base64. Characters limited to
        <code>[0-9a-f]</code> suggest hex. Readable text after one decode step means there was no cipher at all.</p>
        <p>Do that classification first, every time. It decides which of the next nine levels you are even looking
        at.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Notice the fix asks a question first: do you need the client to be unable to <em>read</em> the
            data, or unable to <em>change</em> it? They are different requirements with different tools, and most
            "encrypted cookie" designs actually wanted the second one.',
    ],

    'scenario' => '<strong>Scenario:</strong> an application keeps the session in a client-side token which the
        team describes as encrypted.
        <br><strong>Goal:</strong> present a token that reads as <code>role=admin</code>.',

    'model' => [
        'title' => 'How to classify a token in three checks',
        'html'  => '<ol>
            <li><strong>Alphabet.</strong> Only <code>0-9a-f</code>? Hex. <code>A-Za-z0-9+/=</code>? base64.
                <code>-_</code> instead of <code>+/</code>? base64url.</li>
            <li><strong>Decode once.</strong> If the result is printable, you are done - it was an encoding.</li>
            <li><strong>Length.</strong> If the decoded bytes are a multiple of 16 and look random, suspect AES.
                A multiple of 16 <em>plus</em> 16 extra bytes often means an IV is prepended.</li>
        </ol>
        <p>Your token here is <code>' . strlen($issued) . '</code> hex characters, so
        <code>' . (strlen($issued) / 2) . '</code> bytes. Run check 2.</p>',
    ],

    'form'     => crypto_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'No key was broken, because no key was ever used.',
    'why'      => '<p>The trace shows a single transformation between your input and the parsed session:
        <code>hex2bin</code>. It takes no key, so it offers no protection - it only changes how bytes are written
        down.</p>
        <p>The rest of this lab uses real ciphers. Keep this level in mind as the baseline question: before asking
        <em>how</em> something is protected, confirm <em>that</em> it is.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
