<?php
require_once __DIR__ . '/helpers.php';

$L    = 6;
$meta = jwt_levels()[$L];

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'main.key'],
    ['sub' => 'guest', 'name' => 'Guest User', 'role' => 'user',
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_strong_secret()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $header = jwt_header($token);
    $alg    = $header['alg'] ?? '';
    $kid    = (string)($header['kid'] ?? 'main.key');

    // ── The vulnerable key lookup: kid is a path fragment. ─────────────
    $path    = __DIR__ . '/keys/hs/' . $kid;
    $keyData = @file_get_contents($path);
    $exists  = $keyData !== false;
    $key     = $exists ? $keyData : '';

    $verified = ($alg === 'HS256') && $exists && jwt_verify_hs256($token, $key);
    $claims   = $verified ? jwt_claims_unverified($token) : null;
    $role     = $claims['role'] ?? '';

    $pipeline = [
        ['label' => '$kid = $header["kid"]', 'value' => $kid,
         'note'  => 'A key <em>identifier</em>, straight from the token. Nothing has validated its shape.'],
        ['label' => '$path = __DIR__ . "/keys/hs/" . $kid', 'value' => $path,
         'note'  => 'String concatenation into a filesystem path. <code>../</code> is meaningful to the OS and
                     meaningless to this code.'],
        ['label' => 'file_get_contents($path)',
         'value' => $exists
            ? ($key === '' ? '' : substr($key, 0, 64) . (strlen($key) > 64 ? '…' : ''))
            : '(false — no such file)',
         'note'  => $exists
            ? 'Read ' . strlen($key) . ' bytes. This is now the HMAC key.'
            : 'The read failed, so verification cannot proceed.',
         'verdict' => $exists ? null : 'block'],
        ['label' => 'jwt_verify_hs256($token, $key)',
         'value' => $verified ? 'verified = true' : 'verified = false',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if (!$exists) {
        $result = jwt_decision(false, '', 'Unknown key id <code>' . lk_esc($kid) . '</code>.');
    } elseif (!$verified) {
        $result = jwt_decision(false, '', 'Signature does not match the key selected by <code>' . lk_esc($kid) . '</code>.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Verified against ' . lk_esc($kid) . ', role is not admin.');
    }
}

$code = <<<'PHP'
// Key rotation: the token names which key signed it.
$kid = $header['kid'] ?? 'main.key';

// keys/hs/main.key        - current signing key
// keys/hs/legacy-2019.key - still accepted during migration
$key = file_get_contents(__DIR__ . '/keys/hs/' . $kid);

if ($key === false) {
    return deny('unknown kid');
}
if (!jwt_verify_hs256($token, $key)) {
    return deny('bad signature');
}
$claims = jwt_claims_unverified($token);
if (($claims['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
$key = file_get_contents(__DIR__ . '/keys/hs/' . $kid);
PHP;

$fixGood = <<<'PHP'
// A kid is a LOOKUP KEY, not a path, not a query, not a URL.
// Resolve it through a fixed map and reject anything not in it.
const KEYS = [
    'main.key'        => 'k1',
    'legacy-2019.key' => 'k2',
];

if (!isset(KEYS[$kid])) {
    return deny('unknown kid');          // no filesystem involved at all
}
$key = KeyStore::get(KEYS[$kid]);

// If keys really must live on disk, the safe shape is:
//   $file = realpath($dir . '/' . basename($kid));
//   if ($file === false || !str_starts_with($file, $dir . '/')) deny();
// but the allowlist above is simpler and cannot be argued with.
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6],
    'annotation' => 'The <code>kid</code> header is concatenated into a filesystem path. The attacker therefore
        chooses <em>which bytes on the host become the HMAC key</em> — and only needs to find a readable file whose
        contents are predictable.',

    'theory' => '<p>Header parameters like <code>kid</code>, <code>jku</code>, <code>x5u</code> and
        <code>x5c</code> exist to help a verifier <em>find</em> the right key. Every one of them is attacker-supplied,
        and every one of them ends up feeding some resolver: a file read, a database query, an HTTP fetch, a
        certificate parse.</p>
        <p>So the classic injection classes reappear in a place people rarely audit. This is path traversal, but the
        sink is not "read a secret file" — it is "choose the verification key". That changes what a useful target
        file looks like: you do not want a file with <em>interesting</em> contents, you want one with
        <strong>predictable</strong> contents.</p>
        <p>On Linux the reliable candidates are <code>/dev/null</code> (always empty) and, on some stacks, files the
        attacker can write through another bug — an uploaded avatar, a log line, a cache entry.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Note that <code>basename()</code> alone is a weaker fix than an allowlist: it stops traversal but
            still lets the attacker select any file in the key directory, which matters once that directory holds a
            revoked or test key.',
    ],

    'scenario' => '<strong>Scenario:</strong> the issuer supports key rotation. Tokens carry a <code>kid</code>
        naming the key file, and the verifier loads it from <code>keys/hs/</code>.
        <br><strong>Goal:</strong> get an admin token accepted without knowing either stored key.',

    'model' => [
        'title' => 'Turn the question around',
        'html'  => '<p>The instinctive move is "traverse to something juicy like <code>/etc/passwd</code>". That
        fails here, because you would then need to HMAC with the exact contents of <code>/etc/passwd</code> on
        <em>this</em> host — which you cannot see.</p>
        <p>The right question is: <strong>which readable file has contents I can reproduce exactly?</strong></p>
        <table class="lk-kv">
            <tr><td>/dev/null</td><td>empty string, on every Linux host. Perfectly predictable.</td></tr>
            <tr><td>/proc/sys/kernel/ostype</td><td><code>Linux\\n</code> — short and fixed, a decent second choice.</td></tr>
            <tr><td>a file you uploaded earlier</td><td>fully controlled, if the app has an upload feature.</td></tr>
        </table>
        <p>Careful with the path depth: the key directory is <code>&lt;app&gt;/keys/hs/</code>, so you need enough
        <code>../</code> segments to climb out of the document root before you reach <code>/</code>. Extra
        <code>../</code> at the root is harmless — the kernel ignores it.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You supplied the key identifier, so you supplied the key.',
    'why'      => '<p>Your <code>kid</code> traversed out of <code>keys/hs/</code> and landed on a file whose bytes
        you already knew. <code>file_get_contents()</code> returned those bytes, the verifier used them as the HMAC
        secret, and you had computed the same MAC with the same secret — so the comparison matched honestly.</p>
        <p>The verification code is not broken in any cryptographic sense. It faithfully checked a signature against
        the key it was told to use. Deciding <em>which</em> key to trust is the part that was never protected.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level6.php',
        'items'  => [
            ['q' => 'Does kid reach the filesystem at all? (nonexistent name vs valid name)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'does-not-exist'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'x'),
             'learn'   => 'An "unknown kid" error that differs from "bad signature" proves the lookup happens before verification, and that you can distinguish the two outcomes — an oracle.'],
            ['q' => 'Is traversal filtered? (climb one level to a directory)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => '../hs'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'x'),
             'learn'   => 'Reading a directory fails differently from reading a missing file on some stacks. Either way it confirms whether <code>../</code> survives to the OS.'],
            ['q' => 'Can I select the other stored key? (rotation is often the intended feature)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'legacy-2019.key'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'letmein123'),
             'learn'   => 'The migration key is the weak one from level 4. Worth remembering: an allowlist of key files is still dangerous if one of the allowed keys is bad.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
