<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = jwt_levels()[$L];

$pub    = jwt_public_key();
$issued = jwt_issue_guest('RS256', jwt_private_key(), ['kid' => 'main-2024']);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $header = jwt_header($token);
    $alg    = $header['alg'] ?? '';

    // ── The vulnerable dispatch: one key variable, two algorithms. ──────
    $key      = $pub;                 // "the key for this issuer"
    $verified = false;
    if ($alg === 'RS256') {
        $verified = jwt_verify_rs256($token, $key);
    } elseif ($alg === 'HS256') {
        $verified = jwt_verify_hs256($token, $key);   // <-- public key as MAC key
    }

    $claims = $verified ? jwt_claims_unverified($token) : null;
    $role   = $claims['role'] ?? '';

    $pipeline = [
        ['label' => '$alg = $header["alg"]', 'value' => (string)$alg,
         'note'  => 'Attacker-controlled, again — but this time both branches are real cryptography, which is what makes it convincing.'],
        ['label' => '$key = load_issuer_key()  // one variable, both branches',
         'value' => 'RSA public key, ' . strlen($pub) . ' bytes of PEM',
         'note'  => 'For RS256 this is a <em>verification</em> key and publishing it is correct. For HS256 the same
                     bytes become a <em>signing</em> key — the asymmetry disappears.'],
        ['label' => $alg === 'HS256'
            ? 'jwt_verify_hs256($token, $key)   // HMAC keyed with the public key'
            : 'jwt_verify_rs256($token, $key)   // RSA verify',
         'value' => $verified ? 'verified = true' : 'verified = false',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if (!$verified) {
        $result = jwt_decision(false, '', 'Signature invalid for algorithm <code>' . lk_esc($alg) . '</code>.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Verified, but not an admin role.');
    }
}

$code = <<<'PHP'
// The issuer signs with RS256. Verifiers only ever need the public key,
// which is published at /jwks.php - that part is by the book.
$key = load_issuer_public_key();       // contents of keys/public.pem

$alg      = $header['alg'] ?? 'RS256';
$verified = false;

if ($alg === 'RS256') {
    $verified = jwt_verify_rs256($token, $key);
} elseif ($alg === 'HS256') {
    // "some legacy clients still use HMAC" - same key variable, though
    $verified = jwt_verify_hs256($token, $key);
}

if ($verified && ($claims['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
$key = load_issuer_public_key();
if ($alg === 'RS256') { $ok = verify_rs256($token, $key); }
elseif ($alg === 'HS256') { $ok = verify_hs256($token, $key); }
PHP;

$fixGood = <<<'PHP'
// Bind the key to its algorithm and its purpose. A key object that only
// knows how to do RSA verification cannot be handed to an HMAC routine.
$key = KeyStore::verificationKey('issuer-main');   // ['alg' => 'RS256', 'pem' => ...]

if (($header['alg'] ?? null) !== $key['alg']) {
    return deny('alg does not match the key this endpoint trusts');
}
$ok = jwt_verify_rs256($token, $key['pem']);
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 11, 12],
    'annotation' => 'The verifier keeps <em>one</em> key and lets the token choose which primitive consumes it.
        RSA verification with a public key is safe; HMAC verification with that same public key is a signing
        oracle, because the "public" key is material the attacker already has.',

    'theory' => '<p>Asymmetric signing splits one capability into two: the private key can <strong>produce</strong>
        signatures, the public key can only <strong>check</strong> them. That split is the entire reason RS256 is
        safer than HS256 in a multi-service architecture.</p>
        <p>HMAC has no such split. The same key that checks a MAC also produces one. So the instant a verifier is
        willing to run HMAC with the RSA public key as its secret, the split collapses — and the key was published
        on purpose, so every attacker already has it.</p>
        <p>The subtle part is that neither primitive is broken. RSA is fine. HMAC is fine. The flaw lives in the
        <em>dispatch</em>: a key is not just bytes, it is bytes plus an algorithm plus a role (sign or verify), and
        this code threw away everything except the bytes.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'This is why JWK objects carry <code>kty</code>, <code>alg</code> and <code>use</code>, and why
            good libraries reject a key whose declared algorithm does not match the operation. Keep keys as typed
            objects, never as loose strings.',
    ],

    'scenario' => '<strong>Scenario:</strong> the issuer moved to RS256 and publishes its public key at
        <a href="jwks.php">/jwks.php</a> (and as raw PEM at <a href="jwks.php?pem=1">/jwks.php?pem=1</a>).
        The verifier still accepts HMAC tokens for an old client.
        <br><strong>Goal:</strong> mint an admin token without the private key.',

    'model' => [
        'title' => 'The exact bytes matter',
        'html'  => '<p>Your HMAC secret must be the public key <strong>byte for byte</strong> as the server loads it:
        the <code>-----BEGIN PUBLIC KEY-----</code> line, the base64 body with its line breaks, the
        <code>-----END PUBLIC KEY-----</code> line, and the trailing newline. One missing <code>\\n</code> and the
        MAC differs completely.</p>
        <p>That is why the Workbench offers <em>HS256 — secret = server RSA public key PEM</em>: it reads the same
        file the server does. Against a real target you would fetch the PEM, or reconstruct it from the JWKS
        <code>n</code> and <code>e</code> values, and then try both DER and PEM encodings.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'A key published for verification was accepted for signing.',
    'why'      => '<p>You changed <code>alg</code> from RS256 to HS256. The dispatch took the second branch and
        called the HMAC verifier, passing it <code>$key</code> — still the RSA public key. Since you hold those exact
        bytes, you could compute the same HMAC the server was about to compute, so the comparison matched.</p>
        <p>Notice what did <em>not</em> happen: no RSA was broken, no private key was recovered. The attack lives
        entirely in the gap between "a key" and "a key <em>for a specific algorithm and purpose</em>".</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level5.php',
        'items'  => [
            ['q' => 'Is an HS256 header even accepted by an RS256 issuer?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'anything'),
             'learn'   => 'A rejection here still tells you something: it distinguishes "HMAC branch does not exist" from "HMAC branch exists but I have the wrong secret".'],
            ['q' => 'Is the secret perhaps the base64 body of the key rather than the whole PEM?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999],
                 trim(preg_replace('/-----[^-]+-----|\s+/', '', jwt_public_key()))),
             'learn'   => 'Real targets differ in how they load the key: PEM text, DER bytes, or the stripped base64. Enumerating the encodings is a short, finite list — not a fuzz.'],
            ['q' => 'And the full PEM, exactly as the server reads it?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], jwt_public_key()),
             'learn'   => 'This is the winning encoding for this server. Compare it with the previous probe to see how much a trailing newline matters.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
