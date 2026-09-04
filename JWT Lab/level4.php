<?php
require_once __DIR__ . '/helpers.php';

$L    = 4;
$meta = jwt_levels()[$L];

/** The whole flaw: a memorable string where 256 bits of entropy belonged. */
function jwt_level4_secret(): string
{
    return 'letmein123';
}

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256'],
    ['sub' => 'guest', 'name' => 'Guest User', 'role' => 'user',
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_level4_secret()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $header = jwt_header($token);
    $alg    = $header['alg'] ?? '';

    // ── Correct verification. Pinned algorithm, constant-time compare. ──
    $verified = ($alg === 'HS256') && jwt_verify_hs256($token, jwt_level4_secret());
    $claims   = $verified ? jwt_claims_unverified($token) : null;
    $role     = $claims['role'] ?? '';
    $expOk    = $verified && (int)($claims['exp'] ?? 0) > time();

    $pipeline = [
        ['label' => 'alg pinned by server policy', 'value' => 'HS256 (expected) / ' . $alg . ' (received)',
         'note'  => 'No confusion available here — a mismatch is rejected outright.',
         'verdict' => $alg === 'HS256' ? null : 'block'],
        ['label' => 'hash_equals(HMAC-SHA256(input, $secret), $sig)',
         'value' => $verified ? 'signature valid' : 'signature INVALID',
         'note'  => 'Constant-time comparison, real key, correct order of operations. The code is not the bug.',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => 'exp in the future?', 'value' => $expOk ? 'yes' : 'no',
         'verdict' => $verified && !$expOk ? 'block' : null],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if (!$verified) {
        $result = jwt_decision(false, '', 'Signature does not match the server key.');
    } elseif (!$expOk) {
        $result = jwt_decision(false, '', 'Token expired.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Valid token, non-admin role.');
    }
}

$code = <<<'PHP'
// config/auth.php
define('JWT_SECRET', 'letmein123');     // TODO: move to env before launch

// middleware - this code is textbook correct
$header = jwt_header($token);
if (($header['alg'] ?? null) !== 'HS256') {
    return deny('unexpected alg');
}
if (!jwt_verify_hs256($token, JWT_SECRET)) {   // hash_equals inside
    return deny('bad signature');
}
$claims = jwt_claims_unverified($token);
if ((int)($claims['exp'] ?? 0) <= time()) {
    return deny('expired');
}
if (($claims['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
define('JWT_SECRET', 'letmein123');
PHP;

$fixGood = <<<'PHP'
// 256 bits from a CSPRNG, injected from the environment, rotated on a schedule.
$secret = base64_decode($_ENV['JWT_SECRET_B64'] ?? '');
if (strlen($secret) < 32) {
    throw new RuntimeException('JWT secret must be >= 256 bits');
}

// generated once, out of band:
//   php -r "echo base64_encode(random_bytes(32));"
//
// Better still: stop using a shared symmetric secret between services.
// With RS256/EdDSA only the issuer holds signing material; verifiers hold a
// public key, so a compromised verifier cannot mint tokens.
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [2],
    'annotation' => 'Every line of the verification is right. The key is a dictionary word, and HS256 lets an
        attacker test candidate keys <strong>offline</strong> — so the strength of this endpoint is exactly the
        strength of one password, with no rate limit in front of it.',

    'theory' => '<p>HS256 is <code>HMAC-SHA256(header + "." + payload, key)</code>. Given any single valid token,
        an attacker has a complete oracle: guess a key, recompute the MAC, compare. No network, no logs, no lockout,
        no 2FA. Commodity hardware runs this in the billions per second.</p>
        <p>So the security of a shared-secret JWT deployment is not "an attacker must break SHA-256". It is
        "an attacker must guess the secret", and that is a password-cracking problem — with all the usual
        wordlist, rules and mask attacks available.</p>
        <p>There is a second, quieter consequence of symmetric JWTs: <em>every service that can verify can also
        forge</em>. A read-only microservice that holds the HMAC key can mint an admin token. Asymmetric signing
        removes that entire class of blast radius.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Minimum bar: key length &ge; hash output size (32 bytes for HS256), from a CSPRNG, never a
            passphrase, never committed. RFC 8725 (JWT Best Current Practices) says this explicitly.',
    ],

    'scenario' => '<strong>Scenario:</strong> the verification code has been reviewed and hardened. Algorithm pinned,
        constant-time compare, expiry enforced. The team stored the secret in a config constant during development
        and shipped it.
        <br><strong>Goal:</strong> recover the key, then mint your own admin token.',

    'model' => [
        'title' => 'Why offline attacks change the maths',
        'html'  => '<table class="lk-kv">
            <tr><td>online login brute force</td><td>rate limited, logged, lockout after N tries — perhaps 10 guesses/second at best</td></tr>
            <tr><td>offline HS256 cracking</td><td>bounded only by your GPU. Billions of guesses/second, invisible to the target</td></tr>
        </table>
        <p>The Workbench has a small dictionary built in so you can watch it happen. Against a real target you would
        use <code>hashcat -m 16500 token.txt rockyou.txt</code>, or <code>jwt_tool</code>.</p>
        <p>Once you hold the key you are not bypassing a check any more — you <em>are</em> the issuer. Any claims,
        any expiry, any subject.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You did not defeat the verification — you became the party it trusts.',
    'why'      => '<p>The trace shows every check passing honestly: correct algorithm, valid MAC, unexpired.
        That is the point. Your token really is authentic, because you signed it with the real key.</p>
        <p>This is why "we validate our JWTs correctly" is not a complete answer during a review. The follow-up
        questions are: where does the key come from, how long is it, who else holds it, and how is it rotated?</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level4.php',
        'items'  => [
            ['q' => 'Confirm verification is real before spending time cracking.',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], 'wrong'),
             'learn'   => 'If this is rejected, levels 2 and 3 are ruled out and the key becomes the only target left. Rule things out before you attack.'],
            ['q' => 'Is alg:none still open here?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'none'], ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], ''),
             'learn'   => 'Cheap to test, and it tells you whether the algorithm is pinned by policy or merely by habit.'],
            ['q' => 'Does a valid signature with an expired exp still get in?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'admin', 'exp' => 1000000000], jwt_level4_secret()),
             'learn'   => 'Uses the real key, so it isolates claim validation from signature validation. Try it once you have cracked the key.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
