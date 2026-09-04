<?php
require_once __DIR__ . '/helpers.php';

$L      = 3;
$meta   = jwt_levels()[$L];
$issued = jwt_issue_guest('HS256', jwt_strong_secret());

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    // ── The vulnerable "verification": there isn't one. ────────────────
    $claims = jwt_claims_unverified($token);
    $role   = $claims['role'] ?? '';

    $sigOk = jwt_verify_hs256($token, jwt_strong_secret());

    $pipeline = [
        ['label' => 'base64url_decode(payload)', 'value' => jwt_payload_raw($token)],
        ['label' => 'json_decode(...)', 'value' => $claims === null ? '(invalid JSON)' : json_encode($claims),
         'note'  => 'This is the entire "authentication" performed by the endpoint.'],
        ['label' => 'signature actually valid for the server key?',
         'value' => $sigOk ? 'yes' : 'no',
         'note'  => $sigOk
            ? 'It happens to be valid — but notice the code never asked.'
            : '<strong>Invalid — and it made no difference.</strong> Nothing in the request path consumed this answer.',
         'verdict' => $sigOk ? null : 'pass'],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if ($claims === null) {
        $result = jwt_decision(false, '', 'Payload is not valid JSON.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Token parsed, role is not admin.');
    }
}

$code = <<<'PHP'
// middleware/auth.php - "we already validated the token at login"
function current_user(string $token): array {
    // decode() to read the user out of the session token
    $claims = jwt_claims_unverified($token);   // json_decode(base64url(payload))
    return [
        'id'   => $claims['sub']  ?? 'anonymous',
        'role' => $claims['role'] ?? 'user',
    ];
}

$user = current_user($_POST['token']);
if ($user['role'] === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
// jsonwebtoken (node) - the two functions differ by one letter of intent
const user = jwt.decode(token);            // parses. verifies NOTHING.
if (user.role === 'admin') { grantAdmin(); }
PHP;

$fixGood = <<<'PHP'
// verify() throws unless the signature, alg, exp and nbf all check out
const user = jwt.verify(token, KEY, {
  algorithms: ['HS256'],
  issuer:     'https://auth.example.com',
  audience:   'api',
});
if (user.role === 'admin') { grantAdmin(); }
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),
    'lang'       => 'php',

    'code'       => $code,
    'vuln_lines' => [4, 5],
    'annotation' => 'There is no signature check anywhere in the request path. The third segment of the token is
        never read. <code>decode()</code> and <code>verify()</code> are one word apart in the source and a whole
        security boundary apart in meaning.',

    'theory' => '<p>Almost every JWT library exposes both a parsing function and a verifying function, and the
        parsing one is usually shorter to type: <code>jwt.decode</code> vs <code>jwt.verify</code>,
        <code>JWT::decode($t, $k, $algs)</code> vs a hand-rolled <code>base64_decode(explode(".", $t)[1])</code>.</p>
        <p>The bug is normally introduced honestly. Someone needs the user id for a log line, reaches for the quick
        decode, and later that same helper gets reused for an authorisation decision. The dangerous moment is not
        when the helper is written — it is when it is <em>promoted</em>.</p>
        <p>Auditing tip: grep for <code>decode</code> and check every call site for what the return value is used
        <em>for</em>, not just where it came from.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Name the helper after its guarantee. A function called <code>claims_unverified()</code> is hard
            to misuse in an <code>if ($user["role"] === "admin")</code>; a function called <code>current_user()</code>
            is almost designed to be.',
        'lang' => 'generic',
    ],

    'scenario' => '<strong>Scenario:</strong> the same admin endpoint, but this time the header says HS256 and the
        server does have the right key. It just never uses it.
        <br><strong>Goal:</strong> get <code>role: admin</code> accepted while leaving a signature that is provably wrong.',

    'model' => [
        'title' => 'How to tell the two apart from the outside',
        'html'  => '<p>You cannot read the source of a real target, so you distinguish these cases by experiment:</p>
        <table class="lk-kv">
            <tr><td>flip one byte of the signature</td><td>still accepted &rarr; nothing is verified (this level)</td></tr>
            <tr><td>set <code>alg: none</code>, empty signature</td><td>accepted &rarr; algorithm confusion (level 2)</td></tr>
            <tr><td>both rejected, payload edits rejected</td><td>verification works — go after the <em>key</em> instead</td></tr>
        </table>
        <p>Three requests, three distinct hypotheses, no wordlist involved. That is the difference between testing
        and fuzzing.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Accepted with a signature the server itself would have rejected — had it looked.',
    'why'      => '<p>Look at trace step 3. The lab computed the correct HMAC for you and compared it: the answer was
        <em>no</em>, your signature does not match the server key. And the endpoint returned 200 anyway, because that
        answer was never an input to any branch.</p>
        <p>This is the most common JWT finding in real assessments, and it is invisible to a scanner that only tries
        <code>alg:none</code> — the header here is a perfectly ordinary HS256.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level3.php',
        'items'  => [
            ['q' => 'Is the signature read at all? (unchanged payload, corrupted signature)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'not-the-key'),
             'learn'   => 'Same claims as your real token, wrong key. If this is accepted, verification is absent — and every later question about keys is moot.'],
            ['q' => 'Does the third segment need to be well-formed base64?',
             'payload' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ1c2VyIiwiZXhwIjo5OTk5OTk5OTk5fQ.!!!!not-base64!!!!',
             'learn'   => 'Narrows down whether the signature is parsed-then-ignored, or never touched at all.'],
            ['q' => 'Is <code>exp</code> enforced? (expired token, otherwise valid shape)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'user', 'exp' => 1000000000], 'x'),
             'learn'   => 'Claim validation usually lives in the same function as signature validation. If exp is ignored too, that is one more sign the verify path was skipped wholesale.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
