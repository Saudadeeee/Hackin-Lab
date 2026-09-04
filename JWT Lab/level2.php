<?php
require_once __DIR__ . '/helpers.php';

$L      = 2;
$meta   = jwt_levels()[$L];
$secret = jwt_strong_secret();
$issued = jwt_issue_guest('HS256', $secret);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $parts  = jwt_split($token);
    $header = jwt_header($token);

    if (!$parts || !$header) {
        $result   = jwt_decision(false, '', 'Malformed token: expected three dot-separated segments with a JSON header.');
        $pipeline = [['label' => 'raw token', 'value' => $token, 'verdict' => 'block']];
    } else {
        // ── The vulnerable verification ────────────────────────────────
        $alg      = $header['alg'] ?? 'HS256';
        $verified = false;

        if ($alg === 'none') {
            $verified = true;                             // <-- the bug
        } elseif ($alg === 'HS256') {
            $verified = jwt_verify_hs256($token, $secret);
        }

        $claims = $verified ? jwt_claims_unverified($token) : null;
        $role   = $claims['role'] ?? '';

        $pipeline = [
            ['label' => 'base64url_decode(header)', 'value' => jwt_header_raw($token)],
            ['label' => '$alg = $header["alg"]', 'value' => (string)$alg,
             'note'  => 'The algorithm came from data the client supplied. The server has not yet made a single decision of its own.'],
            ['label' => $alg === 'none'
                ? 'branch taken: if ($alg === "none") $verified = true;'
                : 'branch taken: hash_equals(HMAC(input, $secret), $sig)',
             'value' => $verified ? 'verified = true' : 'verified = false',
             'note'  => $alg === 'none'
                ? 'No key was consulted, no MAC was computed. "Verification" here is a constant.'
                : 'A real MAC comparison ran against the server secret.',
             'verdict' => $verified ? 'pass' : 'block'],
            ['label' => 'claims read from the payload', 'value' => $verified ? jwt_payload_raw($token) : '(not reached)'],
            ['label' => '$claims["role"]', 'value' => (string)$role,
             'verdict' => $role === 'admin' ? 'pass' : null],
        ];

        if (!$verified) {
            $result = jwt_decision(false, '', 'Signature check failed for algorithm <code>' . lk_esc($alg) . '</code>.');
        } elseif ($role === 'admin') {
            $flag   = jwt_flag($L);
            $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
        } else {
            $result = jwt_decision(true, (string)$role, 'Token accepted, but this role has no admin rights.');
        }
    }
}

$code = <<<'PHP'
$header = jwt_header($token);          // attacker-controlled JSON
$alg    = $header['alg'] ?? 'HS256';   // attacker-controlled algorithm

$verified = false;
if ($alg === 'none') {
    // "unsecured JWT" per RFC 7519 section 6 - kept for legacy clients
    $verified = true;
} elseif ($alg === 'HS256') {
    $verified = jwt_verify_hs256($token, $secret);
}

if ($verified) {
    $claims = jwt_claims_unverified($token);
    if (($claims['role'] ?? '') === 'admin') {
        grant_admin();
    }
}
PHP;

$fixBad = <<<'PHP'
$alg = $header['alg'] ?? 'HS256';
if ($alg === 'none')  { $verified = true; }
elseif ($alg === 'HS256') { $verified = jwt_verify_hs256($token, $secret); }
PHP;

$fixGood = <<<'PHP'
// The SERVER decides the algorithm. The token gets no vote.
const EXPECTED_ALG = 'HS256';

if (($header['alg'] ?? null) !== EXPECTED_ALG) {
    throw new AuthError('unexpected alg');   // reject, do not "handle"
}
$verified = jwt_verify_hs256($token, $secret);
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [2, 5, 6, 7],
    'annotation' => 'The token names its own verification algorithm, and one of the accepted values means
        <em>"do not verify"</em>. An attacker who controls the header controls whether verification happens at all.',

    'theory' => '<p>JWS is not one algorithm, it is a registry. The header field <code>alg</code> selects an entry
        from that registry, and the registry contains <code>none</code> — defined for cases where integrity is
        provided by some outer layer (a signed envelope, a mutual-TLS channel).</p>
        <p>The design mistake is not that <code>none</code> exists. It is <strong>letting the untrusted token pick
        which entry to use</strong>. A verifier is supposed to encode a policy — "this endpoint accepts HS256 signed
        with key K" — and then check the token against that policy. Reading the policy out of the thing you are
        checking inverts the whole trust relationship.</p>
        <p>The same inversion, with a different destination, is what you will exploit in levels 5 through 8.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Every mature JWT library now requires an explicit allowlist at the call site
            (<code>jwt.verify(token, key, {algorithms: ["HS256"]})</code>). If your call does not name the algorithm,
            you are relying on a default that has been wrong before.',
    ],

    'scenario' => '<strong>Scenario:</strong> <code>/api/profile</code> accepts a bearer token and unlocks the admin
        console when the <code>role</code> claim is <code>admin</code>. The verifier still supports the old
        unsecured-JWT path for a legacy mobile client.
        <br><strong>Goal:</strong> reach the admin branch without knowing the signing key.',

    'model' => [
        'title' => 'What the verifier is being asked, vs what it answers',
        'html'  => '<table class="lk-kv">
            <tr><td>should ask</td><td>Was this token produced by the holder of key K, under algorithm A that I chose?</td></tr>
            <tr><td>actually asks</td><td>Does this token satisfy whatever algorithm it says it uses?</td></tr>
        </table>
        <p>An <code>alg: none</code> token is <code>header.payload.</code> — three segments still, but the third is
        the empty string. Keep the trailing dot: dropping it produces a two-segment string that the splitter rejects
        before your payload is ever read.</p>',
    ],

    'form'   => jwt_token_form($issued, $token),
    'result' => $result,
    'flag'   => $flag,
    'flag_msg' => 'The server accepted a token that carried no proof of anything.',
    'why' => '<p>Your header said <code>{"alg":"none"}</code>. The verifier read that value, took the first branch,
        and set <code>$verified = true</code> as a literal — no key lookup, no MAC, no comparison. From that point on
        the payload was treated as authenticated data, so <code>role: admin</code> was simply believed.</p>
        <p>Look again at the trace: step 3 shows a "verification" that never touched a key. That is the signature to
        look for when auditing real code — a verify path where the key variable is unused.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level2.php',
        'items'  => [
            ['q' => 'Does the server reject an unknown algorithm, or just fail closed silently?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS999'], ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], 'x'),
             'learn'   => 'Tells you whether <code>$alg</code> is matched against an allowlist or a chain of <code>if</code>s. An unknown alg that fails is normal; what matters is which values <em>succeed</em>.'],
            ['q' => 'Is HS256 verification actually implemented, or is it decorative?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'], ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], 'wrong-key'),
             'learn'   => 'A correctly-signed-looking token with the wrong key must fail. If this succeeds, the bug is level 3, not level 2.'],
            ['q' => 'What happens with a three-segment token whose signature is empty but alg is still HS256?',
             'payload' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.',
             'learn'   => 'Separates "empty signature is accepted" from "alg none is accepted" — two different bugs that look identical from the outside.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
