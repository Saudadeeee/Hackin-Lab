<?php
require_once __DIR__ . '/helpers.php';

$L    = 10;
$meta = jwt_levels()[$L];

/** Same unrotated key as levels 4 and 9. Signing is not the challenge here. */
function jwt_level10_secret(): string
{
    return 'letmein123';
}

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256'],
    ['sub' => 'guest', 'role' => 'user',
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_level10_secret()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $header   = jwt_header($token);
    $alg      = $header['alg'] ?? '';
    $verified = ($alg === 'HS256') && jwt_verify_hs256($token, jwt_level10_secret());
    $raw      = jwt_payload_raw($token);

    // ── Layer 1: the "token WAF" inspects the payload as TEXT. ─────────
    $wafHit  = preg_match('/"role"\s*:\s*"([^"]*)"/', $raw, $m) === 1;
    $wafSaw  = $wafHit ? $m[1] : '(no role claim found)';
    $wafDeny = $wafHit && strtolower($wafSaw) === 'admin';

    // ── Layer 2: the application parses the same bytes as JSON. ────────
    $claims  = json_decode($raw, true);
    $appRole = is_array($claims) ? (string)($claims['role'] ?? 'user') : 'user';

    $pipeline = [
        ['label' => 'signature check (HS256)', 'value' => $verified ? 'valid' : 'invalid',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => 'payload bytes handed to both readers', 'value' => $raw],
        ['label' => 'WAF: preg_match(\'/"role"\\s*:\\s*"([^"]*)"/\', $raw)',
         'value' => $wafSaw,
         'note'  => 'preg_match stops at the <strong>first</strong> match and never looks further. It also sees the
                     bytes exactly as written — no unescaping happens here.',
         'verdict' => $wafDeny ? 'block' : 'pass'],
        ['label' => 'app: json_decode($raw, true)["role"]',
         'value' => $appRole,
         'note'  => 'json_decode resolves <code>\\uXXXX</code> escapes and, for a repeated key, keeps the
                     <strong>last</strong> value it sees.',
         'verdict' => $appRole === 'admin' && !$wafDeny ? 'pass' : null],
    ];

    if (!$verified) {
        $result = jwt_decision(false, '', 'Signature invalid.');
    } elseif (!is_array($claims)) {
        $result = jwt_decision(false, '', 'Payload is not valid JSON.');
    } elseif ($wafDeny) {
        $result = jwt_decision(false, '', 'Blocked by token WAF: the payload text declares <code>role: admin</code>.');
    } elseif ($appRole === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, $appRole, 'Passed the WAF; the parsed role is not admin.');
    }
}

$code = <<<'PHP'
$raw = base64url_decode(explode('.', $token)[1]);   // payload, as TEXT

// ── Layer 1: token WAF. Cheap, runs before any JSON parsing. ──
if (preg_match('/"role"\s*:\s*"([^"]*)"/', $raw, $m)) {
    if (strtolower($m[1]) === 'admin') {
        return deny('forged admin token');
    }
}

// ── Layer 2: the application. Same bytes, different parser. ──
$claims = json_decode($raw, true);
if (($claims['role'] ?? 'user') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
if (preg_match('/"role"\s*:\s*"([^"]*)"/', $raw, $m)) { ... }
$claims = json_decode($raw, true);
PHP;

$fixGood = <<<'PHP'
// Parse ONCE, then inspect the parsed structure. Never police text that a
// different parser will interpret later.
$claims = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

// And reject the ambiguity itself: a payload whose re-encoding differs from
// its original bytes contained duplicates, escapes or padding that a second
// reader could interpret differently.
if (json_encode($claims, JSON_UNESCAPED_SLASHES) !== $raw) {
    throw new AuthError('ambiguous JSON payload');
}

if (($claims['role'] ?? 'user') === 'admin') {
    requireAdminAuthorisation($claims['sub']);   // authorise, do not pattern-match
}
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4, 5, 11, 12],
    'annotation' => 'Two parsers read the same bytes. A regex reads text and takes the first match; a JSON parser
        reads structure, resolves escapes, and — for a repeated key — keeps the last value. Any payload where those
        two answers differ walks straight through the filter.',

    'theory' => '<p>RFC 8259 says the behaviour of a JSON parser given duplicate object keys is
        <em>unpredictable</em>. Implementations picked differently: PHP, JavaScript and Python keep the last
        occurrence; some Go and Java decoders keep the first; a few raise an error. As long as a system contains two
        readers with different rules, that ambiguity becomes an exploitable gap.</p>
        <p>Escapes give you a second, independent lever. <code>"\\u0072ole"</code> and <code>"role"</code> are the
        same key to a JSON parser and completely different strings to a regex. Same for <code>\\/</code> versus
        <code>/</code>, and for surrogate pairs.</p>
        <p>The general lesson outranks the trick: <strong>a security check must operate on the same representation
        that the decision operates on</strong>. Filtering serialised text and then acting on a parsed object means
        you are defending a document nobody will actually use.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The re-encode comparison is a strong, general defence: it rejects duplicate keys, unusual escapes
            and whitespace tricks in one line, without needing to enumerate them.',
    ],

    'scenario' => '<strong>Scenario:</strong> after three incidents the team added a WAF layer that scans token
        payloads for forged admin roles before the application parses them. The signing key is still the one from
        level 4.
        <br><strong>Goal:</strong> get <code>role: admin</code> past the regex and into the application.',

    'model' => [
        'title' => 'Where the two readers disagree',
        'html'  => '<table class="lk-kv">
            <tr><td>duplicate key</td><td>regex: first occurrence &middot; json_decode: <strong>last</strong> occurrence</td></tr>
            <tr><td><code>\\u0072ole</code></td><td>regex: not the string <code>"role"</code> &middot; json_decode: the key <code>role</code></td></tr>
            <tr><td>whitespace / newlines</td><td>the regex allows some, but only where <code>\\s*</code> appears</td></tr>
            <tr><td>non-string value</td><td>the regex only matches a quoted value; <code>"role":["admin"]</code> is invisible to it</td></tr>
        </table>
        <p>Any one of these is enough. Try to predict the outcome before you send it, then check your prediction
        against the trace — the trace prints exactly what each reader saw.</p>
        <p>Build the payload in the Workbench\'s JSON editor: it transmits your raw text, so duplicate keys and
        escapes survive to the server. A pretty-printer that normalised the JSON would silently destroy the
        exploit.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The filter and the application read different documents.',
    'why'      => '<p>Compare trace steps 3 and 4: same bytes in, different values out. The WAF reported the value it
        found first (or found nothing at all, if you used an escape); the application reported what
        <code>json_decode</code> resolved. Because the deny decision was made on the first answer and the grant
        decision on the second, the filter never protected the thing it was guarding.</p>
        <p>This is the same failure mode as level 9 in a different disguise. There it was two <em>expressions</em>
        over one structure; here it is two <em>parsers</em> over one string. When you audit, look for the moment a
        value is read twice — that moment is where these bugs live.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level10.php',
        'items'  => [
            ['q' => 'Does the WAF fire on a plain admin claim?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'],
                 ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], 'letmein123'),
             'learn'   => 'Baseline. The trace prints the value the regex captured, which tells you the regex actually runs and what it matched on.'],
            ['q' => 'Does the WAF match a non-string value?',
             'payload' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOlsiYWRtaW4iXSwiZXhwIjo5OTk5OTk5OTk5fQ.'
                 . jwt_sign_hs256('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOlsiYWRtaW4iXSwiZXhwIjo5OTk5OTk5OTk5fQ', 'letmein123'),
             'learn'   => 'Payload is <code>"role":["admin"]</code>. The regex needs a quoted scalar, so it sees nothing — but the app then compares an array to a string and fails too. A near miss that shows the regex is the weaker reader.'],
            ['q' => 'Which duplicate does the JSON parser keep?',
             'payload' => (static function () {
                 $h = jwt_b64url_encode('{"typ":"JWT","alg":"HS256"}');
                 $p = jwt_b64url_encode('{"sub":"guest","role":"editor","role":"viewer","exp":9999999999}');
                 return $h . '.' . $p . '.' . jwt_sign_hs256($h . '.' . $p, 'letmein123');
             })(),
             'learn'   => 'Two harmless roles. The response tells you whether the app resolved <code>editor</code> (first) or <code>viewer</code> (last) — the single fact the whole exploit depends on.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
