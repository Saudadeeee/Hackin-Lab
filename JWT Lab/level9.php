<?php
require_once __DIR__ . '/helpers.php';

$L    = 9;
$meta = jwt_levels()[$L];

/** Still the level-4 key: the team rotated nothing, they added a guard instead. */
function jwt_level9_secret(): string
{
    return 'letmein123';
}

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256'],
    ['sub' => 'guest', 'role' => 'user',
     'user' => ['id' => 41, 'name' => 'Guest User', 'role' => 'user'],
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_level9_secret()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($token !== '') {
    $header   = jwt_header($token);
    $alg      = $header['alg'] ?? '';
    $verified = ($alg === 'HS256') && jwt_verify_hs256($token, jwt_level9_secret());
    $claims   = $verified ? jwt_claims_unverified($token) : null;

    // ── Guard added after the key leak: "no forged admin tokens". ──────
    $guardRole   = is_array($claims) ? ($claims['role'] ?? 'user') : 'user';
    $guardBlocks = $guardRole === 'admin';

    // ── The application, written by a different team, months earlier. ──
    $appRole = is_array($claims)
        ? ($claims['user']['role'] ?? $claims['role'] ?? 'user')
        : 'user';

    $pipeline = [
        ['label' => 'signature check (HS256, server key)',
         'value' => $verified ? 'valid' : 'invalid',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => 'middleware: $claims["role"]',
         'value' => is_array($claims) ? (string)$guardRole : '(not reached)',
         'note'  => $guardBlocks
            ? 'Top-level role is <code>admin</code> — the guard rejects the request here.'
            : 'Top-level role is not admin, so the guard lets the request through untouched.',
         'verdict' => $guardBlocks ? 'block' : 'pass'],
        ['label' => 'application: $claims["user"]["role"] ?? $claims["role"]',
         'value' => is_array($claims) ? (string)$appRole : '(not reached)',
         'note'  => 'A different expression, over the same token, evaluated after the guard has already approved it.',
         'verdict' => $appRole === 'admin' && !$guardBlocks ? 'pass' : null],
    ];

    if (!$verified) {
        $result = jwt_decision(false, '', 'Signature invalid.');
    } elseif ($guardBlocks) {
        $result = jwt_decision(false, '', 'Blocked by admin-token guard: <code>role</code> claim is <code>admin</code>.');
    } elseif ($appRole === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$appRole, 'Passed the guard, but the application resolved a non-admin role.');
    }
}

$code = <<<'PHP'
// ── middleware/guard.php  (added last quarter, after a key leak) ──
// "Even if someone forges a token, they will not get admin."
$claims = verify_and_decode($token, JWT_SECRET);   // signature IS checked
if (($claims['role'] ?? 'user') === 'admin') {
    return deny('admin tokens are not accepted from the internet');
}

// ── app/Session.php  (written months earlier, still in use) ──
// Profile data was moved into a nested object during the v2 API migration;
// the flat claim is kept as a fallback for old tokens.
function session_role(array $claims): string {
    return $claims['user']['role'] ?? $claims['role'] ?? 'user';
}

if (session_role($claims) === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
// guard reads one shape
if (($claims['role'] ?? 'user') === 'admin') { deny(); }
// app reads another
$role = $claims['user']['role'] ?? $claims['role'] ?? 'user';
PHP;

$fixGood = <<<'PHP'
// One parse, one shape, one source of truth. Everything downstream receives
// a typed object, never the raw claims array.
final class Principal
{
    public function __construct(
        public readonly string $subject,
        public readonly string $role,
    ) {}

    public static function fromClaims(array $c): self
    {
        // Exactly one place decides where the role lives, and unknown
        // shapes are rejected rather than guessed at.
        if (!isset($c['sub'], $c['role']) || !is_string($c['role'])) {
            throw new AuthError('malformed claims');
        }
        return new self($c['sub'], $c['role']);
    }
}

$principal = Principal::fromClaims($claims);
if ($principal->role === 'admin') { grant_admin(); }
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4, 5, 12],
    'annotation' => 'Two components read the privilege out of the same token using two different expressions.
        The guard inspects <code>role</code>; the application prefers <code>user.role</code>. A token can satisfy
        one and subvert the other at the same time.',

    'theory' => '<p>This is a <strong>parser differential</strong> expressed in application code rather than in a
        library. It needs no encoding trick — just two readers that disagree about where a value lives.</p>
        <p>The pattern shows up whenever a guard is bolted on later: the new code is written against the shape the
        author has in mind <em>today</em>, while the old code still supports a legacy shape. The guard is not wrong
        about anything it checks; it is simply not checking the field that ends up mattering.</p>
        <p>You will meet the same shape outside JWTs — a WAF that inspects <code>Content-Type: application/json</code>
        bodies while the framework also accepts form encoding, a rate limiter keyed on <code>X-Forwarded-For</code>
        while the app logs <code>X-Real-IP</code>, an authorisation filter matching on a URL path that the router
        normalises differently. Whenever a check and a use are separated by a re-parse, ask whether they can
        disagree.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The structural fix is not "make the guard smarter". It is to collapse the two readings into one:
            parse the token once into a typed principal, and forbid every other component from touching the raw
            claims array.',
    ],

    'scenario' => '<strong>Scenario:</strong> after the level-4 key leak, the team added a guard that refuses any
        token claiming <code>role: admin</code>. They did not rotate the key. The application still resolves the
        session role from a nested v2 profile object.
        <br><strong>Goal:</strong> get through the guard <em>and</em> come out the other side as admin.',

    'model' => [
        'title' => 'Two expressions, one token',
        'html'  => '<table class="lk-kv">
            <tr><td>guard sees</td><td><code>$claims["role"]</code> — must not be <code>admin</code></td></tr>
            <tr><td>app sees</td><td><code>$claims["user"]["role"] ?? $claims["role"]</code> — grants admin</td></tr>
        </table>
        <p>The <code>??</code> chain is the crux: the nested value wins whenever it exists, and the guard never
        descends into <code>user</code>. So you need a payload where the two expressions evaluate differently.</p>
        <p>You already know the signing key — it is the one you cracked in level 4, unrotated. This level is not
        about defeating the signature; it is about what you choose to put inside a token you can legitimately sign.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'One token, two honest readers, two different answers.',
    'why'      => '<p>Trace steps 2 and 3 read the same payload and disagreed. The guard evaluated
        <code>$claims["role"]</code>, saw <code>user</code>, and approved. The application evaluated
        <code>$claims["user"]["role"]</code>, found <code>admin</code>, and granted.</p>
        <p>Nothing was bypassed in the usual sense — the guard did exactly what it was written to do. The defect is
        that "the role in this token" was never a single well-defined thing, so a check on one reading said nothing
        about the other.</p>
        <p>When you review authorisation code, trace the privilege value from the token to the decision and count
        how many times it is re-read. Every extra reading is a place the two can drift apart.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level9.php',
        'items'  => [
            ['q' => 'Is the signing key still the level-4 one?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'letmein123'),
             'learn'   => 'A token you signed yourself, with harmless claims. Acceptance proves the key was never rotated — worth confirming before building anything on top of it.'],
            ['q' => 'What exactly does the guard reject?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'],
                 ['sub' => 'guest', 'role' => 'admin', 'exp' => 9999999999], 'letmein123'),
             'learn'   => 'The obvious forgery. The rejection message names the claim the guard reads — which tells you which claim it does <em>not</em> read.'],
            ['q' => 'Does the app read anything other than the top-level role?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256'],
                 ['sub' => 'guest', 'role' => 'user', 'user' => ['id' => 41, 'role' => 'editor'], 'exp' => 9999999999], 'letmein123'),
             'learn'   => 'A harmless nested role. If the response reports <code>editor</code> rather than <code>user</code>, you have proven the two readers diverge — without yet asking for anything privileged.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
