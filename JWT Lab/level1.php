<?php
require_once __DIR__ . '/helpers.php';

$L      = 1;
$meta   = jwt_levels()[$L];
$secret = jwt_strong_secret();

// The token the "app" stores in your browser. Note the extra claim the
// developer added, assuming nobody would look inside.
$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256'],
    [
        'sub'           => 'guest',
        'name'          => 'Guest User',
        'role'          => 'user',
        'internal_note' => 'promo-code-QX7T2',
        'iss'           => 'https://auth.hackinlab.internal',
        'iat'           => time(),
        'exp'           => time() + 3600,
    ],
    $secret
);

$answer   = trim((string)($_POST['answer'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];

if ($answer !== '') {
    if ($answer === 'promo-code-QX7T2') {
        $flag   = jwt_flag($L);
        $result = '<div class="message success">Correct. That claim never left the client, and it never had to.</div>';
    } else {
        $result = '<div class="message error">Not the value of <code>internal_note</code>.</div>';
    }
}

// Trace: show that decoding is three mechanical steps and zero cryptography.
$parts = jwt_split($issued);
$pipeline = [
    ['label' => 'the token as stored in your browser', 'value' => $issued],
    ['label' => 'split on "." -> segment 2 (payload)', 'value' => $parts[1],
     'note'  => 'Segments are <code>header</code>, <code>payload</code>, <code>signature</code>. The signature covers the first two; it does not hide them.'],
    ['label' => 'base64url_decode(segment 2)', 'value' => jwt_b64url_decode($parts[1]),
     'note'  => 'No key was used. No key <em>could</em> be used - this step is an encoding, not a cipher.',
     'verdict' => 'pass'],
];

$code = <<<'PHP'
// The login endpoint mints a token for the browser to keep.
$token = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256'],
    [
        'sub'           => 'guest',
        'name'          => 'Guest User',
        'role'          => 'user',
        // "the browser can't read this, it's inside the token"
        'internal_note' => 'promo-code-XXXXX',
        'exp'           => time() + 3600,
    ],
    $secret          // signing key: keeps the token from being MODIFIED
);

setcookie('session', $token);
PHP;

$fixBad = <<<'PHP'
$claims = ['sub' => $id, 'role' => $role, 'internal_note' => $note];
$token  = jwt_encode($header, $claims, $secret);
PHP;

$fixGood = <<<'PHP'
// A JWT is a signed, PUBLIC document. Put identity in it, never secrets.
$claims = ['sub' => $id, 'role' => $role];
$token  = jwt_encode($header, $claims, $secret);

// Anything confidential stays server-side, keyed by the subject:
$store->put("note:{$id}", $note);

// If the payload genuinely must be confidential, that is JWE
// (encrypted), not JWS (signed) - a different construction entirely.
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [9],
    'annotation' => 'The signature protects <strong>integrity</strong>, not <strong>confidentiality</strong>.
        Every claim in a JWS payload is readable by anyone holding the token — including the user it was issued to.',

    'theory' => '<p>Three signed segments, joined by dots. The first two are
        <code>base64url(JSON)</code>; the third is a MAC or signature over
        <code>header + "." + payload</code>.</p>
        <p>So the guarantee a JWT gives you is: <em>"these bytes have not been altered since the issuer produced them"</em>.
        It does not, and cannot, give you <em>"nobody else can read these bytes"</em>. Treat the payload as a
        billboard that happens to be tamper-evident.</p>
        <p>This distinction is why the rest of this lab exists: every later level is a different way that even the
        <em>integrity</em> half quietly stops holding.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Rule of thumb: if you would not print a value in the page HTML, it does not belong in a JWS payload.',
    ],

    'scenario' => '<strong>Scenario:</strong> a support portal issues you a session token at login.
        A developer tucked an internal field into the claims because "it stays inside the token".
        <br><strong>Goal:</strong> read that field and submit its value.',

    'model' => [
        'title' => 'What each segment is',
        'html'  => '<table class="lk-kv">
            <tr><td>segment 1</td><td>base64url(JSON) — header. Names the algorithm and, optionally, which key.</td></tr>
            <tr><td>segment 2</td><td>base64url(JSON) — payload. The claims. <strong>Public.</strong></td></tr>
            <tr><td>segment 3</td><td>base64url(bytes) — signature or MAC over <code>seg1 + "." + seg2</code>.</td></tr>
        </table>
        <p>base64url differs from base64 in three details: <code>+</code>→<code>-</code>, <code>/</code>→<code>_</code>,
        and the <code>=</code> padding is dropped. That is the entire difference.</p>',
    ],

    'form' => '<form method="post">
        <div class="form-group">
            <label class="form-label">Your session token</label>
            <textarea class="form-control jwt-ta" rows="3" readonly onclick="this.select()">' . lk_esc($issued) . '</textarea>
        </div>
        <div class="form-group">
            <label class="form-label">Value of the <code>internal_note</code> claim</label>
            <input type="text" name="answer" class="form-control" spellcheck="false" autocomplete="off"
                   value="' . lk_esc($answer) . '">
        </div>
        <div class="jwt-actions">
            <button class="btn btn-primary" type="submit">Submit answer</button>
            <a class="btn btn-outline" href="tools.php">Open JWT Workbench &rarr;</a>
        </div>
    </form>',

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You read a claim the developer believed was hidden.',
    'why'      => '<p>Nothing was bypassed, because nothing was protecting the payload in the first place.
        The only cryptography in a JWS is the signature, and a signature answers one question:
        <em>"did the issuer produce these exact bytes?"</em></p>
        <p>Carry this forward: for the rest of the lab, when you read a verification routine, ask
        <strong>"which question is this code actually answering, and which question does it think it is answering?"</strong>
        Every remaining level is a gap between those two.</p>',

    'pipeline' => $pipeline,
    'hints'    => jwt_hints($L),
]);
