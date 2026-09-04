<?php
require_once __DIR__ . '/helpers.php';

$L = 8;
ar_handle_reset($L);
$meta = ar_levels()[$L];

$result   = '';
$pipeline = [];
$json     = '';
$bearer   = trim((string)($_POST['bearer'] ?? ''));

/* ── POST /api/login ────────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim((string)($_POST['email'] ?? ''));
    $pass  = (string)($_POST['password'] ?? '');
    $user  = ar_user_by_email($L, $email);

    if ($user === null || !password_verify($pass, (string)$user['password_hash'])) {
        $json = json_encode(['status' => 'error', 'message' => 'invalid credentials'], JSON_PRETTY_PRINT);
        $result .= ar_err('Those credentials are not accepted.');
    } else {
        // The session is created here, before the second factor is anywhere
        // near the flow, and it is created authenticated.
        $apiSid = bin2hex(random_bytes(12));
        ar_session_create($L, $apiSid, (string)$user['email'], 1, 'created by /api/login');

        $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        ar_token_insert($L, bin2hex(random_bytes(8)), (string)$user['email'], (int)$user['id'], 'otp', $code, null, 600);
        ar_send_otp_mail($L, (string)$user['email'], $code);

        // ...and it is handed back in the response, next to the flag the front
        // end reads to decide which screen to draw.
        $json = json_encode([
            'status'   => 'otp_required',
            'verified' => false,
            'session'  => [
                'sid'           => $apiSid,
                'email'         => (string)$user['email'],
                'role'          => (int)$user['is_admin'] === 1 ? 'admin' : 'user',
                'authenticated' => true,
                'expires_in'    => 3600,
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $result .= ar_info('Password accepted. The interface is now showing you the code prompt, because '
            . '<code>verified</code> came back false.');
        $bearer = '';
    }
}

/* ── POST /api/verify-otp — the step you are meant to complete ──────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_otp'])) {
    $sess = $bearer === '' ? null : ar_session_get($L, $bearer);
    $code = trim((string)($_POST['code'] ?? ''));
    $row  = $sess ? ar_token_latest($L, (string)$sess['email'], 'otp') : null;

    if ($sess === null) {
        $result .= ar_err('Unknown session.');
    } elseif ($row !== null && hash_equals((string)$row['otp_code'], $code)) {
        ar_session_mark_verified($L, $bearer);
        $result .= ar_ok('Code accepted. <code>verified</code> is now true.');
    } else {
        $result .= ar_err('That code is not correct.');
    }
}

/* ── GET /api/console — the protected endpoint ──────────────────────────── */
$granted = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['console'])) {
    $sess = $bearer === '' ? null : ar_session_get($L, $bearer);

    // The only condition. Whether the second factor was completed is not part
    // of it, because that answer lives in the response the client already has.
    if ($sess === null || (int)$sess['authenticated'] !== 1) {
        $result .= ar_err('401 Unauthorized. No authenticated session for that bearer token.');
    } else {
        $granted = $sess;
        $isAdmin = strcasecmp((string)$sess['email'], AR_ADMIN) === 0;
        $skipped = (int)$sess['otp_verified'] === 0;

        $json = json_encode([
            'status'  => 'ok',
            'account' => (string)$sess['email'],
            'role'    => $isAdmin ? 'admin' : 'user',
            'panels'  => ['users', 'billing', 'audit-log', 'api-keys'],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($isAdmin && $skipped) {
            ar_mark_win($L, 'opened the administrator console with a session whose otp_verified flag is 0');
            $result .= ar_ok('200 OK. The administrator console answered for a session that never completed the '
                . 'second factor.');
        } elseif ($isAdmin) {
            $result .= ar_info('200 OK, and this session did complete the second factor. That is the intended '
                . 'path, not the finding.');
        } else {
            $result .= ar_info('200 OK for <code>' . lk_esc((string)$sess['email']) . '</code>.');
        }
    }
}

$flag = ar_win($L) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($json !== '' || $bearer !== '') {
    if (isset($apiSid)) {
        $pipeline[] = [
            'label' => 'POST /api/login  →  session row created',
            'value' => 'sid=' . $apiSid . ' authenticated=1 otp_verified=0',
            'note'  => 'The row is written before the code is generated, let alone checked. From the server\'s point '
                     . 'of view the sign-in is already complete.',
        ];
        $pipeline[] = [
            'label' => 'response body',
            'value' => '"verified": false, "session": { "sid": "' . $apiSid . '", ... }',
            'note'  => 'The flag and the credential travel together. One of them is advice; the other is access.',
        ];
    }
    if ($bearer !== '') {
        $sess = ar_session_get($L, $bearer);
        $pipeline[] = [
            'label'   => 'Authorization: Bearer <sid>',
            'value'   => $bearer,
            'note'    => $sess ? 'Resolves to ' . ar_session_summary($sess) : 'No session row with that id.',
            'verdict' => $sess ? 'pass' : 'block',
        ];
        if ($sess) {
            $pipeline[] = [
                'label'   => 'console check: $session->authenticated === true',
                'value'   => (int)$sess['authenticated'] === 1 ? 'true' : 'false',
                'note'    => 'The whole authorisation condition. <code>otp_verified</code> is '
                           . (int)$sess['otp_verified'] . ' and is not part of it.',
                'verdict' => (int)$sess['authenticated'] === 1 ? 'pass' : 'block',
            ];
        }
    }
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Sign in with the first factor</h4>
    <p class="lk-hintline">The administrator password for this level was committed to a public repository in a
       <code>.env.example</code> file: <code><?= lk_esc(AR_L8_ADMIN_PASSWORD) ?></code>. The password is not the
       puzzle here; what stands between you and the account is the second factor.</p>
    <form method="post" action="level8.php">
        <input type="hidden" name="login" value="1">
        <div class="form-group">
            <label class="form-label">Email</label>
            <input type="text" name="email" class="form-control" autocomplete="off"
                   value="<?= lk_esc((string)($_POST['email'] ?? AR_ADMIN)) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">Password</label>
            <input type="text" name="password" class="form-control" autocomplete="off"
                   value="<?= lk_esc((string)($_POST['password'] ?? AR_L8_ADMIN_PASSWORD)) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Sign in</button>
    </form>
</div>

<?php if ($json !== ''): ?>
<div class="lk-box"><h4><span class="lk-tag lk-tag-red">RAW RESPONSE</span>What the server actually sent</h4>
<div class="lk-body">
    <p class="lk-hintline">The interface renders one part of this. Your HTTP client receives all of it.</p>
    <pre class="ar-json"><?= lk_esc($json) ?></pre>
</div></div>
<?php endif; ?>

<div class="ar-step">
    <h4>2 &middot; The screen the interface draws when <code>verified</code> is false</h4>
    <form method="post" action="level8.php">
        <input type="hidden" name="verify_otp" value="1">
        <div class="form-group">
            <label class="form-label">Authorization: Bearer</label>
            <input type="text" name="bearer" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($bearer) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">Six digit code from the administrator's mailbox</label>
            <input type="text" name="code" class="form-control ar-mono" autocomplete="off" maxlength="6" value="">
        </div>
        <button class="btn btn-outline" type="submit">Verify code</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Call the protected endpoint directly</h4>
    <p class="lk-hintline"><code>GET /api/console</code> with the bearer token from step 1. No browser, no
       rendered screen, no <code>verified</code> flag anywhere in the request.</p>
    <form method="post" action="level8.php">
        <input type="hidden" name="console" value="1">
        <div class="form-group">
            <label class="form-label">Authorization: Bearer</label>
            <input type="text" name="bearer" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($bearer) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Open the administrator console</button>
    </form>
</div>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /api/login
if (!password_verify($_POST['password'], $user->password_hash)) {
    return json(['status' => 'error', 'message' => 'invalid credentials'], 401);
}

// The session exists and is authenticated from this line onwards.
$session = Session::create($user, authenticated: true);
send_otp($user);

return json([
    'status'   => 'otp_required',
    'verified' => false,          // the front end draws the code prompt
    'session'  => $session,       // ...and already holds the credential
]);

// GET /api/console
$session = Session::fromBearer($request->header('Authorization'));
if ($session === null || !$session->authenticated) {
    return json(['status' => 'error'], 401);
}
return json(['status' => 'ok', 'panels' => admin_panels()]);
PHP;

$fixBad = <<<'PHP'
$session = Session::create($user, authenticated: true);
return json(['verified' => false, 'session' => $session]);
// ...
if (!$session->authenticated) { return 401; }
PHP;

$fixGood = <<<'PHP'
// The password step does not produce a session. It produces a short-lived
// challenge that can do exactly one thing: carry a code back.
$challenge = OtpChallenge::create($user, ttl: 300);
send_otp($user);
return json(['status' => 'otp_required', 'challenge' => $challenge->id]);

// The session is issued here, and only here.
// POST /api/verify-otp
$challenge = OtpChallenge::find($_POST['challenge']);
if ($challenge === null || !$challenge->check($_POST['code'])) {
    return json(['status' => 'error'], 401);
}
$session = Session::create($challenge->user, authenticated: true);
return json(['status' => 'ok', 'session' => $session]);

// And the protected endpoint states the requirement itself, so that a session
// issued by some other path in future cannot quietly satisfy it:
//   if (!$session->authenticated || !$session->mfaSatisfied) { return 401; }
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [7, 12, 13, 19, 20],
    'annotation' => 'The session is created, marked authenticated, and returned to the caller by the endpoint that
        checks the <em>first</em> factor. The second factor changes a boolean in the response body that only the
        front end reads. Every server-side check downstream asks whether the session is authenticated, and it has
        been since before the code was sent.',

    'theory' => '<p>A second factor is a condition on <em>issuing a credential</em>. If the credential is already
        in the caller\'s hands when the condition is evaluated, the condition is a suggestion. The rendering layer
        is not an authorisation boundary: it decides what a cooperative client displays, and an attacker\'s client
        is not cooperative.</p>
        <p>The pattern usually arrives through refactoring. A single-page front end wants one round trip, so the
        login response is enriched with everything the client will need next. Somebody adds a
        <code>verified</code> field so the router knows which view to mount. Nothing in that change looks like a
        security decision, and the code review focuses on the view logic.</p>
        <p>The same shape appears without any second factor at all: an admin panel that returns the full record and
        lets the template hide the fields, a list endpoint that filters in the client, a feature flag that gates a
        button while the endpoint behind it stays open. The question to ask of any response is not "what does the
        interface show" but "what has the caller been given, and what can they do with it".</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The structural fix is that the password step returns a challenge, not a session. The defensive
            fix &mdash; making protected endpoints require <code>mfaSatisfied</code> as well &mdash; is worth
            adding on top, because it fails closed if a future code path issues a session somewhere else.',
    ],

    'scenario' => '<strong>Scenario:</strong> the administrator account has a second factor. Its password leaked
        in a committed <code>.env.example</code>, so the second factor is the only control left.
        <br><strong>Goal:</strong> reach the administrator console without ever supplying the code.',

    'model' => [
        'title' => 'Where the decision is made',
        'html'  => '<table class="lk-kv">
            <tr><td>what the interface does</td><td>reads <code>verified</code>, draws either the console or the
                code prompt</td></tr>
            <tr><td>what the server does</td><td>reads <code>session.authenticated</code>, answers or refuses</td></tr>
            <tr><td>when <code>authenticated</code> becomes true</td><td>inside <code>/api/login</code>, before the
                code is generated</td></tr>
            <tr><td>what <code>verified</code> controls on the server</td><td>nothing</td></tr>
        </table>
        <p>So the attack is not a bypass of the code check &mdash; there is nothing to bypass. It is noticing that
        the credential was already delivered, and then using it the way any non-browser client would.</p>
        <p>The habit worth building: after every authentication step, read the whole response body rather than the
        page. Anything in it that looks like an identifier, a token, a signed value or a URL is something you now
        hold, whatever the interface decided to do about it.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The code prompt was a screen, not a gate.',
    'why'      => '<p>The session in the trace has <code>authenticated=1</code> and <code>otp_verified=0</code>.
        It was written that way by <code>/api/login</code>, and the console endpoint asks only about the first of
        those two columns. You presented the identifier the login handed you, and the server had no reason to
        refuse.</p>
        <p>Note which part of the system was correct. The code was random, mailed to an address you cannot read,
        and compared in constant time. Every one of those properties is irrelevant when the credential the code was
        supposed to guard is issued before the code is checked.</p>
        <p>When you test a multi-factor flow, capture the response to the password step and look for anything
        session-shaped in it. If it is there, the second factor is guarding the screen, and you can say so with the
        response body as evidence.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'bearer',
        'method' => 'POST',
        'action' => 'level8.php',
        'items'  => [
            ['q' => 'Does the console refuse an identifier that names no session?',
             'payload' => 'not-a-real-session-id',
             'learn'   => 'Establishes that the endpoint really checks something. Without this control, a later success tells you nothing about which of your changes mattered.'],
            ['q' => 'Does the login response differ for a wrong password?',
             'payload' => '',
             'learn'   => 'Sign in with a wrong password and read the body. If no session object appears, the credential is genuinely tied to the first factor succeeding — which narrows the finding to what the first factor alone is allowed to unlock.'],
            ['q' => 'Is the code checked against the session or against the account?',
             'payload' => 'use one login response, then sign in again before verifying',
             'learn'   => 'Sign in twice and try the second code against the first bearer. How the two are related tells you whether the challenge is bound to a session at all — the answer here is that neither is bound to the other.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
