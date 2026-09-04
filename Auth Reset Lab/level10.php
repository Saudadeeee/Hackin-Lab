<?php
require_once __DIR__ . '/helpers.php';

$L = 10;
ar_handle_reset($L);
$meta = ar_levels()[$L];

$sid = ar_sid($L);
ar_session_touch($L, $sid);

$result   = '';
$pipeline = [];
$issue    = null;
$tried    = 0;
$matched  = null;

/* ── The recovery form ──────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send'])) {
    $target = trim((string)($_POST['target'] ?? ''));
    $user   = ar_user_by_email($L, $target);

    if ($user === null) {
        $issue   = ['ok' => false, 'email' => $target, 'now' => time()];
        $result .= ar_err('No account is registered for <code>' . lk_esc($target) . '</code>.');
    } else {
        $issuedAt = time();
        $token    = md5($target . $issuedAt);
        ar_token_insert($L, $token, $target, (int)$user['id'], 'reset', null, $issuedAt, 900);
        ar_send_reset_mail($L, $target, $token, ar_reset_link($token));

        $issue   = ['ok' => true, 'email' => $target, 'now' => time(), 'issued_at' => $issuedAt];
        $result .= ar_info('Reset instructions sent to <code>' . lk_esc($target) . '</code>. '
            . 'Server time: <strong>' . $issue['now'] . '</strong> ('
            . lk_esc(gmdate('Y-m-d H:i:s', (int)$issue['now'])) . ' UTC).');
    }
}

/* ── Redemption: correctly bound to the token row ───────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['redeem'])) {
    $raw   = (string)($_POST['candidates'] ?? '');
    $new   = (string)($_POST['new_password'] ?? '');
    $lines = array_slice(array_values(array_filter(
        array_map('trim', preg_split('~[\s,]+~', $raw) ?: []), 'strlen'
    )), 0, 500);

    if (!$lines) {
        $result .= ar_err('No token submitted.');
    } elseif ($new === '') {
        $result .= ar_err('Choose a password to set.');
    } else {
        foreach ($lines as $cand) {
            $tried++;
            $row = ar_token_find($L, $cand);
            if ($row === null || $row['used_at'] !== null) {
                continue;
            }
            if ($row['expires_at'] !== null && (int)$row['expires_at'] <= time()) {
                continue;
            }
            $matched = $row;
            break;
        }

        if ($matched === null) {
            $result .= ar_err('Tried ' . $tried . ' value(s); none of them is a live token.');
        } else {
            $owner = ar_user_by_id($L, (int)$matched['user_id']);
            ar_set_password($L, (int)$owner['id'], $new);
            ar_token_mark_used((int)$matched['id']);

            $after = ar_user_by_id($L, (int)$owner['id']);
            $ok    = password_verify($new, (string)$after['password_hash']);

            if ($ok && (int)$owner['is_admin'] === 1) {
                ar_mark_win($L, 'set the administrator password through a predicted recovery token');
                $result .= ar_ok('The administrator password is now the string you chose. Sign in with it below.');
            } elseif ($ok) {
                $result .= ar_info('Password updated for <code>' . lk_esc((string)$owner['email']) . '</code>.');
            } else {
                $result .= ar_err('The update did not take effect.');
            }
        }
    }
}

/* ── Sign in ────────────────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim((string)($_POST['email'] ?? ''));
    $pass  = (string)($_POST['password'] ?? '');
    $user  = ar_user_by_email($L, $email);

    if ($user === null || !password_verify($pass, (string)$user['password_hash'])) {
        $result .= ar_err('Those credentials are not accepted.');
    } else {
        // Written correctly: a fresh identifier at the privilege boundary.
        $sid = bin2hex(random_bytes(12));
        setcookie('ar_sid_l' . $L, $sid, time() + 86400, '/');
        $_COOKIE['ar_sid_l' . $L] = $sid;
        ar_session_create($L, $sid, (string)$user['email'], 1, 'signed in with a password');
        $result .= ar_ok('Signed in as <code>' . lk_esc((string)$user['email']) . '</code>.');
    }
}

$session   = ar_session_get($L, $sid);
$isAdmin   = $session !== null && (int)$session['authenticated'] === 1
          && strcasecmp((string)$session['email'], AR_ADMIN) === 0;
$ownedPw   = ar_win($L) !== null;
$flag      = ($isAdmin && $ownedPw) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($issue !== null) {
    $pipeline[] = [
        'label'   => 'recovery form response for ' . $issue['email'],
        'value'   => $issue['ok']
            ? 'Reset instructions sent to ' . $issue['email']
            : 'No account is registered for ' . $issue['email'],
        'note'    => 'Two different sentences. That is stage one of the chain, and it costs one request per '
                   . 'candidate address.',
        'verdict' => $issue['ok'] ? 'pass' : 'block',
    ];
    if ($issue['ok']) {
        $pipeline[] = [
            'label' => 'clock printed alongside the confirmation',
            'value' => (string)(int)$issue['now'],
            'note'  => 'One second of resolution. Whatever the generator does with this value, you are holding it.',
        ];
    }
}
if ($tried > 0) {
    $pipeline[] = [
        'label'   => 'candidate tokens tested',
        'value'   => $tried . ' value(s)',
        'note'    => 'Each is one indexed lookup. A miss and a hit cost the same.',
        'verdict' => $matched ? 'pass' : 'block',
    ];
}
if ($matched !== null) {
    $pipeline[] = [
        'label' => 'matched token row',
        'value' => 'issued_at=' . (int)$matched['issued_at'] . ' email=' . (string)$matched['email'],
        'note'  => 'A row the server wrote and never showed you.',
        'verdict' => 'pass',
    ];
}
$pipeline[] = [
    'label'   => 'administrator password hash set by you?',
    'value'   => $ownedPw ? 'yes' : 'no',
    'note'    => 'Recorded when a reset on this level changed the administrator row and the new hash verified '
               . 'against the string that was submitted.',
    'verdict' => $ownedPw ? 'pass' : 'block',
];
$pipeline[] = [
    'label'   => 'session you are presenting',
    'value'   => ar_session_summary($session),
    'note'    => 'The second half of the goal. A changed password is not an account takeover until something '
               . 'authenticates with it.',
    'verdict' => $isAdmin ? 'pass' : 'block',
];

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="lk-box"><h4><span class="lk-tag">SCOPE</span>Candidate addresses</h4><div class="lk-body">
    <p class="lk-hintline">The administrator address is one of these. Nothing on this page tells you which, and
       there is no directory to read.</p>
    <table class="ar-table">
        <?php foreach (ar_l10_candidates() as $c): ?>
        <tr><td class="ar-mono"><?= lk_esc($c) ?></td></tr>
        <?php endforeach; ?>
    </table>
</div></div>

<div class="ar-step">
    <h4>1 &middot; Recovery</h4>
    <form method="post" action="level10.php">
        <input type="hidden" name="send" value="1">
        <div class="form-group">
            <label class="form-label">Address</label>
            <input type="text" name="target" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc((string)($_POST['target'] ?? '')) ?>" placeholder="someone@hackinlab.internal">
        </div>
        <button class="btn btn-primary" type="submit">Send reset instructions</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Complete the reset</h4>
    <p class="lk-hintline">One value per line, up to 500. The account that changes is the one on the token row.</p>
    <form method="post" action="level10.php">
        <input type="hidden" name="redeem" value="1">
        <div class="form-group">
            <label class="form-label">Token</label>
            <textarea name="candidates" class="form-control ar-mono" rows="5" spellcheck="false"></textarea>
        </div>
        <div class="form-group">
            <label class="form-label">New password</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Set password</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Sign in</h4>
    <form method="post" action="level10.php">
        <input type="hidden" name="login" value="1">
        <div class="form-group">
            <label class="form-label">Email</label>
            <input type="text" name="email" class="form-control ar-mono" autocomplete="off"
                   value="<?= lk_esc((string)($_POST['email'] ?? '')) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">Password</label>
            <input type="text" name="password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Sign in</button>
    </form>
</div>

<div class="lk-box"><h4><span class="lk-tag">CONSOLE</span><?= $isAdmin ? 'Administrator console' : 'Not signed in' ?></h4>
<div class="lk-body">
    <table class="lk-kv">
        <tr><td>session</td><td class="ar-mono"><?= lk_esc(ar_session_summary($session)) ?></td></tr>
        <tr><td>administrator password owned</td><td><?= $ownedPw ? 'yes' : 'no' ?></td></tr>
        <tr><td>console</td><td><?= $isAdmin && $ownedPw ? 'open' : 'locked' ?></td></tr>
    </table>
</div></div>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /forgot-password
$user = user_by_email($_POST['email']);
if ($user === null) {
    return view('forgot', ['message' => "No account is registered for {$_POST['email']}."]);
}
$token = md5($_POST['email'] . time());
store_token($token, $user, expires: time() + 900);
send_reset_mail($user->email, reset_link($token));
return view('forgot', [
    'message'     => "Reset instructions sent to {$user->email}.",
    'server_time' => time(),
]);

// POST /reset  - this part is written correctly
$row = find_token($_POST['token']);
if ($row === null || $row->used_at || $row->expires_at <= time()) { return deny(); }
user_by_id($row->user_id)->setPassword($_POST['new_password']);
mark_token_used($row->id);

// POST /login  - and so is this
if (!password_verify($_POST['password'], $user->password_hash)) { return deny(); }
session_regenerate_id(true);
$_SESSION['email'] = $user->email;
PHP;

$fixBad = <<<'PHP'
if ($user === null) { return "No account is registered for $email."; }
$token = md5($email . time());
return ['message' => "Reset instructions sent to $email.", 'server_time' => time()];
PHP;

$fixGood = <<<'PHP'
// One sentence, whoever asked, and the same work either way.
ResetQueue::push($user?->id);
$token = bin2hex(random_bytes(32));      // and nothing derived from inputs
return ['message' => 'If that address is registered, we have sent instructions.'];

// Neither change is difficult. What made the takeover possible was that two
// small defects lined up: the form said which addresses exist, and the
// generator said what the token would be. Each one on its own is a low
// severity finding that gets deferred. Report the chain, not the parts.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 4, 5, 6, 12],
    'annotation' => 'Nothing on this page is new. The recovery form distinguishes real addresses from missing ones
        in its wording, and the token is derived from the address and the clock, both of which are printed back to
        you. The reset and the login are written correctly and do not need to be attacked.',

    'theory' => '<p>Individually, these two defects are the kind that get triaged as low severity and left for a
        later sprint. Enumeration "only" reveals which addresses exist. A predictable token "only" matters if you
        know when it was issued. Chained, they are an unauthenticated account takeover of the most privileged
        account in the system, and the whole sequence is four requests.</p>
        <p>That is the argument to make when a finding is disputed. Severity is a property of a path, not of a
        line of code. The path here is: learn the address, cause a token to be issued for it, derive the token,
        redeem it, sign in. Each step is cheap, each step is reliable, and none of them requires anything the
        application was not designed to do.</p>
        <p>It is also why the two halves of the goal are separate on this page. Changing a password is a denial of
        service against the owner; it becomes a takeover when something authenticates with it. Check both before
        you write the report, because "we rotated the password" is a very different remediation from "we have an
        intruder in the console".</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Either fix alone breaks the chain, which is worth saying explicitly in a report: the cheapest of
            the two, uniform wording, removes the first stage and leaves the attacker guessing addresses.',
    ],

    'scenario' => '<strong>Scenario:</strong> a different deployment of the same product, with its own accounts.
        You know there is an administrator and you know roughly what such an address looks like. Nothing else.
        <br><strong>Goal:</strong> identify the address, take the account, and be signed in as it. The console
        opens only when the administrator\'s stored hash verifies against a password you set <em>and</em> you are
        presenting a session that authenticated as that account.',

    'model' => [
        'title' => 'Plan the chain before running it',
        'html'  => '<table class="lk-kv">
            <tr><td>stage 1 &mdash; which address</td><td>5 candidates, 1 request each. The response wording
                separates them.</td></tr>
            <tr><td>stage 2 &mdash; get a token issued</td><td>1 request. Anyone may start a recovery for any
                address.</td></tr>
            <tr><td>stage 3 &mdash; derive it</td><td><code>md5(address . unix_seconds)</code>. The clock is in the
                response; cover a window of a few seconds.</td></tr>
            <tr><td>stage 4 &mdash; redeem</td><td>1 request. This endpoint is correct: the account comes from the
                token row, so the token has to be right.</td></tr>
            <tr><td>stage 5 &mdash; sign in</td><td>1 request with the password you set.</td></tr>
            <tr><td>total</td><td>about nine requests, no guessing beyond a five second window</td></tr>
        </table>
        <p>Confirm each stage before building on it. If stage 3 fails, the question is whether the address bytes
        going into the digest are exactly what you think &mdash; and the way to answer that is to run the same
        sequence against an address whose mailbox you can read.</p>
        <div class="output-box"><code>php -r \'$e="admin@hackinlab.internal"; for($t=$argv[1]-3;$t&lt;=$argv[1]+1;$t++) echo md5($e.$t),"\n";\' 1700000000</code></div>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Four requests, two low severity findings, one administrator account.',
    'why'      => '<p>The trace records the whole path: the response that told you which address exists, the clock
        that told you what the generator had been given, the token row you reconstructed, the hash that now
        verifies against your password, and the session that authenticated as the administrator. The flag needed
        the last two together.</p>
        <p>Neither weakness is exotic and neither would be hard to fix. Uniform wording on the recovery form is a
        one line change. <code>random_bytes(32)</code> instead of <code>md5(...)</code> is another. What made the
        chain possible was that both were deferred, separately, by people who each looked at one of them.</p>
        <p>Recovery flows deserve the same scrutiny as the login they can overrule, and usually get less, because
        they are written once and rarely touched. When you audit an application, read the recovery path first: it
        is the shortest route to every account in the system, and it is where the assumptions are.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'probe',
        'method' => 'GET',
        'action' => 'level10.php',
        'items'  => [
            ['q' => 'What does the recovery form say about an address that certainly does not exist?',
             'payload' => 'send step 1 with nobody@hackinlab.internal',
             'learn'   => 'The baseline. Once you know what a miss reads like, one request per candidate classifies the whole list.'],
            ['q' => 'Can you verify the token construction on an account you own?',
             'payload' => 'send step 1 with guest@hackinlab.internal',
             'learn'   => 'The guest account exists on this level too, and its mail is readable. Compare the token in your mailbox against your own computation before spending a request on the target.'],
            ['q' => 'Is the redemption endpoint as loose as the generator?',
             'payload' => 'submit a made-up token in step 2',
             'learn'   => 'It is not. The account comes from the token row and the row must be live, so the only way through stage 4 is a token that is genuinely correct.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
