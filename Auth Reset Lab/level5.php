<?php
require_once __DIR__ . '/helpers.php';

$L = 5;
ar_handle_reset($L);
$meta = ar_levels()[$L];

$result   = '';
$pipeline = [];
$row      = null;
$owner    = null;

/* ── Optional: issue yourself a token so you can watch reuse work ────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send'])) {
    $target = trim((string)($_POST['target'] ?? AR_GUEST));
    $user   = ar_user_by_email($L, $target);
    if ($user === null) {
        $result .= ar_err('No account is registered for <code>' . lk_esc($target) . '</code>.');
    } else {
        $token = bin2hex(random_bytes(16));
        // Note the ttl: null. Nothing in this codebase ever sets an expiry.
        ar_token_insert($L, $token, $target, (int)$user['id'], 'reset', null, null, null);
        ar_send_reset_mail($L, $target, $token, ar_reset_link($token));
        $result .= ar_info('Reset instructions sent to <code>' . lk_esc($target) . '</code>.');
    }
}

/* ── The redemption handler ─────────────────────────────────────────────── */
$tokenIn = trim((string)($_POST['token'] ?? $_GET['token'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['redeem'])) {
    $new = (string)($_POST['new_password'] ?? '');

    // The entire validation. One row lookup, one null check.
    $row = $tokenIn === '' ? null : ar_token_find($L, $tokenIn);

    if ($row === null) {
        $result .= ar_err('Unknown token.');
    } elseif ($new === '') {
        $result .= ar_err('Choose a password to set.');
    } else {
        $owner = ar_user_by_id($L, (int)$row['user_id']);
        if ($owner === null) {
            $result .= ar_err('The token does not resolve to an account.');
        } else {
            ar_set_password($L, (int)$owner['id'], $new);
            ar_token_mark_used((int)$row['id']);   // written, and never read again

            $after = ar_user_by_id($L, (int)$owner['id']);
            $ok    = password_verify($new, (string)$after['password_hash']);

            if ($ok && strcasecmp((string)$owner['email'], AR_ADMIN) === 0) {
                ar_mark_win($L, 'redeemed a token first used ' . (int)round((time() - (int)$row['issued_at']) / 86400) . ' days ago');
                $result .= ar_ok('The administrator account now holds the password you chose, set with a token that '
                    . 'was issued and redeemed over a year ago.');
            } elseif ($ok) {
                $result .= ar_info('Password updated for <code>' . lk_esc((string)$owner['email'])
                    . '</code>. Redeem the same token again and it will work again.');
            } else {
                $result .= ar_err('The update did not take effect.');
            }
        }
    }
} elseif ($tokenIn !== '') {
    $row   = ar_token_find($L, $tokenIn);
    $owner = $row && $row['user_id'] !== null ? ar_user_by_id($L, (int)$row['user_id']) : null;
}

$flag = ar_win($L) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($tokenIn !== '') {
    $now = time();
    $pipeline[] = [
        'label'   => 'SELECT * FROM tokens WHERE level = ? AND token = ?',
        'value'   => $row ? 'row ' . (int)$row['id'] : 'no row',
        'note'    => 'The only condition in the query is the token value itself.',
        'verdict' => $row ? 'pass' : 'block',
    ];
    if ($row) {
        $age = (int)round(($now - (int)$row['issued_at']) / 86400);
        $pipeline[] = [
            'label' => 'issued_at',
            'value' => gmdate('Y-m-d H:i:s', (int)$row['issued_at']) . ' UTC  (' . $age . ' days ago)',
            'note'  => 'Read for display here. Never compared with anything.',
        ];
        $pipeline[] = [
            'label' => 'expires_at',
            'value' => $row['expires_at'] === null ? 'NULL' : gmdate('Y-m-d H:i:s', (int)$row['expires_at']) . ' UTC',
            'note'  => $row['expires_at'] === null
                ? 'The column exists. Nothing in this codebase ever writes it, and nothing reads it.'
                : 'Set on this row, but the handler does not look at it.',
        ];
        $pipeline[] = [
            'label' => 'used_at',
            'value' => $row['used_at'] === null ? 'NULL' : gmdate('Y-m-d H:i:s', (int)$row['used_at']) . ' UTC',
            'note'  => $row['used_at'] === null
                ? 'Not yet redeemed.'
                : 'Already redeemed once. The handler writes this column after a reset and never consults it before one.',
        ];
        $pipeline[] = [
            'label' => 'account resolved from tokens.user_id',
            'value' => $owner ? (string)$owner['email'] : 'unresolved',
            'note'  => 'The binding is correct on this level: the account comes from the token row, not from the request.',
            'verdict' => $owner ? 'pass' : 'block',
        ];
    }
}
if ($flag !== '') {
    $pipeline[] = [
        'label'   => 'password_verify($yourString, users.password_hash)',
        'value'   => 'true',
        'note'    => 'The administrator row holds the password you set.',
        'verdict' => 'pass',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Read your own mail</h4>
    <p class="lk-hintline">Your mailbox is not only today's messages. It is everything that was ever delivered to
       your account, including things other people forwarded to you.</p>
    <a class="btn btn-primary" href="mailbox.php?level=5">Open your mailbox &rarr;</a>
</div>

<div class="ar-step">
    <h4>2 &middot; Redeem a token</h4>
    <form method="post" action="level5.php">
        <input type="hidden" name="redeem" value="1">
        <div class="form-group">
            <label class="form-label">Token</label>
            <input type="text" name="token" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($tokenIn) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">New password</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Set password</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Optional: issue yourself a token and redeem it twice</h4>
    <form method="post" action="level5.php">
        <input type="hidden" name="send" value="1">
        <div class="form-group">
            <label class="form-label">Address to recover</label>
            <input type="text" name="target" class="form-control" autocomplete="off"
                   value="<?= lk_esc((string)($_POST['target'] ?? AR_GUEST)) ?>">
        </div>
        <button class="btn btn-outline" type="submit">Send reset instructions</button>
    </form>
</div>

<?= ar_admin_state_card($L) ?>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /reset
$row = db()->query(
    'SELECT * FROM tokens WHERE token = ?',   // the whole WHERE clause
    [$_POST['token']]
);

if ($row === null) {
    return deny('unknown token');
}

// Correct: the account comes from the token row.
$user = user_by_id($row->user_id);
$user->password_hash = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
$user->save();

// Bookkeeping for the support team. Written after every reset, read by nobody.
$row->used_at = time();
$row->save();

return 'Your password has been updated.';
PHP;

$fixBad = <<<'PHP'
$row = find_token($_POST['token']);
if ($row === null) { return deny('unknown token'); }
// ... reset happens ...
$row->used_at = time();     // written, never read
PHP;

$fixGood = <<<'PHP'
// Both conditions belong in the query, so there is no window between the
// check and the use and no code path that can skip one of them.
$row = db()->query(
    'SELECT * FROM tokens
      WHERE token_hash = ?
        AND used_at IS NULL
        AND expires_at > ?',
    [hash('sha256', $_POST['token']), time()]
);
if ($row === null) { return deny('invalid or expired token'); }

// Consume it in the same transaction as the password change, and make the
// consumption conditional so two concurrent requests cannot both succeed:
//
//   UPDATE tokens SET used_at = ? WHERE id = ? AND used_at IS NULL
//   if (affected_rows() !== 1) { rollback; return deny(...); }
//
// Then invalidate everything else the credential touched: other outstanding
// reset tokens for this account, and every existing session belonging to it.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [2, 3, 4, 5, 17, 18],
    'annotation' => 'The <code>used_at</code> and <code>expires_at</code> columns both exist, and
        <code>used_at</code> is even written after every successful reset. Neither appears in the query that
        decides whether a token is acceptable, so a reset token in this system is a permanent credential.',

    'theory' => '<p>Two separate controls bound the life of a reset token, and neither implies the other. Expiry
        limits how long a leaked value stays dangerous; single use limits how many times a value that has already
        done its job can do it again. A system with expiry but no consumption lets an attacker who sees a link in a
        proxy log replay it for the rest of the window. A system with consumption but no expiry keeps every token
        that was never clicked alive forever &mdash; and reset messages that nobody acts on are the majority of
        them.</p>
        <p>The reason this survives review is that the bookkeeping looks like enforcement. There is a
        <code>used_at</code> column, it is populated, and a reviewer skimming the schema concludes tokens are
        consumed. The check is not in the schema; it is in the <code>WHERE</code> clause, and that is the line to
        read.</p>
        <p>Reset links also travel further than their designers expect. They get forwarded to a colleague, pasted
        into a ticket, captured by a corporate mail scanner that prefetches every URL, stored in a browser history
        that syncs across devices, and logged by every proxy between the two. Assume the value will be readable by
        somebody else eventually, and make the window in which that matters as small as you can.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The conditional <code>UPDATE ... WHERE used_at IS NULL</code> matters as much as the
            <code>SELECT</code>. Checking in one statement and consuming in another leaves a window in which two
            simultaneous requests both pass the check &mdash; the same class of bug the Race Condition lab is about.',
    ],

    'scenario' => '<strong>Scenario:</strong> fourteen months ago the administrator forwarded their own
        account-setup link to the guest account so that someone else could finish the onboarding. It was used the
        same afternoon and forgotten.
        <br><strong>Goal:</strong> use it now.',

    'model' => [
        'title' => 'Which checks a token has to survive',
        'html'  => '<table class="lk-kv">
            <tr><td>does the row exist</td><td>the only check this handler performs</td></tr>
            <tr><td>has it been redeemed</td><td>column present, written after every reset, never read</td></tr>
            <tr><td>has it expired</td><td>column present, never written on this level, never read</td></tr>
            <tr><td>does it belong to the account being changed</td><td>correct here &mdash; the account comes from
                <code>tokens.user_id</code></td></tr>
        </table>
        <p>So the value you need is not one you have to guess: it is 128 bits of real entropy, and no amount of
        computation will produce it. It is one you have to <em>find</em>, in a place you are allowed to read.</p>
        <p>Before going after the administrator, prove the property on your own account: issue yourself a token,
        redeem it, then redeem the same string a second time. If the second attempt succeeds, you have established
        the behaviour with a control you own, and everything after that is application of a known fact.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Nothing expired, so nothing had to be broken.',
    'why'      => '<p>The token you redeemed was issued to the administrator over a year ago and marked used the
        same day. The trace shows both facts being read for display and neither being read for a decision: the
        query that decides acceptance contains one condition, and it is the token value.</p>
        <p>You did not defeat any entropy. The value was 128 bits from a proper random source, and it was sitting
        in a message you were entitled to open, because somebody forwarded it to you when it was still useful. The
        assumption that made forwarding safe &mdash; "it has been used, so it is dead" &mdash; was never
        implemented.</p>
        <p>When you review a flow like this, do not read the schema for the answer. Read the <code>WHERE</code>
        clause of the query that admits the credential, and ask which of the columns you can see in the schema are
        missing from it.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'GET',
        'action' => 'level5.php',
        'items'  => [
            ['q' => 'What does the handler say about a token that does not exist?',
             'payload' => '00000000000000000000000000000000',
             'learn'   => 'Loads the form with that value. It establishes what a rejection looks like, so you can tell "unknown" apart from "known but refused" — and on this level there is no second category.'],
            ['q' => 'Does a token that has already been redeemed look any different?',
             'payload' => 'redeem your own token, then paste it back in',
             'learn'   => 'Use step 3 to issue yourself a token, redeem it, then redeem the same string again. Two successes on the same value is the finding, and you got it without touching the target.'],
            ['q' => 'Does the age of a token change anything?',
             'payload' => 'compare the issued_at row in the trace',
             'learn'   => 'The trace prints the issue time and the age in days for whatever token you paste in. If a year-old token and a minute-old token behave identically, expiry is not implemented anywhere.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
