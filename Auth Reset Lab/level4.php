<?php
require_once __DIR__ . '/helpers.php';

$L = 4;
ar_handle_reset($L);
$meta = ar_levels()[$L];

$result   = '';
$pipeline = [];

/* ── Step 1: a perfectly ordinary reset request ─────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send'])) {
    $target = trim((string)($_POST['target'] ?? AR_GUEST));
    $user   = ar_user_by_email($L, $target);

    if ($user === null) {
        $result .= ar_err('No account is registered for <code>' . lk_esc($target) . '</code>.');
    } else {
        $token = bin2hex(random_bytes(16));
        ar_token_insert($L, $token, $target, (int)$user['id'], 'reset', null, null, 900);
        ar_send_reset_mail($L, $target, $token, ar_reset_link($token));
        $result .= ar_info('Reset instructions sent to <code>' . lk_esc($target) . '</code>. '
            . ($target === AR_GUEST
                ? 'That is your own address, so the message is in <a href="mailbox.php?level=4">your mailbox</a>.'
                : 'That mailbox is not yours, so you will not see the token.'));
    }
}

/* ── Step 2: the reset handler ──────────────────────────────────────────── */
$tokenIn  = trim((string)($_POST['token'] ?? ''));
$emailIn  = trim((string)($_POST['email'] ?? $_GET['email'] ?? ''));
$row      = null;
$account  = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset'])) {
    $new = (string)($_POST['new_password'] ?? '');
    $row = $tokenIn === '' ? null : ar_token_find($L, $tokenIn);

    // The token is checked thoroughly - as a token.
    $valid = $row !== null
          && $row['used_at'] === null
          && ($row['expires_at'] === null || (int)$row['expires_at'] > time());

    if (!$valid) {
        $result .= ar_err($row === null
            ? 'No such token.'
            : 'That token has already been redeemed or has expired.');
    } elseif ($new === '') {
        $result .= ar_err('Choose a password to set.');
    } else {
        // ...and then the account to modify is read from the form, next to it.
        $account = ar_user_by_email($L, $emailIn);

        if ($account === null) {
            $result .= ar_err('No account is registered for <code>' . lk_esc($emailIn) . '</code>.');
        } else {
            ar_set_password($L, (int)$account['id'], $new);
            ar_token_mark_used((int)$row['id']);

            $after = ar_user_by_id($L, (int)$account['id']);
            $ok    = password_verify($new, (string)$after['password_hash']);

            if ($ok && strcasecmp((string)$account['email'], AR_ADMIN) === 0) {
                ar_mark_win($L, 'redeemed a token issued to ' . (string)$row['email'] . ' against ' . AR_ADMIN);
                $result .= ar_ok('Password changed for <code>' . lk_esc(AR_ADMIN)
                    . '</code> using a token that was issued to <code>' . lk_esc((string)$row['email']) . '</code>.');
            } elseif ($ok) {
                $result .= ar_info('Password changed for <code>' . lk_esc((string)$account['email']) . '</code>.');
            } else {
                $result .= ar_err('The update did not take effect.');
            }
        }
    }
}

$flag = ar_win($L) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($tokenIn !== '' || $emailIn !== '') {
    $pipeline[] = [
        'label'   => 'lookup: SELECT * FROM tokens WHERE token = ?',
        'value'   => $row ? 'row ' . (int)$row['id'] . ' found' : 'no row',
        'note'    => 'The token is validated properly: it must exist, must not have been redeemed, must not have expired.',
        'verdict' => $row ? 'pass' : 'block',
    ];
    if ($row) {
        $pipeline[] = [
            'label' => '$row["email"]  (the address the token was mailed to)',
            'value' => (string)$row['email'],
            'note'  => 'This column is what the token actually proves: somebody read the message sent to this address.',
        ];
        $pipeline[] = [
            'label' => '$_POST["email"]  (the account the handler will modify)',
            'value' => $emailIn,
            'note'  => strcasecmp((string)$row['email'], $emailIn) === 0
                ? 'Same as the token row on this attempt.'
                : 'Different from the token row. Nothing in the handler compares these two values.',
        ];
        $pipeline[] = [
            'label'   => 'user_by_email($_POST["email"])',
            'value'   => $account ? 'user ' . (int)$account['id'] . ' — ' . (string)$account['email'] : 'not found',
            'note'    => 'The account being reset was chosen by the request, not by the credential.',
            'verdict' => $account ? 'pass' : 'block',
        ];
    }
}
if ($flag !== '') {
    $pipeline[] = [
        'label'   => 'password_verify($yourString, users.password_hash)',
        'value'   => 'true',
        'note'    => 'Re-read from the database after the update. The administrator row holds your password.',
        'verdict' => 'pass',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Get a token you are entitled to</h4>
    <form method="post" action="level4.php">
        <input type="hidden" name="send" value="1">
        <div class="form-group">
            <label class="form-label">Address to recover</label>
            <input type="text" name="target" class="form-control" autocomplete="off"
                   value="<?= lk_esc((string)($_POST['target'] ?? AR_GUEST)) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Send reset instructions</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Complete the reset</h4>
    <p class="lk-hintline">This is the form <code>reset.php</code> renders once a token has been accepted. The
       account field is populated from a hidden input in the real page; here it is editable so you can see what the
       server does with it.</p>
    <form method="post" action="level4.php">
        <input type="hidden" name="reset" value="1">
        <div class="form-group">
            <label class="form-label">Token</label>
            <input type="text" name="token" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($tokenIn) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">Account</label>
            <input type="text" name="email" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($emailIn !== '' ? $emailIn : AR_GUEST) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">New password</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Set password</button>
    </form>
</div>

<?= ar_admin_state_card($L) ?>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /reset
$row = db()->query('SELECT * FROM tokens WHERE token = ?', [$_POST['token']]);

if ($row === null)                     { return deny('unknown token'); }
if ($row->used_at !== null)            { return deny('already used'); }
if ($row->expires_at <= time())        { return deny('expired'); }

// The reset form posts the address back so the confirmation email
// can be addressed correctly.
$user = user_by_email($_POST['email']);
if ($user === null)                    { return deny('unknown account'); }

$user->password_hash = password_hash($_POST['new_password'], PASSWORD_DEFAULT);
$user->save();
mark_token_used($row->id);

return 'Your password has been updated.';
PHP;

$fixBad = <<<'PHP'
$row  = find_token($_POST['token']);
$user = user_by_email($_POST['email']);   // the account comes from the request
$user->setPassword($_POST['new_password']);
PHP;

$fixGood = <<<'PHP'
$row = find_token($_POST['token']);
if ($row === null || $row->used_at !== null || $row->expires_at <= time()) {
    return deny('invalid token');
}

// The credential names the account. Nothing else is consulted, and there is
// no parameter left for the caller to disagree with.
$user = user_by_id($row->user_id);
$user->setPassword($_POST['new_password']);
$user->save();
mark_token_used($row->id);

// If the flow really needs the address on screen, read it from $row - never
// from the request - and drop the field from the form entirely. A hidden
// input is a request parameter with a different colour.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [9, 10, 12],
    'annotation' => 'Every check on the token is correct, and none of them is about the account. The token row
        carries the address it was issued to; the handler ignores that column and loads whichever account the form
        names. Holding any valid token therefore lets you reset any account.',

    'theory' => '<p>There are two questions in an authorisation decision: <em>who is this</em> and <em>what may
        they touch</em>. A reset token answers the first one, for one specific account. The bug here is that the
        answer to the second question was taken from a different source, and nothing forced the two to agree.</p>
        <p>The shape recurs everywhere once you look for it: an API key that authenticates the caller while the
        tenant id comes from the path, a signed upload URL that verifies the signature while the destination
        directory comes from a form field, a JWT that is verified correctly while the user id used by the query is
        read from a header. In each case a reviewer reading only the authentication code sees nothing wrong,
        because the authentication really is correct.</p>
        <p>The reliable review question is: <strong>which value in this request decides what gets modified, and
        where did it come from?</strong> If the answer is anywhere other than the credential itself, the check and
        the effect are not connected. Hidden inputs do not count as trusted; a hidden input is a request parameter
        with different styling.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Notice that the patched version deletes a parameter rather than adding a check. Comparing
            <code>$row->email</code> with <code>$_POST["email"]</code> would also work, but it leaves the field in
            place for the next person to use somewhere else. Removing the choice is stronger than validating it.',
    ],

    'scenario' => '<strong>Scenario:</strong> the reset page posts the address back so the confirmation email can
        be addressed correctly. The field is hidden, so it was never thought of as input.
        <br><strong>Goal:</strong> use a token issued to your own address to set the administrator\'s password.',

    'model' => [
        'title' => 'What the token proves, and what it does not',
        'html'  => '<table class="lk-kv">
            <tr><td>the token proves</td><td>somebody was able to read the mailbox this value was sent to</td></tr>
            <tr><td>the token does not prove</td><td>anything at all about the account named in a separate field</td></tr>
            <tr><td>the row already knows</td><td><code>tokens.email</code> and <code>tokens.user_id</code> &mdash;
                both populated at issue time, neither read at redemption time</td></tr>
        </table>
        <p>So the exploit is not a payload; it is a mismatch. Get a token the honest way, for an account you are
        entitled to, and then change the one field that decides the effect.</p>
        <p>Confirm the pieces separately before combining them. Does a token issued to your address work at all?
        Does an invalid token get rejected? Only then send a valid token with a different account, so that when it
        succeeds you know exactly which of the two things you changed was responsible.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The credential was genuine. It just did not name an account.',
    'why'      => '<p>The token you sent was real, unredeemed and inside its lifetime, and the trace shows all
        three checks passing honestly. Then the handler looked up an account using the address from your form, and
        the two values in the trace &mdash; <code>tokens.email</code> and <code>$_POST["email"]</code> &mdash;
        never met.</p>
        <p>The administrator\'s stored hash now verifies against a string you chose, which is the only reason this
        page shows a flag. No wording in the request mattered; the state of the users table did.</p>
        <p>The general lesson is worth carrying into other flows. Whenever a request carries both a credential and
        an identifier for the thing to modify, one of them is redundant. The redundant one is the identifier, and
        leaving it in the request is how this bug gets written.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'email',
        'method' => 'GET',
        'action' => 'level4.php',
        'items'  => [
            ['q' => 'Is the account field used for a lookup, or ignored?',
             'payload' => 'nobody@hackinlab.internal',
             'learn'   => 'This loads the form with that address in the account field. Submit it together with a valid token: an error naming the <em>account</em> rather than the token proves the field decides which row is loaded.'],
            ['q' => 'Does the flow work honestly for the account the token belongs to?',
             'payload' => AR_GUEST,
             'learn'   => 'The control case. Send your own token with your own address and confirm the reset succeeds, so that a later success tells you something new rather than something you already knew.'],
            ['q' => 'Is the account lookup case sensitive?',
             'payload' => 'Guest@hackinlab.internal',
             'learn'   => 'One capital letter. Whether the lookup finds the row tells you which comparison rule this codebase uses for addresses — worth writing down, because level 9 turns on that answer.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
