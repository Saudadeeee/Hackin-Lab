<?php
require_once __DIR__ . '/helpers.php';

$L = 9;
ar_handle_reset($L);
$meta = ar_levels()[$L];

/** Your account is the non-administrator row, whatever address it currently holds. */
function ar_l9_me(int $level): array
{
    $st = ar_db()->prepare('SELECT * FROM users WHERE level = ? AND is_admin = 0 ORDER BY id ASC LIMIT 1');
    $st->execute([$level]);
    return (array)$st->fetch();
}

$me       = ar_l9_me($L);
$result   = '';
$pipeline = [];
$stage    = [];

/* ── Step 1: a reset token for your own account ─────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send'])) {
    $token = bin2hex(random_bytes(16));
    ar_token_insert($L, $token, (string)$me['email'], (int)$me['id'], 'reset', null, null, 900);
    ar_send_reset_mail($L, (string)$me['email'], $token, ar_reset_link($token));
    $result .= ar_info('Reset instructions sent to <code>' . lk_esc((string)$me['email']) . '</code>. '
        . 'That is your own address, so the token is in <a href="mailbox.php?level=9">your mailbox</a>.');
}

/* ── Step 2: change the address on your account ─────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_email'])) {
    $new = trim((string)($_POST['new_email'] ?? ''));

    // Uniqueness is enforced with an exact comparison.
    $clash = $new === '' ? null : ar_user_by_email($L, $new);

    $stage['change_from'] = (string)$me['email'];
    $stage['change_to']   = $new;
    $stage['clash']       = $clash;

    if ($new === '' || !str_contains($new, '@')) {
        $result .= ar_err('Enter an address.');
    } elseif ($clash !== null) {
        $result .= ar_err('That address is already in use by another account.');
    } else {
        ar_set_email($L, (int)$me['id'], $new);
        $me = ar_l9_me($L);
        $result .= ar_ok('The address on your account is now <code>' . lk_esc((string)$me['email']) . '</code>.');
    }
}

/* ── Step 3: redeem the token ───────────────────────────────────────────── */
$tokenIn = trim((string)($_POST['token'] ?? $_GET['token'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['redeem'])) {
    $new = (string)($_POST['new_password'] ?? '');
    $row = $tokenIn === '' ? null : ar_token_find($L, $tokenIn);

    $valid = $row !== null
          && $row['used_at'] === null
          && ($row['expires_at'] === null || (int)$row['expires_at'] > time());

    if (!$valid) {
        $result .= ar_err($row === null ? 'Unknown token.' : 'That token has been redeemed or has expired.');
    } elseif ($new === '') {
        $result .= ar_err('Choose a password to set.');
    } else {
        // The token knows which row asked for the reset ...
        $owner = ar_user_by_id($L, (int)$row['user_id']);
        // ... and the handler then re-resolves the account through the address
        // that row carries right now, so that a person who changed their
        // address between the request and the click still lands correctly.
        $address = (string)$owner['email'];
        $account = ar_user_by_email_ci($L, $address);

        $stage['token_user_id'] = (int)$row['user_id'];
        $stage['address_now']   = $address;
        $stage['resolved']      = $account;

        if ($account === null) {
            $result .= ar_err('No account matches <code>' . lk_esc($address) . '</code>.');
        } else {
            ar_set_password($L, (int)$account['id'], $new);
            ar_token_mark_used((int)$row['id']);

            $after = ar_user_by_id($L, (int)$account['id']);
            $ok    = password_verify($new, (string)$after['password_hash']);

            if ($ok && (int)$account['is_admin'] === 1) {
                ar_mark_win($L, 'retargeted a token issued to user ' . (int)$row['user_id']
                    . ' onto user ' . (int)$account['id']);
                $result .= ar_ok('The password on the administrator row (user ' . (int)$account['id']
                    . ') is now the string you chose. The token was issued to user ' . (int)$row['user_id'] . '.');
            } elseif ($ok) {
                $result .= ar_info('Password updated for user ' . (int)$account['id'] . ' &mdash; <code>'
                    . lk_esc((string)$account['email']) . '</code>.');
            } else {
                $result .= ar_err('The update did not take effect.');
            }
        }
    }
}

$me   = ar_l9_me($L);
$flag = ar_win($L) ? ar_flag($L) : '';

/* Everything in the users table for this level - ids and addresses only. */
$st = ar_db()->prepare('SELECT id, email, is_admin FROM users WHERE level = ? ORDER BY id ASC');
$st->execute([$L]);
$directory = $st->fetchAll();

/* ── Trace ───────────────────────────────────────────────────────────────── */
if (isset($stage['change_to'])) {
    $pipeline[] = [
        'label'   => 'SELECT id FROM users WHERE email = ?   (uniqueness check)',
        'value'   => 'email = "' . $stage['change_to'] . '" → ' . ($stage['clash'] ? 'row ' . (int)$stage['clash']['id'] : 'no row'),
        'note'    => 'An exact, case sensitive comparison. Two addresses that differ only in capitalisation are two '
                   . 'different values as far as this query is concerned.',
        'verdict' => $stage['clash'] ? 'block' : 'pass',
    ];
}
if (isset($stage['token_user_id'])) {
    $pipeline[] = [
        'label' => 'tokens.user_id  (who asked for the reset)',
        'value' => 'user ' . $stage['token_user_id'],
        'note'  => 'Recorded at issue time and still correct. The handler reads it, and then keeps going.',
    ];
    $pipeline[] = [
        'label' => 'users[tokens.user_id].email  (the address on that row now)',
        'value' => $stage['address_now'],
        'note'  => 'The binding is re-derived from a column you are allowed to edit, at the moment the token is used.',
    ];
    $pipeline[] = [
        'label'   => 'SELECT * FROM users WHERE lower(email) = lower(?) ORDER BY id ASC LIMIT 1',
        'value'   => $stage['resolved']
            ? 'user ' . (int)$stage['resolved']['id'] . ' — ' . (string)$stage['resolved']['email']
            : 'no row',
        'note'    => 'A case insensitive comparison, and a tie broken by the lowest row id. The two queries in this '
                   . 'trace disagree about what "the same address" means.',
        'verdict' => $stage['resolved'] && (int)$stage['resolved']['id'] !== $stage['token_user_id'] ? 'pass' : null,
    ];
}
if ($flag !== '') {
    $pipeline[] = [
        'label'   => 'password_verify($yourString, users.password_hash)',
        'value'   => 'true',
        'note'    => 'On the administrator row, not the row the token was issued for.',
        'verdict' => 'pass',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="lk-box"><h4><span class="lk-tag">DIRECTORY</span>The users table on this level</h4><div class="lk-body">
    <table class="ar-table">
        <tr><th>id</th><th>address</th><th>role</th></tr>
        <?php foreach ($directory as $d): ?>
        <tr>
            <td class="ar-mono"><?= (int)$d['id'] ?></td>
            <td class="ar-mono"><?= lk_esc((string)$d['email']) ?></td>
            <td><?= (int)$d['is_admin'] === 1 ? 'administrator' : 'you' ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p class="lk-hintline">Row ids are assigned in the order the accounts were created and never change. Addresses
       do change.</p>
</div></div>

<div class="ar-step">
    <h4>1 &middot; Request a reset for your own account</h4>
    <form method="post" action="level9.php">
        <input type="hidden" name="send" value="1">
        <button class="btn btn-primary" type="submit">Send reset instructions to <?= lk_esc((string)$me['email']) ?></button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Change the address on your account</h4>
    <p class="lk-hintline">Account settings. The address is checked against the other accounts before it is saved.</p>
    <form method="post" action="level9.php">
        <input type="hidden" name="change_email" value="1">
        <div class="form-group">
            <label class="form-label">New address</label>
            <input type="text" name="new_email" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc((string)($_POST['new_email'] ?? $me['email'])) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Save address</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Redeem the token</h4>
    <form method="post" action="level9.php">
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

<?= ar_admin_state_card($L) ?>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// PATCH /account/email
$clash = db()->query('SELECT id FROM users WHERE email = ?', [$_POST['email']]);
if ($clash !== null) {
    return deny('address already in use');
}
$me->email = $_POST['email'];
$me->save();

// POST /reset
$row = find_token($_POST['token']);
if ($row === null || $row->used_at || $row->expires_at <= time()) {
    return deny('invalid token');
}

// Support ticket #4471: people change their address between asking for the
// link and clicking it, then complain the reset went to the old account.
// Resolve through the address the account holds now.
$address = user_by_id($row->user_id)->email;
$account = db()->query(
    'SELECT * FROM users WHERE lower(email) = lower(?) ORDER BY id ASC LIMIT 1',
    [$address]
);

$account->setPassword($_POST['new_password']);
$account->save();
PHP;

$fixBad = <<<'PHP'
// uniqueness: exact match
db()->query('SELECT id FROM users WHERE email = ?', [$new]);
// redemption: case insensitive, first row wins
db()->query('SELECT * FROM users WHERE lower(email) = lower(?) ORDER BY id ASC LIMIT 1', [$address]);
PHP;

$fixGood = <<<'PHP'
// 1. The token already names the account. Use it, and stop.
$account = user_by_id($row->user_id);
$account->setPassword($_POST['new_password']);

// 2. One canonical form for an address, applied on the way in, so the
//    uniqueness check and every lookup are asking the same question.
//    Store it in a column with a unique index and let the database enforce it:
//
//      ALTER TABLE users ADD COLUMN email_canonical TEXT NOT NULL;
//      CREATE UNIQUE INDEX users_email_canonical ON users(email_canonical);
//
//      $user->email           = $input;              // what to display
//      $user->email_canonical = canonicalise($input); // what to compare

// 3. Changing an address is a privileged action in its own right: require the
//    current password, verify the new address before it takes effect, and
//    invalidate outstanding reset tokens for the account when it does.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [2, 20, 21, 22, 23],
    'annotation' => 'The token is bound to a user id at issue time, and then the handler throws that binding away
        and re-derives the account from the address the row currently holds. The two queries that read addresses do
        not use the same comparison rule: uniqueness is exact, resolution is case insensitive with the lowest row
        id winning. A value can therefore be new to one query and already taken to the other.',

    'theory' => '<p>Two lookups over the same field with two different notions of equality is a
        <strong>normalisation differential</strong>, and it is the same family of bug as a WAF and a parser
        disagreeing about a payload. Nothing here is injected. The attacker simply supplies a value that the
        uniqueness check considers new and the resolution query considers identical to something that already
        exists.</p>
        <p>Email addresses attract this because there are so many plausible notions of equality. Case in the local
        part is technically significant and almost always ignored in practice. Gmail treats
        <code>a.b@</code> and <code>ab@</code>, and everything before a <code>+</code>, as one mailbox.
        Unicode normalisation can map distinct code point sequences to the same string. Trailing dots and
        surrounding whitespace get trimmed by some layers and not others. Every one of those is a place two
        components can disagree.</p>
        <p>The second half of the bug is time. The token was correct when it was issued and correct when it was
        redeemed; what changed in between was the data it was resolved through. Any binding that is re-derived at
        use time from mutable state can be steered by whoever can mutate that state. The general rule is that a
        credential should carry an immutable identifier &mdash; a row id, a UUID &mdash; and that the identifier
        should be read, not re-derived.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'A unique index on a canonical column is stronger than any application-level check, because it
            cannot be skipped by a code path nobody remembered, and it also closes the race between two concurrent
            address changes that both pass a <code>SELECT</code> before either writes.',
    ],

    'scenario' => '<strong>Scenario:</strong> support kept seeing people change their address after asking for a
        reset link and then complain that the link updated the wrong account. The fix was to resolve the account
        through the address on file at the moment the link is used.
        <br><strong>Goal:</strong> make a token issued for your own account set the administrator\'s password.',

    'model' => [
        'title' => 'Two questions about the same string',
        'html'  => '<table class="lk-kv">
            <tr><td>address change asks</td><td><code>WHERE email = ?</code> &mdash; is there a row with exactly
                these bytes?</td></tr>
            <tr><td>redemption asks</td><td><code>WHERE lower(email) = lower(?) ORDER BY id ASC</code> &mdash; is
                there a row that matches ignoring case, and if several do, the oldest one</td></tr>
        </table>
        <p>You need a value where the first answer is "no" and the second answer is "the administrator". Any
        difference the first query treats as significant and the second does not will do.</p>
        <p>The ordering matters as much as the comparison. Two rows now match case insensitively, and
        <code>ORDER BY id ASC</code> picks the one created first. Check the directory above to see which of the two
        accounts that is before you spend the token &mdash; if the tie broke the other way, the same trick would
        reset your own password and burn the token.</p>
        <p>Sequence: get the token first, then change the address, then redeem. Getting the order wrong means the
        token is issued to a row whose address already collides, and the request goes somewhere you did not
        intend.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The token was honest about who asked. The handler asked again later.',
    'why'      => '<p>The trace shows the two queries side by side. The uniqueness check compared your new address
        against the existing rows exactly and found nothing, so the change was allowed. The redemption compared the
        same string case insensitively, found two matching rows, and took the one with the lowest id &mdash; the
        administrator, created first when the level was seeded.</p>
        <p>The token never lied. <code>tokens.user_id</code> still points at your account and always did. The
        defect is that the handler treated the account\'s current address as the authoritative link rather than the
        id it already had in hand.</p>
        <p>When you review a flow, list every place a single logical value is compared and note the comparison rule
        used at each one. Where the rules differ, there is a value that satisfies one and subverts the other, and
        finding it is usually a matter of trying case, whitespace and Unicode in that order.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'GET',
        'action' => 'level9.php',
        'items'  => [
            ['q' => 'Does the uniqueness check reject the administrator address exactly as written?',
             'payload' => 'change your address to admin@hackinlab.internal',
             'learn'   => 'Use step 2. The rejection tells you the check runs and that it is comparing against the other row, which is what you need before asking how it compares.'],
            ['q' => 'Does it also reject a different capitalisation?',
             'payload' => 'change your address to Admin@hackinlab.internal',
             'learn'   => 'One capital letter, one query, one answer. Whatever happens here is the whole finding — and it is harmless on its own, because an address change is not a password reset.'],
            ['q' => 'Which row wins when two addresses match case insensitively?',
             'payload' => 'read the directory table',
             'learn'   => 'The redemption query orders by id ascending. The directory above prints the ids, so you can predict which account the reset will land on before you spend the token.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
