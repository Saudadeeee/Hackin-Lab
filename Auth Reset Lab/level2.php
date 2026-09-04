<?php
require_once __DIR__ . '/helpers.php';

$L = 2;
ar_handle_reset($L);
$meta = ar_levels()[$L];

/**
 * The token generator.
 *
 * Both inputs are known to the caller: the caller chose the address, and the
 * confirmation screen prints the clock.
 */
function ar_l2_issue(int $level, string $email): array
{
    $user = ar_user_by_email($level, $email);
    if ($user === null) {
        return ['ok' => false, 'now' => time(), 'email' => $email];
    }

    $issuedAt = time();
    $token    = md5($email . $issuedAt);

    ar_token_insert($level, $token, $email, (int)$user['id'], 'reset', null, $issuedAt, 900);
    ar_send_reset_mail($level, $email, $token, ar_reset_link($token));

    return ['ok' => true, 'now' => time(), 'email' => $email, 'issued_at' => $issuedAt];
}

$target    = trim((string)($_POST['target'] ?? AR_ADMIN));
$issue     = null;
$result    = '';
$pipeline  = [];
$tried     = 0;
$matched   = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_reset'])) {
    $issue = ar_l2_issue($L, $target);
} elseif (($probe = trim((string)($_GET['probe_email'] ?? ''))) !== '') {
    $issue  = ar_l2_issue($L, $probe);
    $target = $probe;
}

if ($issue !== null) {
    $result .= $issue['ok']
        ? ar_info('Reset instructions queued for <code>' . lk_esc((string)$issue['email']) . '</code>. '
            . 'Server time: <strong>' . (int)$issue['now'] . '</strong> ('
            . lk_esc(gmdate('Y-m-d H:i:s', (int)$issue['now'])) . ' UTC).')
        : ar_err('No account is registered for <code>' . lk_esc((string)$issue['email']) . '</code>. '
            . 'Server time: <strong>' . (int)$issue['now'] . '</strong>.');
}

/* ── Redeeming a predicted token ────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['try_candidates'])) {
    $raw   = (string)($_POST['candidates'] ?? '');
    $new   = (string)($_POST['new_password'] ?? '');
    $lines = array_values(array_filter(array_map('trim', preg_split('~[\s,]+~', $raw) ?: []), 'strlen'));
    $lines = array_slice($lines, 0, 500);

    if (!$lines) {
        $result .= ar_err('No candidate tokens submitted.');
    } elseif ($new === '') {
        $result .= ar_err('Choose the password you want the account to end up with.');
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
            $result .= ar_err('Tried ' . $tried . ' candidate(s); none of them is a live token in the store.');
        } else {
            $owner = ar_user_by_id($L, (int)$matched['user_id']);

            if ($owner === null) {
                $result .= ar_err('The matched token does not resolve to an account.');
                $matched = null;
            } else {
                ar_set_password($L, (int)$owner['id'], $new);
                ar_token_mark_used((int)$matched['id']);

                // State check: re-read the row and confirm the stored hash
                // really verifies against the string that was just submitted.
                $after = ar_user_by_id($L, (int)$owner['id']);
                $ok    = password_verify($new, (string)$after['password_hash']);

                if ($ok && strcasecmp((string)$owner['email'], AR_ADMIN) === 0) {
                    ar_mark_win($L, 'predicted a token issued at ' . (int)$matched['issued_at']);
                    $result .= ar_ok('Password for <code>' . lk_esc(AR_ADMIN) . '</code> is now the string you '
                        . 'chose. The matching token was issued at <strong>' . (int)$matched['issued_at'] . '</strong>.');
                } elseif ($ok) {
                    $result .= ar_info('Password updated for <code>' . lk_esc((string)$owner['email'])
                        . '</code>. That is a real reset, but not the account this level is about.');
                } else {
                    $result .= ar_err('The update did not take effect.');
                }
            }
        }
    }
}

$flag = ar_win($L) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($issue !== null) {
    $pipeline[] = [
        'label' => 'account lookup for ' . $issue['email'],
        'value' => $issue['ok'] ? 'found' : 'not found',
        'note'  => 'Anyone may start a recovery for any address. That is the feature working as designed.',
        'verdict' => $issue['ok'] ? 'pass' : 'block',
    ];
    if ($issue['ok']) {
        $pipeline[] = [
            'label' => '$token = md5($email . time())',
            'value' => 'md5("' . $issue['email'] . '" . ' . (int)$issue['issued_at'] . ')',
            'note'  => 'The digest is stored and mailed. It is not shown to you, because that mailbox is not yours '
                     . '&mdash; but every input to the function is.',
        ];
        $pipeline[] = [
            'label' => 'time() reported back in the response',
            'value' => (string)(int)$issue['now'],
            'note'  => 'One second of resolution. Your request and the server\'s clock read are within a second or '
                     . 'two of each other, so the window you have to cover is tiny.',
        ];
    }
}
if ($tried > 0) {
    $pipeline[] = [
        'label'   => 'candidates tested against the token store',
        'value'   => $tried . ' digest(s)',
        'note'    => 'Each one is a single indexed lookup on <code>tokens.token</code>. A miss and a hit are the '
                   . 'same amount of work; only the row you get back differs.',
        'verdict' => $matched ? 'pass' : 'block',
    ];
}
if ($matched !== null) {
    $pipeline[] = [
        'label' => 'matched row',
        'value' => 'token=' . $matched['token'] . ' email=' . $matched['email']
                 . ' issued_at=' . (int)$matched['issued_at'],
        'note'  => 'A real row, issued by the server, never shown to you. You reconstructed it from the two values '
                 . 'the generator uses.',
        'verdict' => 'pass',
    ];
    $pipeline[] = [
        'label'   => 'password_verify($yourString, users.password_hash)',
        'value'   => $flag !== '' ? 'true' : 'false',
        'note'    => 'The flag depends on this line and nothing else. The account really holds the password you set.',
        'verdict' => $flag !== '' ? 'pass' : 'block',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
$clock = time();
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="lk-box"><h4><span class="lk-tag">CLOCK</span>Server time on this page load</h4>
    <div class="lk-body"><p class="ar-mono" style="font-size:1rem"><?= $clock ?>
        &nbsp;<span class="text-muted"><?= lk_esc(gmdate('Y-m-d H:i:s', $clock)) ?> UTC</span></p></div></div>

<div class="ar-step">
    <h4>1 &middot; Start a recovery for an address</h4>
    <form method="post" action="level2.php">
        <input type="hidden" name="request_reset" value="1">
        <div class="form-group">
            <label class="form-label">Address to recover</label>
            <input type="text" name="target" class="form-control" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($target) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Send reset instructions</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Submit candidate tokens</h4>
    <p class="lk-hintline">One digest per line, up to 500. They are tested against the token store in order; the
       first live match is redeemed and the account it belongs to gets the password you type below.</p>
    <form method="post" action="level2.php">
        <input type="hidden" name="try_candidates" value="1">
        <div class="form-group">
            <label class="form-label">Candidate tokens</label>
            <textarea name="candidates" class="form-control ar-mono" rows="6" spellcheck="false"
                      placeholder="one md5 per line"><?= lk_esc((string)($_POST['candidates'] ?? '')) ?></textarea>
        </div>
        <div class="form-group">
            <label class="form-label">Password to set on the account the token belongs to</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Redeem</button>
    </form>
</div>

<?= ar_admin_state_card($L) ?>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /forgot-password
$user = user_by_email($email);
if ($user === null) {
    return view('forgot', ['message' => "No account is registered for $email."]);
}

// "Unique enough": the address never repeats, the clock never repeats.
$token = md5($email . time());

store_token($token, $user, expires: time() + 900);
send_reset_mail($email, reset_link($token));

return view('forgot', [
    'message'     => "Reset instructions queued for $email.",
    'server_time' => time(),      // shown so support can correlate tickets
]);
PHP;

$fixBad = <<<'PHP'
$token = md5($email . time());
PHP;

$fixGood = <<<'PHP'
// 256 bits from the operating system's CSPRNG. Not derived from anything the
// caller knows, not derived from anything an observer can watch.
$token = bin2hex(random_bytes(32));

// Store the digest, compare in constant time, and give it a short life:
//   store_token(hash('sha256', $token), $user, expires: time() + 900);
//
// The test that catches the regression is not "is it long" - it is
// "does the same address at the same moment produce the same value twice".
// A generator that is a pure function of public inputs fails that test.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [8, 14],
    'annotation' => 'The token is a pure function of two public values: the address, which you supplied, and the
        second on the clock, which the response prints. md5 is not the problem here and neither is its speed &mdash;
        replacing it with SHA-256 or bcrypt would change nothing, because the <em>inputs</em> carry no secret.',

    'theory' => '<p>A reset token is a bearer credential: whoever holds it can act as the account. Its entire
        security is that it cannot be guessed, which means it has to be drawn from a source an attacker cannot
        reproduce. A hash function does not create unpredictability &mdash; it preserves whatever was in its input.
        Hash a known string and you get a known digest.</p>
        <p>Time-derived identifiers are common because they look random and sort nicely. <code>uniqid()</code> is
        the microsecond clock in hexadecimal. <code>mt_srand(time())</code> makes the entire sequence a function of
        the second the process started. Auto-increment ids with a hash wrapped around them are the same mistake
        with an extra step. In each case the question to ask is not "how long is the value" but "how many values
        could it have been, given what the attacker already knows".</p>
        <p>The clock in the response is a small extra gift, and one that is easy to ship by accident: a
        <code>Date</code> header, a debug field, a rendered timestamp, an ETag. It costs you nothing to remove and
        it costs the attacker four orders of magnitude &mdash; but note the arithmetic below, because even without
        it the search space is not large.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The rule is that a credential comes from <code>random_bytes()</code> or the platform equivalent,
            and from nowhere else. Everything else &mdash; length, encoding, which hash it is stored under &mdash;
            is secondary to where the entropy came from.',
    ],

    'scenario' => '<strong>Scenario:</strong> a support engineer asked for the server clock to be shown on the
        confirmation screen so tickets could be matched to log lines. The token generator was written years earlier
        and nobody looked at it during that change.
        <br><strong>Goal:</strong> start a recovery for the administrator, work out the token it produced, and use
        it to set a password you choose.',

    'model' => [
        'title' => 'How large is the search actually?',
        'html'  => '<p>The token is <code>md5(address . unix_seconds)</code>. The address is fixed and known, so the
        only unknown is which second. That is the entire key space.</p>
        <table class="lk-kv">
            <tr><td>md5 rate, plain PHP, one core</td><td>roughly 3&ndash;5 million per second</td></tr>
            <tr><td>md5 rate, one commodity GPU</td><td>roughly 10<sup>10</sup> per second</td></tr>
            <tr><td>issue time unknown to &plusmn;1 day</td><td>86,400 candidates &rarr; about 20 ms in PHP</td></tr>
            <tr><td>issue time unknown to &plusmn;1 year</td><td>3.2&times;10<sup>7</sup> candidates &rarr; about 8 s in PHP</td></tr>
            <tr><td>issue time printed in the response</td><td>3&ndash;5 candidates &rarr; instant</td></tr>
            <tr><td>a real token, <code>random_bytes(32)</code></td><td>2<sup>256</sup> candidates</td></tr>
        </table>
        <p>Read the middle rows again. Hiding the clock would have moved this from "instant" to "a few seconds".
        That is the difference between a broken generator with a leak and a broken generator without one &mdash;
        which is to say, not a difference worth relying on.</p>
        <p>Generating the candidates:</p>
        <div class="output-box"><code>php -r \'$e="admin@hackinlab.internal"; for($t=$argv[1]-3;$t&lt;=$argv[1]+1;$t++) echo md5($e.$t),"\n";\' 1700000000</code></div>
        <p>Confirm the construction on an address whose mailbox you can read before you spend a request on the
        administrator. Your own account is the control.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The token was never secret; it was only unread.',
    'why'      => '<p>You never saw the administrator\'s mail. You did not need to: you recomputed the value that
        was in it from the address you typed and the clock the page printed. The row the server matched is the row
        the server wrote, and the password on the account is the string you chose &mdash; the trace shows
        <code>password_verify()</code> returning true against the stored hash, which is the only reason a flag
        appeared.</p>
        <p>Notice what was <em>not</em> wrong. The token was stored, it had a fifteen minute expiry, it was bound
        to an account, and it was single use. All of that is correct, and all of it is irrelevant when the value
        can be derived.</p>
        <p>When you review a recovery flow, find the line that produces the token before you read anything else.
        If its arguments are things you could have written down yourself, stop reading; you have the finding.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'probe_email',
        'method' => 'GET',
        'action' => 'level2.php',
        'items'  => [
            ['q' => 'Is the token really md5(address . clock)? Test it where you can read the mail.',
             'payload' => AR_GUEST,
             'learn'   => 'This issues a token to your own mailbox. Compare it against <code>md5("guest@hackinlab.internal" . t)</code> for t near the printed clock. Confirm the construction on a control before you spend requests on the target.'],
            ['q' => 'Does the endpoint answer differently for an address with no account?',
             'payload' => 'helpdesk@hackinlab.internal',
             'learn'   => 'This form does distinguish the two cases in its wording, which level 1 taught you to look for. It also prints the clock either way.'],
            ['q' => 'Two requests inside the same second: same token or different?',
             'payload' => 'guest@hackinlab.internal',
             'learn'   => 'Run it twice quickly. Identical output proves the resolution is one second, which is what fixes the size of your candidate window.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
