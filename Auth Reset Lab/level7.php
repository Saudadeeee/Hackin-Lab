<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/visit.php';   // the victim, as a library

$L = 7;
ar_handle_reset($L);
$meta = ar_levels()[$L];

/**
 * The application reads the session identifier out of the request. A cookie is
 * the usual carrier, but this code accepts a query parameter as well, because
 * a client without cookie support once needed it.
 */
$sidIn = trim((string)($_REQUEST['sid'] ?? ''));
$sid   = ar_sid($L, $sidIn);
$row   = ar_session_touch($L, $sid);

$result   = '';
$pipeline = [];
$visit    = null;

/* ── The administrator follows a link and signs in ──────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_link'])) {
    $victimSid = trim((string)($_POST['victim_sid'] ?? ''));
    $visit     = ar_visit_login($L, $victimSid);

    $result .= $visit['adopted']
        ? ar_info('The administrator followed a link containing <code>sid=' . lk_esc($visit['sid'])
            . '</code> and then signed in. ' . lk_esc($visit['note']))
        : ar_err('You sent a link with no session id in it. ' . lk_esc($visit['note']));
}

$row     = ar_session_get($L, $sid);
$isAdmin = $row !== null && (int)$row['authenticated'] === 1
        && strcasecmp((string)$row['email'], AR_ADMIN) === 0;

if ($isAdmin) {
    ar_mark_win($L, 'presented a session id that the administrator\'s login authenticated');
}
$flag = $isAdmin ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
$pipeline[] = [
    'label' => '$sid = $_REQUEST["sid"] ?? $_COOKIE["session"]',
    'value' => $sid,
    'note'  => $sidIn !== ''
        ? 'Taken from the URL on this request. The application stores it and uses it as the session identifier.'
        : 'Taken from your cookie. Add <code>?sid=&lt;value&gt;</code> to choose it instead.',
];
if ($visit !== null) {
    $pipeline[] = [
        'label'   => 'the administrator\'s login',
        'value'   => 'session used: ' . $visit['sid'] . ($visit['adopted'] ? ' (adopted from the URL)' : ' (freshly generated)'),
        'note'    => $visit['adopted']
            ? 'The login found an existing row for this id and marked <em>that row</em> authenticated. No new '
              . 'identifier was issued at the moment the privilege changed.'
            : 'With no id in the request the application generated one, which you never see. That is what a '
              . 'regenerating login would do on every sign-in.',
        'verdict' => $visit['adopted'] ? 'pass' : 'block',
    ];
}
$pipeline[] = [
    'label'   => 'session row you are presenting',
    'value'   => ar_session_summary($row),
    'note'    => $isAdmin
        ? 'Same identifier before and after the login, and it now carries the administrator\'s identity.'
        : 'Anonymous. Nothing has authenticated this identifier yet.',
    'verdict' => $isAdmin ? 'pass' : null,
];

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Choose the session identifier you will be using</h4>
    <p class="lk-hintline">The value is yours to pick. It is stored in your cookie as well, so the page keeps
       working after you navigate away.</p>
    <form method="get" action="level7.php">
        <div class="form-group">
            <label class="form-label">sid</label>
            <input type="text" name="sid" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc($sid) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Use this session</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Send the administrator a link</h4>
    <p class="lk-hintline">Anything that makes the administrator arrive at the site carrying a session id will do:
       a link in a message, a redirect from a page they trust, an image tag. Put the identifier in the box and the
       administrator will follow it and then sign in normally.</p>
    <form method="post" action="level7.php">
        <input type="hidden" name="send_link" value="1">
        <div class="form-group">
            <label class="form-label">sid to embed in the link you send</label>
            <input type="text" name="victim_sid" class="form-control ar-mono" autocomplete="off" spellcheck="false"
                   placeholder="leave empty to send a plain link" value="<?= lk_esc((string)($_POST['victim_sid'] ?? '')) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Send the link and wait for the sign-in</button>
    </form>
    <p class="lk-hintline">The same thing happens if you open
       <code>visit.php?action=login&amp;level=7&amp;sid=&lt;value&gt;</code> directly.</p>
</div>

<div class="ar-step">
    <h4>3 &middot; Use the session</h4>
    <a class="btn btn-primary" href="level7.php?sid=<?= rawurlencode($sid) ?>">Reload as <?= lk_esc($sid) ?> &rarr;</a>
</div>

<div class="lk-box"><h4><span class="lk-tag">CONSOLE</span><?= $isAdmin ? 'Administrator console' : 'Not signed in' ?></h4>
<div class="lk-body">
    <table class="lk-kv">
        <tr><td>session id presented</td><td class="ar-mono"><?= lk_esc($sid) ?></td></tr>
        <tr><td>identity on that row</td><td class="ar-mono"><?= lk_esc((string)($row['email'] ?? 'anonymous')) ?></td></tr>
        <tr><td>authenticated</td><td><?= $row && (int)$row['authenticated'] === 1 ? 'yes' : 'no' ?></td></tr>
        <tr><td>console</td><td><?= $isAdmin ? 'open' : 'locked' ?></td></tr>
    </table>
</div></div>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// bootstrap/session.php
// Some clients cannot store cookies, so the id may arrive in the URL.
$sid = $_REQUEST['sid'] ?? $_COOKIE['session'] ?? new_session_id();
session_load($sid);
setcookie('session', $sid);

// POST /login
if (!password_verify($_POST['password'], $user->password_hash)) {
    return deny('bad credentials');
}

// The user is now authenticated. The session they are in is the one they
// arrived with.
$_SESSION['email']         = $user->email;
$_SESSION['authenticated'] = true;

return redirect('/console');
PHP;

$fixBad = <<<'PHP'
$sid = $_REQUEST['sid'] ?? $_COOKIE['session'] ?? new_session_id();
// ... password check ...
$_SESSION['authenticated'] = true;      // same id as before the login
PHP;

$fixGood = <<<'PHP'
// 1. The identifier comes from a cookie and from nowhere else.
//    php.ini: session.use_only_cookies=1, session.use_trans_sid=0
$sid = $_COOKIE['session'] ?? null;

// 2. The identifier changes at every privilege boundary: sign-in, sign-out,
//    completing a second factor, assuming another user's identity.
if (!password_verify($_POST['password'], $user->password_hash)) {
    return deny('bad credentials');
}
session_regenerate_id(true);            // new id, old row destroyed
$_SESSION['email']         = $user->email;
$_SESSION['authenticated'] = true;

// 3. Cookie attributes that keep the new id where it belongs:
//    HttpOnly (not readable from script), Secure (not sent in clear),
//    SameSite=Lax (not sent from another site's form).
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 4, 14, 15],
    'annotation' => 'Two defects combine. The session identifier is accepted from the request, so an attacker can
        choose it; and the login attaches the new identity to the identifier the request already carried instead of
        issuing a fresh one. Either alone is bad practice. Together they mean a value you picked becomes an
        administrator session as soon as the administrator signs in.',

    'theory' => '<p>A session id is a bearer credential that stands for "this browser is that person". The
        statement it makes changes the instant a login succeeds &mdash; before, it meant nothing; afterwards, it
        means everything the account can do. A credential whose meaning changes has to change value at the same
        moment, or everyone who knew the old value silently inherits the new meaning.</p>
        <p>That is why <code>session_regenerate_id()</code> belongs at every privilege boundary and not only at
        login: completing a second factor, switching to an impersonated account, elevating to an administrative
        mode. Each of those is a point where the same identifier would start meaning something stronger.</p>
        <p>Fixation is easier to arrange than it looks, because the attacker does not need to steal anything. Any
        way of getting a chosen identifier into the victim\'s browser works: a link with the id in the query string
        on an application that accepts one, a subdomain that can write the parent domain\'s cookie, a response
        header injection, or a network position that lets a cookie be set over plain HTTP for a site otherwise
        served over TLS. The delivery is the easy half; the reason it pays is the missing regeneration.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Rejecting ids from the URL is the smaller half of the fix. An application that regenerates at
            every privilege change is safe even if the attacker can plant a cookie, because the value they planted
            stops being the one that matters at the exact moment it would start being valuable.',
    ],

    'scenario' => '<strong>Scenario:</strong> a legacy integration needed to pass the session id in the URL, and
        the flag that allowed it was never removed. The login flow was written before that and has never issued a
        new identifier.
        <br><strong>Goal:</strong> hold a session that the administrator\'s own sign-in turns into an
        administrator session.',

    'model' => [
        'title' => 'Four steps, and the one that fails',
        'html'  => '<table class="lk-kv">
            <tr><td>1 &mdash; you choose</td><td>pick any value and present it. The application accepts it and
                creates an anonymous row for it.</td></tr>
            <tr><td>2 &mdash; you deliver</td><td>get the administrator to arrive carrying the same value. A link
                is enough here; in the field it might be a cookie you can set from a neighbouring host.</td></tr>
            <tr><td>3 &mdash; they authenticate</td><td>the login succeeds. This is the moment the identifier
                should change and does not.</td></tr>
            <tr><td>4 &mdash; you return</td><td>present the same value. The row it names is now the
                administrator\'s.</td></tr>
        </table>
        <p>Step 3 is the only one that is a vulnerability; the rest are ordinary application behaviour. That is
        worth holding on to, because a fix aimed at step 1 or step 2 alone leaves the bug in place for every other
        way of planting a value.</p>
        <p>Send a link with no identifier in it first. The application generates one you never see, the
        administrator signs into that, and nothing reaches you. The contrast between the two runs is the whole
        finding.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You did not steal a session. You lent one out and got it back with more privileges.',
    'why'      => '<p>The identifier in the trace is the same string in every stage: the one you chose, the one
        the administrator arrived with, and the one that now names an authenticated administrator row. The login
        never issued a new one, so nothing about the credential distinguishes before from after.</p>
        <p>Nothing was intercepted and no password was involved. The application answered the question "which
        session is this request in" using a value the request supplied, and answered "who is that session" using a
        row an entirely different request had updated.</p>
        <p>When you review session handling, the two lines to find are where the identifier is read from, and
        whether it changes on the line after a successful authentication. If the second line is missing, everything
        else about the session configuration is secondary.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'sid',
        'method' => 'GET',
        'action' => 'level7.php',
        'items'  => [
            ['q' => 'Does the application accept a session id from the URL at all?',
             'payload' => 'hl-probe-0001',
             'learn'   => 'If the console reports that exact string back as the session you are presenting, the identifier is attacker-chosen. That is the first of the two defects, on its own.'],
            ['q' => 'Does an unknown id get replaced, or adopted?',
             'payload' => 'never-seen-before-value',
             'learn'   => 'An application that mints a fresh id for an unrecognised one is much harder to fixate. One that stores whatever it was given has no opinion about where ids come from.'],
            ['q' => 'What happens when the administrator signs in without a planted id?',
             'payload' => 'hl-probe-0002',
             'learn'   => 'Use step 2 with the field left empty, then reload with this id. The administrator is signed in somewhere, and it is not here — which is what a regenerating login looks like from the outside.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
