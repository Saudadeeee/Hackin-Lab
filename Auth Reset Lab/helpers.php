<?php
/**
 * Auth Reset Lab · lab metadata, flags, hints and shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/mail.php';

function arlab(): array
{
    return [
        'slug'    => 'authreset',
        'name'    => 'Account Recovery Lab',
        'icon'    => 'RST',
        'total'   => 10,
        'tagline' => 'The part of authentication that undoes the rest of it',
    ];
}

function ar_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{timing_answered_what_wording_would_not}',
        2  => 'FLAG{a_clock_is_not_a_random_number_generator}',
        3  => 'FLAG{the_host_header_wrote_the_reset_link}',
        4  => 'FLAG{the_token_never_named_the_account}',
        5  => 'FLAG{a_token_that_never_expires_never_stops_working}',
        6  => 'FLAG{a_million_guesses_is_not_a_barrier}',
        7  => 'FLAG{login_kept_the_session_you_handed_it}',
        8  => 'FLAG{the_second_factor_only_changed_the_screen}',
        9  => 'FLAG{the_address_moved_before_the_token_was_read}',
        10 => 'FLAG{recovery_is_the_shortest_path_to_the_account}',
    ];
    return $flags[$level] ?? '';
}

function ar_levels(): array
{
    return [
        1 => [
            'title'      => 'Username Enumeration',
            'difficulty' => 'Easy',
            'skill'      => 'Side channels: a form that answers the same way but not at the same speed',
            'desc'       => 'The reset form returns one generic sentence for every address. It does not spend the same amount of time producing it.',
        ],
        2 => [
            'title'      => 'Predictable Reset Token',
            'difficulty' => 'Easy',
            'skill'      => 'Timestamp-seeded secrets, search-space arithmetic',
            'desc'       => 'The token is <code>md5(email . time())</code>. You know the address, and the response tells you the clock.',
        ],
        3 => [
            'title'      => 'Host Header Poisoning',
            'difficulty' => 'Medium',
            'skill'      => 'Request data used to build absolute URLs in outbound mail',
            'desc'       => 'The reset link is assembled from the incoming <code>Host</code> header. Point it at a machine you own and wait for the click.',
        ],
        4 => [
            'title'      => 'Token Not Bound to the Account',
            'difficulty' => 'Medium',
            'skill'      => 'Authorisation vs authentication in a reset flow',
            'desc'       => 'The token proves a mailbox was reached. The account being reset is read from a form field next to it.',
        ],
        5 => [
            'title'      => 'Token Survives Use',
            'difficulty' => 'Medium',
            'skill'      => 'Credential lifetime: single use and expiry as separate controls',
            'desc'       => 'Nothing invalidates a reset token after it works, and nothing expires it. A link from last year is still a live credential.',
        ],
        6 => [
            'title'      => 'No Rate Limit on the OTP',
            'difficulty' => 'Hard',
            'skill'      => 'Turning entropy into wall-clock time',
            'desc'       => 'Six digits, unlimited attempts, no lockout. Work out how long that lasts before you start typing.',
        ],
        7 => [
            'title'      => 'Session Fixation',
            'difficulty' => 'Hard',
            'skill'      => 'Session identifiers that outlive the privilege change',
            'desc'       => 'The session id is accepted from the URL and is not regenerated when the login succeeds.',
        ],
        8 => [
            'title'      => 'Second Factor Only Guards the Response',
            'difficulty' => 'Hard',
            'skill'      => 'Client-side gating of a server-side decision',
            'desc'       => 'The password step already returns an authenticated session. A <code>verified</code> flag only decides which screen is drawn.',
        ],
        9 => [
            'title'      => 'The Email Change Race',
            'difficulty' => 'Expert',
            'skill'      => 'Two lookups, two comparison rules, one identity',
            'desc'       => 'A token is resolved to an account through the address on file at the moment it is used. Addresses can move.',
        ],
        10 => [
            'title'      => 'Chain',
            'difficulty' => 'Expert',
            'skill'      => 'Composing enumeration, prediction and reset into an account takeover',
            'desc'       => 'Find the administrator address, get a token for it, set a password, sign in. No hints about which weakness to use.',
        ],
    ];
}

/* =========================================================================
 * Hints - 5 per level: concept, observation, technique, shape, payload
 * ===================================================================== */

function ar_hints(int $level): array
{
    $h = [
        1 => [
            'A recovery form must answer identically for every address, or it becomes a directory of who has an account. The text here <em>is</em> identical — so look at what else the response carries.',
            'Read the source: when the address exists, the code issues a token and calls <code>password_hash()</code> on it before storage. When it does not exist, the function returns immediately. One branch does about 100&nbsp;ms of bcrypt work; the other does none.',
            'Measure. Send each candidate once, record the elapsed server time, and sort. You are not looking for a magic threshold — you are looking for two clusters that are two orders of magnitude apart.',
            'Classify every address in the list, then submit the classification. The page requires that you have actually measured each address at least once, so guessing the checkboxes is not a shortcut.',
            'Press <strong>Measure every address</strong>, read the table: rows near 0.3&nbsp;ms do not exist, rows near 100&nbsp;ms do. Tick <code>guest@</code>, <code>admin@</code>, <code>billing@</code> and <code>ops@</code> and submit.',
        ],
        2 => [
            'A reset token is a bearer credential. Its only job is to be unguessable, which means it has to come from a cryptographic random source, not from data an attacker already knows.',
            'The generator on this page is <code>md5($email . time())</code>. Both inputs are public: you choose the address, and the response prints the server clock next to the confirmation.',
            'Anyone may request a reset for any address — that is the normal feature. Trigger one for the administrator, note the server time in the response, and compute the candidate digests yourself.',
            'Your request and the server\'s <code>time()</code> call are a fraction of a second apart, so generate a small window of candidates around the printed value and submit them all.',
            '<code>php -r \'$e="admin@hackinlab.internal"; for($t=TIME-3;$t&lt;=TIME+1;$t++) echo md5($e.$t),"\\n";\'</code> with TIME replaced by the printed clock; paste the five digests into the candidate box together with a new password.',
        ],
        3 => [
            'Outbound mail is generated on the server but describes how to come back to it. Any absolute URL the server writes into an email needs an origin that comes from configuration, never from the request that triggered it.',
            'The builder here is <code>"http://" . $_SERVER["HTTP_X_FORWARDED_HOST"] . "/reset.php?token=" . $token</code>. Nothing validates the host, and the value is concatenated into a URL string.',
            'You never see the administrator\'s mail. You do not need to — you need the administrator\'s mail client to come to you. Send the reset with a host you control, then let the victim open the message.',
            'The lab resolves <code>attacker.hackinlab.internal</code> and <code>collector.hackinlab.internal</code> to itself, and every path on those names is served by <code>collector.php</code>. Anything the victim requests there is logged with its full query string.',
            'Host: <code>attacker.hackinlab.internal</code> &rarr; send &rarr; press <em>the administrator opens the message</em> &rarr; open <a href="collector.php">collector.php</a>, copy the token, then use it with a new password in step 3.',
        ],
        4 => [
            'A reset token answers exactly one question: "did the person holding this reach the mailbox we sent it to?" It says nothing about which account should change. Those two facts have to come from the same record.',
            'Look at the handler: <code>$token</code> is validated against the token table, and then the account is loaded with <code>ar_user_by_email($level, $_POST["email"])</code>. The token row also has an <code>email</code> column. It is never compared.',
            'Request a reset for your own address, read your own mailbox for the token, then send the reset with someone else\'s address in the account field.',
            'The request that wins is a valid token plus a mismatched account: <code>token=&lt;yours&gt;&amp;email=admin@hackinlab.internal&amp;new_password=&lt;anything&gt;</code>.',
            'Step 1 with <code>guest@hackinlab.internal</code>, copy the token out of <a href="mailbox.php?level=4">your mailbox</a>, then step 2 with account <code>admin@hackinlab.internal</code> and a password of your choice.',
        ],
        5 => [
            'A reset token is a credential with a lifetime. Two independent controls bound it: it must expire on a clock, and it must be destroyed the moment it is redeemed. Neither is implied by the other.',
            'The validation here is one line: <code>if (!$row) deny()</code>. The row has <code>used_at</code> and <code>expires_at</code> columns. Read the query again and note which columns appear in the <code>WHERE</code> clause.',
            'You are not going to guess a 128-bit token. Look for one that was written down somewhere you are allowed to read.',
            'Your own mailbox holds more than today\'s messages. Something was forwarded to the guest account a long time ago, and it contained a link rather than a password.',
            'Open <a href="mailbox.php?level=5">your mailbox</a>, find <em>Fwd: Finish setting up the administrator account</em>, take the token out of the URL and redeem it with a new password.',
        ],
        6 => [
            'Entropy is only a defence when guessing costs something. A six digit code is about 20 bits; whether that is strong depends entirely on how many guesses per second the server will accept and how many it will accept in total.',
            'The verifier here reads the code, compares it, and returns. There is no attempt counter consulted, no lockout, no delay, no invalidation of the code after a wrong answer. The <code>attempts</code> column is written but never read.',
            'Do the arithmetic before the attack. 10<sup>6</sup> codes, uniform, means an expected 500,000 attempts. Divide by the rate you can actually achieve and you have the answer in seconds — that number is the finding you report, not the code itself.',
            'The batch runner submits a contiguous range of candidates through the real verifier and reports the measured rate. Run consecutive ranges until one lands.',
            'Start the recovery for <code>admin@hackinlab.internal</code>, then run batches from 0 with a size of 250000 until the correct code is found. Four batches cover the whole space.',
        ],
        7 => [
            'A session id is a bearer credential that names a browser. When a login turns an anonymous browser into an authenticated one, the credential has to change — otherwise anyone who knew the old value now holds the new privilege.',
            'Two things are wrong in the code at once. The id is read from <code>$_REQUEST["sid"]</code>, so an attacker can choose it, and the login path calls <code>ar_session_authenticate()</code> on the id it already has instead of minting a new one.',
            'Pick a value, plant it, get the victim to arrive carrying it, then present the same value yourself. The vulnerability is that step four sees what step three produced.',
            'Load the level with <code>?sid=&lt;your value&gt;</code>, then have the victim arrive at the login endpoint with the same <code>sid</code> in the URL.',
            '<code>level7.php?sid=hl-fixed-001</code>, then <code>visit.php?action=login&amp;level=7&amp;sid=hl-fixed-001</code>, then reload <code>level7.php?sid=hl-fixed-001</code>.',
        ],
        8 => [
            'A second factor is a server-side gate on issuing credentials. If the credential is already in the response, the gate is decoration — the client has been asked to please not use what it was handed.',
            'The login endpoint creates the session and sets <code>authenticated = 1</code> before the code is ever checked. The JSON it returns includes that session id. <code>verified</code> is a rendering hint the front end reads to decide which screen to draw.',
            'Stop looking at the page and look at the response. Any HTTP client, or the browser network tab, shows the whole body, not the part the UI chose to render.',
            'Take the session id out of the login response and present it directly to the protected endpoint as a bearer credential.',
            'Sign in as <code>admin@hackinlab.internal</code> / <code>Kestrel-Autumn-2019</code>, copy <code>session.sid</code> from the JSON, paste it into the <em>Authorization: Bearer</em> box and open the console. Never touch the code field.',
        ],
        9 => [
            'Identity is resolved twice in this flow: once when the token is issued, once when it is redeemed. If the second resolution walks through a mutable field, everything that field can be changed to is in scope.',
            'Read the two lookups side by side. The address-change endpoint rejects duplicates with <code>WHERE email = ?</code>. The redemption path finds the account with <code>WHERE lower(email) = lower(?) ORDER BY id ASC</code>. One is case sensitive, the other is not.',
            'Get a token for your own account, then change the address on that account so that the redemption lookup resolves to a different row than the one the token was issued for.',
            'You need a string that the uniqueness check treats as new and the redemption lookup treats as the administrator\'s. Change one letter\'s case.',
            'Request a token for <code>guest@hackinlab.internal</code>, change your address to <code>ADMIN@hackinlab.internal</code> (accepted: no exact-match row exists), then redeem the token. The lowest matching row id is the real administrator.',
        ],
        10 => [
            'Everything on this page is a feature: a recovery form, a token, a sign-in box. The account takeover is what happens when they are used in the order the designers did not picture.',
            'This level\'s recovery form does not hide anything: it names the address it did or did not find, and it prints the server clock next to the token it issued. Both of those were separate levels earlier.',
            'Work in stages and confirm each one before moving on. Which of the candidate addresses exists? What does the confirmation reveal about how the token was built? What do you need to turn a token into a session?',
            'The flag needs two states at once: the administrator\'s stored hash must verify against a password you chose, and you must be holding a session that authenticated as the administrator.',
            'Enumerate &rarr; <code>admin@hackinlab.internal</code> exists &rarr; request a reset for it &rarr; compute <code>md5("admin@hackinlab.internal" . t)</code> for t around the printed clock &rarr; redeem &rarr; sign in with the password you set.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * Shared level plumbing
 * ===================================================================== */

/** Extra CSS every level page shares. */
function ar_extra_head(): string
{
    return '<style>
        .ar-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 0.6rem; }
        .ar-card { border: 1px solid rgba(255,255,255,0.09); border-radius: 0; padding: 0.7rem 0.8rem;
                   background: rgba(255,255,255,0.02); }
        .ar-card h5 { margin: 0 0 0.35rem; font-size: 0.7rem; letter-spacing: 0.08em;
                      text-transform: uppercase; opacity: 0.65; font-weight: 600; }
        .ar-step { border-left: 2px solid rgba(255,255,255,0.12); padding: 0.15rem 0 0.15rem 0.8rem;
                   margin: 0 0 1rem; }
        .ar-step > h4 { margin: 0 0 0.5rem; font-size: 0.82rem; letter-spacing: 0.02em; }
        .ar-actions { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin-top: 0.45rem; }
        .ar-toolbar { display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0 0 0.9rem; }
        .ar-toolbar form { margin: 0; }
        .ar-mono { font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 0.76rem;
                   word-break: break-all; }
        .ar-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
        .ar-table th, .ar-table td { text-align: left; padding: 0.3rem 0.5rem;
                                     border-bottom: 1px solid rgba(255,255,255,0.07); }
        .ar-table th { font-weight: 600; opacity: 0.7; font-size: 0.7rem;
                       text-transform: uppercase; letter-spacing: 0.05em; }
        .ar-hit { color: #7ee787; }
        .ar-miss { opacity: 0.55; }
        .ar-check { display: flex; flex-wrap: wrap; gap: 0.35rem 1.1rem; margin: 0.4rem 0 0.6rem; }
        .ar-check label { display: flex; gap: 0.4rem; align-items: center; font-size: 0.8rem; }
        pre.ar-json { background: rgba(0,0,0,0.35); border: 1px solid rgba(255,255,255,0.08);
                      border-radius: 0; padding: 0.7rem 0.8rem; font-size: 0.74rem;
                      overflow-x: auto; margin: 0.4rem 0 0; }
    </style>';
}

/**
 * "Reset this level" - handled before any output so the redirect works.
 * Every level page calls this immediately after loading helpers.
 */
function ar_handle_reset(int $level): void
{
    ar_ensure_level($level);
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['_reset_level'])) {
        ar_reset_level($level);
        header('Location: level' . $level . '.php?reset=1');
        exit;
    }
}

function ar_reset_button(int $level): string
{
    return '<form method="post" action="level' . $level . '.php" class="ar-reset-form" style="margin:0">'
         . '<input type="hidden" name="_reset_level" value="1">'
         . '<button type="submit" class="btn btn-outline">Reset this level</button></form>';
}

/** Links every level shows above the challenge: mailbox, collector, reset. */
function ar_toolbar(int $level, array $extra = []): string
{
    $out = '<div class="ar-toolbar">'
         . '<a class="btn btn-outline" href="mailbox.php?level=' . $level . '">Your mailbox &rarr;</a>';
    foreach ($extra as $label => $href) {
        $out .= '<a class="btn btn-outline" href="' . lk_esc($href) . '">' . lk_esc($label) . ' &rarr;</a>';
    }
    return $out . ar_reset_button($level) . '</div>';
}

function ar_ok(string $html): string
{
    return '<div class="message success">' . $html . '</div>';
}

function ar_err(string $html): string
{
    return '<div class="message error">' . $html . '</div>';
}

function ar_info(string $html): string
{
    return '<div class="message info">' . $html . '</div>';
}

/**
 * Current state of the target account, so the learner can see the state they
 * are trying to reach and confirm they reached it.
 */
function ar_admin_state_card(int $level, array $extraRows = []): string
{
    $admin = ar_admin($level);
    $rows  = [
        'account'         => lk_esc(AR_ADMIN),
        'password hash'   => '<span class="ar-mono">' . lk_esc(ar_fingerprint((string)$admin['password_hash'])) . '</span>',
        'address on file' => '<span class="ar-mono">' . lk_esc((string)$admin['email']) . '</span>',
    ];
    foreach ($extraRows as $k => $v) {
        $rows[$k] = $v;
    }
    $html = '<table class="lk-kv">';
    foreach ($rows as $k => $v) {
        $html .= '<tr><td>' . lk_esc((string)$k) . '</td><td>' . $v . '</td></tr>';
    }
    $html .= '</table>';

    return '<div class="lk-box"><h4><span class="lk-tag">TARGET STATE</span>What the database says right now</h4>'
         . '<div class="lk-body">' . $html
         . '<p class="lk-hintline">The hash fingerprint is <code>sha1(password_hash)[0:12]</code>. It changes when, '
         . 'and only when, the stored password actually changes.</p></div></div>';
}

/* =========================================================================
 * Learner sessions
 * ===================================================================== */

/**
 * The learner's session id for one level.
 *
 * Levels keep separate cookies so a session established in one level is
 * meaningless in another. Level 7 passes $forced, because accepting the id
 * from the request is the bug that level is about.
 */
function ar_sid(int $level, ?string $forced = null): string
{
    $name = 'ar_sid_l' . $level;
    $sid  = $forced !== null && $forced !== '' ? $forced : (string)($_COOKIE[$name] ?? '');

    if ($sid === '' || !preg_match('~^[A-Za-z0-9_.:-]{4,64}$~', $sid)) {
        $sid = bin2hex(random_bytes(12));
    }
    if (!headers_sent()) {
        setcookie($name, $sid, time() + 86400, '/');
    }
    $_COOKIE[$name] = $sid;
    return $sid;
}

/** Render the learner's session row for the trace. */
function ar_session_summary(?array $s): string
{
    if ($s === null) {
        return 'no session row';
    }
    return 'sid=' . $s['sid']
         . ' email=' . ($s['email'] ?? 'null')
         . ' authenticated=' . (int)$s['authenticated']
         . ' otp_verified=' . (int)$s['otp_verified'];
}

/* =========================================================================
 * Shared reset primitives used by several levels
 * ===================================================================== */

/**
 * Is this token row usable under the strict rules? Levels switch individual
 * checks off; this function is the yardstick their traces are compared against.
 *
 * @return array<string,bool>
 */
function ar_token_checks(?array $row): array
{
    $now = time();
    return [
        'row exists'                => $row !== null,
        'not already redeemed'      => $row !== null && $row['used_at'] === null,
        'not expired'               => $row !== null && ($row['expires_at'] !== null && (int)$row['expires_at'] > $now),
        'bound account resolvable'  => $row !== null && $row['user_id'] !== null,
    ];
}

function ar_bool_chip(bool $ok): string
{
    return $ok ? 'yes' : 'no';
}

/* =========================================================================
 * Page shell for the supporting endpoints (mailbox, collector, visitor)
 * ===================================================================== */

/**
 * The supporting pages are not challenges, so they do not use lk_page().
 * They share the lab header and stylesheet and nothing else.
 */
function ar_shell(string $title, string $subtitle, string $body, int $level = 0): void
{
    $lab = arlab();
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= lk_esc($title) ?> &mdash; <?= lk_esc($lab['name']) ?></title>
<link rel="stylesheet" href="css/styles.css">
<?= ar_extra_head() ?>
</head>
<body>
<header class="header">
    <div class="header-left">
        <h1><?= lk_esc($lab['icon']) ?> <?= lk_esc($lab['name']) ?></h1>
        <p><?= lk_esc($subtitle) ?></p>
    </div>
    <div class="header-right">
        <?php if ($level > 0): ?><a href="level<?= $level ?>.php" class="back-btn">&larr; Level <?= $level ?></a><?php endif; ?>
        <a href="index.php" class="back-btn">&larr; Levels</a>
    </div>
</header>
<div class="container">
<?= $body ?>
</div>
</body>
</html><?php
}
