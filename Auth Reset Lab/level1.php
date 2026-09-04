<?php
require_once __DIR__ . '/helpers.php';

$L = 1;
ar_handle_reset($L);
$meta = ar_levels()[$L];

/** Anything slower than this is doing work that only a real account triggers. */
const AR_L1_THRESHOLD_MS = 25.0;

/**
 * The real handler behind POST /forgot-password.
 *
 * The sentence it returns is the same for every address. The amount of work it
 * does to produce that sentence is not.
 */
function ar_l1_request(int $level, string $email): array
{
    $t0   = microtime(true);
    $user = ar_user_by_email($level, $email);

    if ($user !== null) {
        $token = bin2hex(random_bytes(16));

        // Reset tokens are stored as a bcrypt digest so a database leak cannot
        // be replayed as a set of live links. That is the right call. It is
        // also about 100 ms of work that only ever runs for real accounts.
        $digest = password_hash($token, PASSWORD_BCRYPT, ['cost' => 11]);

        ar_token_insert($level, $token, $email, (int)$user['id'], 'reset', $digest);
        ar_send_reset_mail($level, $email, $token, ar_reset_link($token));
    }

    $ms = (microtime(true) - $t0) * 1000;
    ar_probe_log($level, $email, $ms);

    return [
        'email'   => $email,
        'ms'      => $ms,
        'message' => 'If that address is registered, we have sent reset instructions to it.',
    ];
}

$candidates = ar_l1_candidates();
$measured   = [];
$result     = '';
$classify   = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['measure_all'])) {
    foreach ($candidates as $c) {
        $measured[] = ar_l1_request($L, $c);
    }
    $result = ar_info('Sent one request per candidate and recorded the elapsed server time for each.');
} else {
    $single = trim((string)($_REQUEST['email'] ?? ''));
    if ($single !== '') {
        $measured[] = ar_l1_request($L, $single);
        $result = ar_info('Server said: <em>&ldquo;If that address is registered, we have sent reset instructions '
            . 'to it.&rdquo;</em> &mdash; the same sentence you get for every address.');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['classify'])) {
    $classify = array_values(array_intersect($candidates, (array)($_POST['exists'] ?? [])));
}

/* ── Award: the classification is right AND every address was really measured ── */
$probed    = ar_probed_addresses($L);
$unprobed  = array_values(array_diff($candidates, $probed));
$expected  = ar_l1_existing();

if ($classify !== null) {
    sort($classify);
    $want = $expected;
    sort($want);
    if ($classify === $want && !$unprobed) {
        ar_mark_win($L, 'enumerated ' . count($want) . ' live accounts from ' . count($candidates) . ' candidates');
        $result .= ar_ok('Classification correct, and every candidate in the list was measured at least once.');
    } elseif ($unprobed) {
        $result .= ar_err('You have not measured ' . count($unprobed) . ' of the addresses yet ('
            . lk_esc(implode(', ', $unprobed)) . '). Measure the whole list before classifying it.');
    } else {
        $wrong = count(array_diff($classify, $want)) + count(array_diff($want, $classify));
        $result .= ar_err('Classification rejected: ' . $wrong . ' address(es) are on the wrong side. Re-read the timings.');
    }
}

$flag = ar_win($L) ? ar_flag($L) : '';

/* ── Trace ───────────────────────────────────────────────────────────────── */
$pipeline = [];
if ($measured) {
    $pipeline[] = [
        'label' => 'response body (identical for every request)',
        'value' => 'If that address is registered, we have sent reset instructions to it.',
        'note'  => 'Nothing to read here. The wording was fixed before you arrived.',
    ];
    foreach ($measured as $m) {
        $hit = $m['ms'] >= AR_L1_THRESHOLD_MS;
        $pipeline[] = [
            'label'   => 'elapsed for ' . $m['email'],
            'value'   => sprintf('%.2f ms', $m['ms']),
            'note'    => $hit
                ? 'Above the ' . AR_L1_THRESHOLD_MS . ' ms line: the handler took the branch that generates a token '
                  . 'and bcrypts it. That branch only exists for real accounts.'
                : 'Below the ' . AR_L1_THRESHOLD_MS . ' ms line: one indexed lookup returned nothing and the function returned.',
            'verdict' => $hit ? 'pass' : 'block',
        ];
    }
}
if ($classify !== null) {
    $pipeline[] = [
        'label'   => 'submitted classification',
        'value'   => implode(', ', $classify) ?: '(nothing selected)',
        'note'    => 'Checked against the users table for level 1, and against the probe log, which records every '
                   . 'address you actually measured.',
        'verdict' => $flag !== '' ? 'pass' : 'block',
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Measure one address</h4>
    <form method="get" action="level1.php">
        <div class="form-group">
            <label class="form-label">Email address</label>
            <input type="text" name="email" class="form-control" autocomplete="off" spellcheck="false"
                   value="<?= lk_esc((string)($_GET['email'] ?? '')) ?>" placeholder="someone@hackinlab.internal">
        </div>
        <button class="btn btn-primary" type="submit">Send reset request</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Measure the whole candidate list</h4>
    <p class="lk-hintline">Eight addresses, one request each. The table below is the raw elapsed time the server
       spent inside the handler &mdash; no network noise, because the clock starts and stops in the same process.</p>
    <form method="post" action="level1.php">
        <input type="hidden" name="measure_all" value="1">
        <button class="btn btn-primary" type="submit">Measure every address</button>
    </form>
    <?php if ($measured && count($measured) > 1): ?>
    <table class="ar-table" style="margin-top:0.7rem">
        <tr><th>address</th><th>elapsed</th><th>reading</th></tr>
        <?php foreach ($measured as $m): $hit = $m['ms'] >= AR_L1_THRESHOLD_MS; ?>
        <tr>
            <td class="ar-mono"><?= lk_esc($m['email']) ?></td>
            <td class="ar-mono"><?= sprintf('%.2f ms', $m['ms']) ?></td>
            <td class="<?= $hit ? 'ar-hit' : 'ar-miss' ?>"><?= $hit ? 'account exists' : 'no account' ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <?php endif; ?>
</div>

<div class="ar-step">
    <h4>3 &middot; Submit the classification</h4>
    <p class="lk-hintline">Tick every address you believe has an account. Addresses you have never measured are
       listed as unmeasured &mdash; the submission is refused until the list is complete, because the finding is the
       measurement, not the answer.</p>
    <form method="post" action="level1.php">
        <input type="hidden" name="classify" value="1">
        <div class="ar-check">
            <?php foreach ($candidates as $c):
                $seen = in_array($c, $probed, true);
                $on   = $classify !== null && in_array($c, $classify, true); ?>
                <label>
                    <input type="checkbox" name="exists[]" value="<?= lk_esc($c) ?>" <?= $on ? 'checked' : '' ?>>
                    <span class="ar-mono"><?= lk_esc($c) ?></span>
                    <span class="<?= $seen ? 'ar-hit' : 'ar-miss' ?>"><?= $seen ? '(measured)' : '(unmeasured)' ?></span>
                </label>
            <?php endforeach; ?>
        </div>
        <button class="btn btn-primary" type="submit">Submit classification</button>
    </form>
</div>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /forgot-password
function request_reset(string $email): string
{
    $user = user_by_email($email);

    if ($user !== null) {
        $token  = bin2hex(random_bytes(16));
        // Store the digest, not the token: a database leak must not hand out
        // live reset links. Correct - and only ever reached for real accounts.
        $digest = password_hash($token, PASSWORD_BCRYPT, ['cost' => 11]);
        store_token($user, $digest);
        send_reset_mail($email, $token);
    }

    // One sentence for everybody. Reviewed, signed off, and useless.
    return 'If that address is registered, we have sent reset instructions to it.';
}
PHP;

$fixBad = <<<'PHP'
if ($user !== null) {
    $digest = password_hash($token, PASSWORD_BCRYPT, ['cost' => 11]);
    store_token($user, $digest);
    send_reset_mail($email, $token);
}
return 'If that address is registered, we have sent reset instructions to it.';
PHP;

$fixGood = <<<'PHP'
// Hand the work to a queue and answer immediately. Both branches now do the
// same thing in the request: enqueue nothing of consequence and return.
if ($user !== null) {
    ResetQueue::push($user->id);          // milliseconds, no hashing here
}
return 'If that address is registered, we have sent reset instructions to it.';

// If the work genuinely has to happen inline, pay the same cost either way:
//
//   $user = user_by_email($email);
//   $target = $user ?? User::decoy();     // a fixed non-account
//   $digest = password_hash(random_token(), PASSWORD_BCRYPT, ['cost' => 11]);
//   if ($user !== null) { store_token($user, $digest); send_reset_mail(...); }
//
// and enforce the shape with a test that asserts the two paths differ by
// less than a few milliseconds, so a later refactor cannot reopen the gap.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 6, 9, 10, 11, 12],
    'annotation' => 'The response text was made uniform and the response <em>time</em> was not. An address that
        exists costs one bcrypt hash at cost 11 plus a database write; an address that does not exist costs one
        indexed <code>SELECT</code> that returns nothing. The two answers differ by about two orders of magnitude,
        which is far more signal than a difference in wording would have given.',

    'theory' => '<p>Account enumeration is the habit of letting an unauthenticated stranger ask "does this person
        have an account here" and getting a reliable answer. It is rarely the finding on its own; it is the step
        that makes every later step cheaper. Credential stuffing against a verified list has a far better hit rate,
        phishing that names a real service is more convincing, and a targeted password spray needs a target.</p>
        <p>Teams usually fix the obvious channel first: the error text. That is the visible one, so it gets a
        ticket. Underneath it, four other channels usually survive &mdash; the HTTP status code, the number of
        redirects, the length of the response body, and the time the server spent producing it. Timing is the one
        that survives longest, because it is not written anywhere in the code. It is an emergent property of which
        branch ran.</p>
        <p>The tell to look for during review is <em>asymmetric work</em>. Any <code>if (found) { expensive }</code>
        in an endpoint that anonymous users can reach is an oracle, whatever the response says. Password
        verification is the classic example: a login that only calls <code>password_verify()</code> when the user
        exists tells you which usernames are real, no matter how carefully the failure message was written.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Uniform wording is necessary and not sufficient. The rule that actually holds is: for any two
            inputs an anonymous caller can supply, the observable response must be indistinguishable &mdash; body,
            status, headers, and duration.',
    ],

    'scenario' => '<strong>Scenario:</strong> the recovery form was hardened after a report about its error
        messages. Every address now gets the same sentence back.
        <br><strong>Goal:</strong> decide which of the eight addresses on the right have accounts, measure every
        one of them, and submit the classification.',

    'model' => [
        'title' => 'The arithmetic before you start',
        'html'  => '<table class="lk-kv">
            <tr><td>address does not exist</td><td>one indexed SELECT, no rows &rarr; ~0.2&ndash;1 ms</td></tr>
            <tr><td>address exists</td><td>the same SELECT, plus <code>password_hash(cost 11)</code> &asymp; 2<sup>11</sup>
                bcrypt rounds, plus an INSERT and a mail write &rarr; ~90&ndash;150 ms</td></tr>
            <tr><td>separation</td><td>roughly 100&times;. A threshold anywhere between 5 ms and 50 ms classifies
                correctly, so you do not need a careful statistic &mdash; one sample per address is enough.</td></tr>
            <tr><td>cost of the attack here</td><td>8 addresses &times; 1 request &asymp; 0.4 s of server time</td></tr>
            <tr><td>cost against a real target</td><td>at 20 requests/second over the network, a 10,000 name list
                takes about 8 minutes. Network jitter is tens of milliseconds; the signal is a hundred. It still
                separates.</td></tr>
        </table>
        <p>That last row is the point. Before running anything, you can state what the attack will cost and what
        it will return. If the two branches had been within a millisecond of each other, no number of samples would
        have helped, and the correct conclusion would have been "not enumerable by timing" rather than "try
        harder".</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The form told you nothing and answered anyway.',
    'why'      => '<p>The handler has one branch that costs a bcrypt hash and one that costs an index lookup. The
        sentence returned by both is identical, so the body carries no information &mdash; but the duration does,
        and duration is part of the response whether or not anyone decided it should be.</p>
        <p>Your measurements separate into two clusters about a hundred times apart, which is why a single sample
        per address was enough. Against a noisier target you would take the median of a few samples per candidate;
        the method does not change, only the sample count.</p>
        <p>What you now have is a verified list of four live accounts, including the administrator address that the
        rest of this lab attacks. Note how little the form gave up on purpose, and how much it gave up anyway.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'email',
        'method' => 'GET',
        'action' => 'level1.php',
        'items'  => [
            ['q' => 'Does the wording change for an address that certainly does not exist?',
             'payload' => 'nobody-1234@hackinlab.internal',
             'learn'   => 'Establishes the baseline response, and the baseline duration. Both matter; only one of them is stable.'],
            ['q' => 'What does an address you know exists cost?',
             'payload' => AR_GUEST,
             'learn'   => 'Your own account is a known-positive control. Without one you cannot tell whether a slow response means "exists" or "the server was busy".'],
            ['q' => 'Does a syntactically invalid address take the fast path too?',
             'payload' => 'not-an-address',
             'learn'   => 'If malformed input is rejected before the lookup, its timing is a third cluster, and mixing it into your data would blur the boundary. Know which of your samples are comparable.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
