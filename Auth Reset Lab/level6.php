<?php
require_once __DIR__ . '/helpers.php';

$L = 6;
ar_handle_reset($L);
$meta = ar_levels()[$L];

/** The whole key space: six decimal digits. */
const AR_L6_SPACE      = 1000000;
/** How many candidates one press of the batch button will submit. */
const AR_L6_BATCH_CAP  = 250000;
/**
 * Attempts per second an attacker gets over the network against a server like
 * this one: roughly 150 on a single connection, twenty connections in
 * parallel. Used for the estimate that actually matters.
 */
const AR_L6_HTTP_RATE  = 3000;

$sid = ar_sid($L);
ar_session_touch($L, $sid);

$result   = '';
$pipeline = [];
$batch    = null;

/* ── Start a recovery ───────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['start'])
    && !isset($_POST['run_batch'])) {
    $target = trim((string)($_POST['target'] ?? AR_ADMIN));
    $user   = ar_user_by_email($L, $target);

    if ($user === null) {
        $result .= ar_err('No account is registered for <code>' . lk_esc($target) . '</code>.');
    } else {
        $code = str_pad((string)random_int(0, AR_L6_SPACE - 1), 6, '0', STR_PAD_LEFT);
        ar_token_insert($L, bin2hex(random_bytes(8)), $target, (int)$user['id'], 'otp', $code, null, null);
        ar_send_otp_mail($L, $target, $code);
        $result .= ar_info('A six digit code was mailed to <code>' . lk_esc($target) . '</code>. '
            . 'It is drawn from <code>random_int(0, 999999)</code>, so there is nothing to predict.');
    }
}

$target  = trim((string)($_POST['target'] ?? AR_ADMIN));
$attempt = ar_token_latest($L, $target, 'otp');

/**
 * The verifier, exactly as the application runs it for one request.
 * There is no attempt counter consulted, no delay, no lockout, and the code is
 * not invalidated by a wrong answer.
 */
function ar_l6_verify(int $level, string $email, string $code): array
{
    $row = ar_token_latest($level, $email, 'otp');
    if ($row === null) {
        return ['ok' => false, 'row' => null];
    }
    ar_token_bump_attempts((int)$row['id'], 1);   // written; nothing reads it
    return ['ok' => hash_equals((string)$row['otp_code'], $code), 'row' => $row];
}

/**
 * The same verifier run over a contiguous range of candidates inside one
 * request, so the arithmetic below can be observed in seconds.
 *
 * In production every attempt is its own HTTP request and its own row read.
 * The row is re-read here every thousand candidates for the same reason: to
 * show that there is no lockout state for a repeated attempt to find.
 */
function ar_l6_batch(int $level, string $email, int $start, int $count): array
{
    $row = ar_token_latest($level, $email, 'otp');
    if ($row === null) {
        return ['ran' => false, 'hit' => null, 'n' => 0, 'elapsed' => 0.0, 'rate' => 0.0, 'row' => null];
    }

    $secret = (string)$row['otp_code'];
    $t0     = microtime(true);
    $n      = 0;
    $hit    = null;
    $end    = min($start + $count, AR_L6_SPACE);

    for ($i = max(0, $start); $i < $end; $i++) {
        $n++;
        $candidate = str_pad((string)$i, 6, '0', STR_PAD_LEFT);
        if (hash_equals($secret, $candidate)) {
            $hit = $candidate;
            break;
        }
        if ($n % 1000 === 0) {
            $row    = ar_token_latest($level, $email, 'otp');
            $secret = (string)$row['otp_code'];
        }
    }

    $elapsed = microtime(true) - $t0;
    ar_token_bump_attempts((int)$row['id'], $n);

    return [
        'ran'     => true,
        'hit'     => $hit,
        'n'       => $n,
        'from'    => max(0, $start),
        'to'      => $end - 1,
        'elapsed' => $elapsed,
        'rate'    => $elapsed > 0 ? $n / $elapsed : 0.0,
        'row'     => ar_token_latest($level, $email, 'otp'),
    ];
}

/** A correct code establishes the authenticated session. That is the state. */
function ar_l6_grant(int $level, string $sid, string $email): void
{
    ar_session_authenticate($level, $sid, $email, 1, 'recovery completed with a one-time code');
    if (strcasecmp($email, AR_ADMIN) === 0) {
        ar_mark_win($level, 'authenticated as ' . AR_ADMIN . ' after brute forcing the one-time code');
    }
}

/* ── One attempt ────────────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify'])) {
    $code = trim((string)($_POST['code'] ?? ''));
    $v    = ar_l6_verify($L, $target, $code);

    if ($v['row'] === null) {
        $result .= ar_err('No recovery is in progress for <code>' . lk_esc($target) . '</code>.');
    } elseif ($v['ok']) {
        ar_l6_grant($L, $sid, $target);
        $result .= ar_ok('Code accepted. You are signed in as <code>' . lk_esc($target) . '</code>.');
    } else {
        $result .= ar_err('That code is not correct. Nothing else happened: no counter was consulted, no delay was '
            . 'added, and the code is still live.');
    }
}

/* ── A batch of attempts ────────────────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run_batch'])) {
    $start = max(0, (int)($_POST['from'] ?? 0));
    $count = min(AR_L6_BATCH_CAP, max(1, (int)($_POST['count'] ?? AR_L6_BATCH_CAP)));
    $batch = ar_l6_batch($L, $target, $start, $count);

    if (!$batch['ran']) {
        $result .= ar_err('No recovery is in progress for <code>' . lk_esc($target) . '</code>.');
    } elseif ($batch['hit'] !== null) {
        ar_l6_grant($L, $sid, $target);
        $result .= ar_ok('Code <code>' . lk_esc($batch['hit']) . '</code> accepted after '
            . number_format($batch['n']) . ' attempts in this batch. You are signed in as <code>'
            . lk_esc($target) . '</code>.');
    } else {
        $result .= ar_info('No hit in ' . number_format((int)$batch['from']) . '&ndash;'
            . number_format((int)$batch['to']) . '. Every one of those attempts was accepted and answered.');
    }
}

$session = ar_session_get($L, $sid);
$isAdmin = $session !== null && (int)$session['authenticated'] === 1
        && strcasecmp((string)$session['email'], AR_ADMIN) === 0;
$flag    = ($isAdmin && ar_win($L)) ? ar_flag($L) : '';

$attempt   = ar_token_latest($L, $target, 'otp');
$totalTry  = $attempt ? (int)$attempt['attempts'] : 0;
$remaining = max(0, AR_L6_SPACE - $totalTry);

/* ── Trace ───────────────────────────────────────────────────────────────── */
if ($attempt !== null) {
    $pipeline[] = [
        'label' => 'recovery record for ' . $target,
        'value' => 'kind=otp  digits=6  expires_at=' . ($attempt['expires_at'] === null ? 'NULL' : (int)$attempt['expires_at'])
                 . '  attempts=' . $totalTry,
        'note'  => 'The <code>attempts</code> column is incremented by every guess and is not part of any condition '
                 . 'in the verifier. Neither is a clock.',
    ];
}
if ($batch !== null && $batch['ran']) {
    $pipeline[] = [
        'label'   => 'batch ' . number_format((int)$batch['from']) . '-' . number_format((int)$batch['to']),
        'value'   => number_format($batch['n']) . ' attempts in ' . sprintf('%.3f s', $batch['elapsed'])
                   . ' = ' . number_format($batch['rate']) . ' attempts/second',
        'note'    => 'Measured in this process, so it excludes the network. Use it to sanity check the model, not to '
                   . 'estimate a real attack.',
        'verdict' => $batch['hit'] !== null ? 'pass' : 'block',
    ];
    $pipeline[] = [
        'label' => 'what distinguishes a hit from a miss',
        'value' => $batch['hit'] !== null
            ? 'hash_equals("' . $batch['hit'] . '", stored) returned true'
            : 'hash_equals(candidate, stored) returned false ' . number_format($batch['n']) . ' times',
        'note'  => 'One boolean. Same status code, same body length, same time, no counter moving anywhere that '
                 . 'affects the next request. A miss costs the attacker nothing.',
    ];
    $pipeline[] = [
        'label' => 'search remaining',
        'value' => number_format($remaining) . ' of ' . number_format(AR_L6_SPACE) . ' candidates untested',
        'note'  => 'Expected attempts to a hit from a cold start: ' . number_format(AR_L6_SPACE / 2)
                 . '. At ' . number_format(AR_L6_HTTP_RATE) . ' attempts/second over the network that is about '
                 . number_format(AR_L6_SPACE / 2 / AR_L6_HTTP_RATE) . ' seconds.',
    ];
}
if ($session !== null) {
    $pipeline[] = [
        'label'   => 'session row after the attempt',
        'value'   => ar_session_summary($session),
        'note'    => 'The flag depends on this row, not on the code you typed.',
        'verdict' => $isAdmin ? 'pass' : null,
    ];
}

/* ── Form ────────────────────────────────────────────────────────────────── */
ob_start(); ?>
<?= ar_toolbar($L) ?>

<div class="ar-step">
    <h4>1 &middot; Start a recovery</h4>
    <form method="post" action="level6.php">
        <input type="hidden" name="start" value="1">
        <div class="form-group">
            <label class="form-label">Address to recover</label>
            <input type="text" name="target" class="form-control" autocomplete="off" value="<?= lk_esc($target) ?>">
        </div>
        <button class="btn btn-primary" type="submit">Send a one-time code</button>
    </form>
</div>

<div class="ar-step">
    <h4>2 &middot; Enter the code</h4>
    <form method="post" action="level6.php">
        <input type="hidden" name="verify" value="1">
        <input type="hidden" name="target" value="<?= lk_esc($target) ?>">
        <div class="form-group">
            <label class="form-label">Six digit code</label>
            <input type="text" name="code" class="form-control ar-mono" autocomplete="off" maxlength="6"
                   inputmode="numeric" value="">
        </div>
        <button class="btn btn-primary" type="submit">Verify</button>
    </form>
</div>

<div class="ar-step">
    <h4>3 &middot; Or submit a range of them</h4>
    <p class="lk-hintline">Each candidate in the range goes through the same verifier the form above uses. The
       batch exists so the arithmetic finishes while you are reading it; work out the answer before you press the
       button, then check it against the measured rate in the trace.</p>
    <form method="post" action="level6.php">
        <input type="hidden" name="run_batch" value="1">
        <input type="hidden" name="target" value="<?= lk_esc($target) ?>">
        <div class="ar-grid">
            <div class="form-group">
                <label class="form-label">Start at</label>
                <input type="number" name="from" class="form-control ar-mono" min="0" max="999999"
                       value="<?= (int)($_POST['from'] ?? 0) ?>">
            </div>
            <div class="form-group">
                <label class="form-label">How many (max <?= number_format(AR_L6_BATCH_CAP) ?>)</label>
                <input type="number" name="count" class="form-control ar-mono" min="1" max="<?= AR_L6_BATCH_CAP ?>"
                       value="<?= (int)($_POST['count'] ?? AR_L6_BATCH_CAP) ?>">
            </div>
        </div>
        <button class="btn btn-primary" type="submit">Run the batch</button>
    </form>
</div>

<div class="lk-box"><h4><span class="lk-tag">CONSOLE</span>Where you are</h4><div class="lk-body">
    <table class="lk-kv">
        <tr><td>your session</td><td class="ar-mono"><?= lk_esc(ar_session_summary($session)) ?></td></tr>
        <tr><td>attempts recorded</td><td><?= number_format($totalTry) ?> of <?= number_format(AR_L6_SPACE) ?></td></tr>
        <tr><td>administrator console</td><td><?= $isAdmin ? 'open' : 'locked' ?></td></tr>
    </table>
</div></div>
<?php $form = (string)ob_get_clean();

$code = <<<'PHP'
// POST /recover/verify
$row = db()->query(
    'SELECT * FROM otp_codes WHERE email = ? ORDER BY id DESC LIMIT 1',
    [$email]
);
if ($row === null) {
    return deny('no recovery in progress');
}

// Bookkeeping. Written every time, read never.
db()->exec('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?', [$row->id]);

if (!hash_equals($row->code, $_POST['code'])) {
    return deny('incorrect code');      // same status, same body, same time
}

login($email);                           // the recovery succeeds
PHP;

$fixBad = <<<'PHP'
db()->exec('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?', [$row->id]);
if (!hash_equals($row->code, $_POST['code'])) {
    return deny('incorrect code');
}
PHP;

$fixGood = <<<'PHP'
// The counter has to be a condition, not a statistic.
if ($row->attempts >= 5 || $row->expires_at <= time()) {
    invalidate($row);                    // burn the code, force a new request
    return deny('too many attempts');
}
db()->exec('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?', [$row->id]);

if (!hash_equals($row->code, $_POST['code'])) {
    return deny('incorrect code');
}
invalidate($row);                        // single use on success as well

// Three independent limits, because each one fails differently:
//   per code    - at most N attempts, then the code dies
//   per account - at most M recovery attempts per hour, whatever the code
//   per source  - a global rate limit, so a botnet costs something too
//
// And raise the entropy while you are there: eight digits is 100x the work
// for the attacker and two extra characters for the user.
PHP;

lk_page([
    'lab'        => arlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => ar_extra_head(),

    'code'       => $code,
    'vuln_lines' => [11, 13, 14, 15],
    'annotation' => 'The code is drawn from a proper random source and compared in constant time, so there is
        nothing to predict and nothing to leak. The defect is that a wrong answer costs the attacker nothing: the
        counter is written and never read, the code survives the miss, and the next request is as good as the
        first.',

    'theory' => '<p>Entropy is not a defence on its own. It is one term in a product, and the other term is how
        many guesses the system will accept. A six digit code is about 20 bits, which is plenty if the answer must
        be produced in five tries and worth nothing if it may be produced in a million. The security of an OTP is
        <em>entropy relative to the attempt budget</em>, and only one of those two numbers usually appears in the
        design document.</p>
        <p>Three limits are needed, because each covers what the others miss. A per-code counter stops a million
        guesses against one code. A per-account limit stops the attacker restarting the recovery to reset that
        counter &mdash; which is the usual bypass, and the reason a per-code counter alone is often theatre. A
        per-source limit makes the whole activity cost something even when it is spread across many accounts.</p>
        <p>The report to write is not "the code can be brute forced". It is "an unauthenticated caller reaches an
        authenticated session for any account in about three minutes of sustained requests, because nothing limits
        attempts". The number is the finding. It is also what turns a disputed severity rating into an agreed
        one.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Invalidating the code on success matters as much as the counter: without it, a code that was
            correct once stays correct, which is level 5 in a different costume.',
    ],

    'scenario' => '<strong>Scenario:</strong> account recovery sends a six digit code to the address on file. The
        code is random, the comparison is constant time, and the attempt counter is recorded for the support team.
        <br><strong>Goal:</strong> reach the administrator console without the code being shown to you &mdash; and
        be able to state, before you start, roughly how long it will take.',

    'model' => [
        'title' => 'The arithmetic, before you press anything',
        'html'  => '<table class="lk-kv">
            <tr><td>key space</td><td>10<sup>6</sup> = 1,000,000 codes, uniform</td></tr>
            <tr><td>expected attempts</td><td>500,000 (half the space; worst case 1,000,000)</td></tr>
            <tr><td>attempts allowed</td><td>unbounded &mdash; the counter is not a condition</td></tr>
            <tr><td>rate over the network</td><td>about 150/second on one connection; about 3,000/second across
                twenty. Nothing here throttles concurrency.</td></tr>
            <tr><td><strong>expected wall clock</strong></td><td><strong>500,000 &divide; 3,000 &asymp; 167 seconds</strong></td></tr>
            <tr><td>with a five attempt cap</td><td>probability of success per code = 5/10<sup>6</sup> = 0.0005%.
                The same code, the same entropy, a different outcome.</td></tr>
        </table>
        <p>The last two rows are the finding. The size of the code barely moves the answer; the attempt budget
        moves it by five orders of magnitude.</p>
        <p>The batch runner below submits a contiguous range through the real verifier so you can watch this
        happen in seconds rather than minutes. It measures the in-process rate, which is much higher than an
        attacker would get over HTTP &mdash; the trace prints both, and the one that belongs in a report is the
        network figure.</p>',
    ],

    'form'     => $form,
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Twenty bits of entropy and an unlimited budget is not twenty bits of security.',
    'why'      => '<p>Nothing about the code was weak. It came from <code>random_int()</code>, it was six digits
        as designed, and it was compared with <code>hash_equals()</code>. You found it by asking the server a
        million yes/no questions, and the server answered every one of them at the same speed with the same
        response.</p>
        <p>The flag came from the sessions table: a row for this browser with <code>authenticated=1</code> and
        <code>email=admin@hackinlab.internal</code>, written by the application\'s own success path. That is the
        state a correct answer produces, and it is the only thing this page checks.</p>
        <p>Carry the arithmetic, not the exploit. Whenever you meet a numeric code, ask for the attempt budget in
        the same breath. Six digits with five attempts is strong; six digits with no limit is a delay, and the
        length of the delay is a division you can do in your head.</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'probe',
        'method' => 'GET',
        'action' => 'level6.php',
        'items'  => [
            ['q' => 'Does a wrong answer change anything for the next request?',
             'payload' => 'submit 000000 twice and compare',
             'learn'   => 'Send an obviously wrong code twice through step 2. Identical responses, and the console still shows the recovery in progress, means no state was consumed by the failure.'],
            ['q' => 'Does the counter in the console affect the verifier?',
             'payload' => 'run one small batch, then one attempt',
             'learn'   => 'Run a batch of 1,000, watch the attempts figure move, then submit a single code. If the single attempt behaves exactly as it did before, the counter is a statistic.'],
            ['q' => 'Is the code invalidated by restarting the recovery?',
             'payload' => 'press step 1 again',
             'learn'   => 'A new code is issued and becomes the newest row. Worth knowing: if you have already searched part of the space, restarting throws that work away.'],
        ],
    ],
    'hints' => ar_hints($L),
]);
