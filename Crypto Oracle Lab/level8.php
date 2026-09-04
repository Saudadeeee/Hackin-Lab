<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 8;
$meta = crypto_levels()[$L];

$answer = trim((string)($_POST['answer'] ?? ''));
$probe  = (string)($_POST['probe'] ?? '');

$flag     = '';
$result   = '';
$pipeline = [];
$probeOut = '';

/** The vulnerable comparison, reproduced exactly as oracle.php runs it. */
function l8_slow_compare(string $given, string $secret): array
{
    $t0 = microtime(true);
    $ok = true;
    $n  = max(strlen($given), strlen($secret));
    $matched = 0;
    for ($i = 0; $i < $n; $i++) {
        if (($given[$i] ?? '') !== ($secret[$i] ?? '')) {
            $ok = false;
            break;
        }
        $matched++;
        usleep(12000);
    }
    return [$ok, $matched, (microtime(true) - $t0) * 1000];
}

if ($probe !== '') {
    [$ok, $matched, $ms] = l8_slow_compare($probe, cl_secret_l8());
    $probeOut = '<div class="message ' . ($ok ? 'success' : 'info') . '">'
        . 'response: <code>' . ($ok ? 'ok' : 'no') . '</code> &middot; elapsed <code>'
        . number_format($ms, 1) . ' ms</code></div>'
        . '<p class="text-muted">The response body is one of two words. The elapsed time is the channel that
           actually carries information: roughly 12 ms per byte the server was willing to keep comparing.</p>';
}

if ($answer !== '') {
    $ok = hash_equals(cl_secret_l8(), $answer);
    $pipeline = [
        ['label' => 'submitted token', 'value' => $answer],
        ['label' => 'constant-time comparison against the real token',
         'value' => $ok ? 'match' : 'no match', 'verdict' => $ok ? 'pass' : 'block'],
    ];
    if ($ok) {
        $flag   = crypto_flag($L);
        $result = '<div class="message success">Token recovered from timing alone.</div>';
    } else {
        $result = '<div class="message error">Not the token. Recover it left to right - each position is decided
            before you move on to the next.</div>';
    }
}

$code = <<<'PHP'
// Admin API token check. The loop exits at the first mismatch, and each
// matching byte costs a lookup.
function check_token(string $given): bool {
    $secret = ADMIN_TOKEN;
    $n = max(strlen($given), strlen($secret));
    for ($i = 0; $i < $n; $i++) {
        if (($given[$i] ?? '') !== ($secret[$i] ?? '')) {
            return false;              // <- early exit leaks the prefix length
        }
        usleep(12000);                 // stands in for a per-byte lookup
    }
    return true;
}
PHP;

$fixBad = <<<'PHP'
for ($i = 0; $i < $n; $i++) {
    if ($given[$i] !== $secret[$i]) { return false; }
}
return true;
PHP;

$fixGood = <<<'PHP'
// Compare every byte, every time, and let the answer depend on an
// accumulator rather than on control flow.
return hash_equals($secret, $given);      // constant time, length-safe

// If you must write it yourself:
//   $diff = strlen($a) ^ strlen($b);
//   for ($i = 0; $i < min(strlen($a), strlen($b)); $i++) {
//       $diff |= ord($a[$i]) ^ ord($b[$i]);
//   }
//   return $diff === 0;
//
// Better still: hash both sides with a keyed hash and compare the digests.
// Then the comparison operates on values an attacker cannot steer.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [7, 8, 10],
    'annotation' => 'The comparison returns as soon as two bytes differ, so its duration is proportional to the
        length of the correct prefix. The response body says nothing useful; the response <em>time</em> says how
        much of the guess was right.',

    'theory' => '<p>A secret is only as private as everything correlated with it. Time, response size, cache
        state, power draw and error wording are all channels, and a comparison loop with an early exit turns the
        first of them into a direct readout.</p>
        <p>What makes this powerful is the change of shape. Guessing a 16-character hex token blindly is
        <code>16^16</code> attempts. Recovering it one position at a time is <code>16 x 16 = 256</code>, because
        each position can be decided independently. Side channels usually collapse an exponential search into a
        linear one - that, rather than the leak itself, is the reason they matter.</p>
        <p>Real timing differences are microseconds, not milliseconds, so practical attacks take many samples per
        candidate and compare medians or low percentiles. The lab exaggerates the delay so the method is visible;
        the statistics you would use are the same.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Use the platform primitive: <code>hash_equals</code> in PHP, <code>crypto.timingSafeEqual</code>
            in Node, <code>hmac.compare_digest</code> in Python. Do not hand-roll it, and never short-circuit.',
    ],

    'scenario' => '<strong>Scenario:</strong> <code>oracle.php?level=8&amp;token=&lt;value&gt;</code> validates a
        16-character lowercase hex admin token and answers <code>ok</code> or <code>no</code>.
        <br><strong>Goal:</strong> recover the token and submit it.',

    'model' => [
        'title' => 'Turning time into bytes',
        'html'  => '<p>Alphabet: <code>0-9a-f</code>. Length: 16.</p>
        <ol>
            <li>Hold a known prefix (initially empty). For each of the 16 candidate characters, send
                <code>prefix + candidate</code> padded out to 16 characters with a fixed filler.</li>
            <li>Time each request several times and take the <strong>median</strong>. One candidate takes about
                12 ms longer than the rest, because the loop went one byte further before bailing out.</li>
            <li>Append the winner to the prefix and repeat.</li>
        </ol>
        <p>Expected requests: <code>16 positions x 16 candidates x samples</code>. With five samples that is 1,280
        requests - seconds of work for a search space of <code>16^16</code>.</p>
        <p>Read the timing table the Workbench prints rather than trusting a single measurement. If two candidates
        are within noise of each other, raise the sample count instead of guessing.</p>',
    ],

    'form' => '<form method="post" style="margin-bottom:1rem">
            <div class="form-group">
                <label class="form-label">Send one guess and see the elapsed time</label>
                <input type="text" name="probe" class="form-control cl-mono" spellcheck="false"
                       placeholder="0000000000000000" value="' . lk_esc($probe) . '">
            </div>
            <button class="btn btn-outline" type="submit">Check token</button>
        </form>' . $probeOut
        . crypto_answer_form('Recovered admin token', $answer, '16 lowercase hex characters'),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The token was never returned. It was measured.',
    'why'      => '<p>Each correct byte bought one more iteration of the loop before the early return, and one more
        iteration costs a fixed amount of time. So the response duration is a direct readout of how long your guess
        matched.</p>
        <p>Notice what the fix changes: <code>hash_equals</code> compares all bytes and accumulates the difference,
        so the duration no longer depends on where the first mismatch fell. The secret stops being correlated with
        anything the attacker can observe.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
