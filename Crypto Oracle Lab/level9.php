<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/secrets.php';

$L    = 9;
$meta = crypto_levels()[$L];

$adminSeed  = cl_l9_admin_seed();
$adminToken = cl_l9_token_from_seed($adminSeed);
$windowFrom = 1756900000;
$windowTo   = 1756900180;
$prefix     = substr($adminToken, 0, 6);

$answer = trim((string)($_POST['answer'] ?? ''));
$issue  = isset($_POST['issue']);

$flag     = '';
$result   = '';
$pipeline = [];
$issued   = '';

if ($issue) {
    $t = time();
    $issued = '<div class="lk-box"><h4><span class="lk-tag">ISSUED</span>A token for your own session</h4>'
        . '<div class="lk-body"><table class="lk-kv">'
        . '<tr><td>server time (seed)</td><td>' . $t . '</td></tr>'
        . '<tr><td>token</td><td>' . cl_l9_token_from_seed($t) . '</td></tr>'
        . '</table><p class="text-muted" style="margin-top:0.4rem">Reproduce this locally with the same seed to
           confirm you have the generation algorithm right before attacking the admin token.</p></div></div>';
}

if ($answer !== '') {
    $ok = hash_equals($adminToken, strtolower($answer));
    $pipeline = [
        ['label' => 'submitted token', 'value' => $answer],
        ['label' => 'compare against the administrator session token',
         'value' => $ok ? 'match' : 'no match', 'verdict' => $ok ? 'pass' : 'block'],
    ];
    if ($ok) {
        $flag   = crypto_flag($L);
        $result = '<div class="message success">Predicted. The token was never guessed - it was regenerated.</div>';
    } else {
        $result = '<div class="message error">Not the administrator token. Confirm your generator against a token
            you were issued, then search the disclosed window.</div>';
    }
}

$code = <<<'PHP'
// Session tokens. "Random enough - it is 16 hex characters."
function new_session_token(): string {
    mt_srand(time());                      // seed = the current second
    $t = '';
    for ($i = 0; $i < 4; $i++) {
        $t .= str_pad(dechex(mt_rand(0, 0xFFFF)), 4, '0', STR_PAD_LEFT);
    }
    return $t;                             // 64 bits of output, ~8 bits of entropy
}
PHP;

$fixBad = <<<'PHP'
mt_srand(time());
$token = dechex(mt_rand()) . dechex(mt_rand());
PHP;

$fixGood = <<<'PHP'
// A CSPRNG, seeded by the OS, with no recoverable state.
$token = bin2hex(random_bytes(32));        // PHP 7+, throws if no good source

// Node:    crypto.randomBytes(32).toString('hex')
// Python:  secrets.token_hex(32)
// Go:      crypto/rand, never math/rand
// Java:    SecureRandom, never Random
//
// The distinction is not "how random does it look" but "can an observer who
// sees some output predict the rest". Mersenne Twister fails that test even
// when seeded well: 624 consecutive outputs reveal the entire internal state.
PHP;

lk_page([
    'lab'        => cryptolab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => crypto_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 8],
    'annotation' => 'The token has 64 output bits and about 8 bits of real entropy, because the only unknown is
        which second the generator was seeded in. Output length is not entropy.',

    'theory' => '<p><code>mt_rand()</code> is a Mersenne Twister: excellent statistical properties, zero resistance
        to prediction. Its entire future output is a function of a 32-bit state, and that state is derived here from
        a timestamp an attacker can narrow to a few hundred possibilities.</p>
        <p>Two independent failures are stacked, and both are worth recognising on their own:</p>
        <ul>
            <li><strong>Wrong generator.</strong> Even seeded from a perfect source, MT is predictable: 624
                consecutive 32-bit outputs let an observer reconstruct the state and roll it forwards or backwards.</li>
            <li><strong>Wrong seed.</strong> <code>time()</code> is public. Any attacker who knows roughly when a
                token was issued knows the seed to within a small window.</li>
        </ul>
        <p>The give-away in real code is a token built out of <code>rand</code>, <code>mt_rand</code>,
        <code>uniqid</code>, <code>microtime</code> or a hash of those. If you can name the inputs, so can an
        attacker.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Ask "how many values would an attacker have to try", not "how long is the string". A 64-character
            token derived from a 32-bit seed has 32 bits of entropy at best.',
    ],

    'scenario' => '<strong>Scenario:</strong> the administrator signed in during a window the support log
        discloses, and a status widget shows the first six characters of the active admin session token.
        <br><strong>Goal:</strong> recover the full token.',

    'model' => [
        'title' => 'The search, sized in advance',
        'html'  => '<table class="lk-kv">
            <tr><td>token space if random</td><td>16^16 = 2^64</td></tr>
            <tr><td>actual key space</td><td>one second in the disclosed window: <strong>' . ($windowTo - $windowFrom + 1) . '</strong> candidates</td></tr>
            <tr><td>window</td><td>' . $windowFrom . ' .. ' . $windowTo . ' (unix seconds)</td></tr>
            <tr><td>known prefix</td><td><code>' . $prefix . '</code> (from the status widget)</td></tr>
        </table>
        <p>For each candidate second <code>t</code>: <code>mt_srand($t)</code>, generate the token the same way the
        server does, and keep the one whose first six characters match the prefix. Confirm your generator first
        against a token issued to you, where the seed is disclosed.</p>
        <p>PHP note: <code>mt_srand()</code> resets a global state, so generate each candidate in its own loop
        iteration and do not interleave other <code>mt_rand()</code> calls.</p>',
    ],

    'form' => '<div class="lk-box"><h4><span class="lk-tag">DISCLOSED</span>What the application leaks</h4>
        <div class="lk-body"><table class="lk-kv">
            <tr><td>admin signed in between</td><td>' . $windowFrom . ' and ' . $windowTo . '</td></tr>
            <tr><td>status widget shows</td><td><code>' . $prefix . '...</code></td></tr>
        </table></div></div>
        <form method="post" style="margin-bottom:1rem">
            <input type="hidden" name="issue" value="1">
            <button class="btn btn-outline" type="submit">Issue me a token (seed disclosed)</button>
        </form>' . $issued
        . crypto_answer_form('Full administrator token', $answer, '16 lowercase hex characters'),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'Regenerated, not guessed.',
    'why'      => '<p>You reproduced the server\'s generator exactly and enumerated its only unknown input. The
        prefix from the status widget then identified which of the few hundred candidates was the real one.</p>
        <p>Nothing about the token\'s <em>appearance</em> changed between the vulnerable and the fixed version -
        both look like random hex. What changed is whether an attacker can name the inputs. That is the question to
        ask of any identifier that grants access.</p>',

    'pipeline' => $pipeline,
    'hints'    => crypto_hints($L),
]);
