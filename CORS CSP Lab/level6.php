<?php
require_once __DIR__ . '/helpers.php';

$L    = 6;
$meta = bp_levels()[$L];

$policy  = bp_policy($L);
$payload = (string)($_POST['payload'] ?? '');
$flag    = '';
$result  = '';
$stages  = [];
$boxes   = '';
$frame   = '';

if ($payload !== '') {

    // Evaluate the injection against the policy render.php really sends.
    $eval   = csp_evaluate($policy, $payload, [
        'page_url'     => bp_render_url($L),
        'page_scripts' => [
            ['label' => "the page's own <script src=\"frame.js\">", 'kind' => 'external', 'src' => 'frame.js'],
        ],
    ]);
    $stages = csp_stages($eval);

    // CSP said yes. Now find out what that script actually returns, by
    // fetching it - a gadget is only a gadget if the response is yours.
    $gadget = null;
    foreach (csp_executed($eval, 'injection') as $f) {
        if ($f['kind'] !== 'external') {
            continue;
        }
        $reach = bp_reachable($f['url']);
        if ($reach === null) {
            $stages[] = [
                'label'   => 'fetch ' . $f['url'],
                'value'   => 'not reachable from this lab',
                'note'    => 'CSP permits this URL, but the lab cannot fetch it to see what it returns, so it cannot '
                           . 'confirm the response is attacker-controlled.',
                'verdict' => 'block',
            ];
            continue;
        }
        parse_str((string)parse_url($f['url'], PHP_URL_QUERY), $q);
        $callback = (string)($q['callback'] ?? '');
        $resp     = bp_http($reach);
        $ctype    = $resp['map']['content-type'] ?? '';
        $isJs     = stripos($ctype, 'javascript') !== false || stripos($ctype, 'ecmascript') !== false;
        $leads    = $callback !== '' && str_starts_with($resp['body'], $callback);

        $stages[] = [
            'label'   => 'GET ' . $f['url'],
            'value'   => substr($resp['body'], 0, 160),
            'note'    => 'Content-Type: <code>' . lk_esc($ctype) . '</code>. '
                       . ($leads
                            ? 'The response begins with text you supplied, so the first thing the browser executes is yours.'
                            : 'The response does not begin with anything you supplied, so this URL returns the '
                            . 'application&rsquo;s own script.'),
            'verdict' => ($isJs && $leads) ? 'pass' : 'block',
        ];

        if ($isJs && $leads && $callback !== 'renderProducts') {
            $gadget = ['url' => $f['url'], 'callback' => $callback, 'body' => $resp['body']];
        }
    }

    $frame = bp_frame($L, ['i' => $payload],
        'This frame is served by render.php with the header shown above. If the status line turns green, '
        . 'your script ran in your own browser under a real CSP.');

    if ($gadget !== null) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'A script the policy allowed returned code you wrote. <code>' . lk_esc($gadget['url']) . '</code> came '
            . 'back as JavaScript beginning with <code>' . lk_esc($gadget['callback']) . '</code>.');
    } elseif (csp_executed($eval, 'injection')) {
        $result = bp_verdict(false,
            'CSP allowed one of your nodes, but what it loaded is not under your control. The endpoint has to hand '
            . 'back <em>your</em> text in executable position.');
    } else {
        $result = bp_verdict(false,
            'Nothing in that markup runs under this policy. Read the trace: each stage names the directive that '
            . 'made the decision.');
    }
}

$code = <<<'PHP'
// The storefront hardened its widget page after an XSS report.
// Inline script is gone; everything is loaded from a file.
header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'self' https://cdn.hackinlab.internal; "
     . "object-src 'none'");

// The note still goes into the document as HTML - the CSP is the control.
echo '<div id="note">' . $note . '</div>';

// ---------------------------------------------------------------------
// /jsonp.php - shipped in 2016, still routed, still on this origin.
// ---------------------------------------------------------------------
$callback = $_GET['callback'] ?? 'renderProducts';

header('Content-Type: application/javascript');
echo $callback . '(' . json_encode(['products' => $products]) . ');';
PHP;

$fixBad = <<<'PHP'
// The policy
script-src 'self' https://cdn.hackinlab.internal

// ... and, on that same origin:
echo $_GET['callback'] . '(' . json_encode($data) . ');';
PHP;

$fixGood = <<<'PHP'
// 1. Retire JSONP. It exists only to defeat the same-origin policy and
//    CORS replaced it. If it must stay, constrain the callback to a
//    name from a fixed list - not to a regex over identifiers, because
//    "alert" is a valid identifier.
$allowed  = ['renderProducts', 'renderCart'];
$callback = in_array($_GET['callback'] ?? '', $allowed, true)
    ? $_GET['callback']
    : 'renderProducts';

// 2. Stop allowlisting whole origins. A per-response nonce says
//    "this exact tag", which no endpoint on the origin can forge.
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'nonce-$nonce' 'strict-dynamic'; "
     . "object-src 'none'; base-uri 'none'");

// 3. And escape the reflection. CSP is a second line, not the first.
echo '<div id="note">' . htmlspecialchars($note, ENT_QUOTES, 'UTF-8') . '</div>';
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 9, 14, 17],
    'annotation' => 'The policy has no <code>unsafe-inline</code>, so injected inline script is dead. It allowlists
        <code>&#39;self&#39;</code>, which covers every path on this origin &mdash; including a JSONP endpoint that
        returns an attacker-chosen callback name as the first token of a JavaScript response.',

    'theory' => '<p>A source expression in <code>script-src</code> allowlists an <em>origin</em>. It cannot say "this
        one file"; a path in a source expression restricts the prefix but nobody writes those, and
        <code>&#39;self&#39;</code> has no path at all. So the real meaning of <code>&#39;self&#39;</code> is: every
        endpoint this origin has ever exposed may supply script to this page.</p>
        <p>That turns any endpoint whose response body an attacker can partly control into a way to run code. JSONP
        is the purest example, because returning attacker-named JavaScript is its entire purpose, but it is not the
        only one: an Angular or Vue template loaded from <code>&#39;self&#39;</code>, an old JavaScript library on
        the origin that evaluates a URL parameter, a file-upload endpoint that serves user content with a JavaScript
        content type. These are called <em>script gadgets</em>, and a large fraction of real-world CSP allowlists
        contain at least one.</p>
        <p>The measured version of this finding: a study of the CSP policies deployed across the web found that the
        great majority of allowlist-based policies could be bypassed through an endpoint the site itself
        allowlisted. That result is why the modern advice is nonces plus <code>&#39;strict-dynamic&#39;</code>
        rather than host lists &mdash; a nonce names one specific tag, and no endpoint on the origin can produce it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Constraining the callback to a fixed list is the correct endpoint-level fix; validating it as an
            "identifier" is not, because plenty of dangerous expressions are valid identifiers. The policy-level fix
            is to stop allowlisting origins altogether. And the injection itself still deserves output escaping:
            CSP is a mitigation for the bug, not a replacement for fixing it.',
    ],

    'scenario' => '<strong>Scenario:</strong> after an XSS report the storefront added a Content-Security-Policy and
        removed every inline script. The note field is still reflected into the page as HTML.
        <br><strong>Goal:</strong> run code in the frame anyway, and call <code>hlab.win()</code>.',

    'model' => [
        'title' => 'What this policy permits, precisely',
        'html'  => '<table class="lk-kv">
            <tr><td><code>&lt;script&gt;code&lt;/script&gt;</code></td><td>blocked &mdash; no
                <code>&#39;unsafe-inline&#39;</code>, no nonce, no hash</td></tr>
            <tr><td><code>&lt;img onerror="code"&gt;</code></td><td>blocked &mdash; event-handler attributes are
                inline script and a nonce cannot cover them</td></tr>
            <tr><td><code>&lt;script src="/anything.js"&gt;</code></td><td><strong>allowed</strong> &mdash;
                <code>&#39;self&#39;</code> is the whole origin</td></tr>
            <tr><td><code>&lt;script src="//evil.test/x.js"&gt;</code></td><td>blocked &mdash; not in the list</td></tr>
        </table>
        <p>So the question is not "how do I get inline script past this" but "what on this origin will hand me a
        response I control". Try <a href="jsonp.php?callback=renderProducts" target="_blank">jsonp.php</a> and look
        at what comes back, then look at what changes when you change the callback.</p>',
    ],

    'form'   => bp_markup_form($payload, 'Markup injected into the frame',
        '<script src="/somewhere-on-this-origin"></script>', 'Inject and render'),
    'result' => $result . $frame . $boxes,
    'flag'   => $flag,
    'flag_msg' => "An origin allowlist is only as tight as the loosest endpoint on the origin.",
    'why'    => '<p>The policy did exactly what it says. Your <code>&lt;script src&gt;</code> pointed at this origin,
        <code>&#39;self&#39;</code> matched, and the browser loaded it. Nothing was bypassed at the CSP layer at
        all.</p>
        <p>The bypass happened one layer down, at the endpoint. <code>jsonp.php</code> copies the
        <code>callback</code> parameter into the start of a JavaScript response, so the first token the browser
        executes is text you wrote. The trailing <code>({...});</code> is neutralised by ending your callback with a
        line comment.</p>
        <p>When you assess a CSP, do not stop at reading the directives. Enumerate what each allowlisted origin
        serves, and look specifically for endpoints that reflect input into a JavaScript or HTML response. The
        policy is only a statement about <em>where</em> script may come from; it says nothing about what those places
        are willing to say.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'payload',
        'method' => 'POST',
        'action' => 'level6.php',
        'items'  => [
            ['q'       => 'Is inline script really blocked?',
             'payload' => '<script>hlab.win()</script>',
             'learn'   => 'The trace will name the directive that refused it. Confirming what does <em>not</em> work '
                        . 'is how you narrow the search before spending effort on a payload.'],
            ['q'       => 'Are event-handler attributes treated differently?',
             'payload' => '<img src=x onerror="hlab.win()">',
             'learn'   => 'They are inline script too, and unlike a script element they can never carry a nonce. '
                        . 'Useful to know for the levels that do use nonces.'],
            ['q'       => 'Does a script element from this origin load at all?',
             'payload' => '<script src="/jsonp.php?callback=renderProducts"></script>',
             'learn'   => 'The application&rsquo;s own callback, so nothing harmful happens &mdash; but the trace '
                        . 'shows the element being allowed, which tells you the mechanism is available.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
