<?php
require_once __DIR__ . '/helpers.php';

$L    = 9;
$meta = bp_levels()[$L];

$policy = bp_policy($L);

$template = (string)($_POST['payload'] ?? '');
$flag     = '';
$result   = '';
$stages   = [];
$frame    = '';

if ($template !== '') {
    $parsed    = csp_parse($policy);
    $scriptSrc = csp_effective($parsed, 'script-src');
    $evalAllowed = csp_has($scriptSrc, "'unsafe-eval'");

    // Step 1 - the policy. Whether the sink is reachable at all is decided here.
    $stages[] = [
        'label' => 'Content-Security-Policy (the header render.php really sent)',
        'value' => $policy,
        'note'  => 'No <code>&#39;unsafe-inline&#39;</code>, and only <code>&#39;self&#39;</code> as a host source. '
                 . 'An injected script element has nowhere to come from.',
    ];
    $stages[] = [
        'label'   => "effective script-src contains 'unsafe-eval'",
        'value'   => $evalAllowed ? 'yes' : 'no',
        'note'    => $evalAllowed
            ? 'So <code>new Function()</code> inside tmpl.js compiles rather than throwing <code>EvalError</code>. '
            . 'This directive is the only reason the rest of the trace can happen.'
            : 'Every call to eval or the Function constructor would throw, and no expression could run.',
        'verdict' => $evalAllowed ? 'pass' : 'block',
    ];

    // Step 2 - the gadget's own parsing, replayed with the gadget's own regex.
    $exprs = tmpl_extract($template);
    $stages[] = [
        'label' => 'tmpl.js: tpl.replace(/\\$\\{([^}]*)\\}/g, ...)',
        'value' => $exprs ? implode('   |   ', $exprs) : '(no interpolation found)',
        'note'  => $exprs
            ? 'Each of these strings is handed to the filter, and then to <code>new Function()</code>.'
            : 'Without a <code>${...}</code> the template is copied out as text and never reaches a sink.',
    ];

    // Step 3 - filter each expression, then actually evaluate it.
    $executed = false;
    $compiled = '';
    foreach ($exprs as $expr) {
        $filter = tmpl_filter($expr);
        $stages[] = [
            'label'   => 'tmpl.js safeExpr("' . $expr . '")',
            'value'   => $filter['ok'] ? 'true' : 'false',
            'note'    => $filter['reason'],
            'verdict' => $filter['ok'] ? 'pass' : 'block',
        ];
        if (!$filter['ok'] || !$evalAllowed) {
            continue;
        }

        $run = JsExpr::evaluate($expr);
        $note = $run['trace']
            ? '<ul style="margin:0 0 0 1rem"><li>' . implode('</li><li>', array_map('lk_esc', $run['trace'])) . '</li></ul>'
            : 'The expression evaluated without reaching any code-construction path.';
        if (!$run['ok']) {
            $note .= '<div>Threw: ' . lk_esc($run['error']) . '</div>';
        }
        $stages[] = [
            'label'   => "new Function('d', 'return (" . $expr . ")')(d)",
            'value'   => $run['executed']
                ? 'the compiled function was called: ' . $run['compiled']
                : ($run['ok'] ? js_show($run['value']) : 'threw'),
            'note'    => $note,
            'verdict' => $run['executed'] ? 'pass' : 'block',
        ];
        if ($run['executed']) {
            $executed = true;
            $compiled = $run['compiled'];
        }
    }

    $frame = bp_frame($L, ['t' => $template],
        'tmpl.js reads the template out of this frame&rsquo;s query string and renders it. The rendered output and '
        . 'the status line below it are your browser&rsquo;s own answer.');

    if ($evalAllowed && $executed) {
        $flag   = bp_flag($L);
        $result = bp_verdict(true,
            'Your expression reached the Function constructor and the result was invoked, so the source '
            . '<code>' . lk_esc($compiled) . '</code> ran as JavaScript. No script element was involved at any point.');
    } elseif ($exprs && !$executed) {
        $result = bp_verdict(false,
            'The expression was evaluated but never reached code execution. Read the last trace stage: it says what '
            . 'each step produced and where the chain stopped.');
    } else {
        $result = bp_verdict(false,
            'Nothing in that template reaches the sink. The gadget only evaluates what sits between '
            . '<code>${</code> and <code>}</code>.');
    }
}

$code = <<<'PHP'
// The policy. No inline script, no host allowlist to abuse - but the
// storefront's template helper needs to compile expressions at runtime,
// so 'unsafe-eval' was added and nobody objected.
header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'self' 'unsafe-eval'; "
     . "object-src 'none'; base-uri 'self'");

// --- tmpl.js, loaded from 'self' ------------------------------------
var ALLOW  = /^[A-Za-z0-9_$.\[\]'"+\-*\/%() ]*$/;
var BANNED = ['eval','function','constructor','import','require',
              'alert','document','window','settimeout','fetch'];

function safeExpr(expr) {
    if (!ALLOW.test(expr)) return false;
    var low = expr.toLowerCase();
    for (var i = 0; i < BANNED.length; i++)
        if (low.indexOf(BANNED[i]) !== -1) return false;
    return true;
}

function render(tpl, d) {
    return tpl.replace(/\$\{([^}]*)\}/g, function (whole, expr) {
        if (!safeExpr(expr)) return '[blocked: ' + expr + ']';
        return String(new Function('d', 'return (' + expr + ')')(d));
    });
}

render(new URLSearchParams(location.search).get('t'),
       { name: 'guest', plan: 'free', id: 41 });
PHP;

$fixBad = <<<'PHP'
// policy
script-src 'self' 'unsafe-eval'
// gadget
new Function('d', 'return (' + expr + ')')(d)   // expr from the URL
PHP;

$fixGood = <<<'PHP'
// 1. Remove 'unsafe-eval'. Compile templates at build time, or use a
//    renderer that walks a parsed AST instead of building source text.
header("Content-Security-Policy: "
     . "default-src 'self'; "
     . "script-src 'nonce-$nonce' 'strict-dynamic'; "
     . "object-src 'none'; base-uri 'none'");

// 2. Resolve interpolations by lookup, not by evaluation. A template
//    needs to read fields; it does not need an expression language.
function render(tpl, data) {
    return tpl.replace(/\$\{([a-z0-9_]+)\}/gi, function (whole, key) {
        return Object.prototype.hasOwnProperty.call(data, key)
            ? String(data[key]) : '';
    });
}

// 3. And do not take the template from the URL. A template is code;
//    treat it with the trust you would give code.
PHP;

lk_page([
    'lab'        => bp_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => bp_extra_head(),
    'lang'       => 'js',

    'code'       => $code,
    'vuln_lines' => [6, 25],
    'annotation' => 'The policy blocks every way of getting a new script element onto the page, and then permits
        <code>&#39;unsafe-eval&#39;</code>, which lets script that is already running compile strings into code. The
        template helper turns a URL parameter into one of those strings.',

    'theory' => '<p><code>&#39;unsafe-eval&#39;</code> is often read as a minor relaxation, because it does not add
        a host to the allowlist and it does not permit inline script. What it actually does is reopen the boundary
        between data and code <em>inside</em> the scripts you already trust. Every string that reaches
        <code>eval</code>, <code>new Function</code>, <code>setTimeout(&#39;…&#39;)</code> or
        <code>setInterval(&#39;…&#39;)</code> becomes executable, and CSP has no further opinion about it.</p>
        <p>The result is that a strict-looking policy sits next to a sink that needs no script element at all. There
        is nothing for the browser to block, because from the browser&rsquo;s point of view the trusted
        <code>tmpl.js</code> is doing what it was allowed to do. This is why "we have a CSP" and "we are
        protected from XSS" are different statements, and why the flag here is awarded by evaluating your expression
        rather than by looking at it.</p>
        <p>The filter in front of the sink is a denylist over an expression language, which is a losing position by
        construction. A denylist has to enumerate every way of naming a capability; JavaScript lets you build a name
        out of pieces at runtime, so the number of ways is unbounded. The reachability chain that matters here is
        the one every JavaScript sandbox escape uses: from any value, reach a function; from any function, reach
        <code>.constructor</code>, which is <code>Function</code>; from <code>Function</code>, compile anything.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'lang' => 'js',
        'note' => 'The durable fix is the first one: remove the directive, and remove the need for it. Where a
            runtime template language is genuinely required, use one that interprets a parsed structure rather than
            generating source, and keep the template itself out of attacker reach. Trusted Types is the platform
            control that enforces this properly, by requiring a policy object for every string that becomes code.',
    ],

    'scenario' => '<strong>Scenario:</strong> the storefront renders product blurbs with a small client-side
        template helper. The template comes from the query string so that marketing can preview copy without a
        deploy.
        <br><strong>Goal:</strong> run JavaScript of your choosing in the frame. No script element will load, so do
        not look for one.',

    'model' => [
        'title' => 'The reachability chain',
        'html'  => '<table class="lk-kv">
            <tr><td><code>&#39;&#39;</code></td><td>a string literal; the allowlist permits quotes</td></tr>
            <tr><td><code>&#39;&#39;.constructor</code></td><td>the <code>String</code> function</td></tr>
            <tr><td><code>String.constructor</code></td><td>the <code>Function</code> constructor &mdash; every
                function&rsquo;s constructor is <code>Function</code></td></tr>
            <tr><td><code>Function(&#39;src&#39;)</code></td><td>compiles <code>src</code> into a callable</td></tr>
            <tr><td><code>&hellip;()</code></td><td>runs it</td></tr>
        </table>
        <p>The obstacle is the denylist, which refuses any expression containing the substring
        <code>constructor</code> (and nine others). Property access does not have to spell the name in one piece:
        <code>obj[&#39;con&#39;+&#39;structor&#39;]</code> reads the same property, and the text
        <code>&#39;con&#39;+&#39;structor&#39;</code> contains no banned substring.</p>
        <p>The server evaluates whatever you send over a small model of that object graph and reports what each step
        produced, so a chain that stops halfway tells you exactly where. The frame runs the same template in your
        browser under the real header.</p>',
    ],

    'form'   => bp_markup_form($template, 'Template rendered by tmpl.js',
        'Hello ${d.name}, you are on the ${d.plan} plan.', 'Render the template'),
    'result' => $result . $frame,
    'flag'   => $flag,
    'flag_msg' => 'The policy never had to be broken, because the sink was inside the trusted script.',
    'why'    => '<p>Trace the stages in order. The policy permitted <code>&#39;unsafe-eval&#39;</code>, so the sink
        was live. The gadget&rsquo;s own regex pulled your expression out of the template. The filter passed it,
        because the banned word was never written down in one piece. Then the expression was evaluated for real: a
        string literal produced <code>String</code>, <code>String</code> produced <code>Function</code>,
        <code>Function</code> compiled your source, and calling the result ran it.</p>
        <p>Nothing in that sequence is a browser bug or a CSP bug. The browser did what the header told it to do.
        The failure is that a policy which is strict about <em>where script comes from</em> was paired with a
        directive that makes the question irrelevant.</p>
        <p>When you review a policy, treat <code>&#39;unsafe-eval&#39;</code> as an instruction to go and read the
        application&rsquo;s JavaScript instead: grep for <code>eval</code>, <code>new Function</code>,
        <code>setTimeout</code> with a string, template compilers, and anything that builds source text. The policy
        has told you the interesting bug is in there somewhere.</p>',

    'pipeline' => $stages,
    'probes'   => [
        'param'  => 'payload',
        'method' => 'POST',
        'action' => 'level9.php',
        'items'  => [
            ['q'       => 'Does an interpolation reach the sink at all?',
             'payload' => 'Hello ${d.name}',
             'learn'   => 'The intended use. It confirms which part of the template is evaluated and shows you the '
                        . 'shape of the object the compiled function receives.'],
            ['q'       => 'Is arbitrary arithmetic allowed inside an interpolation?',
             'payload' => '${41+1}',
             'learn'   => 'If this renders 42 then the expression is being evaluated rather than looked up, which is '
                        . 'the whole difference between a template engine and an eval sink.'],
            ['q'       => 'What exactly does the filter refuse?',
             'payload' => '${d.constructor}',
             'learn'   => 'A harmless property read that the denylist will refuse. The refusal message names the '
                        . 'banned substring, which tells you what you have to avoid spelling.'],
        ],
    ],
    'hints' => bp_hints($L),
]);
