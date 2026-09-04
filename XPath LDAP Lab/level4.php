<?php
require_once __DIR__ . '/helpers.php';

$L    = 4;
$meta = xl_levels()[$L];

/** Console PIN on the administrator account. No page selects this element. */
const L4_PIN = 'PN-77413-KQ';

$raw  = isset($_GET['q']) ? (string)$_GET['q'] : '';
$sent = isset($_GET['q']) && $raw !== '';

/* ── The developer's protection, verbatim. ────────────────────────────── */
$q = str_replace(["'", '"'], '', $raw);
$stripped = strlen($raw) - strlen($q);

/* ── The vulnerable code, running for real. ───────────────────────────── */
$expr = "//user[position()=" . $q . "]/username/text()";
$run  = xl_xpath_run($expr);

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $got = xl_retrieved($run, L4_PIN);

    $pipeline = [
        ['label' => '$_GET["q"] (raw)', 'value' => $raw],
        ['label' => 'str_replace(["\'", \'"\'], "", $q)', 'value' => $q,
         'note'  => $stripped > 0
            ? '<strong>' . $stripped . '</strong> quote character(s) removed. The filter did what it says it does.'
            : 'Nothing to remove &mdash; there were no quote characters in the input.',
         'verdict' => $stripped > 0 ? 'block' : 'pass'],
        ['label' => 'expression built by concatenation', 'value' => $expr,
         'note'  => 'Look at what surrounds the value: <code>position()=</code> and <code>]</code>. There is no
                     string literal here, so there was never a quote to escape.'],
        ['label' => 'DOMXPath::evaluate() result',
         'value' => $run['ok'] ? $run['count'] . ' node(s) selected' : 'expression did not parse',
         'note'  => $run['ok'] ? '' : '<code>' . lk_esc((string)$run['error']) . '</code>',
         'verdict' => $run['ok'] ? ($run['count'] > 0 ? 'pass' : 'block') : 'block'],
        ['label' => 'rendered to the page', 'value' => implode(' | ', xl_node_strings($run)),
         'verdict' => $got ? 'pass' : null],
    ];

    if (!$run['ok']) {
        $result = '<div class="message error"><strong>Lookup failed.</strong> '
                . lk_esc((string)$run['error']) . '</div>';
    } elseif ($got) {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>The node set contains the administrator console PIN.</strong>
                   Not one quote character was involved.</div>' . xl_nodes_table($run);
    } else {
        $result = '<div class="message info">Row ' . lk_esc($q) . ' of the staff list:</div>'
                . xl_nodes_table($run);
    }
}

$code = <<<'PHP'
// Paged staff list. ?q=1 is the first row, ?q=2 the second, and so on.
$q = $_GET['q'];

// Hardening added after the last pentest: no quotes, no XPath injection.
$q = str_replace(["'", '"'], '', $q);

$expr = "//user[position()=" . $q . "]/username/text()";

foreach ($xpath->evaluate($expr) as $node) {
    echo htmlspecialchars($node->textContent);
}
PHP;

$fixBad = <<<'PHP'
$q = str_replace(["'", '"'], '', $q);
$expr = "//user[position()=" . $q . "]/username/text()";
PHP;

$fixGood = <<<'PHP'
// The value is supposed to be a row number. Say so, and mean it.
$q = filter_var($_GET['q'], FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 500],
]);
if ($q === false) {
    return bad_request('q must be a row number');
}
$expr = "//user[position()=" . $q . "]/username/text()";

// Type validation works here precisely because the value has a type.
// When it does not - a name, a search term - go back to the level 1 and 2
// fix: select with a fixed expression and compare in PHP.
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 7],
    'annotation' => 'The quote filter is real and it works. It is also irrelevant: the injection point is a numeric
        predicate, so no payload needed a string literal in the first place. The filter removes characters the
        attacker was never going to send.',

    'theory' => '<p>Character filtering encodes an assumption about where the input lands. "Strip the quotes" is
        shorthand for "the input is inside a quoted string literal, and the quote is the only way out". When that
        assumption is wrong, the filter costs the attacker nothing at all &mdash; and it costs the developer their
        attention, because the code now looks defended.</p>
        <p>XPath is unusually generous to a quote-free attacker. Numbers are literals. <code>position()</code>,
        <code>last()</code>, <code>count()</code> and <code>string-length()</code> all produce numbers. A predicate
        containing nothing but a name, <code>[pin]</code>, is a presence test on a child element. <code>name()</code>
        yields element names for comparison against other element names. Two nodes can be compared to each other
        without either being written out: <code>role = //user[1]/role</code> contains no literal of any kind.</p>
        <p>Generalise it past this lab. Denylists answer "which characters are dangerous", which depends on
        context and therefore changes every time the code around the sink changes. Parameterisation answers "is
        this value data", which does not change. That is the whole reason the industry moved off escaping and onto
        bound parameters for SQL, and the same argument applies to every other query language.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Validating the type is a legitimate fix <em>here</em> because a row number really is an integer.
            It is not a general answer, and reaching for it when the value is free text is how the next level
            happens.',
    ],

    'scenario' => '<strong>Scenario:</strong> a paged staff list. <code>?q=1</code> shows the first row. A previous
        assessment produced the quote filter you can see on line 5.
        <br><strong>Goal:</strong> make the endpoint return the <code>pin</code> element stored on the
        administrator&rsquo;s account, without using a single quote character.',

    'model' => [
        'title' => 'A quote-free toolkit',
        'html'  => '<pre class="lk-sinkline">//user[position()=<span class="lk-inj">Q</span>]/username/text()</pre>
        <p>You are already outside every string in the expression. What is available with no literals at all:</p>
        <table class="lk-kv">
            <tr><td><code>1</code>, <code>7</code>, <code>last()</code></td><td>numbers, for the predicate the
                developer wrote</td></tr>
            <tr><td><code>[pin]</code></td><td>presence test: true for any <code>user</code> that has a
                <code>pin</code> child. Equality without a value.</td></tr>
            <tr><td><code>|</code></td><td>union &mdash; add a second node set beside the developer&rsquo;s</td></tr>
            <tr><td><code>*</code></td><td>any child element, if you want the schema rather than a field</td></tr>
            <tr><td><code>name(*[1])</code></td><td>the name of the first child element, as a string you did not
                have to type</td></tr>
            <tr><td><code>role=//user[1]/role</code></td><td>comparing one node against another, so the literal
                comes out of the document instead of out of your payload</td></tr>
        </table>
        <p>Only one user in the directory has a <code>pin</code> child. That is enough to select it, and it does
        not require knowing, or writing, the administrator&rsquo;s username.</p>
        <p>Remember the trailing text: <code>]/username/text()</code> is still going to be appended, so end your
        payload part-way through a predicate that the leftover completes.</p>',
    ],

    'form' => xl_form(
        [['name' => 'q', 'label' => 'Row number', 'value' => $raw, 'placeholder' => '1']],
        'Show row',
        'Quotes are removed before the expression is built. The trace shows how many were taken out.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'A filter that removes quotes does not stop an injection that never needed one.',
    'why'      => '<p>Your payload contained no <code>\'</code> and no <code>"</code>, so the filter had nothing to
        do and passed the input through unchanged &mdash; the trace shows zero characters removed. The predicate
        <code>[pin]</code> selected the one node in the document that has that child element, and the union placed
        it beside the developer&rsquo;s own node set so the trailing text still parsed.</p>
        <p>The reusable idea is to describe the target by <em>structure</em> rather than by <em>value</em>. Presence
        tests, positional predicates and node-to-node comparisons all identify data without spelling it out, which
        defeats a whole family of filters that assume the attacker must write down what they are looking for.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'expression handed to DOMXPath::evaluate()',
        'before'   => '//user[position()=',
        'injected' => $q,
        'after'    => ']/username/text()',
    ],
    'probes'   => [
        'param'  => 'q',
        'method' => 'GET',
        'action' => 'level4.php',
        'items'  => [
            ['q'       => 'Is the filter actually running, and what does it take out?',
             'payload' => "1' or '1'='1",
             'learn'   => 'The trace prints the input before and after <code>str_replace</code>. Seeing your quotes
                           disappear is worth one request, because it tells you which half of the problem to work
                           on.'],
            ['q'       => 'Does arithmetic reach the parser, or is the value being treated as an integer?',
             'payload' => '1+1',
             'learn'   => 'If row two comes back, the expression is being parsed rather than the value being cast.
                           That single fact rules the type-validation fix in or out.'],
            ['q'       => 'Can I close the predicate and union without any literal?',
             'payload' => '1]|//user[position()=1',
             'learn'   => 'A no-op union that returns the same row. It proves the bracket, the pipe and the
                           reopened predicate all survive, leaving only the middle arm to design.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
