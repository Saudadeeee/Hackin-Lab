<?php
require_once __DIR__ . '/helpers.php';

$L    = 5;
$meta = xl_levels()[$L];

/** Lives in <vault>, which is not under //user at all. */
const L5_SECRET = 'VLT-7Q2M-XZ84';

$v    = isset($_GET['id']) ? (string)$_GET['id'] : '';
$sent = isset($_GET['id']) && $v !== '';

/* ── The vulnerable code, running for real. ───────────────────────────── */
$expr = "//user[@id=" . $v . "]/username/text()";
$run  = xl_xpath_run($expr);

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $got = xl_retrieved($run, L5_SECRET);

    $pipeline = [
        ['label' => '$_GET["id"] (raw)', 'value' => $v,
         'note'  => 'No filter of any kind on this level. There is nothing to defeat except the grammar.'],
        ['label' => 'expression built by concatenation', 'value' => $expr,
         'note'  => '<code>@id=</code> compares an attribute to whatever operand follows. A quote here does not
                     end a string, because no string was open.'],
        ['label' => 'DOMXPath::evaluate() result',
         'value' => $run['ok'] ? $run['count'] . ' node(s) selected' : 'expression did not parse',
         'note'  => $run['ok']
            ? 'The node set can contain nodes from anywhere in the document, not only from <code>//user</code>.'
            : '<code>' . lk_esc((string)$run['error']) . '</code> &mdash; this is what a quote-based payload
               produces in a numeric context.',
         'verdict' => $run['ok'] ? ($run['count'] > 0 ? 'pass' : 'block') : 'block'],
        ['label' => 'rendered to the page', 'value' => implode(' | ', xl_node_strings($run)),
         'verdict' => $got ? 'pass' : null],
    ];

    if (!$run['ok']) {
        $result = '<div class="message error"><strong>Profile lookup failed.</strong> '
                . lk_esc((string)$run['error']) . '</div>';
    } elseif ($got) {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>The node set reached outside the staff subtree.</strong>
                   The vault master secret is in the result.</div>' . xl_nodes_table($run);
    } else {
        $result = '<div class="message info">Profile ' . lk_esc($v) . ':</div>' . xl_nodes_table($run);
    }
}

$code = <<<'PHP'
// Profile page. The id comes from a link on the staff list, so it is
// "always a number" and there is no string literal to escape.
$id = $_GET['id'];

$expr = "//user[@id=" . $id . "]/username/text()";

foreach ($xpath->evaluate($expr) as $node) {
    echo htmlspecialchars($node->textContent);
}

// users.xml also holds <vault>, which no expression in this app touches.
PHP;

$fixBad = <<<'PHP'
$expr = "//user[@id=" . $id . "]/username/text()";
PHP;

$fixGood = <<<'PHP'
// Validate the type, since the value has one...
$id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($id === false) {
    return bad_request('id must be an integer');
}
$expr = "//user[@id=" . $id . "]/username/text()";

// ...and stop keeping secrets in a document that user-facing expressions
// are evaluated against. A union can only reach nodes that are there.
// <vault> belongs in a different file, behind a different access path,
// loaded by code that has a reason to load it.
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5],
    'annotation' => 'The input is compared numerically against an attribute, with no quotes around it. Every
        quote-based payload produces a parse error here, which reads like a defence and is not one &mdash; the
        attacker is already in expression context and does not need to escape into it.',

    'theory' => '<p>The first thing to establish about any injection point is the grammatical context it lands in,
        because that decides which payloads are even syntactically possible. Inside a string literal, the quote is
        the boundary. Inside a numeric comparison, there is no boundary to cross: the parser is expecting an
        expression and it will read one.</p>
        <p>This is why "we escape quotes" and "we are not injectable" are different claims, and why a payload that
        errors is information rather than failure. An <code>Invalid expression</code> in the trace tells you the
        parser saw your bytes as syntax. That is the finding. What remains is writing syntax it likes.</p>
        <p>The second idea here is reach. Predicates filter a node set; they cannot enlarge it. <code>//user[...]</code>
        will never return a node that is not a <code>user</code>, no matter what the predicate says. The union
        operator is the escape hatch, because it evaluates a second location path from the document root and adds
        the result. Anything in the document is reachable from anywhere in the expression &mdash; which is a fact
        about the document, and the reason the fix has two halves.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The second half is the one people skip. If a document contains secrets, every expression
            evaluated against it is a potential disclosure, and one day one of them will be built by
            concatenation.',
    ],

    'scenario' => '<strong>Scenario:</strong> the profile page selects a user by the <code>id</code> attribute and
        prints their username.
        <br><strong>Goal:</strong> retrieve the <code>master</code> secret from the <code>&lt;vault&gt;</code>
        subtree. No predicate can reach it, because it is not a <code>user</code>.',

    'model' => [
        'title' => 'Numeric context, and what a union does about it',
        'html'  => '<pre class="lk-sinkline">//user[@id=<span class="lk-inj">V</span>]/username/text()</pre>
        <p>Try the reflexes first, and read what they produce:</p>
        <table class="lk-kv">
            <tr><td><code>1\' or \'1\'=\'1</code></td><td>parse error. There is no open literal, so the first
                quote starts one and it never closes.</td></tr>
            <tr><td><code>1 or 1=1</code></td><td>parses, and matches every user. Useful, but everything it can
                reach is still a <code>user</code>.</td></tr>
            <tr><td><code>1]|//other/path|//user[@id=1</code></td><td>parses, and the result set is no longer
                confined to one subtree.</td></tr>
        </table>
        <p>The document has this shape:</p>
        <pre class="lk-sinkline">directory
  staff
    user[@id=1..8]
      username, password, role, email, department, ...
  vault
    secret[@name=\'master\']
    secret[@name=\'rotation\']</pre>
        <p>Three arms is the comfortable layout: one that matches nothing to absorb the opening
        <code>//user[@id=</code>, one that is your payload, and one that is left half-written so the
        developer&rsquo;s trailing <code>]/username/text()</code> completes it.</p>',
    ],

    'form' => xl_form(
        [['name' => 'id', 'label' => 'Profile id', 'value' => $v, 'placeholder' => '1']],
        'Open profile',
        'Ids 1 to 8 exist. Anything the parser accepts will be evaluated.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The union pulled a node set out of a subtree the application never queries.',
    'why'      => '<p>The expression the engine evaluated was three location paths joined by <code>|</code>. Two of
        them came from you and one from the developer, and XPath has no way to prefer one over another &mdash; a
        union is a union. The node you wanted was returned alongside the node the page expected, and the rendering
        loop printed both.</p>
        <p>Compare the three XPath injection primitives you now have. Level 1 rewrote a <em>predicate</em> to change
        which nodes were kept. Level 2 rewrote a <em>step</em> to change which part of a node was returned. This
        level added an entirely <em>separate path</em>, which is the largest of the three: the only limit on what
        you can select is what the document contains.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'expression handed to DOMXPath::evaluate()',
        'before'   => '//user[@id=',
        'injected' => $v,
        'after'    => ']/username/text()',
    ],
    'probes'   => [
        'param'  => 'id',
        'method' => 'GET',
        'action' => 'level5.php',
        'items'  => [
            ['q'       => 'What does a quote do in a numeric predicate?',
             'payload' => "1' or '1'='1",
             'learn'   => 'Read the error text in the trace. "Invalid expression" means the parser is reading your
                           input as syntax, which is the finding &mdash; it just is not the right syntax yet.'],
            ['q'       => 'Does boolean logic parse here without any quotes?',
             'payload' => '1 or 1=1',
             'learn'   => 'Every user comes back. Confirms full control of the predicate, and confirms the limit:
                           a predicate cannot select anything that is not a <code>user</code>.'],
            ['q'       => 'What is at the top of the document?',
             'payload' => '0]|/*|//user[@id=1',
             'learn'   => 'One node, the document element, with its whole text content flattened. A crude map, but
                           it tells you the root name in one request so the next path can be precise.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
