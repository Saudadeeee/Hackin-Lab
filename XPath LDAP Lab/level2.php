<?php
require_once __DIR__ . '/helpers.php';

$L    = 2;
$meta = xl_levels()[$L];

/** The value the page is trying to keep away from you. Never rendered anywhere. */
const L2_TOKEN = 'RT-9F3K2X';

$u    = isset($_GET['u']) ? (string)$_GET['u'] : '';
$sent = isset($_GET['u']) && $u !== '';

/* ── The vulnerable code, running for real. ───────────────────────────── */
$expr = "//user[username='" . $u . "']/email/text()";
$run  = xl_xpath_run($expr);

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $got = xl_retrieved($run, L2_TOKEN);

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u],
        ['label' => 'expression built by concatenation', 'value' => $expr,
         'note'  => 'The location path does not stop at the closing bracket. Everything after
                     <code>]</code> &mdash; here <code>/email/text()</code> &mdash; decides which
                     <em>part</em> of the matched node you get to see.'],
        ['label' => 'DOMXPath::evaluate() result',
         'value' => $run['ok'] ? $run['count'] . ' node(s) selected' : 'expression did not parse',
         'note'  => $run['ok'] ? '' : '<code>' . lk_esc((string)$run['error']) . '</code>',
         'verdict' => $run['ok'] ? ($run['count'] > 0 ? 'pass' : 'block') : 'block'],
        ['label' => 'rendered to the page',
         'value' => implode(' | ', xl_node_strings($run)),
         'note'  => 'The page prints the string value of every node in the set. It has no idea which elements
                     those nodes came from.',
         'verdict' => $got ? 'pass' : null],
    ];

    if (!$run['ok']) {
        $result = '<div class="message error"><strong>Lookup failed.</strong> '
                . lk_esc((string)$run['error']) . '</div>';
    } elseif ($got) {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>Directory lookup returned '
                . $run['count'] . ' node(s), including a node the contact card was never meant to select.</strong></div>'
                . xl_nodes_table($run);
    } else {
        $result = '<div class="message info">Contact card for <code>' . lk_esc($u) . '</code>:</div>'
                . xl_nodes_table($run);
    }
}

$code = <<<'PHP'
// Staff contact card. Look the person up, show their email address.
$u = $_GET['u'];

$expr = "//user[username='" . $u . "']/email/text()";

foreach ($xpath->evaluate($expr) as $node) {
    echo htmlspecialchars($node->textContent);
}

// Fields the card deliberately does not select:
//   password, pin, recovery_token, apikey
PHP;

$fixBad = <<<'PHP'
$expr = "//user[username='" . $u . "']/email/text()";
PHP;

$fixGood = <<<'PHP'
// The value must not be able to change the SHAPE of the expression.
// Select the candidate nodes with a fixed expression, then compare in PHP.
$node = null;
foreach ($xpath->query('//user') as $candidate) {
    if (child($candidate, 'username') === $u) { $node = $candidate; break; }
}
if ($node === null) {
    return not_found();
}
echo htmlspecialchars(child($node, 'email'));

// A second, independent control: the renderer should whitelist the fields
// it is willing to print, so a mistake in node selection cannot turn into
// disclosure of every element in the document.
$visible = ['username', 'email', 'department', 'role'];
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [4],
    'annotation' => 'The predicate is not the only attacker-reachable part of the expression. Closing the bracket
        early puts the rest of the location path under the attacker&rsquo;s control, so the query can be pointed at
        any node in the document &mdash; including siblings the page has no code to render, but happily prints
        anyway.',

    'theory' => '<p>Level 1 changed which nodes were <em>selected</em>. This one changes which nodes are
        <em>returned</em>, which is a different and usually more valuable primitive. An XPath expression is a
        location path with predicates hanging off it, and injecting into a predicate gives you both.</p>
        <p>The union operator <code>|</code> is what makes this comfortable. It combines two node sets, so you do
        not have to make the developer&rsquo;s path do double duty &mdash; you leave it in place, terminate it with
        something harmless, and add a second path of your own. Structurally this is the same move as
        <code>UNION SELECT</code> in SQL, and it has the same requirement: the leftover text after your payload
        still has to parse.</p>
        <p>Notice what the rendering code contributes. It loops over whatever node set it gets and prints the
        string value of each node. It has no notion of "this is an email element and that is a token element". A
        renderer that whitelisted field names would have turned a full read primitive into a much smaller one.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Two independent controls, on purpose. The first stops the expression from being rewritten; the
            second limits the damage if some other expression in the codebase is rewritten tomorrow.',
    ],

    'scenario' => '<strong>Scenario:</strong> the staff directory shows a contact card. The lookup selects the
        <code>email</code> child of the matching user and prints it.
        <br><strong>Goal:</strong> make the same endpoint return the <code>recovery_token</code> stored on the
        <code>svc_backup</code> account. The flag is awarded when that value appears in the returned node set.',

    'model' => [
        'title' => 'The expression in three parts',
        'html'  => '<pre class="lk-sinkline">//user[username=\'<span class="lk-inj">U</span>\']/email/text()</pre>
        <table class="lk-kv">
            <tr><td><code>//user</code></td><td>the node set to walk</td></tr>
            <tr><td><code>[username=\'U\']</code></td><td>the predicate &mdash; which of them to keep</td></tr>
            <tr><td><code>/email/text()</code></td><td>the step that decides what you are shown</td></tr>
        </table>
        <p>Your input sits inside a string literal inside the predicate. To reach the third part you need to get
        out of both: one <code>\'</code> ends the literal, one <code>]</code> ends the predicate. After that you
        are writing the location path yourself.</p>
        <p>The catch is the text the developer left behind. Whatever you write, the string
        <code>\']/email/text()</code> is still going to be appended to it, and the whole thing has to parse. The
        usual answer is to end your payload halfway through a second expression that the leftover text completes:</p>
        <pre class="lk-sinkline">//user[username=\'<span class="lk-inj">TARGET\']/wanted|//user[username=\'x</span>\']/email/text()</pre>
        <p>Read that as two paths joined by <code>|</code>. The first is yours. The second is the
        developer&rsquo;s, with a username that matches nothing.</p>',
    ],

    'form' => xl_form(
        [['name' => 'u', 'label' => 'Look up a colleague by username',
          'value' => $u, 'placeholder' => 'alice']],
        'Show contact card',
        'Known usernames: <code>alice</code>, <code>bkumar</code>, <code>cwong</code>, <code>dpatel</code>,
         <code>mfrost</code>, <code>svc_backup</code>, <code>tnguyen</code>, <code>jrivera</code>.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The node set contained the break-glass token. The page printed it because the page prints
                   whatever it is handed.',
    'why'      => '<p>You did not read a file or bypass a permission check. You changed which nodes the expression
        selected, and the rendering loop did the rest. That distinction matters when you write this up: the
        vulnerability is the expression construction, and the disclosure is a consequence of it.</p>
        <p>The union is the part worth keeping. Any injection into a query language that supports set union gives
        you the same option: leave the original query intact so the surrounding code keeps working, and bolt your
        own query onto the side of it. The developer&rsquo;s trailing text stops being an obstacle and starts
        being the tail of your second expression.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'expression handed to DOMXPath::evaluate()',
        'before'   => "//user[username='",
        'injected' => $u,
        'after'    => "']/email/text()",
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level2.php',
        'items'  => [
            ['q'       => 'Can I close the predicate as well as the string literal?',
             'payload' => "alice']/email/text()|//user[username='x",
             'learn'   => 'A no-op rewrite: it produces the same output as a normal lookup. If that works, the
                           bracket and the union both survived, and only the path is left to change.'],
            ['q'       => 'Which child elements does a user node actually have?',
             'payload' => "alice']/*|//user[username='x",
             'learn'   => '<code>*</code> selects every child element. The node column in the result table names
                           each one, so you get the schema without guessing field names.'],
            ['q'       => 'Are the extra fields on all users or only on some?',
             'payload' => "x']/x|//user[recovery_token]/username|//user[username='x",
             'learn'   => 'A presence predicate. It answers "who has this element" without needing to know any
                           value, which is the cheapest way to find where the interesting data lives.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
