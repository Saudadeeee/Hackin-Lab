<?php
require_once __DIR__ . '/helpers.php';

$L    = 1;
$meta = xl_levels()[$L];

// The form is prefilled with a known username so that a probe which only
// changes the password still produces a meaningful expression.
$u = isset($_GET['u']) ? (string)$_GET['u'] : 'alice';
$p = isset($_GET['p']) ? (string)$_GET['p'] : '';
$sent = isset($_GET['u']) || isset($_GET['p']);

/* ── The vulnerable code, running for real. ───────────────────────────── */
$expr = "//user[username='" . $u . "' and password='" . $p . "']";
$run  = xl_xpath_run($expr);

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $first = $run['dom'][0] ?? null;
    $who   = $first ? xl_child_text($first, 'username') : '';
    $role  = $first ? xl_child_text($first, 'role') : '';

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u],
        ['label' => '$_GET["p"] (raw)', 'value' => $p,
         'note'  => 'No filtering happens between here and the expression. Whatever you typed is expression source.'],
        ['label' => 'expression built by concatenation', 'value' => $expr,
         'note'  => 'The two <code>\'</code> characters around each value belong to the developer. Everything
                     between them belongs to you.'],
        ['label' => 'DOMXPath::evaluate() result',
         'value' => $run['ok'] ? $run['count'] . ' node(s) selected' : 'expression did not parse',
         'note'  => $run['ok']
            ? 'The engine evaluated the expression above against <code>users.xml</code>.'
            : '<code>' . lk_esc((string)$run['error']) . '</code>',
         'verdict' => $run['ok'] ? ($run['count'] > 0 ? 'pass' : 'block') : 'block'],
        ['label' => 'authorisation decision: role of node[1]',
         'value' => $first ? ($who . ' / ' . $role) : '(no node - login refused)',
         'note'  => 'The application authenticates as the <strong>first</strong> node in document order and
                     reads its <code>role</code>. It never re-checks the password it was given.',
         'verdict' => $role === 'administrator' ? 'pass' : null],
    ];

    if (!$run['ok']) {
        $result = '<div class="message error"><strong>Login failed.</strong> The expression did not parse:
                   <code>' . lk_esc((string)$run['error']) . '</code></div>';
    } elseif ($first === null) {
        $result = '<div class="message error"><strong>Login failed.</strong> No user matched.</div>';
    } elseif ($role === 'administrator') {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>Signed in as ' . lk_esc($who)
                . '</strong> &mdash; role <code>administrator</code>. Directory console unlocked.</div>'
                . xl_user_table($run['dom']);
    } else {
        $result = '<div class="message info"><strong>Signed in as ' . lk_esc($who) . '</strong> &mdash; role <code>'
                . lk_esc($role) . '</code>. That is a matched node, but not an administrator: '
                . $run['count'] . ' node(s) matched and the application took the first one.</div>'
                . xl_user_table($run['dom']);
    }
}

$code = <<<'PHP'
// Staff console sign-in. The directory is an XML file, so the "query"
// is an XPath expression.
$u = $_GET['u'];
$p = $_GET['p'];

$expr = "//user[username='" . $u . "' and password='" . $p . "']";

$hits = $xpath->evaluate($expr);
if ($hits->length === 0) {
    return deny('bad credentials');
}

// Whoever came back first is who you are now.
$user = $hits->item(0);
if (child($user, 'role') === 'administrator') {
    grant_console();
}
PHP;

$fixBad = <<<'PHP'
$expr = "//user[username='" . $u . "' and password='" . $p . "']";
$hits = $xpath->evaluate($expr);
PHP;

$fixGood = <<<'PHP'
// XPath has variables. DOMXPath does not expose them directly, but
// registerPhpFunctions() plus a bound-variable helper, or an XPath 2.0
// engine, does. The point is the same as with SQL: the value must never
// become part of the expression TEXT.
$expr = '//user[username=$u and password=$p]';
$hits = $engine->evaluate($expr, ['u' => $u, 'p' => $p]);

// If the engine genuinely has no variables, do the comparison in the host
// language instead of in the query:
$node = null;
foreach ($xpath->query('//user') as $candidate) {
    if (hash_equals(child($candidate, 'username'), $u)) { $node = $candidate; break; }
}
if ($node === null || !password_verify($p, child($node, 'password'))) {
    return deny('bad credentials');
}

// And store password hashes, not passwords.
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6],
    'annotation' => 'Both form values are concatenated into an XPath predicate. A single quote in the input closes
        the developer&rsquo;s string literal, and everything after it is parsed as expression syntax rather than as
        data &mdash; so the attacker gets to decide what the predicate asks.',

    'theory' => '<p>XPath is a query language with the same structural weakness SQL has. An expression is source
        code; a value is data. When a value is pasted into the source code with no boundary between the two, the
        parser cannot tell them apart, because by the time the parser runs there is nothing left to tell apart.</p>
        <p>A predicate <code>[ ... ]</code> is a boolean expression evaluated once per candidate node. The
        developer wrote <code>username=$u and password=$p</code> intending to ask a question about credentials. The
        attacker rewrites it into a question with a known answer &mdash; the tautology &mdash; and the engine
        answers it faithfully.</p>
        <p>The detail that makes XPath its own skill rather than "SQL injection with different brackets" is
        precedence. <code>and</code> binds tighter than <code>or</code>, so where you inject changes what your
        tautology attaches to. That is worth working out on paper before sending anything.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Escaping quotes is the fix people reach for first, and level 4 exists to show why it is the
            wrong shape of answer. The value has to stay a value.',
    ],

    'scenario' => '<strong>Scenario:</strong> a staff console signs users in against an XML directory. The lookup
        matches a username and a password in one expression, then treats the first matching node as the logged-in
        user.
        <br><strong>Goal:</strong> sign in as an account whose <code>role</code> is <code>administrator</code>,
        without knowing any password.',

    'model' => [
        'title' => 'What the predicate becomes, and where your input lands',
        'html'  => '<pre class="lk-sinkline">//user[username=\'<span class="lk-inj">U</span>\' and password=\'<span class="lk-inj">P</span>\']</pre>
        <p>Two injection points, and they are not equivalent:</p>
        <table class="lk-kv">
            <tr><td>inject into U</td><td><code>x\' or \'1\'=\'1</code> gives
                <code>username=\'x\' or \'1\'=\'1\' and password=\'\'</code>, which precedence groups as
                <code>username=\'x\' or (\'1\'=\'1\' and password=\'\')</code>. Both sides are false. Nothing matches.</td></tr>
            <tr><td>inject into P</td><td><code>x\' or \'1\'=\'1</code> gives
                <code>(username=\'..\' and password=\'x\') or \'1\'=\'1\'</code>. The tautology is at the top level,
                so every user matches.</td></tr>
        </table>
        <p>Matching every user is not the goal, though. The application logs you in as the <strong>first node in
        document order</strong>, and the first user in <code>users.xml</code> is an engineer. A tautology gets you
        a session; a targeted predicate gets you the session you want. Ask yourself what else you know about the
        administrator that you can compare against &mdash; the <code>role</code> element is right there in the
        same node.</p>',
    ],

    'form' => xl_form(
        [
            ['name' => 'u', 'label' => 'Username', 'value' => $u, 'placeholder' => 'alice'],
            ['name' => 'p', 'label' => 'Password', 'value' => $p, 'placeholder' => '············'],
        ],
        'Sign in',
        'The expression built from these two fields is shown in the SINK box below, exactly as the engine received it.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The predicate you wrote selected an administrator, and the application believed it.',
    'why'      => '<p>Your quote ended the developer&rsquo;s string literal, which put the rest of your input into
        expression context. There you wrote a comparison the engine could satisfy without any password at all:
        <code>role=\'administrator\'</code> is true for exactly one node in the document, so the node set contained
        exactly that node, and the application took it.</p>
        <p>Nothing was bypassed in the sense of "a check was skipped". The check ran, honestly, against a question
        it had no business being asked. That is the shape of every injection in this lab: the engine is correct,
        the expression is not the one the developer wrote.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'expression handed to DOMXPath::evaluate()',
        'before'   => "//user[username='" . $u . "' and password='",
        'injected' => $p,
        'after'    => "']",
    ],
    'probes'   => [
        'param'  => 'p',
        'method' => 'GET',
        'action' => 'level1.php',
        'items'  => [
            ['q'       => 'Does a single quote reach the XPath parser?',
             'payload' => "x'",
             'learn'   => 'One unbalanced quote makes the expression malformed. If the trace prints an
                           "Invalid expression" error rather than "no user matched", the quote is being parsed,
                           not compared. One request, one fact.'],
            ['q'       => 'Can I close the literal and add my own operator without breaking the parse?',
             'payload' => "x' or '1'='2",
             'learn'   => 'A deliberately <em>false</em> tautology. It should parse cleanly and match nothing.
                           That separates "my syntax is right" from "my logic is right", which are different
                           problems and worth debugging one at a time.'],
            ['q'       => 'Is the whole document reachable from this predicate?',
             'payload' => "x' or '1'='1",
             'learn'   => 'Now the tautology is true. Read the node count in the trace: if it equals the number
                           of users in the directory, you have full read access to the node set and only need to
                           narrow it to the node you want.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
