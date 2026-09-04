<?php
require_once __DIR__ . '/helpers.php';

$L    = 6;
$meta = xl_levels()[$L];

$u    = isset($_GET['u']) ? (string)$_GET['u'] : '';
$p    = isset($_GET['p']) ? (string)$_GET['p'] : '';
$sent = isset($_GET['u']) || isset($_GET['p']);

/* ── The vulnerable code, running for real. ───────────────────────────────
 * The password is hashed before it reaches the filter, so only the uid field
 * carries attacker bytes into the grammar. */
$hash   = xl_ldap_hash($p);
$filter = "(&(uid=" . $u . ")(userPassword=" . $hash . "))";

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $parsed   = null;
    $perr     = null;
    $entries  = [];
    $consumed = '';
    $trailing = '';

    try {
        // A client library that reads ONE filter off the front of the string
        // and never looks at the rest. See ldap.php for why that is modelled.
        $r        = ldap_parse_first($filter);
        $parsed   = $r['tree'];
        $consumed = $r['consumed'];
        $trailing = $r['trailing'];
        $entries  = ldap_search(xl_directory(), $parsed);
    } catch (LdapFilterError $e) {
        $perr = $e->getMessage();
    }

    $first = $entries[0] ?? null;
    $who   = $first['attrs']['uid'][0] ?? '';
    $role  = $first['attrs']['role'][0] ?? '';

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u,
         'note'  => 'Goes into the filter unchanged. Nothing escapes it.'],
        ['label' => '$_GET["p"] -> {SHA} hash', 'value' => $hash,
         'note'  => 'Hashed first, so the password field cannot carry filter syntax. Only the uid can.'],
        ['label' => 'filter assembled by concatenation', 'value' => $filter],
        ['label' => 'client parses the first complete filter',
         'value' => $perr === null ? $consumed : 'parse error',
         'note'  => $perr !== null
            ? '<code>' . lk_esc($perr) . '</code>'
            : ($trailing !== ''
                ? 'Bytes after the first filter: <code>' . lk_esc($trailing) . '</code> &mdash; the client
                   discards them without complaint. That is the whole reason the payload has a tail.'
                : 'The whole string was one filter; nothing left over.'),
         'verdict' => $perr === null ? 'pass' : 'block'],
        ['label' => 'parse tree actually searched',
         'value' => $parsed !== null ? ldap_filter_to_string($parsed) : '(none)',
         'note'  => $parsed !== null ? xl_tree_block($parsed) : ''],
        ['label' => 'search result', 'value' => count($entries) . ' entry/entries matched',
         'note'  => 'The application binds as the <strong>first</strong> entry the search returned.'],
        ['label' => 'authorisation decision',
         'value' => $first ? ($who . ' / role=' . $role) : '(no entry - login refused)',
         'verdict' => $role === 'administrator' ? 'pass' : null],
    ];

    if ($perr !== null) {
        $result = '<div class="message error"><strong>Bind failed.</strong> The filter did not parse:
                   <code>' . lk_esc($perr) . '</code></div>';
    } elseif ($first === null) {
        $result = '<div class="message error"><strong>Bind failed.</strong> No entry matched the filter.</div>';
    } elseif ($role === 'administrator') {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>Bound as ' . lk_esc($who)
                . '</strong> &mdash; role <code>administrator</code>.</div>'
                . xl_entry_table([$first], ['uid', 'cn', 'objectClass', 'role', 'ou']);
    } else {
        $result = '<div class="message info"><strong>Bound as ' . lk_esc($who) . '</strong> &mdash; role <code>'
                . lk_esc($role) . '</code>. ' . count($entries) . ' entry/entries matched and the application took
                   the first.</div>' . xl_entry_table([$first], ['uid', 'cn', 'objectClass', 'role', 'ou']);
    }
}

$code = <<<'PHP'
// Directory sign-in. The password is hashed before it goes anywhere near
// the filter, which the developer considered the risky part.
$u    = $_GET['u'];
$hash = '{SHA}' . base64_encode(sha1($_GET['p'], true));

$filter = "(&(uid=" . $u . ")(userPassword=" . $hash . "))";

$entries = $ldap->search($base, $filter);
if (count($entries) === 0) {
    return deny('bad credentials');
}
$user = $entries[0];              // whoever came back first
if ($user['role'][0] === 'administrator') {
    grant_console();
}
PHP;

$fixBad = <<<'PHP'
$filter = "(&(uid=" . $u . ")(userPassword=" . $hash . "))";
PHP;

$fixGood = <<<'PHP'
// Escape every value that goes into a filter. PHP ships this.
$filter = sprintf(
    '(&(uid=%s)(userPassword=%s))',
    ldap_escape($u, '', LDAP_ESCAPE_FILTER),
    ldap_escape($hash, '', LDAP_ESCAPE_FILTER)
);

// Then stop authenticating by search result. The correct LDAP flow is:
//   1. search for exactly one entry matching the uid
//   2. if the search returned anything other than one entry, deny
//   3. BIND as that entry's DN with the supplied password, and let the
//      directory server decide
$hits = $ldap->search($base, $filter);
if (count($hits) !== 1) {
    return deny('bad credentials');
}
if (!$ldap->bind($hits[0]['dn'], $password)) {
    return deny('bad credentials');
}
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6],
    'annotation' => 'The username is concatenated into an RFC 4515 filter. An assertion value ends at the first
        unescaped <code>)</code>, so a <code>)</code> in the username closes the uid clause and a <code>(</code>
        opens a clause of the attacker&rsquo;s own &mdash; they are writing nodes into the parse tree.',

    'theory' => '<p>An LDAP filter is a tree written in prefix notation. <code>(&amp;(a=1)(b=2))</code> is an AND
        node with two leaves; <code>(|(a=1)(!(b=2)))</code> is an OR node whose second child is a NOT. Reading a
        filter as a tree rather than as a sentence is the single most useful habit for this class of bug, because
        an injection is only ever "the attacker added, removed or re-parented a node".</p>
        <p>The grammar has exactly three metacharacters inside a value: <code>(</code>, <code>)</code> and
        <code>*</code>, plus <code>\\</code> which introduces their escaped forms. That is a much smaller surface
        than SQL, which is why an escaping function for LDAP is short and why there is no excuse for not using one.
        PHP has shipped <code>ldap_escape()</code> since 5.6.</p>
        <p>The second half of this level is not a parsing bug at all. The application authenticates by
        <em>searching</em> and then trusting the first row, instead of binding. Searching answers "does an entry
        match this filter"; binding answers "does this principal hold this credential". Those are different
        questions, and only one of them is authentication. Plenty of real applications get the escaping right and
        this part wrong, at which point a filter that matches more entries than intended is still an account
        takeover.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Escaping alone would have stopped this payload. Binding alone would have stopped it too. Doing
            both is what makes the next mistake survivable.',
    ],

    'scenario' => '<strong>Scenario:</strong> a directory sign-in page. It searches for an entry matching the
        username and the password hash, then treats the first result as the authenticated user.
        <br><strong>Goal:</strong> bind as an entry whose <code>role</code> is <code>administrator</code>, without
        a password.',

    'model' => [
        'title' => 'Where your bytes land in the tree',
        'html'  => '<pre class="lk-sinkline">(&amp;(uid=<span class="lk-inj">U</span>)(userPassword=&lt;hash&gt;))</pre>
        <p>The developer&rsquo;s filter is an AND with two children. You are inside the assertion value of the
        first one. The bytes that mean something there:</p>
        <table class="lk-kv">
            <tr><td><code>)</code></td><td>ends the current assertion value, and therefore the current clause</td></tr>
            <tr><td><code>(</code></td><td>begins a new clause, if the parser is expecting one</td></tr>
            <tr><td><code>*</code></td><td>turns an equality assertion into a presence or substring assertion</td></tr>
        </table>
        <p>The password clause is not going away, so it has to end up somewhere it cannot fail. The usual answer is
        to close the AND group early and let the rest of the developer&rsquo;s text become a second filter that the
        client never evaluates. Write the whole string out before you send it:</p>
        <pre class="lk-sinkline">(&amp;(uid=<span class="lk-inj">*)(uid=*))(|(uid=*</span>)(userPassword=&lt;hash&gt;))</pre>
        <p>Read it left to right. <code>(&amp;(uid=*)(uid=*))</code> is complete and closed. Everything after it,
        <code>(|(uid=*)(userPassword=&lt;hash&gt;))</code>, is a second complete filter that the client reads off
        the end of the buffer and discards. The trace prints both halves separately so you can check your
        arithmetic.</p>
        <p>One more thing to decide: <code>(uid=*)</code> matches every entry, and the application takes the first
        one. Whether that is an administrator depends on the order the directory returns entries in &mdash; which
        is not something an application should be relying on either way. Look at what the trace says came back.</p>',
    ],

    'form' => xl_form(
        [
            ['name' => 'u', 'label' => 'Username', 'value' => $u, 'placeholder' => 'awhitfield'],
            ['name' => 'p', 'label' => 'Password', 'value' => $p, 'placeholder' => '············'],
        ],
        'Sign in',
        'The assembled filter, the bytes the client consumed, the bytes it discarded and the resulting parse tree
         are all in the trace.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'You wrote the parse tree, and the directory evaluated it faithfully.',
    'why'      => '<p>Your <code>)</code> closed the uid clause; your <code>(</code> opened a clause of your own;
        your second <code>)</code> closed the AND group before the password clause was reached. What the client
        parsed was a complete filter that never mentions <code>userPassword</code> at all, and the remainder of the
        developer&rsquo;s string was read off the end of the buffer and thrown away.</p>
        <p>Notice that the evaluator behaved correctly at every step. It matched the entries the filter described.
        The vulnerability is upstream of it, in the four lines that turned two strings into a filter, and the
        second-order problem is downstream of it, in the line that treats a search hit as proof of identity.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'filter string handed to the LDAP client',
        'before'   => '(&(uid=',
        'injected' => $u,
        'after'    => ')(userPassword=' . $hash . '))',
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level6.php',
        'items'  => [
            ['q'       => 'Does a bare closing parenthesis reach the parser?',
             'payload' => 'awhitfield)',
             'learn'   => 'The trace shows the client consuming <code>(&amp;(uid=awhitfield))</code> and discarding
                           the rest. Two facts for one request: the byte is structural, and leftovers are ignored
                           rather than rejected.'],
            ['q'       => 'What does the parser do with an unbalanced payload?',
             'payload' => 'awhitfield)(',
             'learn'   => 'A parse error naming the offset. Errors are the cheapest way to learn a grammar, and
                           this one tells you the client validates the part it reads even though it ignores the
                           part it does not.'],
            ['q'       => 'Is the password clause the only thing standing between me and an entry?',
             'payload' => 'awhitfield)(uid=awhitfield',
             'learn'   => 'Still no match: the AND now has three children and the password clause is still one of
                           them. Adding clauses is not enough &mdash; the group has to close.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
