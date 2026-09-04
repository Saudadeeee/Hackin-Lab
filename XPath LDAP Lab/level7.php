<?php
require_once __DIR__ . '/helpers.php';

$L    = 7;
$meta = xl_levels()[$L];

$raw  = isset($_GET['q']) ? (string)$_GET['q'] : '';
$sent = isset($_GET['q']) && $raw !== '';

/* ── The developer's protection, verbatim. ────────────────────────────── */
$q       = str_replace(['(', ')'], '', $raw);
$removed = strlen($raw) - strlen($q);

/* ── The vulnerable code, running for real. ───────────────────────────── */
$filter = "(uid=" . $q . "*)";

$flag     = '';
$result   = '';
$pipeline = [];
$total    = count(xl_directory());

if ($sent) {
    $tree = null;
    $err  = null;
    $hits = [];

    try {
        $tree = ldap_parse($filter);          // strict: the whole string is one filter
        $hits = ldap_search(xl_directory(), $tree);
    } catch (LdapFilterError $e) {
        $err = $e->getMessage();
    }

    $everything = count($hits) === $total && $total > 0;

    $pipeline = [
        ['label' => '$_GET["q"] (raw)', 'value' => $raw],
        ['label' => 'str_replace(["(", ")"], "", $q)', 'value' => $q,
         'note'  => $removed > 0
            ? '<strong>' . $removed . '</strong> parenthesis character(s) removed, so no clause can be added.'
            : 'Nothing removed. The input contained no parentheses.',
         'verdict' => $removed > 0 ? 'block' : 'pass'],
        ['label' => 'filter assembled by concatenation', 'value' => $filter,
         'note'  => 'The trailing <code>*</code> is the developer&rsquo;s, added so that typing three letters
                     finds a colleague.'],
        ['label' => 'parse tree', 'value' => $tree !== null ? ldap_filter_to_string($tree) : 'parse error',
         'note'  => $tree !== null ? xl_tree_block($tree) : '<code>' . lk_esc((string)$err) . '</code>',
         'verdict' => $tree !== null ? 'pass' : 'block'],
        ['label' => 'search result',
         'value' => count($hits) . ' of ' . $total . ' entries matched',
         'note'  => $everything
            ? 'Every entry in the tree, including the ones that are not in <code>ou=people</code>.'
            : 'The assertion still constrains the value.',
         'verdict' => $everything ? 'pass' : null],
    ];

    if ($err !== null) {
        $result = '<div class="message error"><strong>Search failed.</strong> ' . lk_esc($err) . '</div>';
    } elseif ($everything) {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>' . count($hits) . ' of ' . $total
                . ' entries returned.</strong> The substring assertion places no constraint on the value at all,
                   so the search walked the whole tree.</div>'
                . xl_entry_table($hits, ['uid', 'cn', 'ou', 'objectClass', 'mail', 'description']);
    } else {
        $result = '<div class="message info">' . count($hits) . ' match(es) for <code>' . lk_esc($q)
                . '*</code>:</div>'
                . xl_entry_table($hits, ['uid', 'cn', 'ou', 'mail']);
    }
}

$code = <<<'PHP'
// Staff directory autocomplete. Type a few letters, get colleagues.
$q = $_GET['q'];

// Hardening: strip the parentheses so nobody can add filter clauses.
$q = str_replace(['(', ')'], '', $q);

// The trailing * is ours - it is what makes this a prefix search.
$filter = "(uid=" . $q . "*)";

foreach ($ldap->search($base, $filter) as $entry) {
    echo $entry['uid'][0], ' - ', $entry['cn'][0];
}
PHP;

$fixBad = <<<'PHP'
$q = str_replace(['(', ')'], '', $q);
$filter = "(uid=" . $q . "*)";
PHP;

$fixGood = <<<'PHP'
// Escape the value, then add your own wildcard OUTSIDE the escaped part.
// ldap_escape turns * into \2a, which matches a literal asterisk - exactly
// what you want for a value and exactly not what you want for the wildcard
// the developer is adding on purpose.
$filter = '(uid=' . ldap_escape($q, '', LDAP_ESCAPE_FILTER) . '*)';

// Autocomplete endpoints deserve two more constraints, whatever the query
// language: require a minimum prefix length, and scope the search so it
// cannot leave the part of the tree that is meant to be browsable.
if (strlen($q) < 3) {
    return [];
}
$filter = '(&(objectClass=inetOrgPerson)(ou=people)' . $filter . ')';
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 8],
    'annotation' => 'Removing parentheses stops clauses from being added, and stops nothing else. The asterisk is
        also grammar: it changes an equality assertion into a substring assertion, and a substring assertion with
        no text in it constrains nothing.',

    'theory' => '<p><code>(uid=alice)</code> and <code>(uid=al*)</code> are not the same node with a different
        value. The first is an equality match; the second is a substring match, a distinct assertion type in the
        protocol with its own initial / any / final parts. The asterisk is not a character in the value &mdash; it
        is the thing that decides which assertion the parser builds.</p>
        <p>Everyone already knows the SQL version of this bug. <code>LIKE \'%\' . $q . \'%\'</code> is unsafe even
        with a bound parameter, because <code>%</code> and <code>_</code> are pattern syntax inside the value and
        binding does not neutralise them. LDAP has the identical shape with a different character, and it gets
        audited far less often because "we escaped the parentheses" sounds like the whole job.</p>
        <p>The result is usually classified as information disclosure, and it usually is more than that. Directory
        trees separate people from service accounts, and applications rely on that separation for scoping. A filter
        that matches every entry hands over the accounts that were never meant to be enumerable, along with their
        descriptions, their mail addresses and, on a lot of real directories, enough of their attributes to plan
        the next step.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The escaped value and the developer&rsquo;s wildcard are on opposite sides of the escaping call
            for a reason: one is data and one is syntax, and the code should be able to tell you which is which.',
    ],

    'scenario' => '<strong>Scenario:</strong> the staff directory autocomplete. It prefix-matches on
        <code>uid</code> and shows names and mail addresses.
        <br><strong>Goal:</strong> make one search return every entry in the directory, including the service
        accounts that live outside <code>ou=people</code>.',

    'model' => [
        'title' => 'How a substring assertion is put together',
        'html'  => '<pre class="lk-sinkline">(uid=<span class="lk-inj">Q</span>*)</pre>
        <p>The parser splits the assertion value on unescaped asterisks and keeps three things:</p>
        <table class="lk-kv">
            <tr><td><code>(uid=abc)</code></td><td>EQUAL. Not a substring assertion at all.</td></tr>
            <tr><td><code>(uid=ab*)</code></td><td>SUBSTRING initial=<code>ab</code>, final=<code>&quot;&quot;</code>.
                Starts with "ab".</td></tr>
            <tr><td><code>(uid=*ab)</code></td><td>SUBSTRING initial=<code>&quot;&quot;</code>, final=<code>ab</code>.
                Ends with "ab".</td></tr>
            <tr><td><code>(uid=a*b*c)</code></td><td>SUBSTRING with an <code>any</code> part in the middle, matched
                in order.</td></tr>
            <tr><td><code>(uid=*)</code></td><td>PRESENT. A different node type again: "this attribute exists".</td></tr>
            <tr><td><code>(uid=\\2a)</code></td><td>EQUAL to a literal asterisk. This is what escaping produces,
                and it is why escaping is the fix.</td></tr>
        </table>
        <p>The developer already appended one <code>*</code>. Ask what the smallest input is that leaves every part
        of the assertion empty, and check your answer against the parse tree the trace prints.</p>',
    ],

    'form' => xl_form(
        [['name' => 'q', 'label' => 'Find a colleague', 'value' => $raw, 'placeholder' => 'aw']],
        'Search',
        'Parentheses are removed before the filter is built. The trace shows how many.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'One metacharacter, and the assertion stopped asserting anything.',
    'why'      => '<p>The parse tree in the trace is the explanation. Your input plus the developer&rsquo;s
        trailing asterisk produced a substring assertion whose initial part, any parts and final part are all
        empty, so every value of <code>uid</code> satisfies it &mdash; and every entry in this tree has a
        <code>uid</code>. The parenthesis filter ran, removed nothing, and was never relevant.</p>
        <p>Carry the pattern rather than the payload. Any time an application wraps user input in its own pattern
        syntax &mdash; <code>LIKE</code>, a glob, a regular expression, an LDAP substring assertion &mdash; ask
        which characters are syntax in that pattern and whether the value was escaped for <em>that</em> layer.
        Escaping for the outer grammar and forgetting the inner one is a recurring shape.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'filter string handed to the LDAP client',
        'before'   => '(uid=',
        'injected' => $q,
        'after'    => '*)',
    ],
    'probes'   => [
        'param'  => 'q',
        'method' => 'GET',
        'action' => 'level7.php',
        'items'  => [
            ['q'       => 'What does the filter look like for an ordinary search?',
             'payload' => 'aw',
             'learn'   => 'Baseline. The trace prints <code>SUBSTRING uid initial="aw" final=""</code>, which is
                           the vocabulary the rest of the level is written in.'],
            ['q'       => 'Are parentheses really being removed?',
             'payload' => 'aw)(objectClass=*',
             'learn'   => 'The trace shows the count of removed characters and the filter that survived. Confirms
                           the stated defence works, which is worth knowing before you spend time on it.'],
            ['q'       => 'Is the asterisk data or syntax here?',
             'payload' => 'a*d',
             'learn'   => 'If it were data, this would look for a uid containing a literal asterisk and nothing
                           would come back. If it is syntax, the parse tree gains an <code>any</code> part and a
                           colleague appears. One request settles it.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
