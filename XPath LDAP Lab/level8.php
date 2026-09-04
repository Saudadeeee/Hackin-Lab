<?php
require_once __DIR__ . '/helpers.php';

$L    = 8;
$meta = xl_levels()[$L];

$u    = isset($_GET['u']) ? (string)$_GET['u'] : '';
$sent = isset($_GET['u']) && $u !== '';

/* ── The vulnerable code, running for real. ───────────────────────────── */
$filter = "(&(uid=" . $u . ")(objectClass=person))";

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $parts     = null;      // every complete filter found in the string
    $checkErr  = null;      // why the well-formedness check refused it
    $hits      = [];
    $searched  = null;

    try {
        // "Sanity check": the string we are about to send must decompose into
        // complete filters with no bytes left dangling.
        $parts    = ldap_split_filters($filter);
        $searched = $parts[0];
        $hits     = ldap_search(xl_directory(), $searched);
    } catch (LdapFilterError $e) {
        $checkErr = $e->getMessage();
    }

    $reached = false;
    foreach ($hits as $h) {
        if (($h['attrs']['uid'][0] ?? '') === 'vault_agent') {
            $reached = true;
        }
    }

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u,
         'note'  => 'Unescaped. The mandatory clause after it is the only stated defence.'],
        ['label' => 'filter assembled by concatenation', 'value' => $filter],
        ['label' => 'well-formedness check: ldap_split_filters()',
         'value' => $checkErr === null
            ? count($parts) . ' complete filter(s), 0 bytes left over'
            : 'rejected',
         'note'  => $checkErr === null
            ? 'Every byte of the string was consumed by a syntactically complete filter, so the check passes.'
            : '<code>' . lk_esc($checkErr) . '</code>',
         'verdict' => $checkErr === null ? 'pass' : 'block'],
        ['label' => 'filters found in the string',
         'value' => $parts !== null
            ? implode('   +   ', array_map('ldap_filter_to_string', $parts))
            : '(none)',
         'note'  => $parts !== null && count($parts) > 1
            ? 'Only the <strong>first</strong> one is searched. The rest exist to keep the check happy.'
            : ''],
        ['label' => 'parse tree actually searched',
         'value' => $searched !== null ? ldap_filter_to_string($searched) : '(none)',
         'note'  => $searched !== null ? xl_tree_block($searched) : ''],
        ['label' => 'search result', 'value' => count($hits) . ' entry/entries matched',
         'verdict' => $reached ? 'pass' : null],
    ];

    if ($checkErr !== null) {
        $result = '<div class="message error"><strong>Refused before sending.</strong> The assembled filter is not
                   well formed: <code>' . lk_esc($checkErr) . '</code></div>';
    } elseif ($reached) {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>The staff lookup returned a service account.</strong>
                   <code>vault_agent</code> has no <code>person</code> in its objectClass, so the mandatory clause
                   stopped applying.</div>' . xl_entry_table($hits);
    } elseif (!$hits) {
        $result = '<div class="message error">0 entries matched.</div>';
    } else {
        $result = '<div class="message info">' . count($hits) . ' staff entry/entries:</div>'
                . xl_entry_table($hits, ['uid', 'cn', 'ou', 'objectClass', 'mail']);
    }
}

$code = <<<'PHP'
// Staff lookup. The objectClass clause is appended by the framework so
// that service accounts can never come back from this endpoint.
$u = $_GET['u'];

$filter = "(&(uid=" . $u . ")(objectClass=person))";

// Sanity check added after a previous incident: whatever we send has to
// parse. Complete filters, nothing dangling.
if (!filter_is_well_formed($filter)) {
    return bad_request('malformed filter');
}

foreach ($ldap->search($base, $filter) as $entry) {
    print_entry($entry);          // every attribute, this is an admin tool
}
PHP;

$fixBad = <<<'PHP'
$filter = "(&(uid=" . $u . ")(objectClass=person))";
if (!filter_is_well_formed($filter)) { return bad_request(); }
PHP;

$fixGood = <<<'PHP'
// Escape the value. The mandatory clause then genuinely is mandatory,
// because the attacker can no longer close the group it lives in.
$filter = sprintf(
    '(&(uid=%s)(objectClass=person))',
    ldap_escape($u, '', LDAP_ESCAPE_FILTER)
);

// A well-formedness check is not a security control - a valid filter and a
// safe filter are unrelated properties. If you want a structural check,
// check the STRUCTURE you intended: parse the string and assert the shape.
$tree = ldap_parse($filter);                  // one filter, whole string
assert_and_group($tree);                      // top node is AND
assert_has_clause($tree, 'objectClass', 'person');
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [5, 9],
    'annotation' => 'The mandatory clause sits after the injection point, so the attacker cannot get in front of
        it &mdash; and does not need to. Closing the AND group early leaves the clause outside the filter that is
        searched, and the well-formedness check is satisfied as long as the leftover text still parses as a
        filter of its own.',

    'theory' => '<p>"The attacker\'s input comes first, so our clause always applies" is a claim about string
        order. Filters are not evaluated in string order; they are evaluated as a tree. What matters is which node
        a clause ends up under, and an attacker who can write parentheses can re-parent it, orphan it, or push it
        past the end of the filter entirely.</p>
        <p>The well-formedness check is worth studying on its own, because it is the kind of control that gets
        written after an incident and then trusted forever. It answers "does this string parse". The question that
        needed answering was "is this string the filter I meant to build". Those come apart immediately: here the
        payload produces two perfectly valid filters, and the check has no opinion about there being two.</p>
        <p>The same shape turns up wherever a validator and a consumer disagree about what they are looking at. A
        JSON schema check that runs on a re-serialised copy; a URL allowlist that parses differently from the HTTP
        client; a WAF that reads a request body the application will read again with different rules. When you find
        a check, ask what it would have to know in order to be sufficient, and whether it knows it.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Escaping the value is the actual fix. Asserting the parsed shape is a useful second layer,
            because it fails loudly if a future refactor reintroduces concatenation somewhere else.',
    ],

    'scenario' => '<strong>Scenario:</strong> an internal staff lookup. The framework appends
        <code>(objectClass=person)</code> so that service accounts can never be returned, and the app refuses to
        send a filter that does not parse. Matched entries are printed in full.
        <br><strong>Goal:</strong> retrieve the <code>vault_agent</code> entry, whose objectClass contains
        <code>applicationProcess</code> and no <code>person</code>.',

    'model' => [
        'title' => 'Two constraints, and the payload that satisfies both',
        'html'  => '<pre class="lk-sinkline">(&amp;(uid=<span class="lk-inj">U</span>)(objectClass=person))</pre>
        <p>Constraint one: the <code>(objectClass=person)</code> clause must stop applying to the entry you want.
        Adding clauses does not help &mdash; new children of an AND make it stricter, never looser. The clause has
        to end up outside the filter that gets searched, which means closing the AND group before the parser
        reaches it.</p>
        <p>Constraint two: after your payload, the string <code>)(objectClass=person))</code> is still there, and
        the well-formedness check will not accept a dangling remainder. So the remainder has to become a complete
        filter in its own right. Count the parentheses:</p>
        <table class="lk-kv">
            <tr><td><code>x)</code></td><td>closes the uid clause. The AND is still open.</td></tr>
            <tr><td><code>x))</code></td><td>closes the uid clause and the AND. First filter complete &mdash; but
                now <code>)(objectClass=person))</code> is dangling and the check refuses it.</td></tr>
            <tr><td><code>x))(&amp;(objectClass=&hellip;</code></td><td>closes both, then opens a fresh AND group
                whose first clause is left half-written, so the developer&rsquo;s leftover finishes it.</td></tr>
        </table>
        <p>Write the whole string out on paper before you send it. The trace prints each complete filter it found,
        separated by <code>+</code>, so you can check your arithmetic against the parser&rsquo;s.</p>',
    ],

    'form' => xl_form(
        [['name' => 'u', 'label' => 'Staff username', 'value' => $u, 'placeholder' => 'dkoval']],
        'Look up',
        'Try <code>vault_agent</code> first and watch the mandatory clause do its job.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The clause is still in the string. It is not in the filter that ran.',
    'why'      => '<p>The string you produced contained two complete filters. The check counted zero leftover
        bytes and passed it; the client read the first filter and searched with it; the second filter, the one
        holding <code>(objectClass=person)</code>, was never evaluated by anything.</p>
        <p>Two things generalise. First, a mandatory clause is only mandatory while it stays inside the node that
        is evaluated &mdash; appending it is not the same as enforcing it. Second, a validator that checks a
        different property from the one you care about is worse than no validator, because it is where people stop
        looking.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'filter string handed to the well-formedness check and then to the client',
        'before'   => '(&(uid=',
        'injected' => $u,
        'after'    => ')(objectClass=person))',
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level8.php',
        'items'  => [
            ['q'       => 'Does the mandatory clause actually exclude the target?',
             'payload' => 'vault_agent',
             'learn'   => 'Zero results for an entry that certainly exists. Establishes what the defence is doing
                           before you try to take it apart.'],
            ['q'       => 'Does adding a clause loosen the AND?',
             'payload' => 'vault_agent)(objectClass=applicationProcess',
             'learn'   => 'Still nothing. The AND now has three children and one of them is still
                           <code>person</code>. Confirms that the group has to close, not grow.'],
            ['q'       => 'What exactly does the well-formedness check reject?',
             'payload' => 'vault_agent))',
             'learn'   => 'The first filter would have matched. The check refuses the string because of what comes
                           after it, and names the offset &mdash; which tells you precisely how many bytes you
                           have to absorb.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
