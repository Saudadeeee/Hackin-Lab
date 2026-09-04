<?php
require_once __DIR__ . '/helpers.php';

$L    = 10;
$meta = xl_levels()[$L];

/**
 * The application's own escaper. Three metacharacters, hex forms, and no
 * handling for the byte that introduces every one of those hex forms.
 */
function l10_bad_escape(string $s): string
{
    return str_replace(['(', ')', '*'], ['\\28', '\\29', '\\2a'], $s);
}

$u    = isset($_GET['u']) ? (string)$_GET['u'] : '';
$p    = isset($_GET['p']) ? (string)$_GET['p'] : '';
$sent = isset($_GET['u']) || isset($_GET['p']);

/* ── The vulnerable code, running for real. ───────────────────────────── */
$escaped    = l10_bad_escape($u);
$subs       = substr_count($u, '(') + substr_count($u, ')') + substr_count($u, '*');
$hash       = xl_ldap_hash($p);
$filter     = "(&(uid=" . $escaped . ")(userPassword=" . $hash . "))";

// The client "normalises" the filter with one left-to-right unescape pass
// before parsing it. See ldap.php: a correct parser does this the other way
// round, and that ordering is the entire vulnerability.
$normalised = ldap_unescape_whole_filter($filter);

$flag     = '';
$result   = '';
$pipeline = [];

if ($sent) {
    $tree = null;
    $err  = null;
    $trailing = '';
    $consumed = '';
    $hits = [];

    try {
        $r        = ldap_parse_first($normalised);
        $tree     = $r['tree'];
        $consumed = $r['consumed'];
        $trailing = $r['trailing'];
        $hits     = ldap_search(xl_directory(), $tree);
    } catch (LdapFilterError $e) {
        $err = $e->getMessage();
    }

    $first = $hits[0] ?? null;
    $who   = $first['attrs']['uid'][0] ?? '';
    $role  = $first['attrs']['role'][0] ?? '';

    // What the correct escaper would have produced, put through the same
    // broken normaliser, so the difference is visible rather than asserted.
    $correct     = ldap_escape_value($u);
    $correctNorm = ldap_unescape_whole_filter("(&(uid=" . $correct . ")(userPassword=" . $hash . "))");

    $pipeline = [
        ['label' => '$_GET["u"] (raw)', 'value' => $u],
        ['label' => 'bad_escape($u)  -  ( ) * to \\28 \\29 \\2a', 'value' => $escaped,
         'note'  => $subs > 0
            ? '<strong>' . $subs . '</strong> metacharacter(s) replaced. Every backslash in your input passed
               through untouched &mdash; that is the byte the whole scheme is built out of.'
            : 'Nothing to replace: the input contained no <code>(</code>, <code>)</code> or <code>*</code>.
               The escaper had no work to do, and the backslashes survived.',
         'verdict' => $subs > 0 ? 'block' : 'pass'],
        ['label' => 'filter assembled by concatenation', 'value' => $filter],
        ['label' => 'client normalisation: one unescape pass over the whole string', 'value' => $normalised,
         'note'  => $normalised !== $filter
            ? 'Compare the two lines. Bytes that were escape sequences a moment ago are now grammar.'
            : 'Nothing changed &mdash; there were no escape sequences to expand.',
         'verdict' => $normalised !== $filter ? 'pass' : null],
        ['label' => 'parser reads the first complete filter',
         'value' => $err === null ? $consumed : 'parse error',
         'note'  => $err !== null
            ? '<code>' . lk_esc($err) . '</code>'
            : ($trailing !== ''
                ? 'Discarded: <code>' . lk_esc($trailing) . '</code>'
                : 'The whole string was one filter.'),
         'verdict' => $err === null ? 'pass' : 'block'],
        ['label' => 'parse tree actually searched',
         'value' => $tree !== null ? ldap_filter_to_string($tree) : '(none)',
         'note'  => $tree !== null ? xl_tree_block($tree) : ''],
        ['label' => 'for comparison: ldap_escape($u) put through the same normaliser',
         'value' => $correctNorm,
         'note'  => 'The correct escaper writes <code>\\</code> as <code>\\5c</code> first. The normalisation pass
                     turns that back into a single backslash and stops there, so <code>\\29</code> survives as three
                     ordinary characters and never becomes a parenthesis.'],
        ['label' => 'authorisation decision',
         'value' => $first ? ($who . ' / role=' . $role) : '(no entry - login refused)',
         'verdict' => $role === 'administrator' ? 'pass' : null],
    ];

    if ($err !== null) {
        $result = '<div class="message error"><strong>Bind failed.</strong> <code>' . lk_esc($err) . '</code></div>';
    } elseif ($first === null) {
        $result = '<div class="message error"><strong>Bind failed.</strong> No entry matched.</div>';
    } elseif ($role === 'administrator') {
        $flag   = xl_flag($L);
        $result = '<div class="message success"><strong>Bound as ' . lk_esc($who)
                . '</strong> &mdash; role <code>administrator</code>.</div>'
                . xl_entry_table([$first], ['uid', 'cn', 'objectClass', 'role', 'ou']);
    } else {
        $result = '<div class="message info"><strong>Bound as ' . lk_esc($who) . '</strong> &mdash; role <code>'
                . lk_esc($role) . '</code>.</div>'
                . xl_entry_table([$first], ['uid', 'cn', 'objectClass', 'role', 'ou']);
    }
}

$code = <<<'PHP'
// This sign-in escapes its input. That was the finding from the last
// assessment and it was fixed.
function bad_escape(string $s): string {
    return str_replace(['(', ')', '*'], ['\28', '\29', '\2a'], $s);
}

$filter = "(&(uid=" . bad_escape($_GET['u']) . ")(userPassword=" . $hash . "))";

// The client normalises the filter before parsing it: one left-to-right
// pass turning every \XX into the byte it names.
$filter = unescape_pass($filter);

$entries = $ldap->search($base, $filter);
$user    = $entries[0] ?? null;
PHP;

$fixBad = <<<'PHP'
function bad_escape(string $s): string {
    return str_replace(['(', ')', '*'], ['\28', '\29', '\2a'], $s);
}
$filter = unescape_pass("(&(uid=" . bad_escape($u) . ")...");
PHP;

$fixGood = <<<'PHP'
// 1. Escape the escape character, and escape it FIRST. strtr() with a map
//    does one pass and never revisits what it wrote, so "(" cannot turn
//    into "\5c28" on the way through.
function escape_filter_value(string $s): string {
    return strtr($s, [
        '\\' => '\5c', '(' => '\28', ')' => '\29', '*' => '\2a', "\0" => '\00',
    ]);
}
// Or do not write it at all: ldap_escape($s, '', LDAP_ESCAPE_FILTER).

// 2. Delete the normalisation pass. Unescaping before parsing is what made
//    the escaping worthless; a correct parser decides where each value ends
//    and unescapes afterwards, so \28 inside a value is an inert byte.
$filter = "(&(uid=" . escape_filter_value($u) . ")(userPassword=" . $hash . "))";
$entries = $ldap->search($base, $filter);   // no normalisation, no rewriting
PHP;

lk_page([
    'lab'        => xl_lab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => xl_extra_head(),

    'code'       => $code,
    'vuln_lines' => [3, 4, 12],
    'annotation' => 'The escaper covers the three filter metacharacters and not the backslash that introduces
        their escaped forms. Because a later stage unescapes the whole filter string before parsing it, a payload
        written entirely as <code>\\28</code>, <code>\\29</code> and <code>\\2a</code> passes the escaper with
        nothing to escape and arrives at the parser as structure.',

    'theory' => '<p>Escaping is a two-party agreement. One side writes a value into a grammar; the other side reads
        it back out. It holds only while both sides agree about when unescaping happens, and the correct answer is
        <em>after</em> the structure has been determined. RFC 4515 is explicit about this, which is why
        <code>\\28</code> inside an assertion value is an ordinary byte and not an opening parenthesis: by the time
        anything looks at it, the value already ended at an unescaped <code>)</code>.</p>
        <p>Move the unescaping earlier and the property evaporates. A "normalise the filter before we parse it"
        step, a debug log that is re-read, a proxy that decodes and re-emits &mdash; any of them turns escape
        sequences back into grammar while there is still grammar to be part of. The same shape appears far away
        from LDAP: double URL decoding, an HTML sanitiser that runs before an entity decoder, a path canonicaliser
        that runs after the allowlist check.</p>
        <p>That is also why the backslash is the first character any escaper must handle, and why the order of the
        replacements is not a style question. Escape <code>\\</code> to <code>\\5c</code> first, and an attacker
        who sends <code>\\28</code> gets <code>\\5c28</code>, which even a naive normaliser reduces to the three
        harmless characters <code>\\28</code>. Escape it last, or not at all, and the attacker is writing your
        escape sequences for you. The trace on this page prints both versions side by side.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'Either half alone stops this payload. Both together is the point: the escaper becomes correct in
            isolation, and no downstream component is left free to undo it.',
    ],

    'scenario' => '<strong>Scenario:</strong> the same directory sign-in as level 6, after someone fixed it. Input
        is escaped now. The client normalises the filter before parsing.
        <br><strong>Goal:</strong> bind as <code>root_admin</code> again, this time through the escaper.',

    'model' => [
        'title' => 'Which byte survived, and what it is worth',
        'html'  => '<p>Work through the escaper one input at a time:</p>
        <table class="lk-kv">
            <tr><td>you send <code>)</code></td><td>escaper writes <code>\\29</code>. Normaliser turns it back into
                <code>)</code>. The escaper stopped nothing, but you had to send a metacharacter to find out.</td></tr>
            <tr><td>you send <code>\\29</code></td><td>escaper sees no <code>(</code>, <code>)</code> or
                <code>*</code> and changes nothing. Normaliser turns it into <code>)</code>. Same result, and the
                input never contained a metacharacter at all.</td></tr>
            <tr><td>correct escaper, you send <code>\\29</code></td><td>it writes <code>\\5c29</code>. Normaliser
                expands <code>\\5c</code> to one backslash and moves on, leaving the literal text
                <code>\\29</code>. Nothing structural survives.</td></tr>
        </table>
        <p>So the payload is level 6&rsquo;s payload with every metacharacter written in hex:</p>
        <table class="lk-kv">
            <tr><td><code>\\28</code></td><td><code>(</code></td></tr>
            <tr><td><code>\\29</code></td><td><code>)</code></td></tr>
            <tr><td><code>\\2a</code></td><td><code>*</code></td></tr>
        </table>
        <p>You need the uid clause to close, the AND group to close, and the leftover
        <code>)(userPassword=&hellip;))</code> to end up in a discarded second filter. Sketch the filter you want in
        plain characters first, then translate it. The trace prints the string before and after normalisation, so a
        mistranslation is visible in one request.</p>',
    ],

    'form' => xl_form(
        [
            ['name' => 'u', 'label' => 'Username', 'value' => $u, 'placeholder' => 'awhitfield'],
            ['name' => 'p', 'label' => 'Password', 'value' => $p, 'placeholder' => '············'],
        ],
        'Sign in',
        'The trace prints the escaper output, the normaliser output, and what a correct escaper would have produced
         from the same input.'
    ),

    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The escaper ran, replaced nothing, and the parser received a filter you wrote.',
    'why'      => '<p>Your input contained no <code>(</code>, no <code>)</code> and no <code>*</code>, so the
        escaper had nothing to replace and passed it through byte for byte &mdash; the trace shows zero
        substitutions. The normalisation pass then expanded your hex escapes, and by the time the parser looked at
        the string the metacharacters were back and structural. The parser then behaved correctly on a filter that
        was never the developer&rsquo;s.</p>
        <p>Set this beside level 6. Same directory, same target, same parse tree, and in between them an escaping
        function that a code review would very likely wave through. When you audit escaping, the two questions are
        always: does it handle the escape character itself, and is anything downstream allowed to unescape. A
        denylist of metacharacters answers neither.</p>',

    'pipeline' => $pipeline,
    'sink'     => [
        'label'    => 'filter string after normalisation, as the parser sees it',
        'before'   => '(&(uid=',
        'injected' => ldap_unescape_whole_filter($escaped),
        'after'    => ')(userPassword=' . $hash . '))',
    ],
    'probes'   => [
        'param'  => 'u',
        'method' => 'GET',
        'action' => 'level10.php',
        'items'  => [
            ['q'       => 'Does the escaper actually stop a plain parenthesis?',
             'payload' => 'awhitfield)',
             'learn'   => 'The trace shows one substitution and then the normaliser undoing it. Two stages, and
                           the second one is where the level lives &mdash; worth seeing before you write anything
                           clever.'],
            ['q'       => 'Does a backslash reach the filter untouched?',
             'payload' => 'awhitfield\\5c',
             'learn'   => 'Read the escaper output line: unchanged. Then read the normaliser line: your
                           <code>\\5c</code> became a single backslash. That confirms which byte the escaper is
                           missing and that the normaliser is real.'],
            ['q'       => 'Can I get one structural byte through as hex?',
             'payload' => 'awhitfield\\29',
             'learn'   => 'The uid clause should close early and the remainder should be discarded, exactly as in
                           level 6. One metacharacter proven, and the rest of the payload is the same trick
                           repeated.'],
        ],
    ],
    'hints' => xl_hints($L),
]);
