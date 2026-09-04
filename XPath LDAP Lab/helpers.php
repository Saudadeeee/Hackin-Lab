<?php
/**
 * XPath & LDAP Lab · lab metadata, flags, hints and the shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/ldap.php';
require_once __DIR__ . '/directory.php';

function xl_lab(): array
{
    return [
        'slug'    => 'xpathldap',
        'name'    => 'XPath & LDAP Injection Lab',
        'icon'    => 'XL',
        'total'   => 10,
        'tagline' => 'Two query languages, one habit: building a filter by gluing strings together',
    ];
}

function xl_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{the_predicate_became_a_tautology}',
        2  => 'FLAG{a_predicate_ends_where_the_input_says}',
        3  => 'FLAG{one_bit_per_request_is_still_a_read}',
        4  => 'FLAG{stripping_quotes_is_not_a_parser}',
        5  => 'FLAG{a_union_selects_a_second_node_set}',
        6  => 'FLAG{i_supplied_the_parse_tree}',
        7  => 'FLAG{a_filter_star_is_not_a_like_pattern}',
        8  => 'FLAG{closed_my_group_and_kept_the_parse}',
        9  => 'FLAG{substring_filters_leak_one_char_each}',
        10 => 'FLAG{the_backslash_was_the_escape_character}',
    ];
    return $flags[$level] ?? '';
}

function xl_levels(): array
{
    return [
        1 => [
            'title'      => 'XPath Authentication Bypass',
            'difficulty' => 'Easy',
            'skill'      => 'XPath predicates, operator precedence, tautologies',
            'desc'       => 'A login builds <code>//user[username=\'..\' and password=\'..\']</code> by concatenation. Change what the predicate asks and the password stops mattering.',
        ],
        2 => [
            'title'      => 'Reading Sibling Nodes',
            'difficulty' => 'Easy',
            'skill'      => 'Escaping a predicate, unions, selecting a different node',
            'desc'       => 'The lookup selects one field of the matched node. End the predicate early and steer the location path at a field the page never renders.',
        ],
        3 => [
            'title'      => 'Blind Boolean XPath',
            'difficulty' => 'Medium',
            'skill'      => 'Boolean oracles, string-length() and substring(), search cost',
            'desc'       => 'The page answers "found" or "not found" and nothing else. Turn that one bit into a stolen API key, and count what each character costs.',
        ],
        4 => [
            'title'      => 'Quotes Are Filtered',
            'difficulty' => 'Medium',
            'skill'      => 'Injection without string literals; why input filtering is not parsing',
            'desc'       => 'Single and double quotes are stripped before the expression is built. The injection point was never inside a string, so the filter protects nothing.',
        ],
        5 => [
            'title'      => 'XPath Into an Attribute Predicate',
            'difficulty' => 'Hard',
            'skill'      => 'Numeric predicate context, union operator, reaching another subtree',
            'desc'       => 'Input lands in <code>@id=..</code> with no quotes around it. Quote-based payloads produce syntax errors; a union produces a second node set.',
        ],
        6 => [
            'title'      => 'LDAP Authentication Bypass',
            'difficulty' => 'Easy',
            'skill'      => 'RFC 4515 filter grammar, reading the parse tree you created',
            'desc'       => 'The bind filter is <code>(&amp;(uid=..)(userPassword=..))</code>. Write your own parse tree into the uid field and read what the parser made of it.',
        ],
        7 => [
            'title'      => 'Wildcard Truncation',
            'difficulty' => 'Medium',
            'skill'      => 'Substring assertions, why * is structure and not data',
            'desc'       => 'Parentheses are stripped, so the filter shape is safe. The asterisk is not a parenthesis, and it is still a metacharacter.',
        ],
        8 => [
            'title'      => 'Injecting Into an AND',
            'difficulty' => 'Medium',
            'skill'      => 'Closing your own group, keeping the remainder well formed',
            'desc'       => 'A mandatory <code>(objectClass=person)</code> clause follows your input, and the app rejects anything that does not parse. Close your group and leave a valid remainder.',
        ],
        9 => [
            'title'      => 'Blind Attribute Extraction',
            'difficulty' => 'Hard',
            'skill'      => 'Substring filters, ordering filters, extraction cost arithmetic',
            'desc'       => 'Matched or not matched, no data. Recover an attribute one character at a time with <code>(attr=a*)</code>, then do it again in a sixth of the requests.',
        ],
        10 => [
            'title'      => 'Escaping That Missed a Character',
            'difficulty' => 'Expert',
            'skill'      => 'Escape-then-unescape ordering, the backslash as the first thing to escape',
            'desc'       => 'The escaper handles <code>(</code>, <code>)</code> and <code>*</code>. It leaves the backslash alone, and something downstream unescapes.',
        ],
    ];
}

/* =========================================================================
 * Hints - exactly five per level:
 *   1 concept   2 observation about THIS code   3 technique
 *   4 the shape of the payload   5 a working payload
 * ===================================================================== */

function xl_hints(int $level): array
{
    $h = [
        1 => [
            'XPath predicates are boolean expressions. <code>//user[A and B]</code> keeps the users for which both A and B are true. Your input is being pasted <em>inside</em> that expression, not compared against it.',
            'Look at where the quotes come from: <code>"..username=\'" . $u . "\' and password=\'" . $p . "\']"</code>. The opening and closing quotes belong to the developer. Anything you type between them is expression source code.',
            'A single quote closes the developer\'s string literal and puts you back in expression context, where you can write your own operators. The classic move is to add an <code>or</code> whose right-hand side is always true.',
            'Beware precedence: <code>and</code> binds tighter than <code>or</code>, so <code>A or B and C</code> means <code>A or (B and C)</code>. Injecting into the <em>username</em> leaves your tautology trapped inside the <code>and</code>; injecting into the <em>password</em> puts it at the top level.',
            'Password <code>x\' or \'1\'=\'1</code> matches every user and logs you in as the first one, which is not an administrator. Aim instead: password <code>x\' or role=\'administrator</code>.',
        ],
        2 => [
            'An XPath expression has two halves: a location path that says which nodes to walk, and predicates that say which of them to keep. Level 1 rewrote a predicate. This level rewrites the <strong>path</strong>.',
            'The expression ends in <code>/email/text()</code>. That suffix is why you only ever see an email address. Break out of the predicate and you get to choose what comes after the closing bracket.',
            'The union operator <code>|</code> joins two node sets. <code>pathA | pathB</code> returns everything either path selects, so you can leave the developer\'s path intact and simply add your own next to it.',
            'Shape: close the quote, close the bracket, write your own path, then <code>|</code> and enough text that the developer\'s leftover <code>\']/email/text()</code> still parses as part of a second, harmless path.',
            '<code>svc_backup\']/recovery_token|//user[username=\'x</code> — the whole expression becomes <code>//user[username=\'svc_backup\']/recovery_token|//user[username=\'x\']/email/text()</code>.',
        ],
        3 => [
            'A page that answers only yes or no is still a read primitive. Each request returns one bit; a value is just a sequence of bits you have not asked for yet.',
            'The expression is <code>//user[username=\'$u\']</code> and the page prints "found" when the node set is non-empty. Add <code>and &lt;something&gt;</code> to the predicate and "found" now answers <em>your</em> question instead of the developer\'s.',
            'XPath 1.0 gives you <code>string-length(apikey)</code> and <code>substring(apikey,N,1)</code>. Compare them with <code>=</code>, <code>&gt;=</code> or <code>&lt;=</code> and the page becomes an oracle you can binary-search.',
            'Length first, then characters. For characters, the cheap trick is to turn a character into a number: <code>string-length(substring-before(\'abcdefghijklmnopqrstuvwxyz0123456789\', substring(apikey,N,1)))</code> is the index of that character in the alphabet, and numbers can be bisected.',
            'One probe looks like <code>svc_backup\' and substring(apikey,1,1)=\'k</code>. Use the console on the page: the binary buttons recover all six characters in about forty requests. Then submit the value you recovered.',
        ],
        4 => [
            'A filter that removes characters is a guess about where your input lands. If the guess is wrong, the filter costs the attacker nothing.',
            'Read the expression being built: <code>//user[position()=$q]/username/text()</code>. There are no quotes around <code>$q</code>. Stripping quotes removes something that was never load bearing here.',
            'Everything you need is quote-free. Numbers are literals. <code>position()</code>, <code>last()</code> and <code>count()</code> return numbers. A bare predicate such as <code>[pin]</code> is a presence test - true for any node that has a <code>pin</code> child - and needs no string at all.',
            'Shape: close the bracket, union in a path that selects the node you want using presence rather than equality, then reopen a predicate so the trailing <code>]/username/text()</code> still parses.',
            '<code>1]|//user[pin]/pin|//user[position()=1</code> — three node sets unioned, not a single quote in sight.',
        ],
        5 => [
            'The context an injection lands in decides which payloads are even syntactically legal. Quoting is a habit; the grammar is the fact.',
            '<code>//user[@id=$v]</code> compares an attribute to a <em>number</em>. Type a single quote and you get an "Invalid expression" error, because you have written a string where the parser wanted an operand.',
            'You do not need to escape anything - you are already outside any string. Close the predicate with <code>]</code> and the rest of the expression is yours to write.',
            'The target is not under <code>//user</code> at all, so no predicate can reach it. A union can: <code>|</code> takes the node set from an entirely different part of the document and adds it to the result.',
            '<code>0]|//vault/secret/text()|//user[@id=1</code> — the first arm matches nothing, the second is the payload, the third swallows the developer\'s trailing <code>]/username/text()</code>.',
        ],
        6 => [
            'An LDAP filter is a parenthesised tree, not a sentence. <code>(&amp;(a=1)(b=2))</code> is an AND node with two children. Injection here means writing nodes the developer did not write.',
            'The filter is <code>"(&amp;(uid=" . $u . ")(userPassword=" . $hash . "))"</code>. Your input sits inside an assertion value, and an assertion value ends at the first unescaped <code>)</code>.',
            'So a <code>)</code> in your input ends the uid clause, and a <code>(</code> starts a clause of your own. The password clause still exists - your job is to make it land somewhere it cannot fail the match.',
            'The classic shape ends the AND group early and leaves the developer\'s remainder as a second, complete filter that the client never looks at. Count the parentheses on paper before you send anything.',
            '<code>*)(uid=*))(|(uid=*</code> in the username field. Read the parse tree in the trace: the filter that actually ran is <code>(&amp;(uid=*)(uid=*))</code>, and everything after it was discarded.',
        ],
        7 => [
            'In an LDAP filter, <code>*</code> is grammar. <code>(uid=a*)</code> is a substring assertion, a different node type from <code>(uid=a)</code>. It is not a character that happens to mean "anything".',
            'This endpoint strips <code>(</code> and <code>)</code>, so you cannot add clauses. Look at what it does <em>not</em> strip, and at the <code>*</code> the developer appends themselves.',
            'Compare with SQL: <code>LIKE \'a%\'</code> has exactly the same problem, and everybody already knows to escape <code>%</code> in user input. The LDAP equivalent is escaping <code>*</code> to <code>\\2a</code>. This code does neither.',
            'You are looking for the smallest input that makes the assertion place no constraint on the value at all.',
            'Search for <code>*</code>. The filter becomes <code>(uid=**)</code>: initial empty, final empty, nothing in between - every entry in the tree, including the ones that are not in <code>ou=people</code>.',
        ],
        8 => [
            'Appending a mandatory clause after user input feels safe because the attacker "cannot get in front of it". They do not need to get in front of it. They need it to stop applying.',
            'The filter is <code>(&amp;(uid=$u)(objectClass=person))</code> and the entry you want has no <code>person</code> in its objectClass. Closing the AND group early removes the requirement.',
            'The code also runs a well-formedness check: the string it sends must decompose into complete filters with no bytes left over. So the developer\'s leftover <code>)(objectClass=person))</code> has to end up inside something that parses.',
            'Shape: <code>uid)</code> then <code>)</code> to close the AND, then open a fresh group whose opening bracket lines up with the leftover text. Write the whole string out and balance it by hand.',
            '<code>vault_agent))(&amp;(objectClass=person</code> gives <code>(&amp;(uid=vault_agent))(&amp;(objectClass=person)(objectClass=person))</code>: two complete filters, nothing dangling, and only the first one is searched.',
        ],
        9 => [
            'LDAP has no <code>substring()</code> function, but it has substring <em>assertions</em>, and those are enough. <code>(attr=a*)</code> asks "does the value start with a?" - one bit per request.',
            'Your input goes into <code>(&amp;(uid=$u)(objectClass=inetOrgPerson))</code> and the parse is strict, so whatever you inject has to leave the parentheses balanced.',
            'Add a clause: <code>uid)(recoveryKey=a*</code> turns the filter into <code>(&amp;(uid=..)(recoveryKey=a*)(objectClass=inetOrgPerson))</code>. Extend the prefix by one character each time it matches.',
            'Linear costs up to 36 requests per character. <code>&gt;=</code> is an ordering filter, so <code>(recoveryKey&gt;=&lt;prefix&gt;m)</code> halves the alphabet instead of stepping through it: 6 requests per character.',
            'A probe is <code>svc_rotate)(recoveryKey=k*</code>. Use the console: run the linear recovery once to see the counter, then run the binary recovery and compare. Submit the six characters you recover.',
        ],
        10 => [
            'Escaping is only ever safe if nothing downstream reverses it. The order in which you escape matters as much as the set of characters you escape.',
            'Read <code>bad_escape()</code>: it maps <code>(</code>, <code>)</code> and <code>*</code> to their hex forms. It never touches <code>\\</code>. So a backslash you send arrives at the filter untouched, and it is the byte the whole escape scheme is built out of.',
            'Now read the client. It normalises the filter with one left-to-right unescape pass <em>before</em> parsing. A correct parser decides where values end first and unescapes afterwards; this one does it the other way round.',
            'So write your payload entirely in hex escapes: <code>\\28</code> is <code>(</code>, <code>\\29</code> is <code>)</code>, <code>\\2a</code> is <code>*</code>. The escaper sees no metacharacters to escape, and the normaliser puts them all back.',
            'Username <code>root_admin\\29\\29\\28|\\28uid=\\2a</code>. After normalisation that is <code>root_admin))(|(uid=*</code>, and the first complete filter is <code>(&amp;(uid=root_admin))</code>.',
        ],
    ];
    return $h[$level] ?? [];
}

/* =========================================================================
 * XPath engine wrapper (levels 1-5)
 * ===================================================================== */

/** Load the shipped XML directory and hand back an XPath evaluator for it. */
function xl_xpath(): DOMXPath
{
    static $xp = null;
    if ($xp !== null) {
        return $xp;
    }
    $doc = new DOMDocument();
    $doc->preserveWhiteSpace = false;
    $doc->load(__DIR__ . '/users.xml');
    $xp = new DOMXPath($doc);
    return $xp;
}

/**
 * Evaluate an expression for real and describe the outcome.
 *
 * DOMXPath emits a PHP warning and returns false for a malformed expression;
 * the warning text is the most useful thing on the page when a payload does
 * not parse, so it is captured rather than discarded.
 *
 * @return array{ok:bool,error:?string,count:int,nodes:array<int,array{name:string,value:string}>,dom:array<int,DOMNode>,scalar:?string}
 */
function xl_xpath_run(string $expr): array
{
    $xp  = xl_xpath();
    $err = null;

    set_error_handler(static function (int $no, string $msg) use (&$err): bool {
        $err = $msg;
        return true;
    });
    $res = $xp->evaluate($expr);
    restore_error_handler();

    if ($res === false && $err !== null) {
        return ['ok' => false, 'error' => $err, 'count' => 0, 'nodes' => [], 'dom' => [], 'scalar' => null];
    }

    if ($res instanceof DOMNodeList) {
        $nodes = [];
        $dom   = [];
        foreach ($res as $n) {
            $dom[]   = $n;
            $nodes[] = [
                'name'  => $n->nodeType === XML_TEXT_NODE ? 'text()' : $n->nodeName,
                'value' => trim(preg_replace('/\s+/', ' ', (string)$n->textContent)),
            ];
        }
        return ['ok' => true, 'error' => null, 'count' => count($nodes), 'nodes' => $nodes,
                'dom' => $dom, 'scalar' => null];
    }

    // Boolean / number / string result - still a legitimate XPath answer.
    $scalar = is_bool($res) ? ($res ? 'true' : 'false') : (string)$res;
    return ['ok' => true, 'error' => null, 'count' => 0, 'nodes' => [], 'dom' => [], 'scalar' => $scalar];
}

/** Text of a named child element, or '' - used to read a matched <user>. */
function xl_child_text(DOMNode $node, string $child): string
{
    foreach ($node->childNodes as $c) {
        if ($c->nodeType === XML_ELEMENT_NODE && $c->nodeName === $child) {
            return trim((string)$c->textContent);
        }
    }
    return '';
}

/** Render matched <user> elements as an account list (passwords withheld). */
function xl_user_table(array $domNodes): string
{
    $rows = '';
    foreach ($domNodes as $n) {
        if ($n->nodeType !== XML_ELEMENT_NODE || $n->nodeName !== 'user') {
            continue;
        }
        $rows .= '<tr><td>' . lk_esc(xl_child_text($n, 'username')) . '</td>'
               . '<td>' . lk_esc(xl_child_text($n, 'role')) . '</td>'
               . '<td>' . lk_esc(xl_child_text($n, 'department')) . '</td></tr>';
    }
    if ($rows === '') {
        return '';
    }
    return '<table class="data-table"><thead><tr><th>username</th><th>role</th><th>department</th></tr></thead>'
         . '<tbody>' . $rows . '</tbody></table>';
}

/** Every string the node set actually returned, for effect-based flag checks. */
function xl_node_strings(array $run): array
{
    return array_map(static fn(array $n): string => $n['value'], $run['nodes']);
}

/** Does the node set contain a node whose text contains $needle? */
function xl_retrieved(array $run, string $needle): bool
{
    foreach (xl_node_strings($run) as $s) {
        if ($needle !== '' && strpos($s, $needle) !== false) {
            return true;
        }
    }
    return false;
}

/** Render a node set as a table. This is "what the expression selected". */
function xl_nodes_table(array $run): string
{
    if (!$run['ok']) {
        return '<div class="message error"><strong>XPath error:</strong> ' . lk_esc((string)$run['error'])
             . '<br>The expression did not parse, so nothing was evaluated.</div>';
    }
    if ($run['scalar'] !== null) {
        return '<div class="output-box">expression returned a scalar: <code>' . lk_esc($run['scalar']) . '</code></div>';
    }
    if (!$run['nodes']) {
        return '<div class="output-box">node set is empty (0 nodes selected)</div>';
    }
    $rows = '';
    foreach ($run['nodes'] as $i => $n) {
        $rows .= '<tr><td>' . ($i + 1) . '</td><td><code>' . lk_esc($n['name']) . '</code></td><td>'
               . lk_esc($n['value']) . '</td></tr>';
    }
    return '<table class="data-table"><thead><tr><th>#</th><th>node</th><th>string value</th></tr></thead>'
         . '<tbody>' . $rows . '</tbody></table>';
}

/* =========================================================================
 * LDAP display helpers (levels 6-10)
 * ===================================================================== */

/** Parse tree, printed. Levels put this in a pipeline stage note. */
function xl_tree_block(array $tree): string
{
    return '<pre class="xl-tree">' . lk_esc(rtrim(ldap_tree_pretty($tree))) . '</pre>';
}

/**
 * Render matched entries.
 *
 * @param array<int,array> $entries
 * @param array<int,string> $only   attribute names to show; empty means all
 */
function xl_entry_table(array $entries, array $only = []): string
{
    if (!$entries) {
        return '<div class="output-box">0 entries returned</div>';
    }
    $out = '';
    foreach ($entries as $e) {
        $rows = '';
        foreach ($e['attrs'] as $name => $vals) {
            if ($only && !in_array($name, $only, true)) {
                continue;
            }
            $rows .= '<tr><td>' . lk_esc($name) . '</td><td>' . lk_esc(implode(', ', $vals)) . '</td></tr>';
        }
        $out .= '<div class="xl-entry"><div class="xl-dn">' . lk_esc($e['dn']) . '</div>'
              . '<table class="lk-kv">' . $rows . '</table></div>';
    }
    return $out;
}

/* =========================================================================
 * Blind-level probe counter (levels 3 and 9)
 * ===================================================================== */

function xl_counter_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }
}

function xl_counter_bump(int $level): int
{
    xl_counter_start();
    $k = 'probes_' . $level;
    $_SESSION[$k] = (int)($_SESSION[$k] ?? 0) + 1;
    return $_SESSION[$k];
}

function xl_counter_get(int $level): int
{
    xl_counter_start();
    return (int)($_SESSION['probes_' . $level] ?? 0);
}

function xl_counter_reset(int $level): void
{
    xl_counter_start();
    $_SESSION['probes_' . $level] = 0;
}

/* =========================================================================
 * Shared page furniture
 * ===================================================================== */

function xl_extra_head(): string
{
    return '<style>
        .xl-tree { margin:0; font-family:"JetBrains Mono",ui-monospace,monospace; font-size:0.74rem;
                   line-height:1.55; white-space:pre; overflow-x:auto; }
        .xl-entry { margin-bottom:0.75rem; }
        .xl-dn { font-family:"JetBrains Mono",ui-monospace,monospace; font-size:0.72rem;
                 opacity:0.75; margin-bottom:0.3rem; word-break:break-all; }
        .xl-form .form-group { margin-bottom:0.65rem; }
        .xl-actions { display:flex; gap:0.6rem; flex-wrap:wrap; margin-top:0.5rem; }
        .xl-console { border:1px solid rgba(255,255,255,0.12); border-radius: 0;
                      padding:0.85rem; margin:0.9rem 0; }
        .xl-console h4 { margin:0 0 0.55rem; font-size:0.82rem; letter-spacing:0.04em; text-transform:uppercase; }
        .xl-btnrow { display:flex; gap:0.45rem; flex-wrap:wrap; margin:0.55rem 0; }
        .xl-btnrow .btn { padding:0.32rem 0.6rem; font-size:0.74rem; }
        .xl-log { max-height:230px; overflow:auto; margin:0.5rem 0 0;
                  font-family:"JetBrains Mono",ui-monospace,monospace; font-size:0.7rem;
                  line-height:1.5; white-space:pre-wrap; word-break:break-all; }
        .xl-meter { display:flex; gap:1.1rem; flex-wrap:wrap; font-size:0.76rem; margin-top:0.45rem; }
        .xl-meter b { font-family:"JetBrains Mono",ui-monospace,monospace; }
        .xl-recovered { font-family:"JetBrains Mono",ui-monospace,monospace; font-size:0.95rem;
                        letter-spacing:0.14em; }
    </style>';
}

/**
 * The plain GET form most levels use. Fields are ['name','label','value','placeholder'].
 *
 * @param array<int,array<string,string>> $fields
 */
function xl_form(array $fields, string $button, string $note = ''): string
{
    $out = '<form method="get" class="xl-form">';
    foreach ($fields as $f) {
        $out .= '<div class="form-group"><label class="form-label">' . $f['label'] . '</label>'
              . '<input type="text" name="' . lk_esc($f['name']) . '" class="form-control" spellcheck="false"'
              . ' autocomplete="off" placeholder="' . lk_esc($f['placeholder'] ?? '') . '"'
              . ' value="' . lk_esc($f['value'] ?? '') . '"></div>';
    }
    $out .= '<div class="xl-actions"><button class="btn btn-primary" type="submit">' . lk_esc($button) . '</button>';
    $out .= '<a class="btn btn-outline" href="?">Reset</a></div>';
    if ($note !== '') {
        $out .= '<div class="lk-hintline" style="margin-top:0.5rem">' . $note . '</div>';
    }
    return $out . '</form>';
}

/** Answer box for the two blind levels: the flag is gated on the recovered value. */
function xl_answer_form(string $label, string $value, string $hidden = ''): string
{
    return '<form method="get" class="xl-form" style="margin-top:0.9rem">'
         . $hidden
         . '<div class="form-group"><label class="form-label">' . $label . '</label>'
         . '<input type="text" name="answer" class="form-control" spellcheck="false" autocomplete="off"'
         . ' value="' . lk_esc($value) . '"></div>'
         . '<div class="xl-actions"><button class="btn btn-primary" type="submit">Submit recovered value</button></div>'
         . '</form>';
}
