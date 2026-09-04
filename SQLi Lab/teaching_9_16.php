<?php
/**
 * SQLi Lab · teaching content for levels 9 and above.
 *
 * Kept in its own file only to keep teaching.php readable; it is included from
 * there and merged into the same content array.
 */

function sqli_teach_content_high(int $level): array
{
    $c = [];

    /* ------------------------------------------------------------------ 9 */
    $c[9] = [
        'model_title' => 'Injection point: an XPath predicate, not SQL',
        'model' => '<p>The sink here is an XPath expression evaluated over an XML document:</p>
            <pre class="lk-sinkline">//user[username/text()=&#39;INPUT&#39; and password/text()=&#39;INPUT&#39;]</pre>
            <p>The grammar is different from SQL but the shape of the flaw is identical: your value sits inside a
            single-quoted string literal, and a <code>&#39;</code> that reaches the parser ends that literal and
            puts you in the predicate.</p>
            <p>What differs is the toolkit, and it is worth knowing which SQL habits transfer:</p>
            <table class="lk-kv">
                <tr><td>booleans</td><td><code>or 1=1</code> works, written as <code>&#39; or &#39;1&#39;=&#39;1</code>. XPath has no <code>TRUE</code> keyword; use a comparison or a non-empty string.</td></tr>
                <tr><td>comments</td><td>There are none. You cannot discard the trailing <code>and password/text()=&#39;&hellip;&#39;</code> - you have to satisfy it or absorb it.</td></tr>
                <tr><td>node selection</td><td><code>|</code> is union, so <code>&#39;]|//user[&#39;1&#39;=&#39;1</code> selects a second node set. This is how you read nodes the predicate was meant to hide.</td></tr>
                <tr><td>reading data</td><td>No <code>UNION SELECT</code>, but <code>name()</code>, <code>string-length()</code> and <code>substring()</code> give you a blind read of any node, including ones outside the document subtree the query names.</td></tr>
            </table>
            <p>The practical consequence for a real target: an XML-backed login has no prepared statements to
            reach for, so the fix is a different shape too - bind variables through the XPath API, or compare in
            code after selecting by a value you control.</p>',
        'why' => '<p>Your quote closed the <code>username/text()=&#39;&hellip;&#39;</code> literal, and the tokens
            after it were read as part of the predicate. Because there is no comment syntax in XPath, the payload
            had to leave the expression balanced and the trailing password test satisfied - which is what the
            <code>or</code> in the working payload does.</p>
            <p>Carry forward the generalisation rather than the payload: the vulnerability class is "a query
            language assembled by string concatenation". SQL, XPath, LDAP filters, Mongo query documents and
            GraphQL resolver filters are all the same bug with a different grammar.</p>',
        'fix_bad' => '$query = "//user[username/text()=\'{$username}\' and password/text()=\'{$password}\']";
$nodes = $xml->xpath($query);',
        'fix_good' => '// PHP\'s SimpleXML has no parameter binding, so do the comparison
// in code: select by a value you control, then verify in PHP.
$candidates = $xml->xpath(\'//user\');

foreach ($candidates as $u) {
    if (hash_equals((string) $u->username, $username)
        && password_verify($password, (string) $u->password)) {
        return $u;                      // no user data in the expression
    }
}

// Where an expression genuinely must be built, use a binding API
// (DOMXPath::registerPhpFunctions is not one) or escape by
// splitting on the quote and rebuilding with concat():
//   concat(\'it\', "\'", \'s\')
// Encoding a quote is fiddly and easy to get wrong, which is the
// argument for not putting input in the expression at all.',
        'fix_note' => sqli_fix_note('This level has no prepared statement available, so the fix is structural
            rather than a swap of API. Note that the reasoning is the same one binding encodes: keep the query
            fixed, and let input choose only values that never re-enter the grammar.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does a single quote reach the XPath parser?', 'payload' => "alice'",
             'learn' => 'An unbalanced literal makes the expression invalid. The trace shows the assembled expression and whether evaluation errored, which tells you the quote was not escaped.'],
            ['q' => 'Is the expression a predicate I can extend?', 'payload' => "alice' and '1'='2",
             'learn' => 'Parses cleanly and matches nothing. A well-formed but false predicate is the strongest evidence you are inside the grammar rather than inside a string.'],
            ['q' => 'Does XPath union work here?', 'payload' => "nobody']|//user[username/text()='nobody",
             'learn' => 'Selects an empty second node set, so nothing is returned - but it proves <code>|</code> is available, which is the XPath equivalent of UNION.'],
        ],
    ];

    /* ----------------------------------------------------------------- 10 */
    $c[10] = [
        'model_title' => 'Injection point: a VALUES list',
        'model' => '<p>The statement is an <code>INSERT</code> whose column list is fixed and whose values are
            concatenated:</p>
            <pre class="lk-sinkline">INSERT INTO users (username, password, email, role)
VALUES (&#39;INPUT&#39;, &#39;defaultpass&#39;, &#39;INPUT&#39;, &#39;user&#39;)</pre>
            <p>Reasoning about an <code>INSERT</code> is different from a <code>SELECT</code> in one way that
            matters: there is no <code>WHERE</code> clause to make true, so a boolean payload achieves nothing.
            What you control is <strong>what gets written</strong>.</p>
            <p>The <code>role</code> column is filled with the literal <code>&#39;user&#39;</code> and sits
            <em>after</em> your injection point. So the goal is to close your literal, supply the remaining values
            yourself, and discard the developer\'s tail:</p>
            <pre class="lk-sinkline">VALUES (&#39;x&#39;, &#39;p&#39;, &#39;e&#39;, &#39;admin&#39;)-- &#39;, &#39;defaultpass&#39;, &hellip;</pre>
            <p>Two constraints to check before writing the payload. The value count after your rewrite must match
            the four columns named, or MySQL raises error 1136. And a <code>UNIQUE</code> index on
            <code>username</code> means a second attempt with the same name fails with 1062 rather than telling
            you anything about your syntax - so vary the username between attempts.</p>',
        'why' => '<p>You closed the first string literal and then wrote the rest of the <code>VALUES</code> list
            yourself, including a <code>role</code> of your choosing, and commented out the values the developer
            intended. The row that landed in the table is the row you specified.</p>
            <p>This is the version of SQL injection that persists. A boolean bypass ends with the response; a
            written row is still there on the next request, and on every request after that - which is also why it
            feeds the second-order level.</p>',
        'fix_bad' => '$sql = "INSERT INTO users (username, password, email, role)
         VALUES (\'$username\', \'defaultpass\', \'$email\', \'user\')";',
        'fix_good' => '// Bind the values, and never let a privilege column be reachable
// from a registration form at all.
$st = $conn->prepare(
    \'INSERT INTO users (username, password, email, role)
          VALUES (?, ?, ?, ?)\'
);
$st->bind_param(
    \'ssss\',
    $username,
    password_hash($password, PASSWORD_DEFAULT),
    $email,
    $role = \'user\'                     // a constant, decided server-side
);
$st->execute();

// Also worth noting: this endpoint stored a plaintext password.
// Use password_hash() on write and password_verify() on read.',
        'fix_note' => sqli_fix_note('An <code>INSERT</code> is where an injection stops being transient. Review
            registration, import, webhook and bulk-upload paths with the same attention as a login form - they
            write, and what they write is read back later by code that trusts it.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does a quote reach the parser?', 'payload' => "probe1'",
             'learn' => 'Expect error 1064. The trace prints the statement and the MySQL error, so one request tells you both that the quote survived and where the parse broke.'],
            ['q' => 'How many values does the list expect?', 'payload' => "probe2', 'x')-- ",
             'learn' => 'A deliberate count mismatch. Error 1136 names the expected number, so you never have to guess your way up from one.'],
            ['q' => 'Is username unique-indexed?', 'payload' => 'alice',
             'learn' => 'Error 1062 on a duplicate key. Worth knowing before you attribute a failed attempt to your syntax.'],
        ],
    ];

    /* ----------------------------------------------------------------- 11 */
    $c[11] = [
        'model_title' => 'Injection point: a SET list',
        'model' => '<p>The statement is an <code>UPDATE</code> with four assignments and a numeric
            <code>WHERE</code>:</p>
            <pre class="lk-sinkline">UPDATE users
   SET email = &#39;INPUT&#39;, phone = &#39;INPUT&#39;, bio = &#39;INPUT&#39;, website = &#39;INPUT&#39;
 WHERE id = 2</pre>
            <p>A <code>SET</code> list is the most directly dangerous injection point in SQL, because the grammar
            you are injecting into is <em>assignment</em>. Close your literal, add a comma, and you can assign any
            column in the table:</p>
            <pre class="lk-sinkline">SET email = &#39;x&#39;, role = &#39;admin&#39;, phone = &hellip;</pre>
            <p>You do not need a comment here: the developer\'s remaining assignments are still syntactically
            valid after yours, so the statement parses either way. That makes this the rare case where a payload
            can be a comma and a name.</p>
            <p>The <code>WHERE id = 2</code> is also worth reading. It is not quoted, so it is a numeric context -
            and any injection reaching it could widen the update from one row to every row. Check whether the
            statement you assembled still names a single row before you send it, because an <code>UPDATE</code>
            that loses its <code>WHERE</code> rewrites the whole table.</p>',
        'why' => '<p>Your quote closed the first assignment\'s literal, and the comma that followed started a new
            assignment - one the form never offered. The statement remained valid, so MySQL applied every
            assignment in the list, including yours.</p>
            <p>The lesson that generalises past SQL: a form field is not the same thing as a column, and a
            <code>SET</code> list built from concatenation erases that distinction. It is the SQL-level twin of the
            mass-assignment bug you meet in ORMs, where <code>User::update($request->all())</code> writes whatever
            keys the request happened to carry.</p>',
        'fix_bad' => '$sql = "UPDATE users SET email = \'$email\', phone = \'$phone\',
                bio = \'$bio\', website = \'$website\' WHERE id = $user_id";',
        'fix_good' => '// Bind every value, and name every column yourself. The set of
// writable columns is a decision in your code, not in the request.
$st = $conn->prepare(
    \'UPDATE users SET email = ?, phone = ?, bio = ?, website = ?
      WHERE id = ?\'
);
$st->bind_param(\'ssssi\', $email, $phone, $bio, $website, $userId);
$st->execute();

// $userId comes from the session, never from the request body -
// otherwise the statement is still an access-control bug even
// once the injection is fixed.',
        'fix_note' => sqli_fix_note('Two independent defects live in this one statement: the values are
            concatenated, and the row is selected by an id that the request could influence. Fixing the injection
            without fixing the second leaves an IDOR behind.'),
        'param' => 'email',
        'probes' => [
            ['q' => 'Does a quote reach the parser?', 'payload' => "a@b.test'",
             'learn' => 'Error 1064, with the statement printed in the trace. Confirm the quote is unescaped before designing anything more elaborate.'],
            ['q' => 'Can I start a new assignment?', 'payload' => "a@b.test', phone = 'probe",
             'learn' => 'Assigns a value the form did not offer for that field, and nothing privileged. If the phone column changes, the SET list is open.'],
            ['q' => 'Is the WHERE clause numeric?', 'payload' => "a@b.test' /* ",
             'learn' => 'An unterminated block comment swallows the rest of the statement, including the WHERE. The resulting error tells you where the clause boundary is without risking a table-wide update.'],
        ],
    ];

    /* ----------------------------------------------------------------- 12 */
    $c[12] = [
        'model_title' => 'A type system that validates shape, not content',
        'model' => '<p>The request body is JSON, parsed with <code>json_decode</code>, and three fields are
            concatenated into the statement:</p>
            <pre class="lk-sinkline">SELECT * FROM users
 WHERE username = &#39;INPUT&#39; AND password = &#39;INPUT&#39; AND role = &#39;INPUT&#39;</pre>
            <p>JSON parsing is often mistaken for validation. It is not: it guarantees the document is
            well-formed and that a field is a string, and it says nothing whatsoever about what is inside that
            string. A quote is a perfectly ordinary character in a JSON string value.</p>
            <p>What the JSON shape does change is your reconnaissance. There are three injectable fields rather
            than two, and the third one is the interesting one: <code>role</code> defaults to
            <code>&#39;user&#39;</code> and the UI never exposes it, so it is the field least likely to have been
            considered. Reading the parameter list is worth more here than any payload.</p>
            <p>Two JSON-specific notes. Duplicate keys are undefined in RFC 8259 and PHP keeps the last, so a
            filter that inspected the body as text can disagree with the parser. And a field whose value is a
            number or an array reaches the concatenation as something other than a string - which is where
            type-juggling bugs appear in this shape of code.</p>',
        'why' => '<p>Your payload travelled through <code>json_decode</code> unchanged, because none of its
            characters are special to JSON, and was then concatenated into the statement. The quote closed a
            literal exactly as it would have in a form field.</p>
            <p>The transport was irrelevant. The same is true of XML, YAML, protobuf, multipart bodies and header
            values: crossing a parsing boundary does not sanitise anything. What matters is the encoding applied at
            the sink, and there was none.</p>',
        'fix_bad' => '$data = json_decode($json_input, true);
$sql  = "SELECT * FROM users WHERE username = \'{$data[\'username\']}\'
         AND password = \'{$data[\'password\']}\' AND role = \'{$data[\'role\']}\'";',
        'fix_good' => '// Validate the shape, bind the values, and do not accept a
// privilege filter from the client at all.
$data = json_decode($json_input, true, 512, JSON_THROW_ON_ERROR);

if (!is_string($data[\'username\'] ?? null)
    || !is_string($data[\'password\'] ?? null)) {
    throw new InvalidArgumentException(\'bad request\');
}

$st = $conn->prepare(
    \'SELECT id, username, role FROM users
      WHERE username = ? AND password_hash = ?\'
);
$st->bind_param(\'ss\', $data[\'username\'], $hash);
$st->execute();

// Reject ambiguous documents too, so a text-level filter and the
// parser cannot disagree about a repeated key:
if (json_encode($data, JSON_UNESCAPED_SLASHES) !== $json_input) {
    throw new InvalidArgumentException(\'ambiguous JSON\');
}',
        'fix_note' => sqli_fix_note('An API endpoint deserves the same review as a form: enumerate every field
            the body can carry, and check each one for both injection and authorisation. Fields the UI never sends
            are the ones nobody tested.'),
        'param' => 'json_data',
        'probes' => [
            ['q' => 'Does JSON parsing touch a quote?', 'payload' => '{"username":"probe\'","password":"x","role":"user"}',
             'learn' => 'Error 1064 in the trace. The quote is a normal JSON character and reaches the statement unchanged.'],
            ['q' => 'Is the third field really used in the query?', 'payload' => '{"username":"alice","password":"x","role":"nosuchrole"}',
             'learn' => 'Compare the assembled SQL in the trace with a request that omits <code>role</code>. This confirms which fields are injectable before you spend attempts on them.'],
            ['q' => 'Which duplicate key wins?', 'payload' => '{"username":"a","username":"b","password":"x","role":"user"}',
             'learn' => 'Read the assembled statement. PHP keeps the last occurrence, which matters whenever a filter inspects the raw body before the parser sees it.'],
        ],
    ];

    /* ----------------------------------------------------------------- 13 */
    $c[13] = [
        'model_title' => 'Comments blocked, grammar untouched',
        'model' => '<p>The filter rejects four substrings, case-insensitively: <code>--</code>,
            <code>#</code>, <code>/*</code>, <code>*/</code>. Nothing else is checked, so quotes, keywords,
            operators and whitespace all reach the parser.</p>
            <p>That means only one technique is unavailable: discarding the tail of the statement. Everything else
            about level 1 still applies. So the question becomes what a comment was for, and whether you need it:</p>
            <table class="lk-kv">
                <tr><td>comment out the tail</td><td>Blocked here.</td></tr>
                <tr><td>satisfy the tail</td><td><code>&#39; or &#39;1&#39;=&#39;1</code> leaves <code>and password = &#39;&hellip;&#39;</code> in place and simply makes the whole predicate true.</td></tr>
                <tr><td>absorb the tail</td><td>Close your literal so that the developer\'s trailing quote opens a new literal you finish yourself.</td></tr>
                <tr><td>end the statement</td><td><code>;</code> is not blocked, though <code>mysqli::query</code> executes only the first statement.</td></tr>
            </table>
            <p>The habit worth building: when a filter blocks a technique, ask what that technique was
            <em>achieving</em>. A comment achieves "ignore the rest of the statement", and there is more than one
            way to reach that outcome.</p>',
        'why' => '<p>Your payload contained none of the four comment markers and still produced a true predicate,
            because it satisfied the trailing password test rather than removing it.</p>
            <p>The filter is accurate about what it checks. It simply chose a target - comment syntax - that is a
            convenience rather than a requirement, so blocking it raised the effort of the attack without changing
            whether it works.</p>',
        'fix_bad' => 'foreach ([\'--\', \'#\', \'/*\', \'*/\'] as $pattern) {
    if (stripos($username, $pattern) !== false) { $input_blocked = true; }
}
if (!$input_blocked) {
    $sql = "SELECT * FROM users WHERE username = \'$username\'
            AND password = \'$password\'";
}',
        'fix_good' => '// Bind the values. Once the data cannot move the parse boundary,
// comment syntax in the input is just text in a username.
$st = $conn->prepare(
    \'SELECT id, username, role FROM users WHERE username = ?\'
);
$st->bind_param(\'s\', $username);
$st->execute();
$user = $st->get_result()->fetch_assoc();

if (!$user || !password_verify($password, $user[\'password_hash\'])) {
    return deny();
}

// Note the second change: the password is verified in PHP against
// a hash, not compared inside the query. That keeps the secret out
// of the statement entirely.',
        'fix_note' => sqli_fix_note('A blacklist of comment markers is a common first patch after an incident,
            because the proof-of-concept in the report contained one. It addresses the payload that was reported
            rather than the defect that allowed it.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Exactly which markers are blocked?', 'payload' => "alice' -- x",
             'learn' => 'Blocked, and the response names the pattern. Four entries, so four requests map the whole filter.'],
            ['q' => 'Do quotes still reach the parser?', 'payload' => "alice'",
             'learn' => 'Error 1064. The filter never looked at quotes, so every level-1 technique that does not need a comment is available.'],
            ['q' => 'Is a semicolon blocked?', 'payload' => 'alice;',
             'learn' => 'Not blocked. <code>mysqli::query</code> runs only the first statement, so this is a fact about the filter rather than a route to stacked queries.'],
        ],
    ];

    /* ----------------------------------------------------------------- 14 */
    $c[14] = [
        'model_title' => 'The filter and the query read different strings',
        'model' => '<p>Read the order of operations in the source panel, because that is the whole level:</p>
            <ol>
                <li>the filter checks <code>$username . $password</code> for <code>&#39;</code>, <code>&quot;</code>,
                    <code>=</code>, <code>OR</code>, <code>UNION</code>, <code>SELECT</code>;</li>
                <li><code>urldecode()</code> and <code>html_entity_decode()</code> then run;</li>
                <li>the decoded value is concatenated into the statement.</li>
            </ol>
            <p>So the string that was approved is not the string that is parsed. Anything that decodes into a
            blocked character passes, because at the moment of the check that character is not present.</p>
            <p>One detail that decides the payload: PHP has <strong>already</strong> URL-decoded the request body
            before your code sees it. So a single <code>%27</code> in the raw body arrives as <code>&#39;</code>
            and is blocked, and you need one more layer:</p>
            <table class="lk-kv">
                <tr><td>you send</td><td><code>%2527</code></td></tr>
                <tr><td>PHP hands the filter</td><td><code>%27</code> - no quote present, passes</td></tr>
                <tr><td>urldecode() produces</td><td><code>&#39;</code> - reaches the statement</td></tr>
            </table>
            <p>The HTML entity path needs no double layer: <code>&amp;#39;</code> contains no quote at all, and
            <code>html_entity_decode()</code> expands it after the check.</p>
            <p>This is time-of-check to time-of-use expressed in encodings, and the rule is the same one as
            everywhere else it appears: <strong>validate the value you are going to use</strong>, not an earlier
            form of it. Decode first, canonicalise once, then check - or better, bind and stop checking.</p>',
        'why' => '<p>The filter inspected bytes that contained no blocked character. The decoders then produced
            one, and the statement was built from the decoded value. Both halves behaved exactly as written; the
            defect is the order they run in.</p>
            <p>The trace above prints the value at both points, which is the clearest way to see the gap: the
            row the filter judged and the row MySQL parsed hold different bytes.</p>',
        'fix_bad' => '// filter first...
foreach ($dangerous_chars as $char) { ... }
// ...decode after
$username = urldecode($username);
$username = html_entity_decode($username, ENT_QUOTES);
$sql = "SELECT * FROM users WHERE username = \'$username\' ...";',
        'fix_good' => '// If you must filter, canonicalise first and check the result -
// the value the query will actually receive.
$username = html_entity_decode(urldecode($username), ENT_QUOTES, \'UTF-8\');

// Then, better, do not filter at all. Bind, and the question of
// which encoding layer produced a quote stops mattering.
$st = $conn->prepare(
    \'SELECT id, username, role FROM users WHERE username = ?\'
);
$st->bind_param(\'s\', $username);
$st->execute();

// Also: do not decode twice. Values should be canonical at the
// edge of the system and never re-decoded downstream, or the same
// gap reopens between two later components.',
        'fix_note' => sqli_fix_note('This ordering bug is not specific to SQL. A WAF that inspects a request
            before the application URL-decodes it, a path check that runs before normalisation, a signature
            verified before a JSON re-serialisation - all the same shape, and all fixed by checking the value at
            the point of use.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Is a plain quote blocked?', 'payload' => "alice'",
             'learn' => 'Blocked, and the response names the character. This establishes that the filter is real before you try to route around it.'],
            ['q' => 'Does a single percent-encoding survive?', 'payload' => 'alice%27',
             'learn' => 'PHP decoded the body already, so the filter sees a literal quote and blocks it. One request rules out the obvious attempt and points at double encoding.'],
            ['q' => 'What does the query receive after decoding?', 'payload' => 'alice%2520bob',
             'learn' => 'Harmless: a double-encoded space. Compare the filter stage and the SQL stage in the trace to watch one string become another.'],
        ],
    ];

    /* ----------------------------------------------------------------- 15 */
    $c[15] = [
        'model_title' => 'Whitespace is not part of the grammar',
        'model' => '<p>The filter rejects one character: the ASCII space, checked with <code>strpos</code>. Tabs,
            newlines and comments are not checked, and neither is anything else.</p>
            <p>The reason this filter fails is a property of SQL rather than a mistake in the code: MySQL needs
            token <em>separation</em>, and a space is only one of several things that separate tokens.</p>
            <table class="lk-kv">
                <tr><td><code>/**/</code></td><td>An empty inline comment. Separates tokens anywhere a space would, and contains no space.</td></tr>
                <tr><td><code>%09</code>, <code>%0a</code>, <code>%0b</code>, <code>%0c</code>, <code>%0d</code></td><td>Tab, newline, vertical tab, form feed, carriage return. All whitespace to MySQL, none of them the character being checked.</td></tr>
                <tr><td><code>()</code></td><td>Parentheses delimit expressions, so <code>or(1)=(1)</code> needs no separator at all.</td></tr>
                <tr><td>operators</td><td><code>&#39;a&#39;=&#39;a&#39;</code> and <code>&#39;1&#39;||&#39;1&#39;</code> are already self-delimiting.</td></tr>
            </table>
            <p>The shortest payload for this level uses none of the above: <code>&#39;||&#39;1</code> contains no
            space because it contains no keyword that would need one.</p>
            <p>General form of the lesson: a filter that blocks one spelling of a syntactic role will be defeated
            by another spelling of the same role. That is true of whitespace, of comment markers, of quote
            characters in HTML attributes, and of command separators in a shell.</p>',
        'why' => '<p>Your payload separated its tokens with something other than a space - or needed no separator
            at all - so the filter found nothing and MySQL parsed the statement normally.</p>
            <p>Notice how little the filter cost you. It removed one of at least six ways to separate tokens, and
            the shortest working payload avoids the whole question by using operators that are self-delimiting.</p>',
        'fix_bad' => 'if (strpos($username, \' \') !== false) {
    $message = \'Spaces are not allowed\';
} else {
    $sql = "SELECT * FROM users WHERE username = \'$username\'
            AND password = \'$password\'";
}',
        'fix_good' => '// Bind. Whitespace in a username is then a formatting question,
// not a security one - and "O\'Brien" stops being a bug report.
$st = $conn->prepare(
    \'SELECT id, username, role FROM users WHERE username = ?\'
);
$st->bind_param(\'s\', $username);
$st->execute();

// If a field has a genuine format, validate it positively against
// that format rather than negatively against a character:
//   if (!preg_match(\'/^[a-z0-9_.-]{3,32}$/i\', $username)) deny();
// An allowlist of what is permitted is bounded; a blacklist of
// what is dangerous is not.',
        'fix_note' => sqli_fix_note('Character blacklists also break legitimate input. This one rejects every
            display name with a space in it, which is the usual reason such filters are quietly removed a release
            later - taking the only defence with them.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Which whitespace character is actually blocked?', 'payload' => 'alice bob',
             'learn' => 'Blocked. <code>strpos</code> was given a literal space, so this is the only character on the list.'],
            ['q' => 'Does a tab survive?', 'payload' => "alice\tbob",
             'learn' => 'Passes the filter and is whitespace to MySQL. One request establishes that the separator problem is already solved.'],
            ['q' => 'Does an inline comment separate tokens?', 'payload' => "alice'/**/",
             'learn' => 'Error 1064 with the statement shown - the comment reached the parser. This is the general-purpose space replacement.'],
        ],
    ];

    /* ----------------------------------------------------------------- 16 */
    $c[16] = [
        'model_title' => 'Five layers: enumerate the gaps before writing a payload',
        'model' => '<p>Every filter runs against <code>$username . $password</code>, so a payload split across the
            two fields does not help. Write out what each layer covers:</p>
            <table class="lk-kv">
                <tr><td>Layer 1</td><td><code>--</code>, <code>#</code>, <code>/*</code>, <code>*/</code> - no comments, so the tail cannot be discarded.</td></tr>
                <tr><td>Layer 2</td><td><code>UNION SELECT FROM WHERE INSERT UPDATE DELETE DROP</code> - no new statement, no new query.</td></tr>
                <tr><td>Layer 3</td><td><code>&quot;</code> <code>=</code> <code>&lt;</code> <code>&gt;</code> <code>(</code> <code>)</code> - no comparison of your own, no grouping.</td></tr>
                <tr><td>Layer 4</td><td><code>OR</code>, <code>AND</code>, <code>NOT</code> - no named logical operator.</td></tr>
                <tr><td>Layer 5</td><td><code>preg_match(&#39;/\\s/&#39;)</code> - no whitespace of any kind, so the level-15 substitutions are gone too.</td></tr>
            </table>
            <p>Now list what is left, which is the step people skip: the apostrophe, the pipe, the comma, the
            semicolon, digits, letters, and the <code>=</code> characters <em>already present in the developer\'s
            statement</em>.</p>
            <p>That last point is the key. You do not need to write a comparison - there is one waiting for you:</p>
            <pre class="lk-sinkline">WHERE username = &#39;INPUT&#39; AND password = &#39;INPUT&#39;</pre>
            <p>And MySQL accepts <code>||</code> as a synonym for <code>OR</code> (unless
            <code>PIPES_AS_CONCAT</code> is set), while the pipe character appears on none of the five lists.
            Since <code>AND</code> binds tighter than <code>||</code>, a payload of
            <code>admin&#39;||&#39;1</code> produces:</p>
            <pre class="lk-sinkline">username = &#39;admin&#39; || (&#39;1&#39; AND password = &#39;&hellip;&#39;)</pre>
            <p>The right operand is false, the left is true for the admin row, and the statement contains no
            whitespace, no comment, no blocked keyword and no <code>=</code> that you supplied. Operator
            precedence did the work a comment usually does.</p>',
        'why' => '<p>Every layer passed, because the payload avoided all five categories rather than trying to
            sneak past any of them. The statement then parsed, and precedence made the trailing password test
            irrelevant without removing it.</p>
            <p>That is the method this level exists to teach. Stacking filters raises the cost of writing a
            payload and does not change whether one exists, because each layer enumerates bad inputs while the
            grammar keeps offering new spellings of the same intent. Enumerate what is <em>left</em>, not what is
            blocked.</p>',
        'fix_bad' => '// five blacklists over $username . $password
foreach ($comment_patterns as $p) { ... }
foreach ($sql_keywords    as $k) { ... }
foreach ($special_chars   as $c) { ... }
foreach ($logical_ops     as $o) { ... }
if (preg_match(\'/\\s/\', $username . $password)) { ... }

if (!$blocked) {
    $sql = "SELECT * FROM users WHERE username = \'$username\'
            AND password = \'$password\'";
}',
        'fix_good' => '// One prepared statement replaces all five layers and is
// complete, because it removes the property they were trying to
// police: data can no longer reach the parser as syntax.
$st = $conn->prepare(
    \'SELECT id, username, role, password_hash FROM users
      WHERE username = ?\'
);
$st->bind_param(\'s\', $username);
$st->execute();
$user = $st->get_result()->fetch_assoc();

if (!$user || !password_verify($password, $user[\'password_hash\'])) {
    return deny();
}

// Keep a WAF if you want defence in depth and detection, but do
// not let it be the control that makes the query safe. Grant the
// database account only the privileges the application needs, so
// that a future injection elsewhere reads less and writes nothing.',
        'fix_note' => sqli_fix_note('When you meet a stack of filters in a real codebase, trace one input through
            every layer in order and write down what each changed. The gaps are usually visible after a single
            pass, and they tell you more than any payload list.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Which layers does an ordinary payload trip?', 'payload' => "admin' OR '1'='1",
             'learn' => 'The response lists every layer that matched. One request gives you the full map of the WAF, which is worth more than an attempt at a bypass.'],
            ['q' => 'Is the apostrophe on any list?', 'payload' => "admin'",
             'learn' => 'It passes the WAF and reaches the parser, producing error 1064. That single fact is what makes the level solvable.'],
            ['q' => 'Is the pipe character blocked?', 'payload' => 'admin||1',
             'learn' => 'Passes. It is not a comment, a keyword, a listed special character, a named logical operator, or whitespace - and MySQL reads it as OR.'],
        ],
    ];


    /* ----------------------------------------------------------------- 17 */
    $c[17] = [
        'model_title' => 'The error message as a read primitive',
        'model' => '<p>Every technique so far needed somewhere for data to appear. A <code>UNION</code> needs a
            row that gets printed; a boolean or time oracle needs an observable difference. This endpoint offers
            none of that: the statement selects a <code>COUNT(*)</code> that the page compares and throws away, so
            even an allowed <code>UNION</code> would have nothing to surface.</p>
            <p>What the page does return is the driver&#39;s error text. That turns a diagnostic into a channel,
            and the standard way to load it with data on MySQL is to hand a subquery to a function that reports the
            value it choked on:</p>
            <pre class="lk-sinkline">extractvalue(1, concat(0x7e, (SELECT &hellip;)))
updatexml(1, concat(0x7e, (SELECT &hellip;)), 1)</pre>
            <p>Both parse their second argument as an XPath expression. A leading <code>~</code> is not valid
            XPath, so MySQL raises <code>XPATH syntax error</code> and quotes the offending string back &mdash;
            your subquery&#39;s result, verbatim.</p>
            <table class="lk-kv">
                <tr><td>context</td><td><code>id = INPUT</code>, numeric. No quote to escape, so no quote filter can help.</td></tr>
                <tr><td>window</td><td>32 characters: the <code>~</code> plus 31 of yours. Anything longer is silently cut.</td></tr>
                <tr><td>paging</td><td><code>substring(value, start, 31)</code>, moving <code>start</code> by 31 each request.</td></tr>
                <tr><td>quoting</td><td>String literals can be written as hex (<code>0x7365637265745f6d657373616765</code>) when quotes are inconvenient.</td></tr>
            </table>
            <p>Budget it before you start: a 55-character value is two requests, not one, and not fifty-five. That
            is the difference between error-based extraction and the blind levels &mdash; here each request returns
            31 characters rather than one bit.</p>',
        'why' => '<p>Your subquery ran, its result was concatenated after a <code>~</code>, and MySQL rejected the
            whole thing as invalid XPath &mdash; quoting the value back to you on the way out. The page then printed
            that error verbatim, so the data crossed the boundary inside a diagnostic rather than inside a result
            set.</p>
            <p>The general lesson is about what counts as output. An endpoint that returns no data can still be a
            read primitive if it returns <em>anything</em> that varies with the data: an error string, a status
            code, a response time, a content length. When you are told "this endpoint does not return anything",
            the next question is what it returns when it fails.</p>',
        'fix_bad' => '$sql    = "SELECT COUNT(*) FROM users WHERE id = $orderId";
$result = $conn->query($sql);

if ($result === false) {
    echo \'Lookup failed: \' . $conn->error;   // the whole channel
}',
        'fix_good' => '// Two independent fixes, and you want both.
//
// 1. Bind the parameter, so no subquery can be introduced at all.
$st = $conn->prepare(\'SELECT COUNT(*) FROM users WHERE id = ?\');
$st->bind_param(\'i\', $orderId);
$st->execute();

// 2. Never return the driver\'s error to the client. Log it with an id and
//    show the id, so support can correlate without the caller learning
//    anything about the schema.
try {
    $st->execute();
} catch (mysqli_sql_exception $e) {
    $ref = bin2hex(random_bytes(4));
    error_log("[$ref] " . $e->getMessage());
    http_response_code(500);
    exit("Lookup failed. Reference: $ref");
}

// In production also set display_errors=Off. Verbose errors are a finding on
// their own, independent of whether an injection is reachable.',
        'fix_note' => sqli_fix_note('Suppressing the error text would have blocked this particular read while
            leaving the injection itself intact &mdash; the boolean and timing channels from levels 5 and 6 still
            work against an endpoint that says nothing. Fix the concatenation first; treat the error disclosure as
            the second, separate defect it is.'),
        'param' => 'order_id',
        'probes' => [
            ['q' => 'Is the context numeric, or quoted?', 'payload' => '3 AND 1=1',
             'learn' => 'If this behaves like <code>3</code> and the trace shows no error, the value is being parsed as SQL in a numeric position &mdash; so nothing needs escaping.'],
            ['q' => 'Does the page return the driver&#39;s error text?', 'payload' => '3 AND',
             'learn' => 'A deliberate syntax error. What comes back tells you whether the error channel exists at all, which decides the whole approach.'],
            ['q' => 'How wide is the error window?', 'payload' => '1 AND extractvalue(1,concat(0x7e,repeat(0x41,60)))',
             'learn' => 'Sixty A&#39;s go in; count how many come back. That number is your page size for the rest of the extraction.'],
        ],
    ];

    return $c[$level] ?? [];
}
