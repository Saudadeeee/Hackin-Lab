<?php
/**
 * SQLi Lab · teaching layer
 * ---------------------------------------------------------------------------
 * Adds, underneath the existing two-panel challenge, the things a learner needs
 * in order to stop guessing:
 *
 *   - the exact statement the level built, with the controlled span highlighted
 *   - a trace of THEIR input through the SAME filter code the level runs, and
 *     on to what MySQL answered (row count, or the error text)
 *   - where the injection point sits in the SQL grammar, and what has to stay
 *     true for the statement to keep parsing
 *   - probes: one question each, never a finished exploit
 *   - on success, why that payload changed the parse
 *   - the fix, concatenation beside a prepared statement
 *
 * Nothing here changes challenge behaviour or flag values. Filters are
 * recomputed with the same expressions the level pages run, and no statement is
 * ever re-executed from this file.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/teaching_9_16.php';
require_once __DIR__ . '/teaching_render.php';

/* =========================================================================
 * Shared prose
 * ===================================================================== */

/** The part of "the fix" that is identical everywhere: what binding cannot do. */
function sqli_fix_note(string $lead = ''): string
{
    $common = '<p>A bound parameter is a value, not text. The driver sends the statement and the data on
        separate paths, so nothing in the data can move the parse boundary. That covers every <em>value</em>
        position, including all of the ones on this page.</p>
        <p>Parameters cannot bind <strong>identifiers</strong>. Table names, column names, the column in
        <code>ORDER BY</code>, and <code>LIMIT</code>/<code>OFFSET</code> on MySQL are parsed as syntax rather
        than as data, so a placeholder is rejected there. When user input has to choose one of those, map it
        through an allowlist you wrote:</p>
        <pre class="lk-sinkline">$cols  = [&#39;name&#39; =&gt; &#39;username&#39;, &#39;joined&#39; =&gt; &#39;created_at&#39;];
$order = $cols[$_GET[&#39;sort&#39;] ?? &#39;&#39;] ?? &#39;id&#39;;          // input picks a key, never the SQL
$dir   = ($_GET[&#39;dir&#39;] ?? &#39;&#39;) === &#39;desc&#39; ? &#39;DESC&#39; : &#39;ASC&#39;;
$limit = max(1, min(100, (int)($_GET[&#39;limit&#39;] ?? 20)));  // cast, then clamp</pre>
        <p>The text that reaches the statement is text you wrote; the input only chooses which of your strings
        is used. Escaping functions (<code>addslashes</code>, <code>mysqli_real_escape_string</code>) are not a
        substitute: they are correct only for a quoted string literal, they do nothing useful in a numeric
        context, and they are undone the moment the value is read back out and concatenated a second time.</p>';

    return ($lead !== '' ? '<p>' . $lead . '</p>' : '') . $common;
}

/* =========================================================================
 * Per-level static content
 * ===================================================================== */

function sqli_teach_content(int $level): array
{
    $c = [];

    $c[1] = [
        'model_title' => 'Injection point: inside a single-quoted string literal',
        'model' => '<p>The statement is one <code>SELECT</code> with two string literals in its
            <code>WHERE</code> clause. Your username is written between the opening quote of the first literal
            and its closing quote. From the lexer&#39;s point of view everything after that opening quote is
            string content until the next unescaped <code>&#39;</code>: no keyword, no operator and no comment
            marker means anything while the lexer is in that state.</p>
            <p>So the whole question for this context is whether a <code>&#39;</code> reaches the parser. If it
            does, the literal ends where you say it ends, and from that point you are writing SQL. Three things
            then have to stay true for the statement to run:</p>
            <table class="lk-kv">
                <tr><td>balance</td><td>Every literal that opens must close. The statement already contains a
                    trailing <code>&#39; AND password = &#39;&hellip;&#39;</code> and those quotes are still
                    being counted.</td></tr>
                <tr><td>the tail</td><td>You either satisfy that trailing predicate, absorb it into a literal of
                    your own, or remove it with a comment.</td></tr>
                <tr><td>comments</td><td>MySQL accepts <code>#</code> to end of line, <code>-- </code> to end of
                    line <em>only when a whitespace character follows the two dashes</em>, and
                    <code>/*&hellip;*/</code> inline.</td></tr>
            </table>
            <p>One more property of the PHP around it: <code>fetch_assoc()</code> is called once, so the role
            check runs against whichever row MySQL returned first, not against every match.</p>',
        'why' => '<p>Your <code>&#39;</code> closed the username literal. The bytes after it were read as SQL
            tokens instead of as data, so the row test became one you wrote rather than the one in the source.
            The statement still parsed, which is what separates an injection from a syntax error.</p>
            <p>Nothing was escaped anywhere along the path: <code>$_POST[&#39;username&#39;]</code> is
            concatenated into the string exactly as received. The trace above shows the value at each step, and
            every step holds the same bytes.</p>',
        'fix_bad' => '$sql = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\'";
$result = $conn->query($sql);',
        'fix_good' => '// The statement is fixed text. The values travel separately and are
// never parsed as SQL, whatever bytes they contain.
$stmt = $conn->prepare(
    \'SELECT id, username, role, password_hash FROM users WHERE username = ?\'
);
$stmt->bind_param(\'s\', $username);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

if ($row && password_verify($password, $row[\'password_hash\'])) {
    // authenticated
}

// Note what changed besides the binding: the password is no longer
// compared in SQL at all. Select the user by name, verify the hash
// in PHP. That removes the second literal instead of escaping it.',
        'fix_note' => sqli_fix_note('This level has two value positions. The rewrite binds the first and
            deletes the second, because comparing a plaintext password inside a query is a second bug sitting
            on top of the first one.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does a single quote reach the parser?', 'payload' => "'",
             'learn' => 'The panel reports the MySQL error and the statement it tried to run. An error is the useful answer here: it proves the byte arrived unescaped and that the literal ended one character early.'],
            ['q' => 'Is failing to match the same as failing to parse?', 'payload' => 'admin',
             'learn' => 'A name that exists, sent with an empty password. The statement parses and returns nothing, because the second literal matches nobody. Compare the two responses: one is the data saying no, the other is the parser saying no.'],
            ['q' => 'Where does my value end, in the parser&#39;s view?', 'payload' => "a' AND '1'='1",
             'learn' => 'Quotes balance, so the statement parses. Read the assembled SQL in the trace: it now contains a comparison you wrote. No rows come back, which is what a probe should do &mdash; answer the question without finishing the job.'],
        ],
    ];

    $c[2] = [
        'model_title' => 'Injection point: a numeric context, with no quote to escape',
        'model' => '<p><code>WHERE id = $user_id</code> has no quotes around it. You do not begin inside a
            string literal, you begin in <em>expression</em> position, and there is nothing to close before you
            can write SQL. Filters that strip or escape quotes do nothing to a context like this one, which is
            why numeric parameters are so often the ones still vulnerable after a codebase has been
            &quot;fixed&quot;.</p>
            <p>The left-hand query is <code>SELECT id, username, role FROM users</code>, so a
            <code>UNION</code> has to line up with it:</p>
            <table class="lk-kv">
                <tr><td>column count</td><td>Both sides must project the same number of columns.
                    <code>ORDER BY n</code> is the cheap way to count: the largest <code>n</code> that does not
                    raise <em>Unknown column &#39;n&#39; in &#39;order clause&#39;</em> is the answer.</td></tr>
                <tr><td>the tail</td><td><code>AND password = &#39;&hellip;&#39;</code> is still appended.
                    Attached to a second <code>SELECT</code> that has no <code>FROM</code> clause, the name
                    <code>password</code> is not a column of anything and MySQL raises error 1054. Removing the
                    tail with a comment is what makes the union parse.</td></tr>
                <tr><td>what PHP checks</td><td>Every returned row is examined and any row whose
                    <code>role</code> or <code>username</code> is <code>admin</code> is enough. A row you
                    fabricated counts.</td></tr>
            </table>
            <p>The panel prints only &quot;Login failed&quot; when a statement errors, because
            <code>mysqli</code> is not in exception mode under PHP 8.0 and the <code>catch</code> block in the
            source panel never runs. The trace below prints <code>$conn-&gt;error</code>, so read your errors
            there.</p>',
        'why' => '<p>The union appended a second result set whose columns line up with the first, and PHP read
            your fabricated row as though it had come out of the <code>users</code> table. The comment removed
            the trailing password predicate, which the second <code>SELECT</code> could not have satisfied: it
            has no <code>FROM</code> clause, so <code>password</code> names nothing.</p>
            <p>No quote was needed to get here. That is what this level teaches &mdash; in a numeric context the
            injection point is open before you type anything.</p>',
        'fix_bad' => '$sql = "SELECT id, username, role FROM users WHERE id = $user_id AND password = \'$password\'";
$result = $conn->query($sql);',
        'fix_good' => '// \'i\' binds an integer. The value is sent as a number, so text in it
// is not text in the statement - there is no expression to extend.
$stmt = $conn->prepare(
    \'SELECT id, username, role FROM users WHERE id = ? AND password_hash = ?\'
);
$stmt->bind_param(\'is\', $userId, $hash);
$stmt->execute();

// If a value has to stay inside the string for some reason, cast it.
// (int) is total: every possible input maps to an integer.
//   $id = (int)($_POST[\'user_id\'] ?? 0);
// (int) and intval() are correct here. addslashes() is not, because
// an unquoted number needs no quote to be attacked.',
        'fix_note' => sqli_fix_note('The mistake worth naming on this level is reaching for an escaping
            function. <code>mysqli_real_escape_string()</code> escapes quotes so a value is safe <em>inside a
            quoted literal</em>. In an unquoted numeric context it changes nothing that matters, because the
            attack never needs a quote. A cast is the correct minimum; a bound integer is better.'),
        'param' => 'user_id',
        'probes' => [
            ['q' => 'Is this value inside quotes or not?', 'payload' => "1'",
             'learn' => 'One unbalanced quote. Read the error in the trace: it points at the quote as unexpected input rather than at an unterminated string, which is what a numeric context looks like from the parser.'],
            ['q' => 'How many columns does this SELECT project?', 'payload' => '1 ORDER BY 4#',
             'learn' => 'The trailing predicate is commented away so only the ORDER BY is under test. Compare with <code>1 ORDER BY 3#</code>. The largest position that does not raise error 1054 is the column count a UNION has to match.'],
            ['q' => 'Is the value evaluated as an expression?', 'payload' => '2-1',
             'learn' => 'If the row for id 1 comes back, MySQL evaluated arithmetic where the source expected a literal. Expression position confirmed with three characters and no quote.'],
        ],
    ];

    $c[3] = [
        'model_title' => 'Two statements, and only one of them accepts a list',
        'model' => '<p>This page runs your username through two different APIs:</p>
            <table class="lk-kv">
                <tr><td><code>$conn-&gt;query()</code></td><td>The existence check,
                    <code>SELECT COUNT(*) &hellip; WHERE username = &#39;$username&#39;</code>. This function
                    executes exactly one statement. A <code>;</code> followed by more SQL is a syntax error, the
                    call returns <code>false</code>, the page reports that the user does not exist, and the
                    second query never runs.</td></tr>
                <tr><td><code>$conn-&gt;multi_query()</code></td><td>The login,
                    <code>SELECT * &hellip; username = &#39;$username&#39; AND password = &#39;$password&#39;</code>.
                    This one executes a <code>;</code>-separated <em>list</em> of statements.</td></tr>
            </table>
            <p><code>$password</code> appears only in the second one. That is the whole map: the semicolon has
            to go in the password field, because the username field has to survive a single-statement parser
            first.</p>
            <p>What a stacked statement buys you is a <em>write</em>. <code>SELECT</code> is not the only verb,
            and the account this page uses (<code>webapp</code>) holds <code>INSERT</code>, <code>UPDATE</code>
            and <code>DELETE</code> on <code>users</code> as well.</p>
            <p>Output is a separate matter. The PHP loop inspects result sets, and a stacked
            <code>UPDATE</code> produces none, so a successful write shows you nothing on that request. The
            effect is in the database. You observe it on the <em>next</em> request, by logging in normally and
            reading back what you changed. Expecting immediate feedback is what makes people conclude that a
            working stacked payload failed.</p>',
        'why' => '<p>Your <code>;</code> ended the <code>SELECT</code> and the bytes after it were parsed as a
            second statement, which <code>multi_query()</code> then ran. The first result set was empty, so the
            page reported a failed login while the write had already happened. Reading the row back on the next
            request is what turned an invisible effect into a visible one.</p>
            <p>The semicolon had to be in the password field because of the existence check above it:
            <code>query()</code> would have rejected the same bytes in the username before the login statement
            was ever built.</p>',
        'fix_bad' => '$check = "SELECT COUNT(*) as count FROM users WHERE username = \'$username\'";
$sql   = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\'";
$conn->multi_query($sql);',
        'fix_good' => '// Bind both values, and do not use the multi-statement API at all.
$stmt = $conn->prepare(\'SELECT id, username, role, password_hash FROM users WHERE username = ?\');
$stmt->bind_param(\'s\', $username);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

if ($row && password_verify($password, $row[\'password_hash\'])) {
    // authenticated
}

// multi_query() exists for batch scripts, not for request handling.
// A prepared statement cannot execute a statement list at all, which
// is a second and independent reason this class of payload dies.',
        'fix_note' => sqli_fix_note('Two independent defences appear above and either one alone would have
            stopped this. Binding the values removes the injection; using a single-statement API removes the
            <em>stacking</em>. Both are worth having, because the two failures have different blast radii: a
            <code>SELECT</code> injection reads, a stacked statement writes.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does my username really reach two separate queries?', 'payload' => 'admin',
             'learn' => 'A name that exists, with an empty password. The page reports a wrong password rather than an unknown user, so the first query found a row and the second did not. Two round trips, two injection points.'],
            ['q' => 'Which of the two rejects a statement list?', 'payload' => "test';SELECT 1;",
             'learn' => 'This dies in the existence check. <code>query()</code> parses one statement, fails, and the page says the user does not exist &mdash; nothing ran. That failure is what tells you the username field is the wrong place for a semicolon.'],
            ['q' => 'Does the quote reach both statements?', 'payload' => "test' AND '1'='1",
             'learn' => 'Balanced, so both parse. The count query returns a row (the user exists) and the login query returns none (the password is empty). Both statements were rewritten by the same field.'],
        ],
    ];

    $c[4] = [
        'model_title' => 'A keyword list you can see, and a character strip doing the real work',
        'model' => '<p>The order of operations decides everything on this level:</p>
            <ol>
                <li>the input is lowercased and searched for 13 substrings &mdash;
                    <code>union select or and admin -- # /* */ drop insert update delete</code> &mdash; with
                    <code>strpos</code>, so the match is by <em>substring</em>, anywhere in either field;</li>
                <li>then <code>str_replace([&quot;&#39;&quot;, &#39;&quot;&#39;, &#39;;&#39;], &quot;&quot;)</code>
                    <strong>deletes</strong> every quote and semicolon from both fields;</li>
                <li>then the string is concatenated into the statement.</li>
            </ol>
            <p>Step 2 is the one that holds. Your value is written inside
            <code>username = &#39;&hellip;&#39;</code>, and in that context the only character that can end the
            literal is <code>&#39;</code>. It is deleted, so no input can move the parse boundary. The
            13-word list is the visible part and the least important part.</p>
            <p>That leaves a statement whose shape you cannot change:
            <code>username = &#39;X&#39; AND password = &#39;Y&#39; AND role = &#39;admin&#39;</code>. It
            returns a row only if such a row exists. The stock administrator is not usable, because the word
            <code>admin</code> is on the block list and is checked against what you send.</p>
            <p>So the question this level actually asks is: <em>where does a row like that come from?</em> The
            database is shared by all sixteen levels, and levels 3, 8 and 10 each write to <code>users</code>. A
            row created there, with a username and a password containing none of the 13 substrings, satisfies
            this statement with no injection here at all. That is the realistic version of the attack &mdash;
            the filter on this endpoint holds, and the endpoint next to it does not.</p>',
        'why' => '<p>The row your credentials matched already had <code>role = &#39;admin&#39;</code>, so the
            third predicate was true without a single character of the statement changing shape. What you got
            past was the word list. The quote strip was never defeated, because it does not need to be.</p>
            <p>That reading generalises: a filter that removes the metacharacter of the context works, and a
            filter that removes keywords does not. What breaks the first one is a second endpoint writing to the
            same table.</p>',
        'fix_bad' => '$blocked = [\'union\', \'select\', \'or\', \'and\', \'admin\', \'--\', \'#\', \'/*\'];
foreach ($blocked as $word) {
    if (strpos(strtolower($username), $word) !== false) { /* reject */ }
}
$username = str_replace(["\'", \'"\', \';\'], "", $username);
$sql = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\' AND role = \'admin\'";',
        'fix_good' => '// Bind the values and delete the filter. It has a false-positive rate
// (every name containing "or" or "and" is rejected: Doris, Sandra,
// Alexander) and a false-negative rate, and it costs a code review
// every time somebody adds a word to it.
$stmt = $conn->prepare(
    \'SELECT id, username, role, password_hash FROM users WHERE username = ?\'
);
$stmt->bind_param(\'s\', $username);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

// Authorisation is a separate decision from lookup. Building
// "AND role = \'admin\'" into the query makes the query the access
// control check, so every future caller inherits it silently.
// Fetch the user, then ask whether that user may do the thing.',
        'fix_note' => sqli_fix_note('Note what happened to the blacklist under pressure: it grew to 13
            entries, it rejects ordinary names, and the level is still solvable. A blacklist has to enumerate
            every dangerous input. A bound parameter has to enumerate nothing.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Which stage stops me &mdash; the word list or the character strip?', 'payload' => 'Or',
             'learn' => 'Two letters, blocked. The input is lowercased before the search and the search is a substring search, so this also fires inside any longer word. Note which stage the trace marks as blocking.'],
            ['q' => 'Do quotes reach the statement, or are they removed?', 'payload' => "a'b",
             'learn' => 'No blocked word, so this passes stage 1. Watch stage 2 in the trace turn it into <code>ab</code>. Deletion, not escaping &mdash; there is no encoded form of the quote left to work with.'],
            ['q' => 'Is the role check in SQL or in PHP?', 'payload' => 'alice',
             'learn' => 'A real user, with an empty password. Read the assembled statement: <code>AND role = &#39;admin&#39;</code> is part of it. Any row you can match must already be an administrator, which tells you what you actually need to find.'],
        ],
    ];

    $c[5] = [
        'model_title' => 'Blind: one bit per request, and the arithmetic that follows from that',
        'model' => '<p>The statement is <code>SELECT COUNT(*) as count &hellip;</code>. It always returns
            exactly one row, so the row count carries no information. The only thing that varies is the number
            inside that row, and PHP reduces even that to a yes or a no.</p>
            <p><strong>Three responses, all HTTP 200.</strong> Telling them apart is the first job, before any
            extraction:</p>
            <table class="lk-kv">
                <tr><td><code>COUNT &gt; 0</code></td><td>the success block and the flag &mdash; your predicate
                    was true</td></tr>
                <tr><td><code>COUNT = 0</code></td><td><em>Access denied.</em> &mdash; your predicate was false,
                    and the statement ran</td></tr>
                <tr><td>query returned false</td><td><em>Security system triggered.</em> &mdash; the statement
                    did not parse, so it never ran</td></tr>
            </table>
            <p>The third is not a &quot;false&quot;. It carries no information about the data, only about your
            syntax. Mistaking it for a false is how a blind search returns confident garbage; the two look
            similar in a diff and mean opposite things.</p>
            <p><strong>The cost arithmetic.</strong> An oracle that answers one bit per request has a price you
            can compute in advance, which is the reason to compute it rather than start typing. For an unknown
            of length <code>L</code> over an alphabet of <code>N</code> candidates:</p>
            <table class="lk-kv">
                <tr><td>find the length</td><td>linear <code>LENGTH()=1,2,3&hellip;</code>: <code>L</code>
                    requests. Binary over 1&ndash;64: <strong>6</strong>.</td></tr>
                <tr><td>one character, linear</td><td>compare against each candidate in turn: <code>N</code>
                    worst case, <code>N/2</code> on average. Printable ASCII is 95 candidates, so about
                    <strong>48</strong>.</td></tr>
                <tr><td>one character, binary</td><td>compare the byte value with <code>&gt;</code> and halve
                    the range: <code>ceil(log2 N)</code>. 95 candidates &rarr; <strong>7</strong>. Lowercase and
                    digits (36) &rarr; 6. Hex (16) &rarr; 4.</td></tr>
                <tr><td>an 8-character secret</td><td>binary: 8 &times; 7 = <strong>56</strong>, plus 6 for the
                    length = <strong>62 requests</strong>. Linear: 8 &times; 48 &asymp; <strong>384</strong>.</td></tr>
                <tr><td>guessing the value itself</td><td>95<sup>8</sup> &asymp; 6.6 &times; 10<sup>15</sup>.
                    This is the number that makes fuzzing the wrong tool: it is not slower than the search, it
                    is a different order of problem.</td></tr>
            </table>
            <p>Two things cut the 62 further. The requests are independent, so they parallelise; and the moment
            you learn the alphabet is narrower &mdash; hex, lowercase, digits &mdash; <code>log2 N</code> drops
            and every remaining character gets cheaper. Spend a request finding that out before spending 56 on
            the assumption that it is 95.</p>
            <p><strong>The shape you need.</strong> The whole <code>WHERE</code> clause has to be true exactly
            when your predicate is true, which means the parts you did not write &mdash; the password literal
            and <code>AND role = &#39;admin&#39;</code> &mdash; have to be neutralised or satisfied first. Get
            that shape parsing with a constant condition, verify you can produce both a true and a false, and
            only then substitute the real predicate.</p>',
        'why' => '<p>Your predicate replaced the row test, and the page answered it with one of the two states
            above. Nothing was leaked directly: the statement never returned data, it returned a count, and PHP
            reduced the count to a boolean. Everything you can learn from this endpoint arrives one bit at a
            time, which is why the arithmetic above is the design step rather than an afterthought.</p>',
        'fix_bad' => '$sql = "SELECT COUNT(*) as count FROM users
         WHERE username = \'$username\' AND password = \'$password\' AND role = \'admin\'";
$count = $conn->query($sql)->fetch_assoc()[\'count\'];',
        'fix_good' => '// Binding closes the oracle: the predicate cannot be replaced, so
// there is no bit to read out.
$stmt = $conn->prepare(
    \'SELECT id, password_hash, role FROM users WHERE username = ?\'
);
$stmt->bind_param(\'s\', $username);
$stmt->execute();
$row = $stmt->get_result()->fetch_assoc();

$ok = $row !== null && password_verify($password, $row[\'password_hash\']);
// Compare in PHP, and answer with one message for every failure.
// Distinct responses for "no such user" and "wrong password" are a
// user-enumeration oracle even when the injection is gone.',
        'fix_note' => sqli_fix_note('Blind injection is not a weaker bug than the ones that print data, it is
            the same bug with a slower readout. Rate limiting raises the cost of the 62 requests but does not
            remove the oracle, and it is not a fix &mdash; it is a delay applied to an attack that still
            terminates.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'What does a well-formed false look like?', 'payload' => 'admin',
             'learn' => 'A real name with an empty password. The statement parses and the count is zero, so the page says <em>Access denied.</em> This is your baseline for false.'],
            ['q' => 'What does a parse failure look like?', 'payload' => "admin'",
             'learn' => 'One unbalanced quote. The page says <em>Security system triggered.</em> Learn this response before you start searching, or half the bits you collect will be syntax errors recorded as false.'],
            ['q' => 'Can I build a condition that is false without touching the password column?',
             'payload' => "admin' AND '1'='2",
             'learn' => 'Balanced, parses, count is zero. You now hold a shape that reaches the parser and a constant you can swap. The search is this same statement with <code>&#39;1&#39;=&#39;2</code> replaced by the question you actually want answered.'],
        ],
    ];

    $c[6] = [
        'model_title' => 'Blind: the channel is elapsed time, and time is expensive',
        'model' => '<p>Every failure on this page produces the same sentence &mdash; <em>Login failed: Invalid
            credentials.</em> &mdash; followed by the measured query time. A statement that does not parse lands
            in the same branch with a small time. So there are two states you read (fast and slow) and one you
            have to exclude (did not parse), and the response body cannot tell you which.</p>
            <p><strong>How SLEEP behaves.</strong> <code>SLEEP(n)</code> is a function evaluated per row the
            predicate is tested against, not once per statement. Two consequences:</p>
            <table class="lk-kv">
                <tr><td>put it behind a branch</td><td><code>IF(condition, SLEEP(n), 0)</code> costs time only
                    when the condition holds, which is what makes the reading a bit rather than a constant.</td></tr>
                <tr><td>pin the row</td><td>Anchor the predicate on an indexed equality so it is evaluated once.
                    <code>username</code> is indexed here (<code>idx_username</code> in
                    <code>init.sql</code>). Without an anchor, a sleep inside a full scan of this 36-row table
                    runs 36 times.</td></tr>
            </table>
            <p><strong>The cost arithmetic.</strong> The request count is the same as the boolean level &mdash;
            binary search, <code>ceil(log2 N)</code> per character &mdash; but each true answer now costs
            wall-clock time:</p>
            <table class="lk-kv">
                <tr><td>requests</td><td>7 per character over printable ASCII. An 8-character secret: 56
                    requests, plus about 6 to find the length.</td></tr>
                <tr><td>true answers</td><td>A binary search splits the range in half each step, so roughly half
                    the 56 come back true: about <strong>28</strong>.</td></tr>
                <tr><td>with SLEEP(3)</td><td>28 &times; 3 s = <strong>84 seconds</strong> of sleeping, on top
                    of a baseline this page reports in fractions of a millisecond.</td></tr>
                <tr><td>with SLEEP(1)</td><td>about <strong>28 seconds</strong> &mdash; but the gap between true
                    and false has to stay larger than the jitter, so measure the baseline first and pick
                    <code>n</code> against that measurement, not by habit.</td></tr>
                <tr><td>linear instead of binary</td><td>about 384 requests, roughly 192 of them true:
                    <strong>9.6 minutes</strong> at 3 s. The same factor of seven as the boolean level, now
                    denominated in minutes.</td></tr>
                <tr><td>an unanchored sleep</td><td>36 rows &times; <code>n</code>. At
                    <code>SLEEP(1)</code> that is a 36-second request that looks like a timeout rather than a
                    signal.</td></tr>
            </table>
            <p>Time-based extraction is strictly worse than boolean-based: same request count, far higher
            latency, and a channel that noise can corrupt. Reach for it only when the response body is
            genuinely identical for true and false. Here it is, which is what makes this the right level to
            practise it on.</p>',
        'why' => '<p>The sleep ran only on the branch your condition selected, so the number of milliseconds the
            page printed carried the bit. The response text was the same either way, which is the definition of
            this channel: you are not reading the answer, you are timing it.</p>',
        'fix_bad' => '$start = microtime(true);
$sql = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\' AND role = \'admin\'";
$result = $conn->query($sql);
$time_taken = round((microtime(true) - $start) * 1000, 2);',
        'fix_good' => '// Binding removes the ability to call SLEEP at all, because the value
// is never parsed as an expression.
$stmt = $conn->prepare(\'SELECT id, password_hash, role FROM users WHERE username = ?\');
$stmt->bind_param(\'s\', $username);
$stmt->execute();

// Do not print timing to the client. Timing that varies with data
// is a channel whether or not you label it, and publishing the
// measurement removes the attacker\'s need for statistics.
// Log it server-side instead, and alert on statements whose
// duration exceeds a threshold - a SLEEP payload is visible there.',
        'fix_note' => sqli_fix_note('A statement timeout (<code>MAX_EXECUTION_TIME</code>, or
            <code>max_statement_time</code>) caps the delay a single request can be made to produce, which
            shrinks the channel without closing it. It is a useful hardening measure and it is not the fix; the
            fix is that the value never becomes an expression.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'What is the baseline?', 'payload' => 'alice',
             'learn' => 'Read the milliseconds the page prints. Every measurement you take later is relative to this number, and if you skip it you have no idea how large a delay has to be before it means something.'],
            ['q' => 'Does SLEEP execute inside this predicate?', 'payload' => "alice' AND SLEEP(2)#",
             'learn' => 'Expect roughly 2000 ms and no rows. The delay confirms the syntax reached the parser; the failed login confirms the probe did not do anything else. Both halves matter.'],
            ['q' => 'Is the response body identical between true and false?', 'payload' => "alice' AND '1'='2",
             'learn' => 'Same sentence as the previous probe, small time. Put the two responses side by side: the only difference is the number of milliseconds, which is what tells you the body is not a channel here.'],
        ],
    ];

    $c[7] = [
        'model_title' => 'Injection point: a string literal, with the database account as the boundary',
        'model' => '<p>The statement has the same shape as level 6 without the timer. What is different is the
            target. <code>SELECT &hellip; INTO OUTFILE &#39;/path&#39;</code> writes the result set to a file on
            the <em>database</em> server, one row per line, tab-separated. It is the classic out-of-band
            channel: the data leaves through the filesystem instead of through the response.</p>
            <p>Three conditions all have to hold, and separating them is the point of this level:</p>
            <table class="lk-kv">
                <tr><td>the statement parses</td><td>your injection is syntactically correct</td></tr>
                <tr><td>the account holds <code>FILE</code></td><td>a global privilege, not a table
                    grant</td></tr>
                <tr><td>the path is allowed</td><td>it must sit under <code>secure_file_priv</code>, and the
                    file must not already exist</td></tr>
            </table>
            <p>Here the account is <code>webapp</code>, and <code>init.sql</code> grants it
            <code>SELECT, INSERT, UPDATE, DELETE</code> on three tables and nothing else &mdash; no
            <code>FILE</code>. <code>secure_file_priv</code> is set to <code>/var/lib/mysql-files</code> by the
            <code>command:</code> line in <code>docker-compose.yml</code>. So <code>INTO OUTFILE</code> returns
            error 1045 instead of writing.</p>
            <p>That error is the useful result, not a dead end. It separates &quot;my SQL is wrong&quot; from
            &quot;my SQL is right and this account is not allowed&quot;, and those two lead to completely
            different next moves. The challenge panel does not print it, because <code>mysqli</code> is not in
            exception mode under PHP 8.0 and the <code>catch</code> block in the source panel never runs. The
            trace below prints <code>$conn-&gt;error</code>.</p>
            <p>Worth knowing about the plumbing: a successful write would land on the <code>db</code> container.
            <code>./mysql-files</code> is bind-mounted there as <code>/var/lib/mysql-files</code>, so the file
            would appear in the lab directory on your disk &mdash; not at the path the PHP existence check in
            the source panel looks at, which is a path inside the <em>web</em> container.</p>',
        'why' => '<p>The literal closed and the statement parsed, which is the part of this attack that depends
            on the application. What happens next does not: it depends on a grant in the database, and on this
            installation that grant is missing. The flag is awarded for reaching the administrator row, and the
            file channel is the lesson sitting beside it.</p>
            <p>The generalisable point is that the application boundary and the database boundary are different
            boundaries. An injection that reads every row can still be unable to write one byte to disk, and the
            reason is one line in a <code>GRANT</code>.</p>',
        'fix_bad' => '$sql = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\' AND role = \'admin\'";
$result = $conn->query($sql);',
        'fix_good' => '// The application fix is the same as every other level: bind it.
$stmt = $conn->prepare(\'SELECT id, password_hash, role FROM users WHERE username = ?\');
$stmt->bind_param(\'s\', $username);
$stmt->execute();

// The database fix is a grant, and it is what limits the damage of
// the injection you have not found yet:
//   GRANT SELECT, INSERT, UPDATE ON app.users TO \'webapp\'@\'%\';
// and never FILE, never SUPER, never a superuser account for the
// request path. Set secure_file_priv to a directory nothing reads,
// or disable it. local_infile = 0 closes the read direction too.',
        'fix_note' => sqli_fix_note('This is where least privilege earns its keep. The application bug is
            identical to level 1, and the difference in outcome &mdash; reading one table versus writing files
            on the database host &mdash; is decided entirely by what the connection account was granted. Give
            the request path an account that can do the queries the application actually issues, and nothing
            else.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does the literal close cleanly here?', 'payload' => "admin' AND '1'='2",
             'learn' => 'Balanced and parses, no rows, and no error line in the trace. Establish that the injection point works before you test what the account is allowed to do with it.'],
            ['q' => 'Does this account hold FILE?', 'payload' => "x' INTO OUTFILE '/var/lib/mysql-files/probe.txt'#",
             'learn' => 'Read the trace. Error 1045 means the syntax was accepted and the privilege was refused &mdash; two different facts, and only the second one is bad news for this route.'],
            ['q' => 'How many columns would a dump write?', 'payload' => "x' AND 1=2 UNION SELECT 1#",
             'learn' => 'Error 1222 reports that the two SELECTs project different numbers of columns, which tells you how wide <code>SELECT *</code> on this table is. UNION and INTO OUTFILE both care about that number.'],
        ],
    ];

    $c[8] = [
        'model_title' => 'Second order: data in the first statement, syntax in the third',
        'model' => '<p>Two requests and three statements. Follow the value, not the payload:</p>
            <table class="lk-kv">
                <tr><td>register</td><td><code>INSERT INTO users (username, password, email) VALUES
                    (&#39;$u&#39;, &#39;$p&#39;, &#39;$e&#39;)</code> &mdash; your email is a <em>value</em>
                    here</td></tr>
                <tr><td>login, statement 1</td><td><code>SELECT * FROM users WHERE username = &#39;$u&#39; AND
                    password = &#39;$p&#39;</code> &mdash; reads the row back</td></tr>
                <tr><td>login, statement 2</td><td><code>SELECT COUNT(*) as count FROM users WHERE email =
                    &#39;$stored_email&#39; AND role = &#39;admin&#39;</code> &mdash; concatenates the column
                    you controlled</td></tr>
            </table>
            <p>The requirement is unusual and it is the whole lesson: the payload has to survive statement 1
            <strong>as data</strong> and act in statement 3 <strong>as syntax</strong>. Those pull in opposite
            directions.</p>
            <p>Send a bare <code>&#39;</code> in the email and the <code>INSERT</code> itself changes shape, so
            what gets stored is not what you wrote. <code>x&#39; OR &#39;1&#39;=&#39;1</code> placed in that
            <code>VALUES</code> list is evaluated by MySQL as the expression
            <code>&#39;x&#39; OR &#39;1&#39;=&#39;1&#39;</code>, which is the number 1, and the column ends up
            holding <code>1</code>. The payload arrived and was consumed.</p>
            <p>Escaping the quote for the <code>INSERT</code> solves both halves at once. MySQL stores a literal
            <code>&#39;</code> in the column, and that stored quote is a metacharacter again the moment
            statement 2 concatenates it. This is exactly why &quot;escape on input&quot; is not a strategy: an
            escape belongs to one statement, and a value that has been read back out of storage is raw text
            again.</p>
            <p>Precedence finishes the job. <code>email = &#39;x&#39; OR &#39;1&#39;=&#39;1&#39; AND role =
            &#39;admin&#39;</code> groups as <code>email = &#39;x&#39; OR (&#39;1&#39;=&#39;1&#39; AND role =
            &#39;admin&#39;)</code>, which counts every administrator, and the PHP only asks whether the count
            is above zero.</p>',
        'why' => '<p>The column held a real quote, and the second statement concatenated it without escaping.
            From the parser&#39;s point of view statement 2 was never given a value at all &mdash; it was given
            a fragment of SQL that happened to be stored in a table.</p>
            <p>Nothing about the login request was malicious. That is what makes this class hard to find by
            testing: the request that carries the payload and the request that triggers it are different
            requests, often days apart, and neither looks wrong on its own.</p>',
        'fix_bad' => '// registration
$sql  = "INSERT INTO users (username, password, email) VALUES (\'$u\', \'$p\', \'$e\')";
// login, second query - the stored value is concatenated again
$sql2 = "SELECT COUNT(*) as count FROM users WHERE email = \'$stored_email\' AND role = \'admin\'";',
        'fix_good' => '// Bind at BOTH ends. The second one is the one people miss, because
// the value came out of their own database and feels trusted.
$ins = $conn->prepare(\'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)\');
$ins->bind_param(\'sss\', $username, $hash, $email);
$ins->execute();

$chk = $conn->prepare(\'SELECT COUNT(*) FROM users WHERE email = ? AND role = ?\');
$chk->bind_param(\'ss\', $storedEmail, $adminRole);
$chk->execute();

// Do not "escape on the way in". An escape is correct for exactly
// one statement, and the value outlives that statement. Store the
// bytes the user sent, and escape - or better, bind - at every
// point of use.',
        'fix_note' => sqli_fix_note('The rule this level exists to teach: <strong>a value read back from your
            own database is untrusted input</strong>. So is a value from a queue, a cache, a config table, an
            imported CSV or an internal service. Trust attaches to the boundary a value crossed, and a round
            trip through storage does not launder anything.'),
        'param' => 'username',
        'probes' => [
            ['q' => 'Does the login query see the stored bytes?', 'payload' => 'alice',
             'learn' => 'A real user with an empty password: the login fails. Read the trace &mdash; it shows statement 1 with your username concatenated into it, so the first query is an injection point in its own right.'],
            ['q' => 'Which statement is the second-order sink?', 'payload' => "alice' AND '1'='2",
             'learn' => 'Parses, returns nothing, and statement 2 never runs &mdash; it only runs after a successful login. A first-order payload in this field cannot reach the second-order sink at all.'],
            ['q' => 'Does the registration INSERT escape anything?', 'payload' => "alice'",
             'learn' => 'The trace shows error 1064 on statement 1. The registration INSERT concatenates in exactly the same way, which is why a bare quote in the email field corrupts that statement instead of being stored by it.'],
        ],
    ];

    if ($level >= 9) {
        return sqli_teach_content_9_16($level);
    }
    return $c[$level] ?? [];
}
