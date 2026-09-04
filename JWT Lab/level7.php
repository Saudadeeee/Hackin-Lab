<?php
require_once __DIR__ . '/helpers.php';

$L    = 7;
$meta = jwt_levels()[$L];

/** Key table for the "key management service". Rebuilt if missing. */
function jwt_keydb(): ?PDO
{
    if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
        return null;
    }
    $file  = __DIR__ . '/keys/keys.sqlite';
    $fresh = !is_file($file);
    $pdo   = new PDO('sqlite:' . $file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
    if ($fresh) {
        $pdo->exec('CREATE TABLE signing_keys (kid TEXT PRIMARY KEY, secret TEXT, active INTEGER)');
        $st = $pdo->prepare('INSERT INTO signing_keys VALUES (?, ?, ?)');
        $st->execute(['main-2024', jwt_strong_secret(), 1]);
        $st->execute(['legacy-2019', 'letmein123', 0]);
    }
    return $pdo;
}

$issued = jwt_encode(
    ['typ' => 'JWT', 'alg' => 'HS256', 'kid' => 'main-2024'],
    ['sub' => 'guest', 'name' => 'Guest User', 'role' => 'user',
     'iss' => 'https://auth.hackinlab.internal', 'iat' => time(), 'exp' => time() + 3600],
    jwt_strong_secret()
);

$token    = trim((string)($_POST['token'] ?? ''));
$flag     = '';
$result   = '';
$pipeline = [];
$db       = jwt_keydb();

if ($db === null) {
    $result = '<div class="message error">This level needs the <code>pdo_sqlite</code> driver, which is missing
        from this PHP build. Rebuild the container image.</div>';
} elseif ($token !== '') {
    $header = jwt_header($token);
    $alg    = $header['alg'] ?? '';
    $kid    = (string)($header['kid'] ?? 'main-2024');

    // ── The vulnerable key lookup: kid concatenated into SQL. ──────────
    $sql = "SELECT secret FROM signing_keys WHERE kid = '" . $kid . "'";
    $row = $db->query($sql);
    $key = $row ? (string)$row->fetchColumn() : '';
    $err = $row ? null : ($db->errorInfo()[2] ?? 'query failed');

    $verified = ($alg === 'HS256') && $key !== '' && jwt_verify_hs256($token, $key);
    $claims   = $verified ? jwt_claims_unverified($token) : null;
    $role     = $claims['role'] ?? '';

    $pipeline = [
        ['label' => '$kid = $header["kid"]', 'value' => $kid],
        ['label' => 'SQL built by concatenation', 'value' => $sql,
         'note'  => 'The quote characters around <code>$kid</code> belong to the developer. Everything inside them
                     belongs to you.'],
        ['label' => 'first column of the first row -> $key',
         'value' => $key === '' ? '(no row / empty)' : $key,
         'note'  => $err !== null ? 'SQLite error: <code>' . lk_esc($err) . '</code>' :
                    'Whatever this query returns <em>becomes the HMAC key</em>.',
         'verdict' => $key === '' ? 'block' : null],
        ['label' => 'jwt_verify_hs256($token, $key)',
         'value' => $verified ? 'verified = true' : 'verified = false',
         'verdict' => $verified ? 'pass' : 'block'],
        ['label' => '$claims["role"]', 'value' => (string)$role, 'verdict' => $role === 'admin' ? 'pass' : null],
    ];

    if ($key === '') {
        $result = jwt_decision(false, '', 'Key lookup returned nothing for <code>' . lk_esc($kid) . '</code>.'
            . ($err !== null ? '<br><code>' . lk_esc($err) . '</code>' : ''));
    } elseif (!$verified) {
        $result = jwt_decision(false, '', 'Signature does not match the key that lookup returned.');
    } elseif ($role === 'admin') {
        $flag   = jwt_flag($L);
        $result = jwt_decision(true, 'admin', 'Admin console unlocked.');
    } else {
        $result = jwt_decision(true, (string)$role, 'Verified, role is not admin.');
    }
}

$code = <<<'PHP'
// Key management service: keys live in a table so they can be rotated
// without a deploy.
//   signing_keys(kid TEXT, secret TEXT, active INTEGER)
$kid = $header['kid'] ?? 'main-2024';

$sql = "SELECT secret FROM signing_keys WHERE kid = '" . $kid . "'";
$key = (string) $db->query($sql)->fetchColumn();

if ($key === '' || !jwt_verify_hs256($token, $key)) {
    return deny('bad key or signature');
}
$claims = jwt_claims_unverified($token);
if (($claims['role'] ?? '') === 'admin') {
    grant_admin();
}
PHP;

$fixBad = <<<'PHP'
$sql = "SELECT secret FROM signing_keys WHERE kid = '" . $kid . "'";
$key = (string) $db->query($sql)->fetchColumn();
PHP;

$fixGood = <<<'PHP'
// Bind the parameter, and constrain the row you are willing to accept.
$st = $db->prepare(
    'SELECT secret FROM signing_keys WHERE kid = ? AND active = 1'
);
$st->execute([$kid]);
$key = (string) $st->fetchColumn();

if ($key === '') {
    return deny('unknown or retired kid');
}

// Defence in depth: a kid has a known shape. Reject anything else before
// the query even runs.
if (!preg_match('/^[a-z0-9-]{1,32}$/', $kid)) {
    return deny('malformed kid');
}
PHP;

lk_page([
    'lab'        => jwtlab(),
    'level'      => $L,
    'title'      => $meta['title'],
    'difficulty' => $meta['difficulty'],
    'extra_head' => jwt_extra_head(),

    'code'       => $code,
    'vuln_lines' => [6, 7],
    'annotation' => 'Same root cause as the previous level, different sink. <code>kid</code> is concatenated into
        SQL, and the query result <em>is</em> the verification key — so an injection that returns a literal hands
        the attacker control of the key itself.',

    'theory' => '<p>Ordinary SQL injection is valued for what it lets you <em>read</em>. Here the interesting
        capability is different: the query output is fed straight into a security decision, so you do not need to
        exfiltrate anything. You need the query to return a constant you chose.</p>
        <p><code>UNION SELECT \'value\'</code> does exactly that. The original <code>WHERE</code> matches nothing,
        the union contributes one synthetic row, and <code>fetchColumn()</code> returns your literal.</p>
        <p>Generalise the pattern: whenever attacker input selects a <em>credential, key, policy or role record</em>,
        an injection is not an information leak — it is direct authorisation control. Look for this shape in
        multi-tenant key lookups, feature-flag tables, and "which SSO config applies to this domain" queries.</p>',

    'fix' => [
        'bad'  => $fixBad,
        'good' => $fixGood,
        'note' => 'The <code>active = 1</code> clause matters as much as the binding: without it, a retired key that
            leaked years ago still verifies tokens today.',
    ],

    'scenario' => '<strong>Scenario:</strong> keys are stored in a table so operations can rotate them without a
        deploy. The verifier looks the key up by <code>kid</code>.
        <br><strong>Goal:</strong> make the lookup return a key you know, then sign an admin token with it.',

    'model' => [
        'title' => 'What the query has to end up looking like',
        'html'  => '<p>Template: <code>SELECT secret FROM signing_keys WHERE kid = \'<span class="lk-inj">HERE</span>\'</code></p>
        <p>You want the final statement to be, in effect:</p>
        <pre class="lk-sinkline">SELECT secret FROM signing_keys WHERE kid = \'nope\' UNION SELECT \'mykey\'--\'</pre>
        <p>Three moving parts, and each one is a decision you can reason about:</p>
        <ul>
            <li><code>nope</code> — anything that matches no row, so your union row is the only one.</li>
            <li><code>UNION SELECT \'mykey\'</code> — one column, matching the one column being selected. A column-count
                mismatch is an error, not a silent failure, and the trace will show it.</li>
            <li><code>--</code> — comment out the developer\'s trailing quote. SQLite needs a space or newline after
                <code>--</code>; a bare <code>--\'</code> at the very end still parses, but the habit of adding a
                trailing space saves you on MySQL.</li>
        </ul>
        <p>Then HMAC your token with <code>mykey</code>. The server will do the same and agree.</p>',
    ],

    'form'     => jwt_token_form($issued, $token),
    'result'   => $result,
    'flag'     => $flag,
    'flag_msg' => 'The key store returned a key you wrote.',
    'why'      => '<p>The union added a row that the key table never contained. <code>fetchColumn()</code> is
        indifferent to where a row came from, so your literal became <code>$key</code>, and the HMAC comparison then
        succeeded honestly — you and the server used the same secret.</p>
        <p>Compare this with level 6: identical logic, one is a path and one is a query. That is the value of
        thinking in terms of <em>sinks</em> rather than in terms of vulnerability names. "Where does <code>kid</code>
        end up?" is a better question than "is this app vulnerable to SQLi?".</p>',

    'pipeline' => $pipeline,
    'probes'   => [
        'param'  => 'token',
        'method' => 'POST',
        'action' => 'level7.php',
        'items'  => [
            ['q' => 'Does a single quote reach the parser? (syntax error = yes)',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => "main-2024'"],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'x'),
             'learn'   => 'The trace prints the SQLite error. A syntax error proves the quote was not escaped — one request, one fact.'],
            ['q' => 'How many columns does the SELECT return?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => "nope' UNION SELECT 'a','b'-- "],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'x'),
             'learn'   => 'A deliberate mismatch. The error message names the expected count, so you never have to guess-and-check your way up from one.'],
            ['q' => 'Can I see the stored keys instead of replacing them?',
             'payload' => jwt_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => "nope' UNION SELECT group_concat(kid||':'||secret) FROM signing_keys-- "],
                 ['sub' => 'guest', 'role' => 'user', 'exp' => 9999999999], 'x'),
             'learn'   => 'The trace shows the resolved key, so this level doubles as a readable oracle. Exfiltrating the real key is the noisier route to the same place — worth seeing that both work.'],
        ],
    ],
    'hints' => jwt_hints($L),
]);
